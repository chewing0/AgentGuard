from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..gateway import SecurityGateway
from ..schemas import GatewayDecision, SecurityContext, ToolCall, ToolResult, ToolSpec

if TYPE_CHECKING:
    from ..agents.base import AgentRun, AgentStep


_MODEL_OBSERVATION_LIMIT = 64_000
_MODEL_OBSERVATION_EDGE = 4_096
_STRUCTURED_PROVENANCE_LIMIT = 128_000


class LangGraphAdapterError(RuntimeError):
    """Raised when the optional LangGraph/LangChain integration cannot run."""


@dataclass
class LangGraphGatewayAdapter:
    """Expose AgentGuard tools as guarded LangGraph-compatible tools.

    LangGraph itself does not own the security policy. This adapter translates
    framework tool calls into AgentGuard ``ToolCall`` objects, runs them through
    ``SecurityGateway``, and returns a JSON observation for the graph state.
    """

    gateway: SecurityGateway
    context: SecurityContext
    task_id: str = "langgraph"
    labels: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.steps: list[AgentStep] = []
        self._counter = 0
        self._structured_tool_source_content = ""
        self._framework_to_agentguard: dict[str, str] = {}
        for name in self.gateway.registry.names():
            framework_name = self.to_framework_tool_name(name)
            existing = self._framework_to_agentguard.get(framework_name)
            if existing and existing != name:
                raise LangGraphAdapterError(
                    f"Tool names {existing!r} and {name!r} both map to LangGraph name {framework_name!r}"
                )
            self._framework_to_agentguard[framework_name] = name
        self._agentguard_to_framework = {
            original: framework for framework, original in self._framework_to_agentguard.items()
        }

    def to_framework_tool_name(self, tool_name: str) -> str:
        """Return a provider-safe tool name for LangChain/LangGraph binding."""

        safe = re.sub(r"[^A-Za-z0-9_-]+", "__", tool_name).strip("_")
        return f"agentguard__{safe or 'tool'}"

    def to_agentguard_tool_name(self, tool_name: str) -> str:
        """Map a LangGraph tool name back to the registered AgentGuard tool."""

        if self.gateway.registry.get(tool_name):
            return tool_name
        original = self._framework_to_agentguard.get(tool_name)
        if original is None:
            raise KeyError(f"Unknown AgentGuard/LangGraph tool: {tool_name}")
        return original

    def as_tools(self, tool_names: list[str] | None = None) -> list[Any]:
        """Build LangChain ``StructuredTool`` wrappers for use in LangGraph graphs."""

        StructuredTool = _require_structured_tool()
        names = (
            tool_names
            if tool_names is not None
            else [
                name
                for name in self.gateway.registry.names()
                if not self.gateway.registry.require(name).metadata.get("benchmark_fixture", False)
            ]
        )
        tools: list[Any] = []
        for name in names:
            spec = self.gateway.registry.require(name)
            framework_name = self._agentguard_to_framework[name]
            args_schema = _args_schema_for(spec, framework_name)
            tools.append(
                StructuredTool.from_function(
                    func=self._tool_runner(name),
                    name=framework_name,
                    description=_tool_description(spec, name),
                    args_schema=args_schema,
                )
            )
        return tools

    def execute(
        self,
        tool_name: str,
        params: dict[str, Any] | None = None,
        *,
        step_id: str | None = None,
        source_content: str = "",
        declared_purpose: str = "",
        phase: str = "langgraph_tool",
        labels: dict[str, Any] | None = None,
    ) -> str:
        """Execute a framework tool call through the AgentGuard gateway."""

        original_tool_name = self.to_agentguard_tool_name(tool_name)
        self._counter += 1
        call = ToolCall(
            tool_name=original_tool_name,
            params=dict(params or {}),
            task_id=self.task_id,
            step_id=step_id or f"{self.task_id}-tool-{self._counter}",
            source_content=source_content,
            declared_purpose=declared_purpose,
        )
        event_labels = {
            "framework": "langgraph",
            "adapter": type(self).__name__,
            "framework_tool_name": self._agentguard_to_framework.get(original_tool_name, tool_name),
            "agentguard_tool_name": original_tool_name,
            **self.labels,
            **(labels or {}),
        }
        decision, result = self.gateway.execute(call, self.context, labels=event_labels)
        from ..agents.base import AgentStep

        self.steps.append(AgentStep(call.step_id, call, decision, result, phase=phase))
        return _observation_json(
            call,
            decision,
            result,
            sensitive_detector=self.gateway.sensitive_detector,
        )

    def tool_node(self, state: dict[str, Any]) -> dict[str, Any]:
        """LangGraph node function that handles tool calls from the latest message."""

        ToolMessage = _require_tool_message()
        messages = list(state.get("messages", []))
        if not messages:
            return {"messages": []}

        tool_messages: list[Any] = []
        source_content = str(state.get("agentguard_source_content", state.get("source_content", "")))
        declared_purpose = str(state.get("agentguard_declared_purpose", state.get("declared_purpose", "")))
        next_source_parts: list[str] = []
        for tool_call in _extract_tool_calls(messages[-1]):
            name, args, call_id = _normalize_framework_tool_call(tool_call)
            params = dict(args)
            content = _bounded_model_observation(
                self.execute(
                    name,
                    params,
                    step_id=str(call_id) if call_id else None,
                    # Provenance is application-owned graph state. Tool
                    # arguments are model-controlled and cannot set detector
                    # input or trust metadata.
                    source_content=source_content,
                    declared_purpose=declared_purpose,
                    phase="langgraph_tool_node",
                    labels={"tool_call_id": call_id} if call_id else None,
                )
            )
            step = self.steps[-1]
            step_id = step.call.step_id
            observation_source = _untrusted_observation(
                step,
                self.gateway.registry.get(step.call.tool_name),
                content,
            )
            if observation_source:
                next_source_parts.append(observation_source)
            tool_messages.append(
                ToolMessage(
                    content=content,
                    tool_call_id=str(call_id or step_id),
                    name=self._agentguard_to_framework.get(self.steps[-1].call.tool_name, name),
                )
            )
        # Preserve the exact bounded response made visible to the model.
        # Detector provenance for the next call must never be a narrower view
        # of the observation that can steer that call.
        update: dict[str, Any] = {"messages": tool_messages}
        # Generic ``MessagesState`` graphs may not declare AgentGuard's
        # provenance channels.  Only update them when the caller opted in.
        if "agentguard_source_content" in state or "source_content" in state:
            update["agentguard_source_content"] = "\n".join(next_source_parts)
        if "agentguard_declared_purpose" in state or "declared_purpose" in state:
            update["agentguard_declared_purpose"] = declared_purpose
        return update

    def should_continue(self, state: dict[str, Any], tool_node_name: str = "tools") -> str:
        """Conditional edge helper for a LangGraph ``StateGraph``."""

        messages = list(state.get("messages", []))
        if messages and _extract_tool_calls(messages[-1]):
            return tool_node_name
        try:
            from langgraph.graph import END
        except ImportError as exc:  # pragma: no cover - exercised when optional dep is absent
            raise LangGraphAdapterError(
                "LangGraph is not installed. Install with: python -m pip install -e .[langgraph]"
            ) from exc
        return END

    def to_agent_run(
        self,
        task: str,
        *,
        report_path: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentRun:
        """Return the adapter's executed LangGraph tool calls as an AgentGuard run trace."""

        from ..agents.base import AgentRun

        return AgentRun(
            task=task,
            context=self.context,
            steps=list(self.steps),
            report_path=report_path,
            metadata={"title": "LangGraph Agent Run", "agent": "langgraph", **(metadata or {})},
        )

    def _tool_runner(self, tool_name: str) -> Any:
        def run_tool(**kwargs: Any) -> str:
            content = _bounded_model_observation(
                self.execute(
                    tool_name,
                    kwargs,
                    source_content=self._structured_tool_source_content,
                    phase="langchain_structured_tool",
                )
            )
            step = self.steps[-1]
            self._structured_tool_source_content = _merge_structured_provenance(
                self._structured_tool_source_content,
                _untrusted_observation(
                    step,
                    self.gateway.registry.get(step.call.tool_name),
                    content,
                ),
            )
            return content

        run_tool.__name__ = self._agentguard_to_framework[tool_name]
        return run_tool


def _require_structured_tool() -> Any:
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on optional dependency state
        raise LangGraphAdapterError(
            "langchain-core is required for LangGraph tool binding. "
            "Install with: python -m pip install -e .[langgraph]"
        ) from exc
    return StructuredTool


def _require_tool_message() -> Any:
    try:
        from langchain_core.messages import ToolMessage
    except ImportError as exc:  # pragma: no cover - depends on optional dependency state
        raise LangGraphAdapterError(
            "langchain-core is required for LangGraph message handling. "
            "Install with: python -m pip install -e .[langgraph]"
        ) from exc
    return ToolMessage


def _args_schema_for(spec: ToolSpec, framework_name: str) -> Any:
    try:
        from pydantic import BaseModel, ConfigDict, Field, create_model
    except ImportError as exc:  # pragma: no cover - depends on optional dependency state
        raise LangGraphAdapterError(
            "pydantic is required for LangGraph tool schemas. "
            "Install with: python -m pip install -e .[langgraph]"
        ) from exc

    class StrictToolArgs(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True)

    fields: dict[str, tuple[Any, Any]] = {}
    for param_name, policy in spec.parameters.items():
        annotation = _annotation_for_policy(policy.allowed_values, policy.kind)
        default = ... if policy.required else None
        if not policy.required:
            annotation = annotation | None
        fields[param_name] = (
            annotation,
            Field(default, description=_parameter_description(policy.to_dict())),
        )
    model_name = "".join(part.capitalize() for part in framework_name.split("__")) + "Args"
    return create_model(model_name, __base__=StrictToolArgs, **fields)


def _annotation_for_policy(allowed_values: list[Any], kind: str) -> type[Any]:
    if allowed_values:
        non_bool_values = [value for value in allowed_values if not isinstance(value, bool)]
        if all(isinstance(value, bool) for value in allowed_values):
            return bool
        if non_bool_values and all(isinstance(value, int) for value in non_bool_values):
            return int
        if all(isinstance(value, float) for value in allowed_values):
            return float
    if kind in {"integer", "int"}:
        return int
    if kind in {"number", "float"}:
        return float
    if kind in {"boolean", "bool"}:
        return bool
    return str


def _parameter_description(raw_policy: dict[str, Any]) -> str:
    parts: list[str] = [f"kind={raw_policy.get('kind', 'string')}"]
    if raw_policy.get("allowed_values"):
        parts.append(f"allowed_values={raw_policy['allowed_values']}")
    if raw_policy.get("allowed_roots"):
        parts.append(f"allowed_roots={raw_policy['allowed_roots']}")
    if raw_policy.get("allowed_domains"):
        parts.append(f"allowed_domains={raw_policy['allowed_domains']}")
    if raw_policy.get("max_length"):
        parts.append(f"max_length={raw_policy['max_length']}")
    return "; ".join(parts)


def _untrusted_observation(
    step: "AgentStep",
    spec: ToolSpec | None,
    model_observation: str,
) -> str:
    if not spec or not step.decision.allowed_to_execute or step.result is None:
        return ""
    return f"Untrusted model-visible response from {step.call.tool_name}:\n{model_observation}"


def _bounded_model_observation(content: str) -> str:
    """Bound model and provenance views identically while retaining both edges."""

    if len(content) <= _MODEL_OBSERVATION_LIMIT:
        return content
    return json.dumps(
        {
            "truncated": True,
            "original_chars": len(content),
            "head": content[:_MODEL_OBSERVATION_EDGE],
            "tail": content[-_MODEL_OBSERVATION_EDGE:],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _merge_structured_provenance(current: str, new_observation: str) -> str:
    """Retain prior wrapper provenance across blocks and fail closed on growth."""

    if not new_observation:
        return current
    combined = "\n".join(part for part in (current, new_observation) if part)
    if len(combined) <= _STRUCTURED_PROVENANCE_LIMIT:
        return combined
    return (
        "BEGIN_SYSTEM_OVERRIDE provenance budget exceeded; "
        "block subsequent tool calls until a new adapter/task is created."
    )


def _tool_description(spec: ToolSpec, original_name: str) -> str:
    return (
        f"{spec.description} AgentGuard tool={original_name}; "
        f"operation={spec.operation.value}; risk={spec.risk_level.name.lower()}."
    )


def _extract_tool_calls(message: Any) -> list[Any]:
    tool_calls = getattr(message, "tool_calls", None)
    if tool_calls:
        return list(tool_calls)
    additional_kwargs = getattr(message, "additional_kwargs", {}) or {}
    raw_tool_calls = additional_kwargs.get("tool_calls")
    return list(raw_tool_calls or [])


def _normalize_framework_tool_call(tool_call: Any) -> tuple[str, dict[str, Any], str | None]:
    if isinstance(tool_call, dict):
        if "function" in tool_call:
            function = tool_call.get("function") or {}
            raw_args = function.get("arguments") or {}
            if isinstance(raw_args, str):
                try:
                    raw_args = json.loads(raw_args)
                except json.JSONDecodeError:
                    raw_args = {"arguments": raw_args}
            return str(function.get("name", "")), dict(raw_args), tool_call.get("id")
        return str(tool_call.get("name", "")), dict(tool_call.get("args") or {}), tool_call.get("id")

    name = str(getattr(tool_call, "name", ""))
    args = getattr(tool_call, "args", {}) or {}
    call_id = getattr(tool_call, "id", None)
    return name, dict(args), call_id


def _observation_json(
    call: ToolCall,
    decision: GatewayDecision,
    result: ToolResult | None,
    *,
    sensitive_detector: Any,
) -> str:
    public_decision, _ = sensitive_detector.redact(decision.to_dict())
    payload = {
        "tool_name": call.tool_name,
        # A blocked call can itself contain a credential.  The model-visible
        # observation must not echo it through sanitized_params or signal
        # evidence even though the raw decision remains available in memory
        # for the trusted audit sink.
        "decision": public_decision,
        "result": result.to_dict() if result else None,
        "ok": bool(result and result.ok),
        "error": None if result and result.ok else decision.reason if result is None else result.error,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
