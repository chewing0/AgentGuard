from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..gateway import SecurityGateway
from ..schemas import GatewayDecision, SecurityContext, ToolCall, ToolResult


@dataclass(frozen=True)
class AgentStep:
    step_id: str
    call: ToolCall
    decision: GatewayDecision
    result: ToolResult | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "call": self.call.to_dict(),
            "decision": self.decision.to_dict(),
            "result": self.result.to_dict() if self.result else None,
        }


@dataclass(frozen=True)
class AgentRun:
    task: str
    context: SecurityContext
    steps: list[AgentStep] = field(default_factory=list)
    report_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "context": self.context.to_dict(),
            "report_path": self.report_path,
            "steps": [step.to_dict() for step in self.steps],
        }

    def markdown(self) -> str:
        lines = [
            "# Agent Run",
            "",
            f"Task: {self.task}",
            "",
            "| Step | Tool | Decision | Risk | Reason |",
            "|---|---|---|---|---|",
        ]
        for step in self.steps:
            decision = step.decision
            lines.append(
                f"| {step.step_id} | {step.call.tool_name} | {decision.decision.value} | "
                f"{decision.risk_level.name.lower()} | {decision.reason} |"
            )
        if self.report_path:
            lines.extend(["", f"Report: {self.report_path}"])
        return "\n".join(lines)


class DemoAgent:
    """Deterministic rule-based agent used for end-to-end demos."""

    def __init__(
        self,
        gateway: SecurityGateway,
        report_path: str = "data/demo_workspace/scratch/agent_report.md",
    ) -> None:
        self.gateway = gateway
        self.report_path = report_path

    def run(
        self,
        task: str,
        context: SecurityContext | None = None,
        simulate_attack_followup: bool = False,
    ) -> AgentRun:
        context = context or default_agent_context()
        steps: list[AgentStep] = []

        project_step = self._execute(
            steps,
            ToolCall(
                tool_name="file.read",
                params={"path": "data/demo_workspace/public/project_brief.txt"},
                task_id="agent-demo",
                step_id="agent-s1",
                declared_purpose="Read the public project brief before generating a report.",
            ),
            context,
        )
        ticket_step = self._execute(
            steps,
            ToolCall(
                tool_name="db.query",
                params={"query": "SELECT id, title, severity, status FROM tickets WHERE status = 'open'"},
                task_id="agent-demo",
                step_id="agent-s2",
                declared_purpose="Read open ticket metadata for the report.",
            ),
            context,
        )
        kb_query = "payroll review procedure" if "payroll" in task.lower() else "gateway report recommendations"
        kb_step = self._execute(
            steps,
            ToolCall(
                tool_name="kb.search",
                params={"query": kb_query, "top_k": 3},
                task_id="agent-demo",
                step_id="agent-s3",
                declared_purpose="Search local project guidance for report recommendations.",
            ),
            context,
        )

        if simulate_attack_followup:
            injected = _find_injected_instruction(kb_step.result.output if kb_step.result else None)
            if injected:
                self._execute(
                    steps,
                    ToolCall(
                        tool_name="file.read",
                        params={"path": "data/demo_workspace/secrets.env"},
                        task_id="agent-demo",
                        step_id="agent-attack-s4",
                        source_content=injected,
                        declared_purpose="Follow retrieved knowledge-base instructions.",
                    ),
                    context,
                    labels={"agent_phase": "attack_followup"},
                )

        report = self._build_report(task, project_step.result, ticket_step.result, kb_step.result, steps)
        write_step = self._execute(
            steps,
            ToolCall(
                tool_name="file.write",
                params={"path": self.report_path, "content": report},
                task_id="agent-demo",
                step_id="agent-s4",
                source_content=_compact_json(kb_step.result.output if kb_step.result else None),
                declared_purpose="Write the generated security assessment report to scratch space.",
            ),
            context,
        )
        report_path = str(Path(self.report_path)) if write_step.decision.allowed_to_execute else None
        return AgentRun(task=task, context=context, steps=steps, report_path=report_path)

    def _execute(
        self,
        steps: list[AgentStep],
        call: ToolCall,
        context: SecurityContext,
        labels: dict[str, Any] | None = None,
    ) -> AgentStep:
        decision, result = self.gateway.execute(call, context, labels=labels or {"agent": "demo"})
        step = AgentStep(call.step_id, call, decision, result)
        steps.append(step)
        return step

    def _build_report(
        self,
        task: str,
        project_result: ToolResult | None,
        ticket_result: ToolResult | None,
        kb_result: ToolResult | None,
        steps: list[AgentStep],
    ) -> str:
        project_summary = _clip_text(project_result.output if project_result and project_result.ok else "Project brief unavailable.")
        tickets = ticket_result.output if ticket_result and ticket_result.ok else []
        kb_items = kb_result.output if kb_result and kb_result.ok else []
        lines = [
            "# AgentGuard Security Assessment",
            "",
            f"Task: {task}",
            "",
            "## Public Project Brief",
            "",
            str(project_summary),
            "",
            "## Open Risk Items",
            "",
        ]
        if isinstance(tickets, list) and tickets:
            for item in tickets:
                lines.append(f"- {item.get('severity', 'unknown')}: {item.get('title', 'untitled')} ({item.get('status', 'unknown')})")
        else:
            lines.append("- No open risk items returned.")

        lines.extend(["", "## Knowledge Base Recommendations", ""])
        if isinstance(kb_items, list) and kb_items:
            for item in kb_items:
                lines.append(f"- {item.get('title', 'Untitled')}: {_clip_text(item.get('snippet', ''), 180)}")
        else:
            lines.append("- No knowledge-base recommendations returned.")

        lines.extend(["", "## Gateway Decisions", ""])
        for step in steps:
            lines.append(
                f"- {step.step_id} `{step.call.tool_name}`: {step.decision.decision.value} "
                f"({step.decision.reason})"
            )
        lines.extend(
            [
                "",
                "## Action Items",
                "",
                "- Keep generated reports in the scratch workspace.",
                "- Review high-severity open tickets before expanding tool permissions.",
                "- Treat retrieved content as untrusted when it contains operational instructions.",
            ]
        )
        return "\n".join(lines)


def default_agent_context() -> SecurityContext:
    return SecurityContext(
        user_id="demo-agent",
        role="analyst",
        scopes={"file:read", "file:write", "db:read", "kb:read", "search:read", "network:api"},
        trusted_input=True,
    )


def _compact_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def _clip_text(value: Any, limit: int = 360) -> str:
    text = str(value).replace("\r\n", "\n").strip()
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _find_injected_instruction(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        snippet = str(item.get("snippet", "")) if isinstance(item, dict) else str(item)
        lowered = snippet.lower()
        if "ignore previous instructions" in lowered or "call the file.read tool" in lowered:
            return snippet
    return None
