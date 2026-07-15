from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .audit import AuditLogger
from .defense import PolicyEngine
from .detectors import PromptInjectionDetector, SensitiveDataDetector
from .registry import ToolRegistry
from .schemas import (
    Decision,
    GatewayDecision,
    RiskLevel,
    RiskSignal,
    RiskSignalType,
    SecurityContext,
    ToolCall,
    ToolResult,
)


_MAX_RETAINED_RESULT_CHARS = 262_144
_RESULT_EDGE_CHARS = 4_096


class SecurityGateway:
    def __init__(
        self,
        registry: ToolRegistry,
        workspace_root: str | Path | None = None,
        audit_logger: AuditLogger | None = None,
        prompt_detector: PromptInjectionDetector | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        self.registry = registry
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.audit_logger = audit_logger or AuditLogger()
        self.audit_logger.bind_workspace_root(self.workspace_root)
        self.policy_engine = policy_engine or PolicyEngine(
            registry=registry,
            workspace_root=self.workspace_root,
            prompt_detector=prompt_detector,
            sensitive_detector=sensitive_detector,
        )
        self.sensitive_detector = self.policy_engine.sensitive_detector

    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        return self.policy_engine.inspect(call, context)

    def execute(
        self,
        call: ToolCall,
        context: SecurityContext,
        labels: dict[str, Any] | None = None,
    ) -> tuple[GatewayDecision, ToolResult | None]:
        decision = self.inspect(call, context)
        result: ToolResult | None = None
        if decision.allowed_to_execute:
            executable_call = ToolCall(
                tool_name=call.tool_name,
                params=decision.sanitized_params,
                task_id=call.task_id,
                step_id=call.step_id,
                source_content=call.source_content,
                declared_purpose=call.declared_purpose,
            )
            result = _bounded_tool_result(self.registry.execute(executable_call))
            spec = self.registry.get(call.tool_name)
            if spec and spec.redact_output:
                # Every model-visible result field is an outbound channel.
                # Sanitize output, errors, metadata, and attacker-controlled
                # dictionary keys before adapters or audit sinks receive them.
                redacted_result, counts = self.sensitive_detector.redact(result.to_dict())
                if counts:
                    result = ToolResult(
                        ok=result.ok,
                        output=redacted_result.get("output"),
                        error=redacted_result.get("error"),
                        metadata=dict(redacted_result.get("metadata") or {}),
                    )
                    decision = GatewayDecision(
                        decision=Decision.ALLOW_WITH_REDACTION,
                        risk_level=max(decision.risk_level, RiskLevel.HIGH),
                        reason="Allowed after output redaction",
                        signals=[
                            *decision.signals,
                            RiskSignal(
                                RiskSignalType.SENSITIVE_DATA,
                                RiskLevel.HIGH,
                                "Sensitive output was redacted",
                                ",".join(sorted(counts)),
                            ),
                        ],
                        sanitized_params=decision.sanitized_params,
                        redactions=counts,
                    )
        self.audit_logger.record(context, call, decision, result, labels)
        return decision, result

    def resolve_confirmation(
        self,
        call: ToolCall,
        context: SecurityContext,
        approve: bool,
        labels: dict[str, Any] | None = None,
    ) -> tuple[GatewayDecision, ToolResult | None]:
        if type(approve) is not bool:
            raise TypeError("approve must be a boolean")
        labels = labels or {}
        first_decision = self.inspect(call, context)
        if first_decision.decision != Decision.REQUIRE_CONFIRMATION:
            return self.execute(call, context, labels)

        self.audit_logger.record(
            context,
            call,
            first_decision,
            None,
            labels | {"confirmation_phase": "requested"},
        )
        if not approve:
            denied = GatewayDecision(
                decision=Decision.BLOCK,
                risk_level=first_decision.risk_level,
                reason="Human rejected confirmation",
                signals=first_decision.signals,
                sanitized_params=first_decision.sanitized_params,
            )
            self.audit_logger.record(
                context,
                call,
                denied,
                None,
                labels | {"confirmation_phase": "denied"},
            )
            return denied, None

        confirmed_context = _with_confirmation(context)
        return self.execute(call, confirmed_context, labels | {"confirmation_phase": "approved"})


def _with_confirmation(context: SecurityContext) -> SecurityContext:
    return SecurityContext(
        user_id=context.user_id,
        role=context.role,
        scopes=set(context.scopes),
        confirmed=True,
        session_id=context.session_id,
        trusted_input=context.trusted_input,
    )


def _bounded_tool_result(result: ToolResult) -> ToolResult:
    """Bound retained/audited result data before any framework can observe it."""

    try:
        serialized = json.dumps(
            result.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
    except (TypeError, ValueError):
        serialized = str(result.to_dict())
    if len(serialized) <= _MAX_RETAINED_RESULT_CHARS:
        return result
    return ToolResult(
        ok=result.ok,
        output={
            "truncated": True,
            "original_chars": len(serialized),
            "head": serialized[:_RESULT_EDGE_CHARS],
            "tail": serialized[-_RESULT_EDGE_CHARS:],
        },
        error=(
            None
            if result.ok
            else "Tool result exceeded the guarded retention limit"
        ),
        metadata={
            "truncated": True,
            "original_chars": len(serialized),
        },
    )
