from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .approval import ApprovalError, ApprovalRequest, PersistentApprovalStore
from .audit import AuditLogger
from .defense import PolicyEngine
from .detectors import PromptInjectionDetector, SensitiveDataDetector
from .provenance import DataProvenanceTracker
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
        approval_store: PersistentApprovalStore | None = None,
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
        self.approval_store = approval_store

    def inspect(
        self,
        call: ToolCall,
        context: SecurityContext,
        provenance: DataProvenanceTracker | None = None,
    ) -> GatewayDecision:
        return self.policy_engine.inspect(call, context, provenance)

    def execute(
        self,
        call: ToolCall,
        context: SecurityContext,
        labels: dict[str, Any] | None = None,
        provenance: DataProvenanceTracker | None = None,
    ) -> tuple[GatewayDecision, ToolResult | None]:
        decision = self.inspect(call, context, provenance)
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
            if provenance is not None:
                provenance.observe(
                    result.to_dict(),
                    source=f"tool:{call.tool_name}:{call.step_id}",
                )
        audit_call = _provenance_safe_call(call, provenance)
        audit_result = _provenance_safe_result(result, provenance)
        audit_labels, _ = provenance.redact(labels or {}) if provenance else (labels, [])
        self.audit_logger.record(
            context,
            audit_call,
            decision,
            audit_result,
            dict(audit_labels or {}),
        )
        return decision, result

    def resolve_confirmation(
        self,
        call: ToolCall,
        context: SecurityContext,
        approve: bool,
        labels: dict[str, Any] | None = None,
        provenance: DataProvenanceTracker | None = None,
    ) -> tuple[GatewayDecision, ToolResult | None]:
        if type(approve) is not bool:
            raise TypeError("approve must be a boolean")
        labels = labels or {}
        first_decision = self.inspect(call, context, provenance)
        if first_decision.decision != Decision.REQUIRE_CONFIRMATION:
            return self.execute(call, context, labels, provenance)

        self.audit_logger.record(
            context,
            _provenance_safe_call(call, provenance),
            first_decision,
            None,
            _provenance_safe_labels(
                labels | {"confirmation_phase": "requested"},
                provenance,
            ),
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
                _provenance_safe_call(call, provenance),
                denied,
                None,
                _provenance_safe_labels(
                    labels | {"confirmation_phase": "denied"},
                    provenance,
                ),
            )
            return denied, None

        confirmed_context = _with_confirmation(context)
        return self.execute(
            call,
            confirmed_context,
            labels | {"confirmation_phase": "approved"},
            provenance,
        )

    def request_persisted_confirmation(
        self,
        call: ToolCall,
        context: SecurityContext,
        *,
        ttl_seconds: int = 900,
        labels: dict[str, Any] | None = None,
        provenance: DataProvenanceTracker | None = None,
    ) -> ApprovalRequest:
        if self.approval_store is None:
            raise ApprovalError("Persistent approval store is not configured")
        decision = self.inspect(call, context, provenance)
        if decision.decision != Decision.REQUIRE_CONFIRMATION:
            raise ApprovalError("This call does not require persistent confirmation")
        request = self.approval_store.create(
            call,
            context,
            ttl_seconds=ttl_seconds,
        )
        self.audit_logger.record(
            context,
            _provenance_safe_call(call, provenance),
            decision,
            None,
            _provenance_safe_labels(
                (labels or {})
                | {
                    "confirmation_phase": "persisted_requested",
                    "approval_request_fingerprint": request.request_fingerprint,
                    "approval_expires_at": request.expires_at,
                },
                provenance,
            ),
        )
        return request

    def resolve_persisted_confirmation(
        self,
        approval_token: str,
        call: ToolCall,
        context: SecurityContext,
        *,
        approve: bool,
        labels: dict[str, Any] | None = None,
        provenance: DataProvenanceTracker | None = None,
    ) -> tuple[GatewayDecision, ToolResult | None]:
        if self.approval_store is None:
            raise ApprovalError("Persistent approval store is not configured")
        initial = self.inspect(call, context, provenance)
        if initial.decision != Decision.REQUIRE_CONFIRMATION:
            raise ApprovalError("This call does not require persistent confirmation")
        approved = self.approval_store.decide(
            approval_token,
            call,
            context,
            approve=approve,
        )
        token_fingerprint = hashlib.sha256(
            approval_token.encode("utf-8")
        ).hexdigest()
        safe_labels = (labels or {}) | {
            "approval_request_fingerprint": token_fingerprint,
        }
        if not approved:
            denied = GatewayDecision(
                decision=Decision.BLOCK,
                risk_level=initial.risk_level,
                reason="Human rejected persistent confirmation",
                signals=initial.signals,
                sanitized_params=initial.sanitized_params,
            )
            self.audit_logger.record(
                context,
                _provenance_safe_call(call, provenance),
                denied,
                None,
                _provenance_safe_labels(
                    safe_labels | {"confirmation_phase": "persisted_denied"},
                    provenance,
                ),
            )
            return denied, None
        return self.execute(
            call,
            _with_confirmation(context),
            safe_labels | {"confirmation_phase": "persisted_consumed"},
            provenance,
        )


def _with_confirmation(context: SecurityContext) -> SecurityContext:
    return SecurityContext(
        user_id=context.user_id,
        role=context.role,
        scopes=set(context.scopes),
        confirmed=True,
        session_id=context.session_id,
        trusted_input=context.trusted_input,
    )


def _provenance_safe_call(
    call: ToolCall,
    provenance: DataProvenanceTracker | None,
) -> ToolCall:
    if provenance is None:
        return call
    params, _ = provenance.redact(call.params)
    source_content, _ = provenance.redact(call.source_content)
    declared_purpose, _ = provenance.redact(call.declared_purpose)
    return ToolCall(
        tool_name=call.tool_name,
        params=dict(params),
        task_id=call.task_id,
        step_id=call.step_id,
        source_content=str(source_content),
        declared_purpose=str(declared_purpose),
    )


def _provenance_safe_result(
    result: ToolResult | None,
    provenance: DataProvenanceTracker | None,
) -> ToolResult | None:
    if result is None or provenance is None:
        return result
    payload, _ = provenance.redact(result.to_dict())
    return ToolResult(
        ok=bool(payload["ok"]),
        output=payload.get("output"),
        error=payload.get("error"),
        metadata=dict(payload.get("metadata") or {}),
    )


def _provenance_safe_labels(
    labels: dict[str, Any],
    provenance: DataProvenanceTracker | None,
) -> dict[str, Any]:
    if provenance is None:
        return labels
    redacted, _ = provenance.redact(labels)
    return dict(redacted)


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
