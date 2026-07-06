from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..detectors import PromptInjectionDetector, SensitiveDataDetector
from ..registry import ToolRegistry
from ..schemas import (
    Decision,
    GatewayDecision,
    OperationType,
    ParameterPolicy,
    RiskLevel,
    RiskSignal,
    RiskSignalType,
    SecurityContext,
    ToolCall,
    ToolSpec,
)


class PolicyEngine:
    """Runs pre-execution policy checks for proposed tool calls."""

    def __init__(
        self,
        registry: ToolRegistry,
        workspace_root: str | Path | None = None,
        prompt_detector: PromptInjectionDetector | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
    ) -> None:
        self.registry = registry
        self.workspace_root = Path(workspace_root or Path.cwd()).resolve()
        self.prompt_detector = prompt_detector or PromptInjectionDetector()
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()

    def inspect(self, call: ToolCall, context: SecurityContext) -> GatewayDecision:
        spec = self.registry.get(call.tool_name)
        if spec is None:
            return GatewayDecision(
                decision=Decision.BLOCK,
                risk_level=RiskLevel.HIGH,
                reason=f"Unknown tool: {call.tool_name}",
                signals=[
                    RiskSignal(
                        RiskSignalType.TOOL_POLICY,
                        RiskLevel.HIGH,
                        "Attempted to call an unregistered tool",
                        call.tool_name,
                    )
                ],
                sanitized_params=call.params,
            )

        signals: list[RiskSignal] = []
        sanitized_params = dict(call.params)

        signals.extend(self._check_permissions(spec, context))
        signals.extend(self._check_prompt_injection(call, context))
        param_signals, sanitized_params = self._check_parameters(spec, call.params)
        signals.extend(param_signals)
        signals.extend(self._check_sensitive_flow(spec, sanitized_params, call))
        signals.extend(self._check_high_risk(spec))

        risk_level = _max_risk([spec.risk_level, *[signal.level for signal in signals]])
        decision, reason = self._decide(spec, context, signals, risk_level)
        return GatewayDecision(
            decision=decision,
            risk_level=risk_level,
            reason=reason,
            signals=signals,
            sanitized_params=sanitized_params,
        )

    def _check_permissions(self, spec: ToolSpec, context: SecurityContext) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        if spec.allowed_roles and context.role not in spec.allowed_roles:
            signals.append(
                RiskSignal(
                    RiskSignalType.PERMISSION,
                    RiskLevel.HIGH,
                    f"Role '{context.role}' is not allowed to use {spec.name}",
                    f"allowed_roles={sorted(spec.allowed_roles)}",
                )
            )
        missing = sorted(spec.required_scopes - context.scopes)
        if missing:
            signals.append(
                RiskSignal(
                    RiskSignalType.PERMISSION,
                    RiskLevel.HIGH,
                    f"Missing required scopes for {spec.name}",
                    ",".join(missing),
                )
            )
        return signals

    def _check_prompt_injection(self, call: ToolCall, context: SecurityContext) -> list[RiskSignal]:
        text = "\n".join(
            part
            for part in [
                call.source_content,
                call.declared_purpose,
                _safe_repr(call.params),
            ]
            if part
        )
        signals = self.prompt_detector.detect(text)
        if signals and not context.trusted_input:
            return [
                RiskSignal(signal.signal_type, max(signal.level, RiskLevel.HIGH), signal.message, signal.evidence)
                for signal in signals
            ]
        return signals

    def _check_parameters(
        self,
        spec: ToolSpec,
        params: dict[str, Any],
    ) -> tuple[list[RiskSignal], dict[str, Any]]:
        signals: list[RiskSignal] = []
        sanitized = dict(params)
        for key, policy in spec.parameters.items():
            if policy.required and key not in params:
                signals.append(
                    RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, f"Missing required parameter: {key}", key)
                )
                continue
            if key not in params:
                continue
            value = params[key]
            validator = getattr(self, f"_validate_{policy.kind}", self._validate_string)
            value_signals, new_value = validator(key, value, policy)
            sanitized[key] = new_value
            signals.extend(value_signals)
        unexpected = sorted(set(params) - set(spec.parameters))
        for key in unexpected:
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.MEDIUM, f"Unexpected parameter for {spec.name}: {key}", key)
            )
        return signals, sanitized

    def _validate_string(
        self,
        key: str,
        value: Any,
        policy: ParameterPolicy,
    ) -> tuple[list[RiskSignal], Any]:
        text = str(value)
        signals = self._generic_value_checks(key, text, policy)
        if policy.allowed_values and value not in policy.allowed_values:
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.MEDIUM, f"Parameter {key} is not in allowed values", text)
            )
        return signals, value

    def _validate_path(
        self,
        key: str,
        value: Any,
        policy: ParameterPolicy,
    ) -> tuple[list[RiskSignal], Any]:
        text = str(value)
        signals = self._generic_value_checks(key, text, policy)
        candidate = Path(text)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        resolved = candidate.resolve()
        sanitized = str(resolved)
        if ".." in Path(text).parts:
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, f"Path traversal detected in {key}", text)
            )
        if policy.allowed_roots:
            allowed_paths = []
            for root in policy.allowed_roots:
                root_path = Path(root)
                if not root_path.is_absolute():
                    root_path = self.workspace_root / root_path
                allowed_paths.append(root_path.resolve())
            if not any(_is_relative_to(resolved, allowed) for allowed in allowed_paths):
                signals.append(
                    RiskSignal(
                        RiskSignalType.PARAMETER,
                        RiskLevel.HIGH,
                        f"Path parameter {key} is outside allowed roots",
                        sanitized,
                    )
                )
        return signals, sanitized

    def _validate_sql(
        self,
        key: str,
        value: Any,
        policy: ParameterPolicy,
    ) -> tuple[list[RiskSignal], Any]:
        query = str(value).strip()
        signals = self._generic_value_checks(key, query, policy)
        normalized = re.sub(r"\s+", " ", query).strip().lower()
        if policy.readonly:
            if not normalized.startswith(("select ", "with ")):
                signals.append(
                    RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, f"SQL parameter {key} must be read-only", query)
                )
            destructive = r"\b(insert|update|delete|drop|alter|attach|pragma|replace|create|vacuum)\b"
            if re.search(destructive, normalized):
                signals.append(
                    RiskSignal(RiskSignalType.PARAMETER, RiskLevel.CRITICAL, "Destructive SQL keyword detected", query)
                )
            if ";" in query.rstrip(";"):
                signals.append(
                    RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, "Multiple SQL statements are not allowed", query)
                )
        return signals, query

    def _validate_url(
        self,
        key: str,
        value: Any,
        policy: ParameterPolicy,
    ) -> tuple[list[RiskSignal], Any]:
        url = str(value).strip()
        signals = self._generic_value_checks(key, url, policy)
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if parsed.scheme not in {"http", "https"}:
            signals.append(RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, f"URL parameter {key} uses invalid scheme", url))
        if policy.allowed_domains and hostname not in policy.allowed_domains:
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, f"URL host {hostname} is not allowlisted", url)
            )
        if not policy.allow_private_networks and _is_private_host(hostname):
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.HIGH, "Private network URL is not allowed", url)
            )
        return signals, url

    def _validate_code(
        self,
        key: str,
        value: Any,
        policy: ParameterPolicy,
    ) -> tuple[list[RiskSignal], Any]:
        code = str(value)
        signals = self._generic_value_checks(key, code, policy)
        forbidden = r"\b(import|open|exec|eval|compile|__import__|subprocess|socket|requests|os\.|sys\.|shutil)\b"
        if re.search(forbidden, code):
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.CRITICAL, "Unsafe code primitive detected", code[:160])
            )
        return signals, code

    def _generic_value_checks(self, key: str, text: str, policy: ParameterPolicy) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        if policy.max_length is not None and len(text) > policy.max_length:
            signals.append(
                RiskSignal(RiskSignalType.PARAMETER, RiskLevel.MEDIUM, f"Parameter {key} exceeds max length", str(len(text)))
            )
        for pattern in policy.deny_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                signals.append(
                    RiskSignal(
                        RiskSignalType.PARAMETER,
                        RiskLevel.HIGH,
                        f"Parameter {key} matches deny pattern",
                        pattern,
                    )
                )
        return signals

    def _check_sensitive_flow(self, spec: ToolSpec, params: dict[str, Any], call: ToolCall) -> list[RiskSignal]:
        signals = self.sensitive_detector.signals(params)
        if signals and spec.operation in {OperationType.NETWORK, OperationType.SEARCH, OperationType.WRITE}:
            signals.append(
                RiskSignal(
                    RiskSignalType.SENSITIVE_DATA,
                    RiskLevel.CRITICAL,
                    f"Sensitive data is being sent to {spec.operation.value} tool",
                    call.tool_name,
                )
            )
        return signals

    def _check_high_risk(self, spec: ToolSpec) -> list[RiskSignal]:
        if spec.risk_level >= RiskLevel.HIGH or spec.requires_confirmation:
            return [
                RiskSignal(
                    RiskSignalType.HIGH_RISK,
                    spec.risk_level,
                    f"Tool {spec.name} is high risk",
                    spec.operation.value,
                )
            ]
        return []

    def _decide(
        self,
        spec: ToolSpec,
        context: SecurityContext,
        signals: list[RiskSignal],
        risk_level: RiskLevel,
    ) -> tuple[Decision, str]:
        if any(signal.signal_type == RiskSignalType.PERMISSION for signal in signals):
            return Decision.BLOCK, "Permission check failed"
        if any(signal.signal_type == RiskSignalType.PARAMETER and signal.level >= RiskLevel.HIGH for signal in signals):
            return Decision.BLOCK, "Parameter policy check failed"
        if any(signal.signal_type == RiskSignalType.SENSITIVE_DATA and signal.level >= RiskLevel.CRITICAL for signal in signals):
            return Decision.BLOCK, "Sensitive data flow was blocked"
        if any(signal.signal_type == RiskSignalType.PROMPT_INJECTION and signal.level >= RiskLevel.CRITICAL for signal in signals):
            return Decision.BLOCK, "Critical prompt injection was blocked"
        if any(signal.signal_type == RiskSignalType.PROMPT_INJECTION and signal.level >= RiskLevel.HIGH for signal in signals):
            if spec.operation in {
                OperationType.DELETE,
                OperationType.EXECUTE,
                OperationType.WRITE,
                OperationType.NETWORK,
                OperationType.SEARCH,
                OperationType.ADMIN,
            }:
                return Decision.BLOCK, "Prompt injection attempted to steer a risky tool"
        if spec.requires_confirmation and not context.confirmed:
            return Decision.REQUIRE_CONFIRMATION, "Human confirmation required for high-risk tool"
        if risk_level >= RiskLevel.CRITICAL and not context.confirmed:
            return Decision.BLOCK, "Critical risk requires an explicit trusted path"
        return Decision.ALLOW, "Policy checks passed"


def _max_risk(levels: list[RiskLevel]) -> RiskLevel:
    return max(levels) if levels else RiskLevel.LOW


def _safe_repr(value: Any) -> str:
    try:
        return repr(value)
    except Exception:  # pragma: no cover
        return "<unrepresentable>"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_private_host(hostname: str) -> bool:
    if not hostname:
        return False
    lowered = hostname.lower()
    if lowered in {"localhost", "metadata.google.internal"}:
        return True
    try:
        return ipaddress.ip_address(lowered).is_private
    except ValueError:
        return False
