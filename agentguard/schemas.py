from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


def strict_bool(value: Any, field_name: str) -> bool:
    """Return a real boolean and reject truthy strings/numbers fail-closed."""

    if type(value) is not bool:
        raise ValueError(f"{field_name} must be a boolean, got {type(value).__name__}")
    return value


class OperationType(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    DATABASE = "database"
    NETWORK = "network"
    SEARCH = "search"
    ADMIN = "admin"


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_value(cls, value: str | int | "RiskLevel") -> "RiskLevel":
        if isinstance(value, RiskLevel):
            return value
        # ``bool`` is a subclass of ``int`` in Python. Treating JSON ``true``
        # as risk level 1 would silently downgrade a malformed policy to LOW.
        if isinstance(value, bool):
            raise ValueError("risk_level must be a named level or integer from 1 to 4")
        if isinstance(value, int):
            return cls(value)
        normalized = str(value).strip().upper()
        if normalized.isdigit():
            return cls(int(normalized))
        return cls[normalized]


class Decision(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_REDACTION = "allow_with_redaction"
    REQUIRE_CONFIRMATION = "require_confirmation"
    BLOCK = "block"


class RiskSignalType(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    PERMISSION = "permission"
    PARAMETER = "parameter"
    SENSITIVE_DATA = "sensitive_data"
    HIGH_RISK = "high_risk"
    TOOL_POLICY = "tool_policy"


@dataclass(frozen=True)
class RiskSignal:
    signal_type: RiskSignalType
    level: RiskLevel
    message: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_type": self.signal_type.value,
            "level": self.level.name.lower(),
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ParameterPolicy:
    kind: str = "string"
    required: bool = False
    allowed_values: list[Any] = field(default_factory=list)
    allowed_roots: list[str] = field(default_factory=list)
    deny_patterns: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    max_length: int | None = None
    readonly: bool = False
    allow_private_networks: bool = False

    def __post_init__(self) -> None:
        strict_bool(self.required, "parameter.required")
        strict_bool(self.readonly, "parameter.readonly")
        strict_bool(self.allow_private_networks, "parameter.allow_private_networks")
        if self.max_length is not None and (
            type(self.max_length) is not int or self.max_length < 0
        ):
            raise ValueError("parameter.max_length must be a non-negative integer")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ParameterPolicy":
        return cls(
            kind=raw.get("kind", "string"),
            required=strict_bool(raw.get("required", False), "parameter.required"),
            allowed_values=list(raw.get("allowed_values", [])),
            allowed_roots=list(raw.get("allowed_roots", [])),
            deny_patterns=list(raw.get("deny_patterns", [])),
            allowed_domains=list(raw.get("allowed_domains", [])),
            max_length=raw.get("max_length"),
            readonly=strict_bool(raw.get("readonly", False), "parameter.readonly"),
            allow_private_networks=strict_bool(
                raw.get("allow_private_networks", False),
                "parameter.allow_private_networks",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "required": self.required,
            "allowed_values": self.allowed_values,
            "allowed_roots": self.allowed_roots,
            "deny_patterns": self.deny_patterns,
            "allowed_domains": self.allowed_domains,
            "max_length": self.max_length,
            "readonly": self.readonly,
            "allow_private_networks": self.allow_private_networks,
        }


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    operation: OperationType
    risk_level: RiskLevel
    required_scopes: set[str] = field(default_factory=set)
    allowed_roles: set[str] = field(default_factory=set)
    requires_confirmation: bool = False
    parameters: dict[str, ParameterPolicy] = field(default_factory=dict)
    redact_output: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        strict_bool(self.requires_confirmation, "tool.requires_confirmation")
        strict_bool(self.redact_output, "tool.redact_output")
        if not isinstance(self.operation, OperationType):
            raise ValueError("tool.operation must be an OperationType")
        if not isinstance(self.risk_level, RiskLevel):
            raise ValueError("tool.risk_level must be a RiskLevel")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ToolSpec":
        return cls(
            name=raw["name"],
            description=raw.get("description", ""),
            operation=OperationType(raw["operation"]),
            risk_level=RiskLevel.from_value(raw["risk_level"]),
            required_scopes=set(raw.get("required_scopes", [])),
            allowed_roles=set(raw.get("allowed_roles", [])),
            requires_confirmation=strict_bool(
                raw.get("requires_confirmation", False),
                "tool.requires_confirmation",
            ),
            parameters={
                key: ParameterPolicy.from_dict(value)
                for key, value in raw.get("parameters", {}).items()
            },
            redact_output=strict_bool(raw.get("redact_output", True), "tool.redact_output"),
            metadata=dict(raw.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "operation": self.operation.value,
            "risk_level": self.risk_level.name.lower(),
            "required_scopes": sorted(self.required_scopes),
            "allowed_roles": sorted(self.allowed_roles),
            "requires_confirmation": self.requires_confirmation,
            "parameters": {k: v.to_dict() for k, v in self.parameters.items()},
            "redact_output": self.redact_output,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class SecurityContext:
    user_id: str
    role: str
    scopes: set[str] = field(default_factory=set)
    confirmed: bool = False
    session_id: str = "default"
    trusted_input: bool = True

    def __post_init__(self) -> None:
        strict_bool(self.confirmed, "context.confirmed")
        strict_bool(self.trusted_input, "context.trusted_input")

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SecurityContext":
        return cls(
            user_id=raw.get("user_id", "anonymous"),
            role=raw.get("role", "guest"),
            scopes=set(raw.get("scopes", [])),
            confirmed=strict_bool(raw.get("confirmed", False), "context.confirmed"),
            session_id=raw.get("session_id", "default"),
            trusted_input=strict_bool(raw.get("trusted_input", True), "context.trusted_input"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "scopes": sorted(self.scopes),
            "confirmed": self.confirmed,
            "session_id": self.session_id,
            "trusted_input": self.trusted_input,
        }


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    params: dict[str, Any]
    task_id: str = "manual"
    step_id: str = "step-0"
    source_content: str = ""
    declared_purpose: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ToolCall":
        return cls(
            tool_name=raw["tool_name"],
            params=dict(raw.get("params", {})),
            task_id=raw.get("task_id", "manual"),
            step_id=raw.get("step_id", "step-0"),
            source_content=raw.get("source_content", ""),
            declared_purpose=raw.get("declared_purpose", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "params": self.params,
            "task_id": self.task_id,
            "step_id": self.step_id,
            "source_content": self.source_content,
            "declared_purpose": self.declared_purpose,
        }


@dataclass(frozen=True)
class GatewayDecision:
    decision: Decision
    risk_level: RiskLevel
    reason: str
    signals: list[RiskSignal] = field(default_factory=list)
    sanitized_params: dict[str, Any] = field(default_factory=dict)
    redactions: dict[str, int] = field(default_factory=dict)

    @property
    def allowed_to_execute(self) -> bool:
        return self.decision in {Decision.ALLOW, Decision.ALLOW_WITH_REDACTION}

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "risk_level": self.risk_level.name.lower(),
            "reason": self.reason,
            "signals": [signal.to_dict() for signal in self.signals],
            "sanitized_params": self.sanitized_params,
            "redactions": self.redactions,
        }


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    output: Any = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        strict_bool(self.ok, "tool_result.ok")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "output": self.output,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    context: dict[str, Any]
    call: dict[str, Any]
    decision: dict[str, Any]
    result: dict[str, Any] | None = None
    labels: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "context": self.context,
            "call": self.call,
            "decision": self.decision,
            "result": self.result,
            "labels": self.labels,
            "integrity": self.integrity,
        }
