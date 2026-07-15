from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .detectors import SensitiveDataDetector
from .schemas import AuditEvent, GatewayDecision, SecurityContext, ToolCall, ToolResult


_SENSITIVE_FIELD_NAMES = {
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "credential",
    "credentials",
    "id_token",
    "passwd",
    "password",
    "private_key",
    "pwd",
    "refresh_token",
    "secret",
    "secret_key",
    "token",
}
_SENSITIVE_FIELD_SUFFIXES = (
    "_access_key",
    "_api_key",
    "_credential",
    "_credentials",
    "_passwd",
    "_password",
    "_private_key",
    "_pwd",
    "_secret",
    "_token",
)
_REDACTION_MARKER = re.compile(r"^\[REDACTED:[^\]]+\]$")


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditLogger:
    def __init__(
        self,
        path: str | Path | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
        workspace_root: str | Path | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def bind_workspace_root(self, workspace_root: str | Path) -> None:
        """Bind audit serialization to a workspace without persisting host paths."""

        root = Path(workspace_root).resolve()
        if self.workspace_root is not None and self.workspace_root != root:
            raise ValueError("AuditLogger is already bound to a different workspace root")
        self.workspace_root = root

    def record(
        self,
        context: SecurityContext,
        call: ToolCall,
        decision: GatewayDecision,
        result: ToolResult | None = None,
        labels: dict[str, Any] | None = None,
    ) -> AuditEvent:
        raw_event = {
            "timestamp": utc_now_iso(),
            "context": context.to_dict(),
            "call": call.to_dict(),
            "decision": decision.to_dict(),
            "result": result.to_dict() if result else None,
            "labels": labels or {},
        }
        raw_event = _make_workspace_paths_portable(raw_event, self.workspace_root)
        redacted_event, _ = self.sensitive_detector.redact(raw_event)
        # Detector redaction counts are trusted integer diagnostics, not
        # credentials. Key-aware result scrubbing may otherwise interpret
        # labels such as ``bearer_token`` as live secret fields.
        redacted_event["decision"]["redactions"] = dict(decision.redactions)
        redacted_event = _redact_sensitive_fields(redacted_event)
        event = AuditEvent(**redacted_event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        return event


def _make_workspace_paths_portable(value: Any, workspace_root: Path | None) -> Any:
    """Replace an absolute workspace prefix in nested audit data.

    Tool execution still uses resolved absolute paths. Only the persisted and
    returned audit representation is normalized, so checked-in evidence does
    not expose a contributor's local directory or become host-specific.
    """

    if workspace_root is None:
        return value
    if isinstance(value, dict):
        return {
            key: _make_workspace_paths_portable(item, workspace_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_make_workspace_paths_portable(item, workspace_root) for item in value]
    if isinstance(value, tuple):
        return [_make_workspace_paths_portable(item, workspace_root) for item in value]
    if isinstance(value, str):
        prefixes = {str(workspace_root), workspace_root.as_posix()}
        for prefix in sorted(prefixes, key=len, reverse=True):
            value = value.replace(prefix, "<WORKSPACE_ROOT>")
        return value
    return value


def _redact_sensitive_fields(value: Any, path: tuple[str, ...] = ()) -> Any:
    """Mask credential fields whose values are not self-identifying to regexes.

    ``SensitiveDataDetector.redact`` handles recognizable secrets anywhere in the
    event. This second pass covers values such as a plain password stored under a
    credential-like key while preserving the shape of nested audit data.
    """

    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            child_path = (*path, key_text)
            if path == ("decision", "redactions"):
                # Detector labels and their numeric counts are useful, non-secret
                # audit metadata even when a label contains words such as token.
                redacted[key] = _redact_sensitive_fields(item, child_path)
            elif _is_sensitive_field(key_text):
                redacted[key] = _mask_field_value(item, _field_marker(key_text))
            else:
                redacted[key] = _redact_sensitive_fields(item, child_path)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive_fields(item, path) for item in value]
    if isinstance(value, tuple):
        return [_redact_sensitive_fields(item, path) for item in value]
    return value


def _is_sensitive_field(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    return normalized in _SENSITIVE_FIELD_NAMES or normalized.endswith(_SENSITIVE_FIELD_SUFFIXES)


def _field_marker(key: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_") or "credential"
    return f"[REDACTED:{normalized}]"


def _mask_field_value(value: Any, marker: str) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value if _REDACTION_MARKER.fullmatch(value) else marker
    if isinstance(value, dict):
        return {key: _mask_field_value(item, marker) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mask_field_value(item, marker) for item in value]
    return marker


def read_audit(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


@dataclass(frozen=True)
class AuditSummary:
    total_events: int
    decisions: dict[str, int]
    risk_levels: dict[str, int]
    blocked_tools: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_events": self.total_events,
            "decisions": self.decisions,
            "risk_levels": self.risk_levels,
            "blocked_tools": self.blocked_tools,
        }


def summarize_events(events: Iterable[dict[str, Any]]) -> AuditSummary:
    decisions: dict[str, int] = {}
    risk_levels: dict[str, int] = {}
    blocked_tools: dict[str, int] = {}
    total = 0
    for event in events:
        total += 1
        decision = event.get("decision", {}).get("decision", "unknown")
        risk = event.get("decision", {}).get("risk_level", "unknown")
        decisions[decision] = decisions.get(decision, 0) + 1
        risk_levels[risk] = risk_levels.get(risk, 0) + 1
        if decision in {"block", "require_confirmation"}:
            tool = event.get("call", {}).get("tool_name", "unknown")
            blocked_tools[tool] = blocked_tools.get(tool, 0) + 1
    return AuditSummary(total, decisions, risk_levels, blocked_tools)
