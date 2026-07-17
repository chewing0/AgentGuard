from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
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
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    def __init__(
        self,
        path: str | Path | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
        workspace_root: str | Path | None = None,
        integrity: bool = True,
        integrity_key: bytes | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()
        self.workspace_root = Path(workspace_root).resolve() if workspace_root else None
        if type(integrity) is not bool:
            raise ValueError("audit integrity must be a boolean")
        if integrity_key is not None and (
            not isinstance(integrity_key, bytes) or len(integrity_key) < 16
        ):
            raise ValueError("audit integrity_key must contain at least 16 bytes")
        self.integrity = integrity
        self.integrity_key = integrity_key
        self._sequence = 0
        self._previous_hash = "0" * 64
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.integrity and self.path.exists() and self.path.stat().st_size:
                report = verify_audit_chain(self.path, integrity_key=self.integrity_key)
                if not report.valid:
                    raise ValueError(f"Existing audit chain is invalid: {report.reason}")
                self._sequence = report.total_events
                self._previous_hash = report.last_hash

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
        next_sequence = self._sequence
        next_hash = self._previous_hash
        if self.integrity:
            next_sequence += 1
            integrity = _build_integrity_record(
                redacted_event,
                sequence=next_sequence,
                previous_hash=self._previous_hash,
                integrity_key=self.integrity_key,
            )
            redacted_event["integrity"] = integrity
            next_hash = integrity["event_hash"]
        event = AuditEvent(**redacted_event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        self._sequence = next_sequence
        self._previous_hash = next_hash
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
class AuditIntegrityReport:
    valid: bool
    total_events: int
    chained_events: int
    last_hash: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "total_events": self.total_events,
            "chained_events": self.chained_events,
            "last_hash": self.last_hash,
            "reason": self.reason,
        }


def verify_audit_chain(
    path: str | Path,
    *,
    integrity_key: bytes | None = None,
) -> AuditIntegrityReport:
    if integrity_key is not None and (
        not isinstance(integrity_key, bytes) or len(integrity_key) < 16
    ):
        raise ValueError("audit integrity_key must contain at least 16 bytes")
    try:
        events = read_audit(path)
    except (OSError, json.JSONDecodeError):
        return AuditIntegrityReport(False, 0, 0, "0" * 64, "invalid_json")
    previous_hash = "0" * 64
    chained_events = 0
    chain_started = False
    for index, event in enumerate(events, start=1):
        integrity = event.get("integrity")
        payload = dict(event)
        payload.pop("integrity", None)
        if not integrity:
            if chain_started:
                return AuditIntegrityReport(
                    False,
                    len(events),
                    chained_events,
                    previous_hash,
                    "unchained_event_after_chain",
                )
            previous_hash = _legacy_event_hash(payload, previous_hash)
            continue
        chain_started = True
        if not isinstance(integrity, dict):
            return AuditIntegrityReport(
                False, len(events), chained_events, previous_hash, "invalid_integrity_record"
            )
        algorithm = integrity.get("algorithm")
        if algorithm == "hmac-sha256" and integrity_key is None:
            return AuditIntegrityReport(
                False, len(events), chained_events, previous_hash, "integrity_key_required"
            )
        if algorithm not in {"sha256", "hmac-sha256"}:
            return AuditIntegrityReport(
                False, len(events), chained_events, previous_hash, "unsupported_algorithm"
            )
        if integrity.get("sequence") != index:
            return AuditIntegrityReport(
                False, len(events), chained_events, previous_hash, "sequence_mismatch"
            )
        if integrity.get("previous_hash") != previous_hash:
            return AuditIntegrityReport(
                False, len(events), chained_events, previous_hash, "previous_hash_mismatch"
            )
        expected = _event_hash(
            payload,
            previous_hash,
            integrity_key if algorithm == "hmac-sha256" else None,
        )
        if not hmac.compare_digest(str(integrity.get("event_hash", "")), expected):
            return AuditIntegrityReport(
                False, len(events), chained_events, previous_hash, "event_hash_mismatch"
            )
        previous_hash = expected
        chained_events += 1
    return AuditIntegrityReport(
        True,
        len(events),
        chained_events,
        previous_hash,
        "ok",
    )


def _build_integrity_record(
    payload: dict[str, Any],
    *,
    sequence: int,
    previous_hash: str,
    integrity_key: bytes | None,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event_hash": _event_hash(payload, previous_hash, integrity_key),
        "algorithm": "hmac-sha256" if integrity_key is not None else "sha256",
    }


def _event_hash(
    payload: dict[str, Any],
    previous_hash: str,
    integrity_key: bytes | None,
) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    message = previous_hash.encode("ascii") + b"\n" + canonical
    if integrity_key is not None:
        return hmac.new(integrity_key, message, hashlib.sha256).hexdigest()
    return hashlib.sha256(message).hexdigest()


def _legacy_event_hash(payload: dict[str, Any], previous_hash: str) -> str:
    return _event_hash(payload, previous_hash, None)


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
