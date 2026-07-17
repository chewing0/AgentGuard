from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditIntegrityReport, read_audit, verify_audit_chain
from .gateway import SecurityGateway
from .schemas import SecurityContext, ToolCall


class AuditReplayError(RuntimeError):
    pass


@dataclass(frozen=True)
class AuditReplayCase:
    event_index: int
    tool_name: str
    original_decision: str
    replay_decision: str
    matched: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_index": self.event_index,
            "tool_name": self.tool_name,
            "original_decision": self.original_decision,
            "replay_decision": self.replay_decision,
            "matched": self.matched,
        }


@dataclass(frozen=True)
class AuditReplayResult:
    integrity: AuditIntegrityReport
    cases: tuple[AuditReplayCase, ...]

    def metrics(self) -> dict[str, Any]:
        matched = sum(case.matched for case in self.cases)
        return {
            "total_events": len(self.cases),
            "matched_events": matched,
            "drifted_events": len(self.cases) - matched,
            "decision_match_rate": round(matched / len(self.cases), 4) if self.cases else 0.0,
            "tool_execution": "disabled",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "integrity": self.integrity.to_dict(),
            "metrics": self.metrics(),
            "cases": [case.to_dict() for case in self.cases],
        }


def replay_audit_decisions(
    path: str | Path,
    gateway: SecurityGateway,
    *,
    integrity_key: bytes | None = None,
) -> AuditReplayResult:
    """Re-run policy inspection only; registered tool handlers are never called."""

    integrity = verify_audit_chain(path, integrity_key=integrity_key)
    if not integrity.valid:
        raise AuditReplayError(f"Audit integrity validation failed: {integrity.reason}")
    cases: list[AuditReplayCase] = []
    for index, event in enumerate(read_audit(path), start=1):
        try:
            call = ToolCall.from_dict(event["call"])
            context = SecurityContext.from_dict(event["context"])
            original = str(event["decision"]["decision"])
        except (KeyError, TypeError, ValueError):
            raise AuditReplayError("Audit event cannot be reconstructed safely") from None
        replayed = gateway.inspect(call, context).decision.value
        cases.append(
            AuditReplayCase(
                event_index=index,
                tool_name=_safe_tool_name(call.tool_name),
                original_decision=original,
                replay_decision=replayed,
                matched=original == replayed,
            )
        )
    return AuditReplayResult(integrity=integrity, cases=tuple(cases))


def _safe_tool_name(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        return value
    return "tool:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
