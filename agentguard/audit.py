from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .schemas import AuditEvent, GatewayDecision, SecurityContext, ToolCall, ToolResult


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditLogger:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        context: SecurityContext,
        call: ToolCall,
        decision: GatewayDecision,
        result: ToolResult | None = None,
        labels: dict[str, Any] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            timestamp=utc_now_iso(),
            context=context.to_dict(),
            call=call.to_dict(),
            decision=decision.to_dict(),
            result=result.to_dict() if result else None,
            labels=labels or {},
        )
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        return event


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

