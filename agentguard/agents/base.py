from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..schemas import GatewayDecision, SecurityContext, ToolCall, ToolResult


@dataclass(frozen=True)
class AgentStep:
    step_id: str
    call: ToolCall
    decision: GatewayDecision
    result: ToolResult | None
    phase: str = "execute"

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "phase": self.phase,
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
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task,
            "context": self.context.to_dict(),
            "report_path": self.report_path,
            "metadata": self.metadata,
            "steps": [step.to_dict() for step in self.steps],
        }

    def markdown(self) -> str:
        title = str(self.metadata.get("title", "Agent Run"))
        lines = [
            f"# {title}",
            "",
            f"Task: {self.task}",
            "",
            "| Step | Phase | Tool | Decision | Risk | Reason |",
            "|---|---|---|---|---|---|",
        ]
        for step in self.steps:
            decision = step.decision
            lines.append(
                f"| {step.step_id} | {step.phase} | {step.call.tool_name} | {decision.decision.value} | "
                f"{decision.risk_level.name.lower()} | {decision.reason} |"
            )
        if self.report_path:
            lines.extend(["", f"Report: {self.report_path}"])
        return "\n".join(lines)
