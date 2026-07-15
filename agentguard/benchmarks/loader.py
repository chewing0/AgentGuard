from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard.schemas import SecurityContext, ToolCall, strict_bool


@dataclass(frozen=True)
class BenchmarkStep:
    step_id: str
    call: ToolCall
    safe: bool
    violation_types: list[str] = field(default_factory=list)
    completion_required: bool = False
    expected_gateway_decision: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        strict_bool(self.safe, "benchmark.safe")
        strict_bool(self.completion_required, "benchmark.completion_required")

    @classmethod
    def from_dict(cls, raw: dict[str, Any], task_id: str) -> "BenchmarkStep":
        call_raw = dict(raw["call"])
        call_raw.setdefault("task_id", task_id)
        call_raw.setdefault("step_id", raw.get("step_id", "step-0"))
        return cls(
            step_id=raw.get("step_id", call_raw["step_id"]),
            call=ToolCall.from_dict(call_raw),
            safe=strict_bool(raw.get("safe", True), "benchmark.safe"),
            violation_types=list(raw.get("violation_types", [])),
            completion_required=strict_bool(
                raw.get("completion_required", False),
                "benchmark.completion_required",
            ),
            expected_gateway_decision=raw.get("expected_gateway_decision"),
            notes=raw.get("notes", ""),
        )

    def labels(self) -> dict[str, Any]:
        return {
            "safe": self.safe,
            "violation_types": self.violation_types,
            "completion_required": self.completion_required,
            "expected_gateway_decision": self.expected_gateway_decision,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class BenchmarkTask:
    task_id: str
    category: str
    objective: str
    prompt: str
    context: SecurityContext
    steps: list[BenchmarkStep]
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BenchmarkTask":
        task_id = raw["task_id"]
        return cls(
            task_id=task_id,
            category=raw.get("category", "unknown"),
            objective=raw.get("objective", ""),
            prompt=raw.get("prompt", ""),
            context=SecurityContext.from_dict(raw.get("context", {})),
            steps=[BenchmarkStep.from_dict(step, task_id) for step in raw.get("steps", [])],
            tags=list(raw.get("tags", [])),
        )


def load_tasks(path: str | Path) -> list[BenchmarkTask]:
    tasks: list[BenchmarkTask] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                tasks.append(BenchmarkTask.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
    return tasks
