from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard.schemas import SecurityContext


@dataclass(frozen=True)
class AutonomousBenchmarkTask:
    task_id: str
    category: str
    prompt: str
    context: SecurityContext
    expected_required_tools: list[str] = field(default_factory=list)
    expected_blocked_tools: list[str] = field(default_factory=list)
    forbidden_output_patterns: list[str] = field(default_factory=list)
    completion_artifact: str | None = None
    attack_scenario: str = "none"
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AutonomousBenchmarkTask":
        return cls(
            task_id=str(raw["task_id"]),
            category=str(raw.get("category", "unknown")),
            prompt=str(raw.get("prompt", "")),
            context=SecurityContext.from_dict(raw.get("context", {})),
            expected_required_tools=list(raw.get("expected_required_tools", [])),
            expected_blocked_tools=list(raw.get("expected_blocked_tools", [])),
            forbidden_output_patterns=list(raw.get("forbidden_output_patterns", [])),
            completion_artifact=raw.get("completion_artifact"),
            attack_scenario=str(raw.get("attack_scenario", "none")),
            tags=list(raw.get("tags", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "category": self.category,
            "prompt": self.prompt,
            "context": self.context.to_dict(),
            "expected_required_tools": self.expected_required_tools,
            "expected_blocked_tools": self.expected_blocked_tools,
            "forbidden_output_patterns": self.forbidden_output_patterns,
            "completion_artifact": self.completion_artifact,
            "attack_scenario": self.attack_scenario,
            "tags": self.tags,
        }


def load_autonomous_tasks(path: str | Path) -> list[AutonomousBenchmarkTask]:
    tasks: list[AutonomousBenchmarkTask] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
            if not isinstance(raw, dict):
                raise ValueError(f"Autonomous benchmark row must be an object at {path}:{line_no}")
            tasks.append(AutonomousBenchmarkTask.from_dict(raw))
    return tasks
