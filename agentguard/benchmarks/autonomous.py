from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard.schemas import SecurityContext


ExpectedUnsafeCall = str | dict[str, Any]


@dataclass(frozen=True)
class AutonomousBenchmarkTask:
    task_id: str
    category: str
    prompt: str
    context: SecurityContext
    expected_required_tools: list[str] = field(default_factory=list)
    expected_blocked_tools: list[ExpectedUnsafeCall] = field(default_factory=list)
    forbidden_output_patterns: list[str] = field(default_factory=list)
    completion_artifact: str | None = None
    completion_artifact_contains: list[str] = field(default_factory=list)
    completion_artifact_content_patterns: list[str] = field(default_factory=list)
    attack_scenario: str = "none"
    attack_vector: str = "none"
    attack_channel: str = "none"
    attack_goal: str = "none"
    expected_model_behavior: str = "complete_benign_task"
    tags: list[str] = field(default_factory=list)
    research_references: list[str] = field(default_factory=list)
    test_scope: str = ""
    enabled_fixture_tools: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AutonomousBenchmarkTask":
        return cls(
            task_id=str(raw["task_id"]),
            category=str(raw.get("category", "unknown")),
            prompt=str(raw.get("prompt", "")),
            context=SecurityContext.from_dict(raw.get("context", {})),
            expected_required_tools=list(raw.get("expected_required_tools", [])),
            expected_blocked_tools=[
                dict(item) if isinstance(item, dict) else str(item)
                for item in raw.get("expected_blocked_tools", [])
            ],
            forbidden_output_patterns=list(raw.get("forbidden_output_patterns", [])),
            completion_artifact=raw.get("completion_artifact"),
            completion_artifact_contains=list(raw.get("completion_artifact_contains", [])),
            completion_artifact_content_patterns=list(
                raw.get("completion_artifact_content_patterns", [])
            ),
            attack_scenario=str(raw.get("attack_scenario", "none")),
            attack_vector=str(raw.get("attack_vector", "none")),
            attack_channel=str(raw.get("attack_channel", "none")),
            attack_goal=str(raw.get("attack_goal", "none")),
            expected_model_behavior=str(
                raw.get("expected_model_behavior", "complete_benign_task")
            ),
            tags=list(raw.get("tags", [])),
            research_references=list(raw.get("research_references", [])),
            test_scope=str(raw.get("test_scope", "")),
            enabled_fixture_tools=list(raw.get("enabled_fixture_tools", [])),
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
            "completion_artifact_contains": self.completion_artifact_contains,
            "completion_artifact_content_patterns": self.completion_artifact_content_patterns,
            "attack_scenario": self.attack_scenario,
            "attack_vector": self.attack_vector,
            "attack_channel": self.attack_channel,
            "attack_goal": self.attack_goal,
            "expected_model_behavior": self.expected_model_behavior,
            "tags": self.tags,
            "research_references": self.research_references,
            "test_scope": self.test_scope,
            "enabled_fixture_tools": self.enabled_fixture_tools,
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
