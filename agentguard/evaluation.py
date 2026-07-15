from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import AuditLogger
from .benchmarks import BenchmarkTask, load_tasks
from .gateway import SecurityGateway
from .metrics import METRIC_NAMES, compute_metrics
from .policies import ProtectionPolicy, build_policies
from .registry import ToolRegistry
from .run_manifest import build_run_manifest, prepare_run_directory, write_run_manifest
from .schemas import Decision, GatewayDecision, ToolResult
from .tools import attach_builtin_handlers


@dataclass
class StepEvaluation:
    task_id: str
    category: str
    step_id: str
    tool_name: str
    safe: bool
    violation_types: list[str]
    completion_required: bool
    decision: str
    risk_level: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision in {Decision.ALLOW.value, Decision.ALLOW_WITH_REDACTION.value}

    @property
    def reviewed(self) -> bool:
        return self.decision == Decision.REQUIRE_CONFIRMATION.value

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "category": self.category,
            "step_id": self.step_id,
            "tool_name": self.tool_name,
            "safe": self.safe,
            "violation_types": self.violation_types,
            "completion_required": self.completion_required,
            "decision": self.decision,
            "risk_level": self.risk_level,
            "reason": self.reason,
        }


@dataclass
class ModeEvaluation:
    mode: str
    steps: list[StepEvaluation] = field(default_factory=list)

    def metrics(self) -> dict[str, float | int]:
        return compute_metrics(self.steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "metrics": self.metrics(),
            "steps": [step.to_dict() for step in self.steps],
        }


@dataclass
class EvaluationResult:
    modes: dict[str, ModeEvaluation]

    def to_dict(self) -> dict[str, Any]:
        return {name: mode.to_dict() for name, mode in self.modes.items()}

    def markdown(self) -> str:
        lines = [
            "# AgentGuard Evaluation Report",
            "",
            "| Mode | " + " | ".join(METRIC_NAMES) + " |",
            "|---|" + "|".join(["---:"] * len(METRIC_NAMES)) + "|",
        ]
        for name, evaluation in self.modes.items():
            metrics = evaluation.metrics()
            values = [str(metrics.get(metric, 0.0)) for metric in METRIC_NAMES]
            lines.append(f"| {name} | " + " | ".join(values) + " |")
        lines.extend(
            [
                "",
                "Lower unsafe, leakage, high-risk, and parameter-tampering rates are better. ",
                "A strong gateway should preserve task completion while reducing unsafe executions.",
            ]
        )
        return "\n".join(lines)


class EvaluationRunner:
    def __init__(
        self,
        registry: ToolRegistry,
        workspace_root: str | Path,
        audit_dir: str | Path | None = None,
        execute_allowed: bool = False,
    ) -> None:
        self.registry = attach_builtin_handlers(registry, workspace_root)
        self.workspace_root = Path(workspace_root).resolve()
        self.audit_dir = Path(audit_dir) if audit_dir else None
        self.execute_allowed = execute_allowed

    def run(self, tasks: list[BenchmarkTask], mode_names: list[str] | None = None) -> EvaluationResult:
        gateway_audit = (
            AuditLogger(self.audit_dir / "gateway_audit.jsonl", workspace_root=self.workspace_root)
            if self.audit_dir
            else AuditLogger(workspace_root=self.workspace_root)
        )
        gateway = SecurityGateway(self.registry, self.workspace_root, gateway_audit)
        policies = build_policies(self.registry, gateway)
        if mode_names is None:
            mode_names = ["none", "prompt_only", "rule_guard", "gateway"]
        modes: dict[str, ModeEvaluation] = {}
        for mode in mode_names:
            if mode not in policies:
                raise ValueError(f"Unknown evaluation mode: {mode}")
            audit = (
                AuditLogger(
                    self.audit_dir / f"{mode}_audit.jsonl",
                    workspace_root=self.workspace_root,
                )
                if self.audit_dir
                else AuditLogger(workspace_root=self.workspace_root)
            )
            modes[mode] = self._run_mode(tasks, mode, policies[mode], audit)
        return EvaluationResult(modes)

    def _run_mode(
        self,
        tasks: list[BenchmarkTask],
        mode: str,
        policy: ProtectionPolicy,
        audit: AuditLogger,
    ) -> ModeEvaluation:
        evaluation = ModeEvaluation(mode=mode)
        for task in tasks:
            for step in task.steps:
                decision = policy.inspect(step.call, task.context)
                result = self._maybe_execute(decision, step.call) if self.execute_allowed else None
                audit.record(task.context, step.call, decision, result, step.labels() | {"mode": mode, "category": task.category})
                evaluation.steps.append(
                    StepEvaluation(
                        task_id=task.task_id,
                        category=task.category,
                        step_id=step.step_id,
                        tool_name=step.call.tool_name,
                        safe=step.safe,
                        violation_types=step.violation_types,
                        completion_required=step.completion_required,
                        decision=decision.decision.value,
                        risk_level=decision.risk_level.name.lower(),
                        reason=decision.reason,
                    )
                )
        return evaluation

    def _maybe_execute(self, decision: GatewayDecision, call) -> ToolResult | None:
        if decision.allowed_to_execute:
            return self.registry.execute(call)
        return None


def run_evaluation(
    tasks_path: str | Path,
    tools_path: str | Path,
    workspace_root: str | Path,
    output_dir: str | Path,
    modes: list[str] | None = None,
    execute_allowed: bool = False,
    overwrite: bool = False,
) -> EvaluationResult:
    registry = ToolRegistry.from_json(tools_path)
    tasks = load_tasks(tasks_path)
    out = prepare_run_directory(output_dir, overwrite=overwrite)
    runner = EvaluationRunner(registry, workspace_root, out / "audit", execute_allowed=execute_allowed)
    result = runner.run(tasks, modes)
    (out / "metrics.json").write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "report.md").write_text(result.markdown(), encoding="utf-8")
    write_run_manifest(
        out,
        build_run_manifest(
            run_type="labeled_trace",
            project_root=workspace_root,
            tasks_path=tasks_path,
            tools_path=tools_path,
            configuration={
                "modes": modes or ["none", "prompt_only", "rule_guard", "gateway"],
                "execute_allowed": execute_allowed,
            },
        ),
    )
    return result
