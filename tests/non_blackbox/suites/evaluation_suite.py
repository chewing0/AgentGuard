"""Shared implementations for labeled-trace evaluation tests."""

from __future__ import annotations

import unittest
from pathlib import Path

from agentguard.benchmarks import BenchmarkStep, load_tasks
from agentguard.evaluation import EvaluationRunner
from agentguard.gateway import SecurityGateway
from agentguard.metrics import compute_metrics
from agentguard.registry import ToolRegistry
from agentguard.tools import attach_builtin_handlers


ROOT = Path(__file__).resolve().parents[3]
BENCHMARKS = ROOT / "data" / "benchmarks"


class EvaluationTests(unittest.TestCase):
    def test_benchmark_flags_reject_truthy_string_coercion(self) -> None:
        raw = {
            "step_id": "strict-bool",
            "call": {"tool_name": "file.read", "params": {}},
            "safe": "false",
            "completion_required": False,
        }
        with self.assertRaises(ValueError):
            BenchmarkStep.from_dict(raw, "strict-task")

    def test_benchmark_expected_gateway_decisions(self) -> None:
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT)
        for task in load_tasks(BENCHMARKS / "benchmark_tasks.jsonl"):
            for step in task.steps:
                if step.expected_gateway_decision:
                    actual = gateway.inspect(step.call, task.context).decision.value
                    self.assertEqual(
                        actual,
                        step.expected_gateway_decision,
                        f"{task.task_id}/{step.step_id}",
                    )

    def test_gateway_reduces_unsafe_calls_without_hurting_completion(self) -> None:
        registry = ToolRegistry.from_json(ROOT / "data" / "tools.json")
        tasks = load_tasks(BENCHMARKS / "benchmark_tasks.jsonl")
        result = EvaluationRunner(registry, ROOT).run(tasks, ["none", "gateway"])
        none_metrics = result.modes["none"].metrics()
        gateway_metrics = result.modes["gateway"].metrics()
        self.assertEqual(none_metrics["unsafe_call_rate"], 1.0)
        self.assertEqual(gateway_metrics["unsafe_call_rate"], 0.0)
        self.assertEqual(gateway_metrics["task_completion_rate"], 1.0)

    def test_component_ablation_modes_are_available(self) -> None:
        registry = ToolRegistry.from_json(ROOT / "data" / "tools.json")
        tasks = load_tasks(BENCHMARKS / "benchmark_tasks.jsonl")
        result = EvaluationRunner(registry, ROOT).run(
            tasks,
            ["gateway", "gateway_without_prompt_injection"],
        )
        full = result.modes["gateway"].metrics()
        self.assertEqual(full["unsafe_call_rate"], 0.0)
        full_step = next(
            step for step in result.modes["gateway"].steps if step.task_id == "ag-inj-003"
        )
        ablated_step = next(
            step
            for step in result.modes["gateway_without_prompt_injection"].steps
            if step.task_id == "ag-inj-003"
        )
        self.assertEqual(full_step.decision, "block")
        self.assertEqual(ablated_step.decision, "require_confirmation")

    def test_completion_excludes_tasks_without_required_steps_and_reports_utility(self) -> None:
        rows = [
            {
                "task_id": "eligible-complete",
                "safe": True,
                "violation_types": [],
                "completion_required": True,
                "decision": "allow",
            },
            {
                "task_id": "eligible-incomplete",
                "safe": True,
                "violation_types": [],
                "completion_required": True,
                "decision": "block",
            },
            {
                "task_id": "not-eligible",
                "safe": True,
                "violation_types": [],
                "completion_required": False,
                "decision": "allow",
            },
        ]

        metrics = compute_metrics(rows)

        self.assertEqual(metrics["total_tasks"], 3)
        self.assertEqual(metrics["eligible_tasks"], 2)
        self.assertEqual(metrics["completed_tasks"], 1)
        self.assertEqual(metrics["task_completion_rate"], 0.5)
        self.assertEqual(metrics["safe_allowed"], 2)
        self.assertEqual(metrics["safe_not_allowed"], 1)
        self.assertEqual(metrics["safe_call_allow_rate"], 0.6667)


if __name__ == "__main__":
    unittest.main()
