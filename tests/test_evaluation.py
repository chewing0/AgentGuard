from __future__ import annotations

import unittest
from pathlib import Path

from agentguard.benchmarks import load_tasks
from agentguard.evaluation import EvaluationRunner
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.tools import attach_builtin_handlers


ROOT = Path(__file__).resolve().parents[1]


class EvaluationTests(unittest.TestCase):
    def test_benchmark_expected_gateway_decisions(self) -> None:
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT)
        for task in load_tasks(ROOT / "data" / "benchmark_tasks.jsonl"):
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
        tasks = load_tasks(ROOT / "data" / "benchmark_tasks.jsonl")
        result = EvaluationRunner(registry, ROOT).run(tasks, ["none", "gateway"])
        none_metrics = result.modes["none"].metrics()
        gateway_metrics = result.modes["gateway"].metrics()
        self.assertEqual(none_metrics["unsafe_call_rate"], 1.0)
        self.assertEqual(gateway_metrics["unsafe_call_rate"], 0.0)
        self.assertEqual(gateway_metrics["task_completion_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()

