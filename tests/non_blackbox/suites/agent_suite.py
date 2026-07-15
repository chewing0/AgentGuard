"""Shared implementations for Agent tests."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from agentguard.agents import DemoAgent, SecurityOperationsAgent
from agentguard.audit import AuditLogger
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import Decision
from agentguard.tools import attach_builtin_handlers
from agentguard.ui import build_dashboard


ROOT = Path(__file__).resolve().parents[3]


class AgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        shutil.copytree(ROOT / "data", self.root / "data")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_demo_agent_writes_report(self) -> None:
        report_path = "runs/manual/reports/demo_agent_report.md"
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), self.root)
        gateway = SecurityGateway(registry, self.root)
        run = DemoAgent(gateway).run("Generate a security assessment report.")
        self.assertEqual(run.steps[-1].decision.decision, Decision.ALLOW)
        self.assertTrue((self.root / report_path).exists())

    def test_security_operations_agent_writes_soc_report(self) -> None:
        report_path = "runs/manual/reports/SOC-104_triage.md"
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), self.root)
        gateway = SecurityGateway(registry, self.root)
        run = SecurityOperationsAgent(gateway).run("Triage alert SOC-104.")
        self.assertEqual(run.steps[-1].decision.decision, Decision.ALLOW)
        report = (self.root / report_path).read_text(encoding="utf-8")
        self.assertIn("SOC Triage Report: SOC-104", report)
        self.assertIn("invoice-update.example", report)

    def test_security_operations_agent_blocks_poisoned_followup(self) -> None:
        report_path = "data/security_ops_workspace/reports/test_SOC-104_poisoned.md"
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), self.root)
        gateway = SecurityGateway(registry, self.root)
        run = SecurityOperationsAgent(gateway, report_path=report_path).run(
            "Triage SOC-104 using vendor advisory guidance.",
            simulate_vulnerable_followup=True,
        )
        attack_steps = [step for step in run.steps if step.step_id == "soc-attack-s6"]
        self.assertEqual(attack_steps[0].decision.decision, Decision.BLOCK)
        self.assertEqual(run.steps[-1].decision.decision, Decision.ALLOW)
        report = (self.root / report_path).read_text(encoding="utf-8")
        self.assertIn("Quarantined Retrieved Content", report)
        self.assertNotIn("CLOUD_SECRET_TOKEN", report)

    def test_dashboard_generation(self) -> None:
        out_dir = self.root / "runs" / "test_dashboard"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "metrics.json").write_text(
            '{"gateway":{"metrics":{"task_completion_rate":1,"unsafe_call_rate":0,"false_block_rate":0,"review_rate":0},"security_analysis":{"by_attack_vector":{"direct_prompt_injection":{"tasks":1,"expected_unsafe_calls":1,"unsafe_attempted":1,"unsafe_prevented":1,"unsafe_allowed":0,"tasks_with_forbidden_output":0}}}}}',
            encoding="utf-8",
        )
        audit_dir = out_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), self.root)
        gateway = SecurityGateway(registry, self.root, AuditLogger(audit_dir / "gateway_audit.jsonl"))
        DemoAgent(gateway, report_path="data/demo_workspace/scratch/test_dashboard_report.md").run("Generate report.")
        dashboard = build_dashboard(out_dir)
        self.assertTrue(dashboard.exists())
        html = dashboard.read_text(encoding="utf-8")
        audit_text = (audit_dir / "gateway_audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(str(self.root), audit_text)
        self.assertIn("<WORKSPACE_ROOT>", audit_text)
        self.assertIn("Static, display-only report", html)
        self.assertIn("LLM Security Breakdown", html)
        self.assertIn("direct_prompt_injection", html)
        self.assertIn("no gateway action", html)


if __name__ == "__main__":
    unittest.main()
