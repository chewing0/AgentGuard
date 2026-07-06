from __future__ import annotations

import unittest
from pathlib import Path

from agentguard.agents import DemoAgent, SecurityOperationsAgent
from agentguard.audit import AuditLogger
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import Decision
from agentguard.tools import attach_builtin_handlers
from agentguard.ui import build_dashboard


ROOT = Path(__file__).resolve().parents[1]


class AgentTests(unittest.TestCase):
    def test_demo_agent_writes_report(self) -> None:
        report_path = "data/demo_workspace/scratch/test_agent_report.md"
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT)
        run = DemoAgent(gateway, report_path=report_path).run("Generate a security assessment report.")
        self.assertEqual(run.steps[-1].decision.decision, Decision.ALLOW)
        self.assertTrue((ROOT / report_path).exists())

    def test_security_operations_agent_writes_soc_report(self) -> None:
        report_path = "data/security_ops_workspace/reports/test_SOC-104_triage.md"
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT)
        run = SecurityOperationsAgent(gateway, report_path=report_path).run("Triage alert SOC-104.")
        self.assertEqual(run.steps[-1].decision.decision, Decision.ALLOW)
        report = (ROOT / report_path).read_text(encoding="utf-8")
        self.assertIn("SOC Triage Report: SOC-104", report)
        self.assertIn("invoice-update.example", report)

    def test_security_operations_agent_blocks_poisoned_followup(self) -> None:
        report_path = "data/security_ops_workspace/reports/test_SOC-104_poisoned.md"
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT)
        run = SecurityOperationsAgent(gateway, report_path=report_path).run(
            "Triage SOC-104 using vendor advisory guidance.",
            simulate_vulnerable_followup=True,
        )
        attack_steps = [step for step in run.steps if step.step_id == "soc-attack-s6"]
        self.assertEqual(attack_steps[0].decision.decision, Decision.BLOCK)
        self.assertEqual(run.steps[-1].decision.decision, Decision.ALLOW)
        report = (ROOT / report_path).read_text(encoding="utf-8")
        self.assertIn("Quarantined Retrieved Content", report)
        self.assertNotIn("CLOUD_SECRET_TOKEN", report)

    def test_dashboard_generation(self) -> None:
        out_dir = ROOT / "runs" / "test_dashboard"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "metrics.json").write_text(
            '{"gateway":{"metrics":{"task_completion_rate":1,"unsafe_call_rate":0,"false_block_rate":0,"review_rate":0}}}',
            encoding="utf-8",
        )
        audit_dir = out_dir / "audit"
        audit_dir.mkdir(exist_ok=True)
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        gateway = SecurityGateway(registry, ROOT, AuditLogger(audit_dir / "gateway_audit.jsonl"))
        DemoAgent(gateway, report_path="data/demo_workspace/scratch/test_dashboard_report.md").run("Generate report.")
        dashboard = build_dashboard(out_dir)
        self.assertTrue(dashboard.exists())


if __name__ == "__main__":
    unittest.main()
