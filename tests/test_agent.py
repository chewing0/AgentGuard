from __future__ import annotations

import unittest
from pathlib import Path

from agentguard.agents import DemoAgent
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
