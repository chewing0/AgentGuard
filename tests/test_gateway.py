from __future__ import annotations

import unittest
from pathlib import Path

from agentguard.detectors import SensitiveDataDetector
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import Decision, SecurityContext, ToolCall
from agentguard.tools import attach_builtin_handlers


ROOT = Path(__file__).resolve().parents[1]


class GatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        registry = attach_builtin_handlers(ToolRegistry.from_json(ROOT / "data" / "tools.json"), ROOT)
        self.gateway = SecurityGateway(registry, ROOT)
        self.analyst = SecurityContext(
            user_id="test",
            role="analyst",
            scopes={"file:read", "file:write", "db:read", "network:api", "search:read"},
        )

    def test_allows_public_file_read(self) -> None:
        call = ToolCall("file.read", {"path": "data/demo_workspace/public/project_brief.txt"})
        decision = self.gateway.inspect(call, self.analyst)
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_blocks_path_traversal_to_secret(self) -> None:
        call = ToolCall("file.read", {"path": "data/demo_workspace/public/../secrets.env"})
        decision = self.gateway.inspect(call, self.analyst)
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertTrue(any(signal.signal_type.value == "parameter" for signal in decision.signals))

    def test_requires_confirmation_for_unconfirmed_code(self) -> None:
        context = SecurityContext(user_id="researcher", role="researcher", scopes={"code:execute"}, confirmed=False)
        call = ToolCall("code.python", {"code": "sum([1, 2, 3])"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.REQUIRE_CONFIRMATION)

    def test_confirmation_approval_executes_high_risk_call(self) -> None:
        context = SecurityContext(user_id="researcher", role="researcher", scopes={"code:execute"}, confirmed=False)
        call = ToolCall("code.python", {"code": "sum([1, 2, 3])"})
        decision, result = self.gateway.resolve_confirmation(call, context, approve=True)
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        self.assertTrue(result.ok)

    def test_blocks_sensitive_network_flow(self) -> None:
        context = SecurityContext(user_id="operator", role="operator", scopes={"network:api"})
        call = ToolCall("api.get", {"url": "https://api.weather.example/current?api_key=sk-agentguard-demo-1234567890abcdef"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_allows_knowledge_base_search(self) -> None:
        context = SecurityContext(user_id="analyst", role="analyst", scopes={"kb:read"})
        call = ToolCall("kb.search", {"query": "gateway report recommendations", "top_k": 2})
        decision, result = self.gateway.execute(call, context)
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        self.assertTrue(result.ok)
        self.assertGreaterEqual(len(result.output), 1)

    def test_allows_threat_intel_lookup(self) -> None:
        context = SecurityContext(user_id="soc", role="analyst", scopes={"threat:intel"})
        call = ToolCall("threat.lookup", {"indicator": "invoice-update.example", "indicator_type": "domain"})
        decision, result = self.gateway.execute(call, context)
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        self.assertEqual(result.output["reputation"], "suspicious")

    def test_blocks_secret_in_threat_intel_lookup(self) -> None:
        context = SecurityContext(user_id="soc", role="analyst", scopes={"threat:intel"})
        call = ToolCall("threat.lookup", {"indicator": "sk-agentguard-demo-1234567890abcdef", "indicator_type": "domain"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_sensitive_detector_redacts_nested_values(self) -> None:
        redacted, counts = SensitiveDataDetector().redact({"token": "sk-agentguard-demo-1234567890abcdef"})
        self.assertIn("openai_api_key", counts)
        self.assertEqual(redacted["token"], "[REDACTED:openai_api_key]")


if __name__ == "__main__":
    unittest.main()
