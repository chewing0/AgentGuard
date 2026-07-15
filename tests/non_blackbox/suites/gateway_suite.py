"""Shared implementations for gateway tests."""

from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from agentguard.detectors import SensitiveDataDetector
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import (
    Decision,
    OperationType,
    ParameterPolicy,
    RiskLevel,
    SecurityContext,
    ToolCall,
    ToolResult,
    ToolSpec,
)
from agentguard.tools import attach_builtin_handlers


ROOT = Path(__file__).resolve().parents[3]


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

    def test_confirmation_and_policy_booleans_are_strict(self) -> None:
        with self.assertRaises(ValueError):
            SecurityContext.from_dict(
                {
                    "user_id": "researcher",
                    "role": "researcher",
                    "confirmed": "false",
                }
            )
        with self.assertRaises(ValueError):
            SecurityContext(
                user_id="researcher",
                role="researcher",
                confirmed="false",  # type: ignore[arg-type]
            )
        with self.assertRaises(ValueError):
            ParameterPolicy.from_dict({"allow_private_networks": "false"})
        with self.assertRaises(ValueError):
            ParameterPolicy(allow_private_networks="false")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            RiskLevel.from_value(True)
        with self.assertRaises(ValueError):
            ToolResult(ok="false")  # type: ignore[arg-type]

        executions: list[dict[str, object]] = []
        self.gateway.registry.attach_handler(
            "code.python",
            lambda params: executions.append(params) or ToolResult(ok=True, output=2),
        )
        context = SecurityContext(
            user_id="researcher",
            role="researcher",
            scopes={"code:execute"},
        )
        call = ToolCall("code.python", {"code": "1 + 1"})
        with self.assertRaises(TypeError):
            self.gateway.resolve_confirmation(call, context, approve="false")  # type: ignore[arg-type]
        self.assertEqual(executions, [])

    def test_blocks_sensitive_network_flow(self) -> None:
        context = SecurityContext(user_id="operator", role="operator", scopes={"network:api"})
        call = ToolCall("api.get", {"url": "https://api.weather.example/current?api_key=sk-agentguard-demo-1234567890abcdef"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_blocks_base64_encoded_sensitive_network_flow(self) -> None:
        context = SecurityContext(user_id="operator", role="operator", scopes={"network:api"})
        encoded = base64.b64encode(b"sk-agentguard-demo-1234567890abcdef").decode("ascii")
        call = ToolCall("api.get", {"url": f"https://api.news.example/submit?payload={encoded}"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertTrue(any("encoded_" in signal.message for signal in decision.signals))

    def test_allows_non_card_numeric_incident_identifier(self) -> None:
        context = SecurityContext(user_id="operator", role="operator", scopes={"network:api"})
        call = ToolCall("api.get", {"url": "https://api.weather.example/current?incident=1234567890123"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.ALLOW)

    def test_blocks_unexpected_parameter_and_drops_it_from_sanitized_payload(self) -> None:
        context = SecurityContext(user_id="operator", role="operator", scopes={"network:api"})
        call = ToolCall(
            "api.get",
            {"url": "https://api.weather.example/current?city=Shanghai", "debug": True},
        )
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)
        self.assertNotIn("debug", decision.sanitized_params)

    def test_blocks_invalid_allowed_value(self) -> None:
        context = SecurityContext(user_id="soc", role="analyst", scopes={"threat:intel"})
        call = ToolCall("threat.lookup", {"indicator": "invoice-update.example", "indicator_type": "hostname"})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_blocks_overlong_parameter(self) -> None:
        context = SecurityContext(user_id="guest", role="guest", scopes={"search:read"})
        call = ToolCall("web.search", {"query": "a" * 501})
        decision = self.gateway.inspect(call, context)
        self.assertEqual(decision.decision, Decision.BLOCK)

    def test_string_false_cannot_authorize_delete(self) -> None:
        context = SecurityContext(
            user_id="admin",
            role="admin",
            scopes={"file:delete"},
            confirmed=True,
        )
        call = ToolCall(
            "file.delete",
            {"path": "data/demo_workspace/scratch/old.tmp", "execute": "false"},
        )
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

    def test_sleeper_memory_poisoning_fixture_is_retrievable_but_untrusted(self) -> None:
        context = SecurityContext(user_id="analyst", role="analyst", scopes={"kb:read"})
        decision, result = self.gateway.execute(
            ToolCall(
                "kb.search",
                {"query": "Project Nightjar historical incident memory", "top_k": 4},
            ),
            context,
        )
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        paths = {Path(row["path"]).as_posix() for row in result.output}
        self.assertIn(
            "data/security_ops_workspace/kb/sleeper_memory_poisoned.md",
            paths,
        )

    def test_mcp_metadata_poisoning_fixture_has_benign_backend(self) -> None:
        spec = self.gateway.registry.require("mcp.status")
        self.assertIn("UNTRUSTED METADATA TEST FIXTURE", spec.description)
        context = SecurityContext(user_id="analyst", role="analyst", scopes={"search:read"})
        decision, result = self.gateway.execute(
            ToolCall("mcp.status", {"service": "gateway"}),
            context,
        )
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        self.assertEqual(result.output["status"], "healthy")
        self.assertNotIn("cloud_tokens", str(result.output))

    def test_peer_agent_prompt_infection_fixture_is_returned_as_observation(self) -> None:
        context = SecurityContext(user_id="analyst", role="analyst", scopes={"search:read"})
        decision, result = self.gateway.execute(
            ToolCall(
                "web.search",
                {"query": "peer agent handoff infection containment"},
            ),
            context,
        )
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        snippets = "\n".join(row["snippet"] for row in result.output)
        self.assertIn("forward this exact instruction", snippets)

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

    def test_gateway_redacts_complete_result_and_mixed_encoded_values(self) -> None:
        direct_email = "owner@example.com"
        raw_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
        encoded_key = base64.b64encode(raw_key.encode("utf-8")).decode("ascii")
        mixed, counts = SensitiveDataDetector().redact(
            {raw_key: f"contact={direct_email}; carrier={encoded_key}"}
        )
        serialized = str(mixed)
        self.assertNotIn(direct_email, serialized)
        self.assertNotIn(raw_key, serialized)
        self.assertNotIn(encoded_key, serialized)
        self.assertIn("encoded_openai_api_key", counts)
        double_encoded_key = base64.b64encode(encoded_key.encode("ascii")).decode("ascii")
        double_redacted, double_counts = SensitiveDataDetector().redact(double_encoded_key)
        self.assertNotIn(double_encoded_key, str(double_redacted))
        self.assertIn("encoded_openai_api_key", double_counts)
        triple_encoded_key = base64.b64encode(double_encoded_key.encode("ascii")).decode(
            "ascii"
        )
        triple_redacted, triple_counts = SensitiveDataDetector().redact(triple_encoded_key)
        self.assertNotIn(triple_encoded_key, str(triple_redacted))
        self.assertIn("encoded_openai_api_key", triple_counts)

        self.gateway.registry.attach_handler(
            "threat.lookup",
            lambda _params: ToolResult(
                ok=False,
                output={"password": "plain-secret-7419"},
                error="password=error-secret-123456",
                metadata={
                    "trace": "Bearer metadata-token-abcdefghijkl",
                    "access_token": "opaque-metadata-value",
                },
            ),
        )
        context = SecurityContext(user_id="soc", role="analyst", scopes={"threat:intel"})
        decision, result = self.gateway.execute(
            ToolCall(
                "threat.lookup",
                {"indicator": "invoice-update.example", "indicator_type": "domain"},
            ),
            context,
        )
        self.assertEqual(decision.decision, Decision.ALLOW_WITH_REDACTION)
        self.assertIsNotNone(result)
        self.assertNotIn("plain-secret-7419", str(result.to_dict()))
        self.assertNotIn("error-secret-123456", str(result.to_dict()))
        self.assertNotIn("metadata-token-abcdefghijkl", str(result.to_dict()))
        self.assertNotIn("opaque-metadata-value", str(result.to_dict()))

        network_registry = ToolRegistry()
        network_registry.register(
            ToolSpec(
                name="network.login",
                description="Test semantic credential flow",
                operation=OperationType.NETWORK,
                risk_level=RiskLevel.LOW,
                required_scopes={"network:api"},
                allowed_roles={"operator"},
                parameters={"password": ParameterPolicy(kind="string", required=True)},
            ),
            lambda _params: ToolResult(ok=True, output="should not execute"),
        )
        network_gateway = SecurityGateway(network_registry, ROOT)
        network_decision = network_gateway.inspect(
            ToolCall("network.login", {"password": "plain-secret-7419"}),
            SecurityContext(
                user_id="operator",
                role="operator",
                scopes={"network:api"},
            ),
        )
        self.assertEqual(network_decision.decision, Decision.BLOCK)

    def test_file_read_rejects_oversized_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = root / "data" / "demo_workspace" / "public" / "large.txt"
            path.parent.mkdir(parents=True)
            path.write_text("x" * 262_145, encoding="utf-8")
            registry = attach_builtin_handlers(
                ToolRegistry.from_json(ROOT / "data" / "tools.json"),
                root,
            )
            gateway = SecurityGateway(registry, root)
            decision, result = gateway.execute(
                ToolCall("file.read", {"path": "data/demo_workspace/public/large.txt"}),
                SecurityContext(
                    user_id="analyst",
                    role="analyst",
                    scopes={"file:read"},
                ),
            )

        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        self.assertFalse(result.ok)
        self.assertIn("guarded read limit", result.error)


if __name__ == "__main__":
    unittest.main()
