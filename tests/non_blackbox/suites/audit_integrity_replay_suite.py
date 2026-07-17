"""Shared implementation for audit integrity and safe replay tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentguard.audit import AuditLogger, verify_audit_chain
from agentguard.audit_replay import AuditReplayError, replay_audit_decisions
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import (
    OperationType,
    ParameterPolicy,
    RiskLevel,
    SecurityContext,
    ToolCall,
    ToolResult,
    ToolSpec,
)


class AuditIntegrityReplayTests(unittest.TestCase):
    def test_hmac_chain_detects_tampering_and_replay_never_executes_tools(self) -> None:
        key = b"agentguard-test-integrity-key-32bytes"
        executions: list[dict[str, object]] = []
        registry = ToolRegistry()
        registry.register(
            ToolSpec(
                name="status.read",
                description="Read status.",
                operation=OperationType.READ,
                risk_level=RiskLevel.LOW,
                required_scopes={"status:read"},
                allowed_roles={"analyst"},
                parameters={
                    "service": ParameterPolicy(
                        kind="string",
                        required=True,
                        allowed_values=["gateway"],
                    )
                },
            ),
            lambda params: executions.append(params) or ToolResult(ok=True, output="healthy"),
        )
        context = SecurityContext(
            user_id="audit-user",
            role="analyst",
            scopes={"status:read"},
        )
        call = ToolCall("status.read", {"service": "gateway"})

        with tempfile.TemporaryDirectory() as temp_dir:
            audit_path = Path(temp_dir) / "audit.jsonl"
            logger = AuditLogger(audit_path, integrity_key=key)
            gateway = SecurityGateway(registry, audit_logger=logger)
            decision, result = gateway.execute(call, context)
            verified = verify_audit_chain(audit_path, integrity_key=key)
            replay = replay_audit_decisions(audit_path, gateway, integrity_key=key)

            event = json.loads(audit_path.read_text(encoding="utf-8"))
            event["call"]["params"]["service"] = "tampered"
            audit_path.write_text(json.dumps(event, ensure_ascii=False) + "\n", encoding="utf-8")
            tampered = verify_audit_chain(audit_path, integrity_key=key)
            with self.assertRaises(AuditReplayError):
                replay_audit_decisions(audit_path, gateway, integrity_key=key)

        self.assertTrue(decision.allowed_to_execute)
        self.assertTrue(result.ok)
        self.assertEqual(executions, [{"service": "gateway"}])
        self.assertTrue(verified.valid)
        self.assertEqual(verified.chained_events, 1)
        self.assertEqual(replay.metrics()["decision_match_rate"], 1.0)
        self.assertEqual(replay.metrics()["tool_execution"], "disabled")
        self.assertEqual(executions, [{"service": "gateway"}])
        self.assertFalse(tampered.valid)
        self.assertEqual(tampered.reason, "event_hash_mismatch")
