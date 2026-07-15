"""Shared implementations for audit tests."""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from agentguard.audit import AuditLogger
from agentguard.schemas import (
    Decision,
    GatewayDecision,
    RiskLevel,
    RiskSignal,
    RiskSignalType,
    SecurityContext,
    ToolCall,
    ToolResult,
)


class AuditLoggerTests(unittest.TestCase):
    def test_redacts_secrets_from_every_audit_section(self) -> None:
        mixed_encoded_secret = "sk-auditmixedabcdefghijklmnopqrstuvwxyz"
        secrets = {
            "context": "owner@example.com",
            "param_password": "plain-password-value-7419",
            "param_assignment": "api_key=abcdefghijklmnop123456",
            "source": "sk-sourceabcdefghijklmnopqrstuv",
            "purpose": "Bearer purpose-token-abcdefghijklmnop",
            "reason": "reason@example.com",
            "signal": "sk-signalabcdefghijklmnopqrstuv",
            "sanitized": "sanitized-password-value-8520",
            "output": "sk-outputabcdefghijklmnopqrstuv",
            "error": "password=error-password-value-9631",
            "metadata": "Bearer metadata-token-abcdefghijkl",
            "label": "label-credential-value-1597",
            "attacker_key": "sk-attackercontrolledabcdefghijklmnop",
            "mixed_encoded_secret": mixed_encoded_secret,
            "mixed_encoded_carrier": base64.b64encode(
                mixed_encoded_secret.encode("utf-8")
            ).decode("ascii"),
        }

        context = SecurityContext(
            user_id=secrets["context"],
            role="analyst",
            scopes={"file:read"},
            session_id="audit-session",
        )
        call = ToolCall(
            tool_name="demo.lookup",
            params={
                "password": secrets["param_password"],
                "nested": {"note": secrets["param_assignment"]},
                "query": "benign search term",
                secrets["attacker_key"]: (
                    f"contact={secrets['context']}; "
                    f"carrier={secrets['mixed_encoded_carrier']}"
                ),
            },
            task_id="task-17",
            step_id="step-2",
            source_content=f"Untrusted source included {secrets['source']}",
            declared_purpose=f"Authenticate using {secrets['purpose']}",
        )
        decision = GatewayDecision(
            decision=Decision.BLOCK,
            risk_level=RiskLevel.CRITICAL,
            reason=f"Rejected value from {secrets['reason']}",
            signals=[
                RiskSignal(
                    signal_type=RiskSignalType.SENSITIVE_DATA,
                    level=RiskLevel.CRITICAL,
                    message=f"Sensitive value detected: {secrets['signal']}",
                    evidence=secrets["signal"],
                )
            ],
            sanitized_params={
                "credentials": {
                    "password": secrets["sanitized"],
                    "account": "service-account",
                }
            },
            redactions={"bearer_token": 1},
        )
        result = ToolResult(
            ok=False,
            output={"access_token": secrets["output"], "status": "rejected"},
            error=f"Request failed with {secrets['error']}",
            metadata={"authorization": secrets["metadata"], "attempts": 1},
        )
        labels = {
            "credential": secrets["label"],
            "suite": "audit-hardening",
            "nested": {"classification": "synthetic"},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "audit.jsonl"
            result.metadata["path"] = str(Path(temp_dir) / "data" / "fixture.txt")
            event = AuditLogger(path, workspace_root=temp_dir).record(
                context, call, decision, result, labels
            )
            serialized = path.read_text(encoding="utf-8")
            persisted = json.loads(serialized)

        for raw_secret in secrets.values():
            self.assertNotIn(raw_secret, serialized)

        # The returned object is the same safe representation that was persisted.
        self.assertEqual(event.to_dict(), persisted)
        self.assertEqual(persisted["context"]["role"], "analyst")
        self.assertEqual(persisted["call"]["params"]["query"], "benign search term")
        self.assertEqual(persisted["call"]["task_id"], "task-17")
        self.assertEqual(persisted["decision"]["decision"], "block")
        self.assertEqual(persisted["decision"]["redactions"], {"bearer_token": 1})
        self.assertEqual(persisted["result"]["output"]["status"], "rejected")
        self.assertEqual(persisted["result"]["metadata"]["attempts"], 1)
        self.assertTrue(
            persisted["result"]["metadata"]["path"].startswith("<WORKSPACE_ROOT>")
        )
        self.assertNotIn(temp_dir, serialized)
        self.assertEqual(persisted["labels"]["suite"], "audit-hardening")
        self.assertEqual(persisted["labels"]["nested"]["classification"], "synthetic")
        self.assertEqual(
            persisted["decision"]["signals"][0]["evidence"],
            "[REDACTED:openai_api_key]",
        )

    def test_masks_plain_values_under_credential_keys_without_a_file(self) -> None:
        event = AuditLogger().record(
            SecurityContext(user_id="researcher", role="analyst"),
            ToolCall(
                tool_name="demo.lookup",
                params={
                    "database_password": "not-regex-shaped",
                    "nested": {"refresh_token": ["opaque-one", "opaque-two"]},
                    "limit": 5,
                },
            ),
            GatewayDecision(
                decision=Decision.ALLOW,
                risk_level=RiskLevel.LOW,
                reason="Allowed benign lookup",
                sanitized_params={"limit": 5},
            ),
        )

        self.assertEqual(event.call["params"]["database_password"], "[REDACTED:database_password]")
        self.assertEqual(
            event.call["params"]["nested"]["refresh_token"],
            ["[REDACTED:refresh_token]", "[REDACTED:refresh_token]"],
        )
        self.assertEqual(event.call["params"]["limit"], 5)
        self.assertEqual(event.decision["reason"], "Allowed benign lookup")


if __name__ == "__main__":
    unittest.main()
