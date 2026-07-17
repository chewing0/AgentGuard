"""Shared implementation for persistent one-time approval tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentguard.approval import ApprovalError, PersistentApprovalStore
from agentguard.audit import AuditLogger
from agentguard.gateway import SecurityGateway
from agentguard.registry import ToolRegistry
from agentguard.schemas import Decision, SecurityContext, ToolCall
from agentguard.tools import attach_builtin_handlers


ROOT = Path(__file__).resolve().parents[3]


class ApprovalTests(unittest.TestCase):
    def test_persistent_approval_is_exactly_bound_and_one_time_without_raw_token_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            database_path = root / "approvals.sqlite3"
            audit_path = root / "audit.jsonl"
            registry = attach_builtin_handlers(
                ToolRegistry.from_json(ROOT / "data" / "tools.json"),
                ROOT,
            )
            gateway = SecurityGateway(
                registry,
                ROOT,
                AuditLogger(audit_path),
                approval_store=PersistentApprovalStore(database_path),
            )
            context = SecurityContext(
                user_id="researcher",
                role="researcher",
                scopes={"code:execute"},
                session_id="approval-session",
            )
            call = ToolCall("code.python", {"code": "sum([1, 2, 3])"})
            changed_call = ToolCall("code.python", {"code": "sum([9, 9, 9])"})
            request = gateway.request_persisted_confirmation(call, context)

            with self.assertRaises(ApprovalError):
                gateway.resolve_persisted_confirmation(
                    request.approval_token,
                    changed_call,
                    context,
                    approve=True,
                )
            decision, result = gateway.resolve_persisted_confirmation(
                request.approval_token,
                call,
                context,
                approve=True,
            )
            with self.assertRaises(ApprovalError):
                gateway.resolve_persisted_confirmation(
                    request.approval_token,
                    call,
                    context,
                    approve=True,
                )

            database_bytes = database_path.read_bytes()
            audit_text = audit_path.read_text(encoding="utf-8")

        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertIsNotNone(result)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, {"result": 6})
        self.assertNotIn(request.approval_token.encode("utf-8"), database_bytes)
        self.assertNotIn(request.approval_token, audit_text)
        self.assertIn(request.request_fingerprint, audit_text)
        self.assertNotIn("approval_token", str(request.public_dict()))
