from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .schemas import SecurityContext, ToolCall


class ApprovalError(RuntimeError):
    """A safe approval validation error without request-controlled content."""


@dataclass(frozen=True)
class ApprovalRequest:
    approval_token: str = field(repr=False)
    request_fingerprint: str
    expires_at: str

    def public_dict(self) -> dict[str, str]:
        """Return persistable metadata; the bearer-like token is excluded."""

        return {
            "request_fingerprint": self.request_fingerprint,
            "expires_at": self.expires_at,
        }


class PersistentApprovalStore:
    """SQLite one-time approvals bound to an exact call and security context."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    request_fingerprint TEXT PRIMARY KEY,
                    binding_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('pending', 'denied', 'consumed', 'expired')
                    ),
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    resolved_at REAL
                )
                """
            )

    def create(
        self,
        call: ToolCall,
        context: SecurityContext,
        *,
        ttl_seconds: int = 900,
    ) -> ApprovalRequest:
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86_400:
            raise ValueError("approval ttl_seconds must be an integer from 1 to 86400")
        token = secrets.token_urlsafe(32)
        request_fingerprint = _token_fingerprint(token)
        created_at = time.time()
        expires_at = created_at + ttl_seconds
        with self._connection() as connection:
            connection.execute(
                """
                INSERT INTO approvals (
                    request_fingerprint, binding_sha256, status,
                    created_at, expires_at, resolved_at
                ) VALUES (?, ?, 'pending', ?, ?, NULL)
                """,
                (
                    request_fingerprint,
                    _binding_fingerprint(call, context),
                    created_at,
                    expires_at,
                ),
            )
        return ApprovalRequest(
            approval_token=token,
            request_fingerprint=request_fingerprint,
            expires_at=datetime.fromtimestamp(expires_at, timezone.utc).isoformat(),
        )

    def decide(
        self,
        approval_token: str,
        call: ToolCall,
        context: SecurityContext,
        *,
        approve: bool,
    ) -> bool:
        if type(approve) is not bool:
            raise TypeError("approval decision must be a boolean")
        if not isinstance(approval_token, str) or len(approval_token) > 256:
            raise ApprovalError("Approval token is invalid")
        request_fingerprint = _token_fingerprint(approval_token)
        now = time.time()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM approvals WHERE request_fingerprint = ?",
                (request_fingerprint,),
            ).fetchone()
            if row is None:
                raise ApprovalError("Approval request was not found")
            if str(row["binding_sha256"]) != _binding_fingerprint(call, context):
                raise ApprovalError("Approval request does not match this call and context")
            status = str(row["status"])
            if status != "pending":
                raise ApprovalError("Approval request is no longer pending")
            if float(row["expires_at"]) < now:
                connection.execute(
                    "UPDATE approvals SET status = 'expired', resolved_at = ? "
                    "WHERE request_fingerprint = ?",
                    (now, request_fingerprint),
                )
                raise ApprovalError("Approval request expired")
            next_status = "consumed" if approve else "denied"
            connection.execute(
                "UPDATE approvals SET status = ?, resolved_at = ? "
                "WHERE request_fingerprint = ? AND status = 'pending'",
                (next_status, now, request_fingerprint),
            )
        return approve

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _binding_fingerprint(call: ToolCall, context: SecurityContext) -> str:
    payload = {
        "call": call.to_dict(),
        "context": {
            "user_id": context.user_id,
            "role": context.role,
            "scopes": sorted(context.scopes),
            "session_id": context.session_id,
            "trusted_input": context.trusted_input,
        },
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
