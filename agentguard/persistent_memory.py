from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .detectors import PromptInjectionDetector, SensitiveDataDetector
from .registry import ToolRegistry
from .schemas import (
    OperationType,
    ParameterPolicy,
    RiskLevel,
    ToolResult,
    ToolSpec,
)


_MAX_CONTENT_CHARS = 262_144
_MAX_QUERY_CHARS = 512
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


@dataclass(frozen=True)
class MemoryRecord:
    record_id: int
    content: str
    content_sha256: str
    source: str
    session_id: str
    trusted: bool
    quarantined: bool
    quarantine_reasons: tuple[str, ...]
    redactions: dict[str, int]
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "content": self.content,
            "content_sha256": self.content_sha256,
            "source": self.source,
            "session_id": self.session_id,
            "trusted": self.trusted,
            "quarantined": self.quarantined,
            "quarantine_reasons": list(self.quarantine_reasons),
            "redactions": dict(self.redactions),
            "created_at": self.created_at,
        }


class PersistentMemoryStore:
    """SQLite-backed cross-session memory with redaction and quarantine."""

    def __init__(
        self,
        path: str | Path,
        *,
        prompt_detector: PromptInjectionDetector | None = None,
        sensitive_detector: SensitiveDataDetector | None = None,
    ) -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prompt_detector = prompt_detector or PromptInjectionDetector()
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()
        self._initialize()

    def write(
        self,
        content: str,
        *,
        source: str,
        session_id: str,
        trusted: bool = False,
    ) -> MemoryRecord:
        if type(trusted) is not bool:
            raise ValueError("memory trusted must be a boolean")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("memory content must be a non-empty string")
        if len(content) > _MAX_CONTENT_CHARS:
            raise ValueError("memory content exceeded the size limit")
        safe_source = _safe_label(source, "source")
        safe_session = _safe_label(session_id, "session")
        redacted, redactions = self.sensitive_detector.redact(content)
        safe_content = str(redacted)
        signals = self.prompt_detector.detect(safe_content)
        quarantined = bool(signals) and not trusted
        reasons = tuple(sorted({signal.message for signal in signals})) if quarantined else ()
        content_sha256 = hashlib.sha256(safe_content.encode("utf-8")).hexdigest()
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO memories (
                    content, content_sha256, source, session_id, trusted,
                    quarantined, quarantine_reasons, redactions, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    safe_content,
                    content_sha256,
                    safe_source,
                    safe_session,
                    int(trusted),
                    int(quarantined),
                    json.dumps(reasons, ensure_ascii=False),
                    json.dumps(redactions, ensure_ascii=False, sort_keys=True),
                    created_at,
                ),
            )
            record_id = int(cursor.lastrowid)
        return MemoryRecord(
            record_id=record_id,
            content=safe_content,
            content_sha256=content_sha256,
            source=safe_source,
            session_id=safe_session,
            trusted=trusted,
            quarantined=quarantined,
            quarantine_reasons=reasons,
            redactions=redactions,
            created_at=created_at,
        )

    def search(self, query: str, *, limit: int = 5) -> list[MemoryRecord]:
        """Search model-visible memory; quarantined rows are always excluded."""

        if not isinstance(query, str) or not query.strip():
            raise ValueError("memory query must be a non-empty string")
        if len(query) > _MAX_QUERY_CHARS:
            raise ValueError("memory query exceeded the size limit")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("memory search limit must be an integer from 1 to 50")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM memories
                WHERE quarantined = 0 AND instr(lower(content), lower(?)) > 0
                ORDER BY record_id DESC
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def quarantined_for_review(self, *, limit: int = 50) -> list[MemoryRecord]:
        """Return isolated rows for a trusted administrative review path."""

        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("memory review limit must be an integer from 1 to 1000")
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM memories
                WHERE quarantined = 1
                ORDER BY record_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def counts(self) -> dict[str, int]:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN quarantined = 0 THEN 1 ELSE 0 END) AS available,
                    SUM(CASE WHEN quarantined = 1 THEN 1 ELSE 0 END) AS quarantined
                FROM memories
                """
            ).fetchone()
        return {
            "total": int(row["total"] or 0),
            "available": int(row["available"] or 0),
            "quarantined": int(row["quarantined"] or 0),
        }

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memories (
                    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    source TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    trusted INTEGER NOT NULL CHECK (trusted IN (0, 1)),
                    quarantined INTEGER NOT NULL CHECK (quarantined IN (0, 1)),
                    quarantine_reasons TEXT NOT NULL,
                    redactions TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_memories_quarantine_id "
                "ON memories (quarantined, record_id DESC)"
            )

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


def attach_memory_tools(
    registry: ToolRegistry,
    store: PersistentMemoryStore,
) -> None:
    """Expose safe write/search tools without a model-controlled quarantine bypass."""

    write_spec = ToolSpec(
        name="memory.write",
        description="Store a bounded note in persistent memory after security checks.",
        operation=OperationType.WRITE,
        risk_level=RiskLevel.MEDIUM,
        required_scopes={"memory:write"},
        allowed_roles={"analyst", "researcher", "operator", "admin"},
        parameters={
            "content": ParameterPolicy(kind="string", required=True, max_length=8_000),
            "source": ParameterPolicy(kind="string", required=True, max_length=128),
            "session_id": ParameterPolicy(kind="string", required=True, max_length=128),
        },
    )
    search_spec = ToolSpec(
        name="memory.search",
        description="Search approved persistent memory; isolated records are excluded.",
        operation=OperationType.SEARCH,
        risk_level=RiskLevel.LOW,
        required_scopes={"memory:read"},
        allowed_roles={"analyst", "researcher", "operator", "admin"},
        parameters={
            "query": ParameterPolicy(kind="string", required=True, max_length=_MAX_QUERY_CHARS),
            "top_k": ParameterPolicy(
                kind="integer",
                required=False,
                allowed_values=list(range(1, 11)),
            ),
        },
    )

    def write_handler(params: dict[str, Any]) -> ToolResult:
        record = store.write(
            params["content"],
            source=params["source"],
            session_id=params["session_id"],
            # The model cannot declare its own content trusted.
            trusted=False,
        )
        return ToolResult(ok=True, output=record.to_dict())

    def search_handler(params: dict[str, Any]) -> ToolResult:
        records = store.search(params["query"], limit=params.get("top_k", 5))
        return ToolResult(ok=True, output=[record.to_dict() for record in records])

    registry.register(write_spec, write_handler)
    registry.register(search_spec, search_handler)


def _safe_label(value: str, prefix: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"memory {prefix} must be a non-empty string")
    if _SAFE_LABEL.fullmatch(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _row_to_record(row: sqlite3.Row) -> MemoryRecord:
    try:
        reasons = tuple(json.loads(row["quarantine_reasons"]))
        redactions = dict(json.loads(row["redactions"]))
    except (TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError("Persistent memory database contains invalid metadata") from None
    return MemoryRecord(
        record_id=int(row["record_id"]),
        content=str(row["content"]),
        content_sha256=str(row["content_sha256"]),
        source=str(row["source"]),
        session_id=str(row["session_id"]),
        trusted=bool(row["trusted"]),
        quarantined=bool(row["quarantined"]),
        quarantine_reasons=reasons,
        redactions=redactions,
        created_at=str(row["created_at"]),
    )
