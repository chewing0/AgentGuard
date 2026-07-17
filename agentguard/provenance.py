from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .detectors import canonical_text_variants, is_sensitive_field_name


_REDACTION_MARKER = re.compile(r"^\[REDACTED:[^\]]+\]$")
_CANDIDATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "agentguard_canary",
        re.compile(r"\bAGENTGUARD_[A-Za-z0-9_:-]{12,}\b"),
    ),
    (
        "api_token",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9_.=-]{16,}"),
    ),
)


@dataclass(frozen=True)
class TaintRecord:
    fingerprint: str
    source: str
    kind: str
    length: int
    _value: str = field(repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "source": self.source,
            "kind": self.kind,
            "length": self.length,
        }


class DataProvenanceTracker:
    """Track secret-like values across tool observations without persisting them.

    This is exact/encoded value tracking, not semantic taint propagation. Raw
    values stay in process memory and only SHA-256 fingerprints are exposed to
    policy decisions, audit events, or run metadata.
    """

    def __init__(self, *, max_records: int = 256) -> None:
        if type(max_records) is not int or max_records <= 0:
            raise ValueError("max_records must be a positive integer")
        self.max_records = max_records
        self._records: dict[str, TaintRecord] = {}

    def observe(self, value: Any, *, source: str) -> list[TaintRecord]:
        added: list[TaintRecord] = []
        for kind, candidate in _extract_candidates(value):
            if len(self._records) >= self.max_records:
                break
            normalized = candidate.strip()
            if not normalized or _REDACTION_MARKER.fullmatch(normalized):
                continue
            fingerprint = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            if fingerprint in self._records:
                continue
            record = TaintRecord(
                fingerprint=fingerprint,
                source=_safe_source_label(source),
                kind=kind,
                length=len(normalized),
                _value=normalized,
            )
            self._records[fingerprint] = record
            added.append(record)
        return added

    def matches(self, value: Any) -> list[TaintRecord]:
        text = _stringify(value)
        if not text or not self._records:
            return []
        variants = [variant for variant, _ in canonical_text_variants(text)]
        return [
            record
            for record in self._records.values()
            if any(record._value in variant for variant in variants)
        ]

    def redact(self, value: Any) -> tuple[Any, list[TaintRecord]]:
        matches = self.matches(value)
        if not matches:
            return value, []

        def redact_text(text: str) -> str:
            direct = text
            direct_match = False
            for record in matches:
                if record._value in direct:
                    direct = direct.replace(
                        record._value,
                        f"[REDACTED:tainted_{record.kind}]",
                    )
                    direct_match = True
            if direct_match:
                return direct
            # A decoded variant matched but its byte range cannot be mapped
            # safely to the original representation. Fail closed for the
            # complete string instead of leaking an encoded derivative.
            if self.matches(text):
                return "[REDACTED:encoded_tainted_data]"
            return text

        return _walk_strings(value, redact_text), matches

    def records(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self._records.values()]


def _extract_candidates(value: Any) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []

    def walk(item: Any, *, sensitive_field: bool = False) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if isinstance(key, str):
                    walk(key, sensitive_field=False)
                child_sensitive = sensitive_field or (
                    isinstance(key, str) and is_sensitive_field_name(key)
                )
                walk(child, sensitive_field=child_sensitive)
            return
        if isinstance(item, (list, tuple, set)):
            for child in item:
                walk(child, sensitive_field=sensitive_field)
            return
        if item is None:
            return
        text = str(item)
        if sensitive_field and len(text.strip()) >= 6:
            candidates.append(("credential_field", text.strip()))
        for kind, pattern in _CANDIDATE_PATTERNS:
            for match in pattern.finditer(text):
                candidates.append((kind, match.group(0)))

    walk(value)
    deduped: dict[tuple[str, str], None] = {}
    for candidate in candidates:
        deduped.setdefault(candidate, None)
    return list(deduped)


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def _safe_source_label(source: Any) -> str:
    label = str(source)
    if re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", label):
        return label
    fingerprint = hashlib.sha256(label.encode("utf-8")).hexdigest()[:12]
    return f"source#{fingerprint}"


def _walk_strings(value: Any, transform: Any) -> Any:
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, dict):
        return {
            transform(key) if isinstance(key, str) else key: _walk_strings(item, transform)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_walk_strings(item, transform) for item in value]
    if isinstance(value, tuple):
        return tuple(_walk_strings(item, transform) for item in value)
    return value
