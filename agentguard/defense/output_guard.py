from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ..detectors import SensitiveDataDetector, canonical_text_variants
from ..provenance import DataProvenanceTracker, TaintRecord
from ..schemas import RiskLevel


@dataclass(frozen=True)
class OutputSafetyResult:
    text: str
    decision: str
    redactions: dict[str, int] = field(default_factory=dict)
    sensitive_labels: list[str] = field(default_factory=list)
    critical_sensitive_labels: list[str] = field(default_factory=list)
    forbidden_matches: list[str] = field(default_factory=list)
    taint_matches: list[TaintRecord] = field(default_factory=list)

    @property
    def safe(self) -> bool:
        return self.decision == "allow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "safe": self.safe,
            "redactions": self.redactions,
            "sensitive_labels": self.sensitive_labels,
            "critical_sensitive_labels": self.critical_sensitive_labels,
            "forbidden_matches": self.forbidden_matches,
            "taint_matches": [match.to_dict() for match in self.taint_matches],
        }


class OutputSafetyGuard:
    """Apply runtime safety policy before a model answer reaches the caller."""

    def __init__(
        self,
        *,
        sensitive_detector: SensitiveDataDetector | None = None,
        forbidden_patterns: list[str] | None = None,
    ) -> None:
        self.sensitive_detector = sensitive_detector or SensitiveDataDetector()
        self.forbidden_patterns = list(forbidden_patterns or [])
        for pattern in self.forbidden_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"Invalid forbidden output pattern: {pattern!r}") from exc

    def inspect(
        self,
        text: str,
        *,
        provenance: DataProvenanceTracker | None = None,
    ) -> OutputSafetyResult:
        raw = str(text or "")
        detections = self.sensitive_detector.find(raw)
        sensitive_labels = sorted({detection.label for detection in detections})
        critical_labels = sorted(
            {
                detection.label
                for detection in detections
                if detection.level >= RiskLevel.CRITICAL
            }
        )
        redacted, redactions = self.sensitive_detector.redact(raw)
        safe_text = str(redacted)
        taint_matches: list[TaintRecord] = []
        if provenance is not None:
            safe_text, taint_matches = provenance.redact(safe_text)
            safe_text = str(safe_text)

        forbidden_matches = _forbidden_match_labels(self.forbidden_patterns, raw)
        if forbidden_matches:
            return OutputSafetyResult(
                text="[REDACTED:forbidden_output]",
                decision="block",
                redactions=redactions,
                sensitive_labels=sensitive_labels,
                critical_sensitive_labels=critical_labels,
                forbidden_matches=forbidden_matches,
                taint_matches=taint_matches,
            )
        if taint_matches or redactions:
            return OutputSafetyResult(
                text=safe_text,
                decision="redact",
                redactions=redactions,
                sensitive_labels=sensitive_labels,
                critical_sensitive_labels=critical_labels,
                taint_matches=taint_matches,
            )
        return OutputSafetyResult(
            text=raw,
            decision="allow",
            sensitive_labels=sensitive_labels,
            critical_sensitive_labels=critical_labels,
        )


def _forbidden_match_labels(patterns: list[str], text: str) -> list[str]:
    variants = [variant for variant, _ in canonical_text_variants(text)]
    return [
        f"forbidden_pattern#{index}"
        for index, pattern in enumerate(patterns, start=1)
        if any(
            re.search(pattern, variant, flags=re.IGNORECASE | re.MULTILINE)
            for variant in variants
        )
    ]
