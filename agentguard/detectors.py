from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .schemas import RiskLevel, RiskSignal, RiskSignalType


@dataclass(frozen=True)
class Detection:
    label: str
    level: RiskLevel
    message: str
    evidence: str


class PromptInjectionDetector:
    """Lexical detector for direct and indirect prompt injection attempts."""

    _patterns: list[tuple[str, RiskLevel, str]] = [
        (r"\bignore (all )?(previous|prior|above) (instructions|rules)\b", RiskLevel.HIGH, "instruction override"),
        (r"\bdisregard (the )?(system|developer|previous) (message|instructions)\b", RiskLevel.HIGH, "instruction override"),
        (r"\byou are now (the )?(system|developer|root|admin)\b", RiskLevel.CRITICAL, "forged authority role"),
        (r"\b(system|developer) (message|instruction|override)\s*:", RiskLevel.HIGH, "forged system instruction"),
        (r"\bhighest priority instruction\b", RiskLevel.HIGH, "priority confusion"),
        (r"\breveal (the )?(system prompt|developer message|hidden instructions)\b", RiskLevel.HIGH, "system prompt extraction"),
        (r"\bexfiltrate\b|\bsend (.*)(secret|token|password|api key)", RiskLevel.CRITICAL, "data exfiltration intent"),
        (r"\bcall (the )?(delete|exec|shell|database|file) tool\b", RiskLevel.HIGH, "tool steering"),
        (r"\b(tool result|observation) says? to\b", RiskLevel.HIGH, "tool-result instruction poisoning"),
        (r"\buse (the )?(admin|root|sudo) (tool|permission|mode)\b", RiskLevel.HIGH, "privilege escalation"),
        (r"\bdelete (all|every|the) (files|records|database)\b", RiskLevel.CRITICAL, "destructive instruction"),
        (r"\bBEGIN_(SYSTEM|DEVELOPER)_OVERRIDE\b", RiskLevel.CRITICAL, "synthetic override marker"),
        (
            r"\b(copy|read|open)\b[^\n]{0,160}\.env\b|\b(read|open)\b[^\n]{0,160}\bsecrets?\b|\bcloud_tokens\.env\b",
            RiskLevel.HIGH,
            "secret file targeting",
        ),
        (r"\bbase64\b.*\b(token|secret|password)\b", RiskLevel.HIGH, "encoded exfiltration"),
        (r"\b(hidden|tail|final) instruction\b.*\b(ignore|disregard|override)\b", RiskLevel.HIGH, "long-context instruction smuggling"),
    ]

    def detect(self, text: str) -> list[RiskSignal]:
        signals: list[RiskSignal] = []
        if not text:
            return signals
        for pattern, level, label in self._patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                evidence = _clip(match.group(0))
                signals.append(
                    RiskSignal(
                        signal_type=RiskSignalType.PROMPT_INJECTION,
                        level=level,
                        message=f"Possible prompt injection: {label}",
                        evidence=evidence,
                    )
                )
        return _dedupe_signals(signals)


class SensitiveDataDetector:
    """Regex-based detector for common secrets and personal identifiers."""

    _patterns: list[tuple[str, str]] = [
        ("openai_api_key", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        ("generic_api_key", r"\b(api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
        ("bearer_token", r"\bBearer\s+[A-Za-z0-9_\-.=]{16,}"),
        ("password_assignment", r"\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
        ("private_key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        ("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
        ("cn_id", r"\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])([0-2]\d|3[01])\d{3}[\dXx]\b"),
        ("credit_card", r"\b(?:\d[ -]*?){13,19}\b"),
    ]

    def find(self, value: Any) -> list[Detection]:
        text = _stringify(value)
        detections: list[Detection] = []
        if not text:
            return detections
        for label, pattern in self._patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                level = RiskLevel.HIGH if label in {"email"} else RiskLevel.CRITICAL
                detections.append(
                    Detection(
                        label=label,
                        level=level,
                        message=f"Sensitive data detected: {label}",
                        evidence=_clip(match.group(0)),
                    )
                )
        return detections

    def signals(self, value: Any) -> list[RiskSignal]:
        return [
            RiskSignal(
                signal_type=RiskSignalType.SENSITIVE_DATA,
                level=detection.level,
                message=detection.message,
                evidence=detection.evidence,
            )
            for detection in self.find(value)
        ]

    def redact(self, value: Any) -> tuple[Any, dict[str, int]]:
        counts: dict[str, int] = {}

        def redact_text(text: str) -> str:
            redacted = text
            for label, pattern in self._patterns:
                redacted, count = re.subn(pattern, f"[REDACTED:{label}]", redacted, flags=re.IGNORECASE | re.MULTILINE)
                if count:
                    counts[label] = counts.get(label, 0) + count
            return redacted

        def walk(obj: Any) -> Any:
            if isinstance(obj, str):
                return redact_text(obj)
            if isinstance(obj, list):
                return [walk(item) for item in obj]
            if isinstance(obj, tuple):
                return tuple(walk(item) for item in obj)
            if isinstance(obj, dict):
                return {key: walk(val) for key, val in obj.items()}
            return obj

        return walk(value), counts


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)


def _clip(text: str, limit: int = 160) -> str:
    clean = re.sub(r"\s+", " ", text).strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def _dedupe_signals(signals: list[RiskSignal]) -> list[RiskSignal]:
    seen: set[tuple[str, str]] = set()
    out: list[RiskSignal] = []
    for signal in signals:
        key = (signal.message, signal.evidence or "")
        if key in seen:
            continue
        seen.add(key)
        out.append(signal)
    return out
