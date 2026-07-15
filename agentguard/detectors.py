from __future__ import annotations

import json
import base64
import binascii
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote_plus

from .schemas import RiskLevel, RiskSignal, RiskSignalType


_SENSITIVE_FIELD_NAMES = {
    "access_key",
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "credential",
    "credentials",
    "id_token",
    "passwd",
    "password",
    "private_key",
    "pwd",
    "refresh_token",
    "secret",
    "secret_key",
    "token",
}
_SENSITIVE_FIELD_SUFFIXES = (
    "_access_key",
    "_access_token",
    "_api_key",
    "_credential",
    "_credentials",
    "_passwd",
    "_password",
    "_private_key",
    "_pwd",
    "_secret",
    "_secret_key",
    "_token",
)
_REDACTION_MARKER = re.compile(r"^\[REDACTED:[^\]]+\]$")


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
        seen: set[tuple[str, str]] = set()
        for variant, encoded in canonical_text_variants(text):
            for label, pattern in self._patterns:
                for match in re.finditer(pattern, variant, re.IGNORECASE | re.MULTILINE):
                    if label == "credit_card" and not _valid_payment_card(match.group(0)):
                        continue
                    evidence = _clip(match.group(0))
                    detection_label = f"encoded_{label}" if encoded else label
                    key = (detection_label, evidence)
                    if key in seen:
                        continue
                    seen.add(key)
                    level = RiskLevel.HIGH if label in {"email"} else RiskLevel.CRITICAL
                    detections.append(
                        Detection(
                            label=detection_label,
                            level=level,
                            message=f"Sensitive data detected: {detection_label}",
                            evidence=evidence,
                        )
                    )
        for field_name in _sensitive_field_names_with_values(value):
            label = _normalize_field_name(field_name) or "credential"
            evidence = f"field:{field_name}"
            key = (label, evidence)
            if key in seen:
                continue
            seen.add(key)
            detections.append(
                Detection(
                    label=label,
                    level=RiskLevel.CRITICAL,
                    message=f"Sensitive data detected in credential field: {field_name}",
                    evidence=evidence,
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
                count = 0

                def replacement(match: re.Match[str]) -> str:
                    nonlocal count
                    if label == "credit_card" and not _valid_payment_card(match.group(0)):
                        return match.group(0)
                    count += 1
                    return f"[REDACTED:{label}]"

                redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE | re.MULTILINE)
                if count:
                    counts[label] = counts.get(label, 0) + count
            # URL/base64 canonicalization can reveal a secret whose byte range
            # does not map cleanly back to the original string. Fail closed by
            # masking that string even when another direct value was already
            # redacted from it; otherwise mixed direct+encoded payloads leak.
            encoded_labels = {
                detection.label
                for detection in self.find(text)
                if detection.label.startswith("encoded_")
            }
            if encoded_labels:
                for encoded_label in encoded_labels:
                    counts[encoded_label] = counts.get(encoded_label, 0) + 1
                return f"[REDACTED:{sorted(encoded_labels)[0]}]"
            return redacted

        def walk(obj: Any) -> Any:
            if isinstance(obj, str):
                return redact_text(obj)
            if isinstance(obj, list):
                return [walk(item) for item in obj]
            if isinstance(obj, tuple):
                return tuple(walk(item) for item in obj)
            if isinstance(obj, dict):
                redacted_dict: dict[Any, Any] = {}
                for index, (key, val) in enumerate(obj.items(), start=1):
                    safe_key = redact_text(key) if isinstance(key, str) else key
                    # Redacted attacker-controlled keys can collide. Preserve
                    # every entry without reintroducing the original secret.
                    if safe_key in redacted_dict:
                        safe_key = f"{safe_key}#{index}"
                    processed_value = walk(val)
                    if (
                        isinstance(key, str)
                        and is_sensitive_field_name(key)
                        and _contains_unmasked_value(processed_value)
                    ):
                        label = _normalize_field_name(key) or "credential"
                        counts[label] = counts.get(label, 0) + 1
                        redacted_dict[safe_key] = _mask_semantic_value(
                            processed_value,
                            f"[REDACTED:{label}]",
                            redact_text,
                        )
                    else:
                        redacted_dict[safe_key] = processed_value
                return redacted_dict
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


def is_sensitive_field_name(key: str) -> bool:
    normalized = _normalize_field_name(key)
    return normalized in _SENSITIVE_FIELD_NAMES or normalized.endswith(
        _SENSITIVE_FIELD_SUFFIXES
    )


def _normalize_field_name(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")


def _sensitive_field_names_with_values(value: Any) -> list[str]:
    fields: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for key, item in obj.items():
                if (
                    isinstance(key, str)
                    and is_sensitive_field_name(key)
                    and _contains_unmasked_value(item)
                ):
                    fields.append(key)
                walk(item)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                walk(item)

    walk(value)
    return fields


def _contains_unmasked_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value) and _REDACTION_MARKER.fullmatch(value) is None
    if isinstance(value, dict):
        return any(_contains_unmasked_value(item) for item in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_contains_unmasked_value(item) for item in value)
    return True


def _mask_semantic_value(value: Any, marker: str, redact_key: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value if _REDACTION_MARKER.fullmatch(value) else marker
    if isinstance(value, dict):
        return {
            redact_key(key) if isinstance(key, str) else key: _mask_semantic_value(
                item,
                marker,
                redact_key,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_mask_semantic_value(item, marker, redact_key) for item in value]
    if isinstance(value, tuple):
        return tuple(_mask_semantic_value(item, marker, redact_key) for item in value)
    return marker


def canonical_text_variants(value: Any) -> list[tuple[str, bool]]:
    """Return raw and bounded URL/Base64 variants through four encode layers."""

    text = _stringify(value)
    variants: list[tuple[str, bool]] = [(text, False)]
    seen = {text}
    decoded = text
    for _ in range(2):
        candidate = unquote_plus(decoded)
        if candidate == decoded:
            break
        decoded = candidate
        if decoded not in seen:
            seen.add(decoded)
            variants.append((decoded, True))

    carrier_pattern = re.compile(
        r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{12,}={0,2}(?![A-Za-z0-9+/=_-])"
    )
    frontier = [decoded]
    for _ in range(4):
        next_frontier: list[str] = []
        for source in frontier:
            for match in carrier_pattern.finditer(source):
                candidate = _decode_base64_text(match.group(0))
                if not candidate or candidate in seen:
                    continue
                seen.add(candidate)
                variants.append((candidate, True))
                next_frontier.append(candidate)
        frontier = next_frontier
        if not frontier:
            break
    return variants


def _decode_base64_text(value: str) -> str:
    if len(value) > 262_144:
        return ""
    normalized = value.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        raw = base64.b64decode(normalized, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""
    if not decoded or sum(char.isprintable() for char in decoded) / len(decoded) < 0.9:
        return ""
    return decoded


def _valid_payment_card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0
