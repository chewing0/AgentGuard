from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .detectors import PromptInjectionDetector, SensitiveDataDetector
from .run_manifest import (
    build_run_manifest,
    prepare_run_directory,
    write_run_manifest,
)


_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_CASES = 100_000
_MAX_TEXT_CHARS = 1_000_000
_INJECAGENT_SOURCE = "https://github.com/uiuc-kang-lab/InjecAgent"
_SENSITIVE_DETECTOR = SensitiveDataDetector()


@dataclass(frozen=True)
class ExternalDetectionCase:
    case_id: str
    source: str
    attack_type: str
    benign_text: str
    injected_text: str


@dataclass(frozen=True)
class ExternalDetectionCaseResult:
    case_id: str
    source: str
    attack_type: str
    positive_detected: bool
    negative_detected: bool
    positive_signal_count: int
    negative_signal_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "source": self.source,
            "attack_type": self.attack_type,
            "positive_detected": self.positive_detected,
            "negative_detected": self.negative_detected,
            "positive_signal_count": self.positive_signal_count,
            "negative_signal_count": self.negative_signal_count,
        }


@dataclass(frozen=True)
class ExternalDetectionEvaluation:
    source_format: str
    source_url: str | None
    source_revision: str | None
    cases: list[ExternalDetectionCaseResult]

    def metrics(self) -> dict[str, Any]:
        return _metrics_for_results(self.cases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_format": self.source_format,
            "source_url": self.source_url,
            "source_revision": self.source_revision,
            "metrics": self.metrics(),
            "cases": [case.to_dict() for case in self.cases],
        }

    def markdown(self) -> str:
        metrics = self.metrics()
        lines = [
            "# External Prompt-Injection Detection Evaluation",
            "",
            f"Source format: `{self.source_format}`",
            "",
            "| Pairs | TPR | FPR | Precision | F1 | TP | FN | FP | TN |",
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
            (
                f"| {metrics['total_pairs']} | {metrics['true_positive_rate']} | "
                f"{metrics['false_positive_rate']} | {metrics['precision']} | "
                f"{metrics['f1']} | {metrics['true_positive']} | "
                f"{metrics['false_negative']} | {metrics['false_positive']} | "
                f"{metrics['true_negative']} |"
            ),
            "",
            "This evaluates the lexical detector on paired benign/injected text. "
            "It is not an end-to-end agent or tool-side-effect benchmark.",
        ]
        return "\n".join(lines)


def load_external_detection_cases(
    path: str | Path,
    *,
    source_format: str,
    limit: int | None = None,
) -> list[ExternalDetectionCase]:
    input_path = Path(path)
    _validate_input_file(input_path)
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError("limit must be a positive integer")
    normalized_format = source_format.strip().casefold()
    if normalized_format == "injecagent":
        raw = json.loads(input_path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("InjecAgent input must be a JSON array")
        rows: Iterable[Any] = raw
        loader = _injecagent_case
    elif normalized_format == "paired-jsonl":
        rows = _jsonl_rows(input_path)
        loader = _paired_jsonl_case
    else:
        raise ValueError(
            "source_format must be 'injecagent' or 'paired-jsonl'"
        )

    cases: list[ExternalDetectionCase] = []
    seen_ids: set[str] = set()
    for index, row in enumerate(rows):
        if limit is not None and len(cases) >= limit:
            break
        if len(cases) >= _MAX_CASES:
            raise ValueError(f"External corpus exceeds {_MAX_CASES} cases")
        if not isinstance(row, dict):
            raise ValueError(f"External case {index + 1} must be an object")
        case = loader(row, index)
        if case.case_id in seen_ids:
            raise ValueError(f"Duplicate external case_id: {case.case_id}")
        seen_ids.add(case.case_id)
        cases.append(case)
    if not cases:
        raise ValueError("External corpus contains no cases")
    return cases


def evaluate_external_detection_cases(
    cases: list[ExternalDetectionCase],
    *,
    source_format: str,
    source_url: str | None = None,
    source_revision: str | None = None,
    detector: PromptInjectionDetector | None = None,
) -> ExternalDetectionEvaluation:
    detector = detector or PromptInjectionDetector()
    results: list[ExternalDetectionCaseResult] = []
    for case in cases:
        positive = detector.detect(case.injected_text)
        negative = detector.detect(case.benign_text)
        results.append(
            ExternalDetectionCaseResult(
                case_id=case.case_id,
                source=case.source,
                attack_type=case.attack_type,
                positive_detected=bool(positive),
                negative_detected=bool(negative),
                positive_signal_count=len(positive),
                negative_signal_count=len(negative),
            )
        )
    return ExternalDetectionEvaluation(
        source_format=source_format,
        source_url=_safe_optional_url(source_url),
        source_revision=_safe_optional_revision(source_revision),
        cases=results,
    )


def run_external_detection_evaluation(
    *,
    input_path: str | Path,
    source_format: str,
    output_dir: str | Path,
    project_root: str | Path,
    limit: int | None = None,
    source_url: str | None = None,
    source_revision: str | None = None,
    overwrite: bool = False,
) -> ExternalDetectionEvaluation:
    cases = load_external_detection_cases(
        input_path,
        source_format=source_format,
        limit=limit,
    )
    result = evaluate_external_detection_cases(
        cases,
        source_format=source_format,
        source_url=source_url or (
            _INJECAGENT_SOURCE if source_format.casefold() == "injecagent" else None
        ),
        source_revision=source_revision,
    )
    out = prepare_run_directory(output_dir, overwrite=overwrite)
    (out / "metrics.json").write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    (out / "report.md").write_text(result.markdown(), encoding="utf-8")
    write_run_manifest(
        out,
        build_run_manifest(
            run_type="external_detection_corpus",
            project_root=project_root,
            tasks_path=input_path,
            tools_path=None,
            configuration={
                "source_format": source_format,
                "source_url": result.source_url,
                "source_revision": result.source_revision,
                "limit": limit,
                "paired_examples": True,
                "scope": "lexical_prompt_injection_detector_only",
            },
        ),
    )
    return result


def _injecagent_case(row: dict[str, Any], index: int) -> ExternalDetectionCase:
    required = ("Tool Response Template", "Tool Response", "Attack Type")
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError(
            f"InjecAgent case {index + 1} is missing fields: {', '.join(missing)}"
        )
    case_id = _stable_case_id("injecagent", row)
    return ExternalDetectionCase(
        case_id=case_id,
        source="injecagent",
        attack_type=_safe_label(row.get("Attack Type", "unknown")),
        benign_text=_bounded_text(row["Tool Response Template"], index),
        injected_text=_bounded_text(row["Tool Response"], index),
    )


def _paired_jsonl_case(row: dict[str, Any], index: int) -> ExternalDetectionCase:
    required = ("benign_text", "injected_text")
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError(
            f"Paired JSONL case {index + 1} is missing fields: {', '.join(missing)}"
        )
    case_id = str(row.get("case_id") or _stable_case_id("paired", row))
    if (
        re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", case_id) is None
        or _SENSITIVE_DETECTOR.find(case_id)
    ):
        case_id = _stable_case_id("paired", row)
    return ExternalDetectionCase(
        case_id=case_id,
        source=_safe_label(row.get("source", "paired-jsonl")),
        attack_type=_safe_label(row.get("attack_type", "unknown")),
        benign_text=_bounded_text(row["benign_text"], index),
        injected_text=_bounded_text(row["injected_text"], index),
    )


def _metrics_for_results(
    cases: list[ExternalDetectionCaseResult],
) -> dict[str, Any]:
    tp = sum(case.positive_detected for case in cases)
    fn = len(cases) - tp
    fp = sum(case.negative_detected for case in cases)
    tn = len(cases) - fp
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    f1 = _rate(2 * precision * recall, precision + recall)
    by_attack_type: dict[str, dict[str, Any]] = {}
    for attack_type in sorted({case.attack_type for case in cases}):
        subset = [case for case in cases if case.attack_type == attack_type]
        subset_tp = sum(case.positive_detected for case in subset)
        subset_fp = sum(case.negative_detected for case in subset)
        by_attack_type[attack_type] = {
            "pairs": len(subset),
            "true_positive_rate": _rate(subset_tp, len(subset)),
            "false_positive_rate": _rate(subset_fp, len(subset)),
        }
    return {
        "total_pairs": len(cases),
        "positive_examples": len(cases),
        "negative_examples": len(cases),
        "true_positive": tp,
        "false_negative": fn,
        "false_positive": fp,
        "true_negative": tn,
        "true_positive_rate": recall,
        "false_positive_rate": _rate(fp, fp + tn),
        "precision": precision,
        "f1": f1,
        "by_attack_type": by_attack_type,
    }


def _jsonl_rows(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
            yield row


def _validate_input_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"External corpus not found: {path}")
    if path.stat().st_size > _MAX_INPUT_BYTES:
        raise ValueError(
            f"External corpus exceeds {_MAX_INPUT_BYTES} bytes: {path}"
        )


def _bounded_text(value: Any, index: int) -> str:
    text = str(value)
    if len(text) > _MAX_TEXT_CHARS:
        raise ValueError(
            f"External case {index + 1} text exceeds {_MAX_TEXT_CHARS} characters"
        )
    return text


def _stable_case_id(prefix: str, row: dict[str, Any]) -> str:
    canonical = json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _safe_label(value: Any) -> str:
    raw = str(value)
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "_", raw).strip("_")
    if 0 < len(text) <= 120 and not _SENSITIVE_DETECTOR.find(raw):
        return text
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"label#{digest}"


def _safe_optional_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
        and len(value) <= 500
    ):
        return value
    raise ValueError("source_url must be a credential-free HTTPS URL")


def _safe_optional_revision(value: str | None) -> str | None:
    if value is None:
        return None
    if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
        return value
    raise ValueError("source_revision contains unsafe characters")


def _rate(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)
