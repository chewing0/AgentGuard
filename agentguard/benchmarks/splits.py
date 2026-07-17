from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_ROLES = frozenset({"development", "held_out", "profile"})
_FORMATS = frozenset({"labeled_trace", "autonomous"})


@dataclass(frozen=True)
class BenchmarkSplit:
    name: str
    role: str
    format: str
    path: Path
    sha256: str
    parent: str | None = None


@dataclass(frozen=True)
class BenchmarkSplitValidation:
    registry_path: str
    splits: list[dict[str, Any]]
    development_task_ids: int
    held_out_task_ids: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_path": self.registry_path,
            "splits": self.splits,
            "development_task_ids": self.development_task_ids,
            "held_out_task_ids": self.held_out_task_ids,
            "valid": True,
        }


def validate_benchmark_splits(
    registry_path: str | Path,
) -> BenchmarkSplitValidation:
    registry = Path(registry_path).resolve()
    raw = json.loads(registry.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise ValueError("Benchmark split registry schema_version must be 1")
    raw_splits = raw.get("splits")
    if not isinstance(raw_splits, list) or not raw_splits:
        raise ValueError("Benchmark split registry must contain a non-empty splits list")
    root = registry.parent
    splits = [_parse_split(item, root) for item in raw_splits]
    by_name = {split.name: split for split in splits}
    if len(by_name) != len(splits):
        raise ValueError("Benchmark split names must be unique")

    rows_by_name: dict[str, list[dict[str, Any]]] = {}
    ids_by_name: dict[str, set[str]] = {}
    prompts_by_name: dict[str, set[str]] = {}
    calls_by_name: dict[str, set[str]] = {}
    summaries: list[dict[str, Any]] = []
    for split in splits:
        actual_hash = _sha256_file(split.path)
        if actual_hash != split.sha256:
            raise ValueError(
                f"Frozen hash mismatch for {split.name}: expected {split.sha256}, got {actual_hash}"
            )
        rows = _jsonl_rows(split.path)
        ids = _unique_task_ids(rows, split.name)
        prompts = {
            _text_fingerprint(str(row.get("prompt", "")))
            for row in rows
            if str(row.get("prompt", "")).strip()
        }
        calls = _call_fingerprints(rows) if split.format == "labeled_trace" else set()
        rows_by_name[split.name] = rows
        ids_by_name[split.name] = ids
        prompts_by_name[split.name] = prompts
        calls_by_name[split.name] = calls
        summaries.append(
            {
                "name": split.name,
                "role": split.role,
                "format": split.format,
                "path": split.path.name,
                "sha256": actual_hash,
                "tasks": len(rows),
                "parent": split.parent,
            }
        )

    development = [split for split in splits if split.role == "development"]
    held_out = [split for split in splits if split.role == "held_out"]
    if not development or not held_out:
        raise ValueError("Registry must include both development and held_out splits")

    for dev in development:
        for held in held_out:
            _assert_disjoint(
                ids_by_name[dev.name],
                ids_by_name[held.name],
                f"task IDs between {dev.name} and {held.name}",
            )
            _assert_disjoint(
                prompts_by_name[dev.name],
                prompts_by_name[held.name],
                f"prompt fingerprints between {dev.name} and {held.name}",
            )
            if dev.format == held.format == "labeled_trace":
                _assert_disjoint(
                    calls_by_name[dev.name],
                    calls_by_name[held.name],
                    f"tool-call fingerprints between {dev.name} and {held.name}",
                )

    for split in splits:
        if split.role != "profile":
            continue
        if not split.parent or split.parent not in by_name:
            raise ValueError(f"Profile {split.name} must reference an existing parent")
        parent = by_name[split.parent]
        if parent.role != "development" or parent.format != split.format:
            raise ValueError(
                f"Profile {split.name} parent must be a development split with the same format"
            )
        parent_rows = {
            str(row["task_id"]): row
            for row in rows_by_name[parent.name]
        }
        for row in rows_by_name[split.name]:
            task_id = str(row["task_id"])
            if not _profile_row_matches(parent_rows.get(task_id), row):
                raise ValueError(
                    f"Profile {split.name} task {task_id} diverges from its frozen parent row"
                )

    return BenchmarkSplitValidation(
        registry_path=registry.name,
        splits=summaries,
        development_task_ids=len(
            set().union(*(ids_by_name[split.name] for split in development))
        ),
        held_out_task_ids=len(
            set().union(*(ids_by_name[split.name] for split in held_out))
        ),
    )


def _parse_split(raw: Any, root: Path) -> BenchmarkSplit:
    if not isinstance(raw, dict):
        raise ValueError("Each benchmark split must be an object")
    name = str(raw.get("name", ""))
    role = str(raw.get("role", ""))
    format_name = str(raw.get("format", ""))
    expected_hash = str(raw.get("sha256", ""))
    if not name or role not in _ROLES or format_name not in _FORMATS:
        raise ValueError(f"Invalid benchmark split definition: {name or '<unnamed>'}")
    if len(expected_hash) != 64 or any(char not in "0123456789abcdef" for char in expected_hash):
        raise ValueError(f"Split {name} must provide a lowercase SHA-256 digest")
    path = (root / str(raw.get("path", ""))).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"Split {name} path escapes the registry directory") from exc
    if not path.is_file():
        raise FileNotFoundError(f"Split {name} file not found: {path}")
    parent = raw.get("parent")
    return BenchmarkSplit(
        name=name,
        role=role,
        format=format_name,
        path=path,
        sha256=expected_hash,
        parent=str(parent) if parent is not None else None,
    )


def _jsonl_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_no}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"Benchmark row must be an object at {path}:{line_no}")
            rows.append(row)
    if not rows:
        raise ValueError(f"Benchmark split is empty: {path}")
    return rows


def _unique_task_ids(rows: list[dict[str, Any]], split_name: str) -> set[str]:
    ids = [str(row.get("task_id", "")) for row in rows]
    if any(not task_id for task_id in ids):
        raise ValueError(f"Split {split_name} contains a missing task_id")
    if len(ids) != len(set(ids)):
        raise ValueError(f"Split {split_name} contains duplicate task IDs")
    return set(ids)


def _call_fingerprints(rows: list[dict[str, Any]]) -> set[str]:
    fingerprints: set[str] = set()
    for row in rows:
        for step in row.get("steps", []):
            call = step.get("call", {}) if isinstance(step, dict) else {}
            payload = {
                "tool_name": call.get("tool_name"),
                "params": call.get("params", {}),
            }
            fingerprints.add(_text_fingerprint(_canonical_json(payload)))
    return fingerprints


def _assert_disjoint(left: set[str], right: set[str], label: str) -> None:
    overlap = sorted(left & right)
    if overlap:
        raise ValueError(f"Overlapping {label}: {overlap[:5]}")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _profile_row_matches(
    parent: dict[str, Any] | None,
    profile: dict[str, Any],
) -> bool:
    if parent is None:
        return False
    parent_copy = dict(parent)
    profile_copy = dict(profile)
    parent_copy.pop("tags", None)
    profile_copy.pop("tags", None)
    return _canonical_json(parent_copy) == _canonical_json(profile_copy)


def _text_fingerprint(text: str) -> str:
    normalized = " ".join(text.casefold().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    # Git may materialize text files with CRLF on Windows. Benchmark hashes
    # describe the JSONL content, so use one canonical newline representation
    # on every platform while still detecting any semantic content drift.
    content = path.read_text(encoding="utf-8")
    canonical = content.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
