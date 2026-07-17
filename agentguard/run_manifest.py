from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


GENERATED_FILES = ("metrics.json", "report.md", "manifest.json", "dashboard.html")
GENERATED_DIRECTORIES = ("audit", "workspaces")


def prepare_run_directory(output_dir: str | Path, *, overwrite: bool = False) -> Path:
    """Create a clean run directory without silently mixing experiments.

    Existing generated artifacts are immutable by default.  ``overwrite`` only
    removes files owned by the benchmark runner; unrelated files are preserved.
    """

    out = Path(output_dir).resolve()
    generated = [out / name for name in GENERATED_FILES]
    generated_directories = [out / name for name in GENERATED_DIRECTORIES]
    existing = [path for path in generated if path.exists()]
    existing.extend(path for path in generated_directories if path.exists())
    if existing and not overwrite:
        names = ", ".join(path.name for path in existing)
        raise FileExistsError(
            f"Run directory already contains generated artifacts ({names}): {out}. "
            "Choose a new --output directory or pass --overwrite."
        )
    if overwrite:
        for path in generated:
            if path.is_file() or path.is_symlink():
                path.unlink()
        for directory in generated_directories:
            if directory.is_dir():
                shutil.rmtree(directory)
            elif directory.exists():
                directory.unlink()
    out.mkdir(parents=True, exist_ok=True)
    return out


def build_run_manifest(
    *,
    run_type: str,
    project_root: str | Path,
    tasks_path: str | Path,
    tools_path: str | Path | None,
    configuration: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    tasks = Path(tasks_path).resolve()
    tools = Path(tools_path).resolve() if tools_path is not None else None
    inputs = {
        "tasks": {"path": _display_path(tasks, root), "sha256": _sha256_file(tasks)},
    }
    if tools is not None:
        inputs["tools"] = {
            "path": _display_path(tools, root),
            "sha256": _sha256_file(tools),
        }
    return {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "run_type": run_type,
        "created_at": datetime.now(UTC).isoformat(),
        "git": _git_state(root),
        "environment": {
            "python": sys.version.split()[0],
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "agentguard": _package_version("agentguard"),
            "dependencies": {
                name: _package_version(name)
                for name in ("langgraph", "langchain", "langchain-core", "pydantic")
            },
        },
        "inputs": inputs,
        "configuration": configuration or {},
    }


def write_run_manifest(output_dir: str | Path, manifest: dict[str, Any]) -> Path:
    path = Path(output_dir) / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _git_state(root: Path) -> dict[str, Any]:
    revision = _run_git(root, "rev-parse", "HEAD")
    status = _run_git(root, "status", "--porcelain")
    return {
        "commit": revision or None,
        "dirty": bool(status),
    }


def _run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name
