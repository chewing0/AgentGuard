from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .expression_sandbox import validate_bounded_expression


class SandboxRuntimeError(RuntimeError):
    pass


class IsolatedExpressionSandbox:
    def __init__(self, *, timeout_seconds: float = 1.0) -> None:
        if not 0.1 <= timeout_seconds <= 10:
            raise ValueError("sandbox timeout_seconds must be between 0.1 and 10")
        self.timeout_seconds = float(timeout_seconds)
        self.worker = Path(__file__).with_name("sandbox_worker.py").resolve()

    def execute(self, code: str) -> Any:
        # Reject invalid/high-amplification expressions before allocating a
        # child process, then validate a second time inside the child.
        validate_bounded_expression(code)
        request = json.dumps({"code": code}, ensure_ascii=False)
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                [sys.executable, "-I", str(self.worker)],
                input=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
                check=False,
                creationflags=creationflags,
            )
        except subprocess.TimeoutExpired:
            raise SandboxRuntimeError("Sandbox execution timed out") from None
        except OSError as exc:
            raise SandboxRuntimeError(
                f"Sandbox process failed: {type(exc).__name__}"
            ) from None
        if completed.returncode != 0:
            raise SandboxRuntimeError("Sandbox process returned a non-zero status")
        if len(completed.stdout) > 65_536:
            raise SandboxRuntimeError("Sandbox output exceeded the size limit")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            raise SandboxRuntimeError("Sandbox process returned invalid JSON") from None
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            error_type = payload.get("error_type") if isinstance(payload, dict) else None
            suffix = f": {error_type}" if isinstance(error_type, str) else ""
            raise SandboxRuntimeError(f"Sandbox rejected the expression{suffix}")
        return payload.get("output")
