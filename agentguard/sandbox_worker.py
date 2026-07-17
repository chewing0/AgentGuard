"""Isolated worker for the bounded expression sandbox."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# ``python -I`` deliberately removes the script directory from ``sys.path``.
# Add back only this trusted package directory so the worker can share the
# validator without inheriting the caller's current directory or user site.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from expression_sandbox import evaluate_bounded_expression


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted((_json_safe(item) for item in value), key=repr)
    return str(value)


try:
    request = json.loads(sys.stdin.read(8_193))
    code = request.get("code", "") if isinstance(request, dict) else ""
    output = _json_safe(evaluate_bounded_expression(code))
    serialized = json.dumps(
        {"ok": True, "output": output},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(serialized) > 65_536:
        raise ValueError("Sandbox result exceeded the output limit")
    sys.stdout.write(serialized)
except Exception as exc:
    sys.stdout.write(
        json.dumps(
            {"ok": False, "error_type": type(exc).__name__},
            separators=(",", ":"),
        )
    )
