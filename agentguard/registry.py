from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .schemas import ToolCall, ToolResult, ToolSpec

ToolHandler = Callable[[dict[str, Any]], ToolResult]


class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, spec: ToolSpec, handler: ToolHandler | None = None) -> None:
        self._specs[spec.name] = spec
        if handler is not None:
            self._handlers[spec.name] = handler

    def attach_handler(self, name: str, handler: ToolHandler) -> None:
        if name not in self._specs:
            raise KeyError(f"Tool spec not found: {name}")
        self._handlers[name] = handler

    def get(self, name: str) -> ToolSpec | None:
        return self._specs.get(name)

    def require(self, name: str) -> ToolSpec:
        spec = self.get(name)
        if spec is None:
            raise KeyError(f"Tool spec not found: {name}")
        return spec

    def names(self) -> list[str]:
        return sorted(self._specs)

    def execute(self, call: ToolCall) -> ToolResult:
        handler = self._handlers.get(call.tool_name)
        if handler is None:
            return ToolResult(ok=False, error=f"No handler registered for {call.tool_name}")
        try:
            return handler(call.params)
        except Exception as exc:  # pragma: no cover - defensive boundary
            return ToolResult(ok=False, error=f"{type(exc).__name__}: {exc}")

    @classmethod
    def from_json(cls, path: str | Path) -> "ToolRegistry":
        registry = cls()
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            entries = raw.get("tools", [])
        else:
            entries = raw
        for item in entries:
            registry.register(ToolSpec.from_dict(item))
        return registry

    def to_json(self, path: str | Path) -> None:
        payload = {"tools": [self._specs[name].to_dict() for name in self.names()]}
        Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def load_registry(path: str | Path) -> ToolRegistry:
    return ToolRegistry.from_json(path)

