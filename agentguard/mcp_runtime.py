from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .registry import ToolRegistry
from .schemas import ToolResult, ToolSpec


_DEFAULT_PROTOCOL_VERSION = "2025-11-25"
_MAX_MESSAGE_CHARS = 1_048_576
_MAX_TEXT_CHARS = 262_144
_MCP_TOOL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class MCPRuntimeError(RuntimeError):
    """A safe MCP lifecycle or protocol error without remote-controlled text."""


@dataclass(frozen=True)
class MCPToolDefinition:
    name: str
    description_fingerprint: str
    input_schema_fingerprint: str


class MCPStdioSession:
    """Minimal synchronous MCP stdio client with bounded JSON-RPC messages.

    Server-provided descriptions and annotations are intentionally represented
    only by fingerprints. Authorization and risk policy must come from local
    ``ToolSpec`` objects supplied to :func:`attach_mcp_tools`.
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None = None,
        timeout_seconds: float = 10.0,
        protocol_version: str = _DEFAULT_PROTOCOL_VERSION,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        if not command or not all(isinstance(part, str) and part for part in command):
            raise ValueError("MCP command must contain non-empty string arguments")
        if not 0.1 <= timeout_seconds <= 300:
            raise ValueError("MCP timeout_seconds must be between 0.1 and 300")
        self.command = tuple(command)
        self.cwd = Path(cwd).resolve() if cwd is not None else None
        self.timeout_seconds = float(timeout_seconds)
        self.protocol_version = protocol_version
        self.environment = (
            _minimal_subprocess_environment()
            if environment is None
            else {str(key): str(value) for key, value in environment.items()}
        )
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._messages: queue.Queue[str | None] = queue.Queue()
        self._request_id = 0
        self._request_lock = threading.Lock()
        self._negotiated_protocol: str | None = None

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def negotiated_protocol(self) -> str | None:
        return self._negotiated_protocol

    def __enter__(self) -> "MCPStdioSession":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def start(self) -> "MCPStdioSession":
        if self.is_running:
            return self
        try:
            self._process = subprocess.Popen(
                list(self.command),
                cwd=str(self.cwd) if self.cwd is not None else None,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
                env=self.environment,
            )
        except OSError as exc:
            raise MCPRuntimeError(f"MCP process launch failed: {type(exc).__name__}") from None

        self._messages = queue.Queue()
        self._reader = threading.Thread(
            target=self._read_stdout,
            name="agentguard-mcp-stdio-reader",
            daemon=True,
        )
        self._reader.start()
        try:
            response = self._request(
                "initialize",
                {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "AgentGuard", "version": "0.1.0"},
                },
            )
            negotiated = response.get("protocolVersion")
            if not isinstance(negotiated, str) or not negotiated:
                raise MCPRuntimeError("MCP initialize response omitted protocolVersion")
            self._negotiated_protocol = negotiated
            self._notify("notifications/initialized", {})
            return self
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        process = self._process
        self._process = None
        self._negotiated_protocol = None
        if process is None:
            return
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=min(self.timeout_seconds, 2.0))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass

    def list_tools(self) -> list[MCPToolDefinition]:
        self._require_running()
        result = self._request("tools/list", {})
        raw_tools = result.get("tools")
        if not isinstance(raw_tools, list):
            raise MCPRuntimeError("MCP tools/list returned an invalid tools collection")
        definitions: list[MCPToolDefinition] = []
        names: set[str] = set()
        for raw in raw_tools:
            if not isinstance(raw, dict):
                raise MCPRuntimeError("MCP tools/list returned an invalid tool entry")
            name = raw.get("name")
            if not isinstance(name, str) or _MCP_TOOL_NAME.fullmatch(name) is None:
                raise MCPRuntimeError("MCP tools/list returned an invalid tool name")
            if name in names:
                raise MCPRuntimeError("MCP tools/list returned duplicate tool names")
            names.add(name)
            definitions.append(
                MCPToolDefinition(
                    name=name,
                    description_fingerprint=_fingerprint(raw.get("description", "")),
                    input_schema_fingerprint=_fingerprint(raw.get("inputSchema", {})),
                )
            )
        return definitions

    def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        self._require_running()
        if not isinstance(name, str) or _MCP_TOOL_NAME.fullmatch(name) is None:
            raise ValueError("MCP tool name must be a non-empty bounded string")
        if not isinstance(arguments, Mapping):
            raise ValueError("MCP tool arguments must be a mapping")
        result = self._request("tools/call", {"name": name, "arguments": dict(arguments)})
        if bool(result.get("isError", False)):
            return ToolResult(
                ok=False,
                error="Remote MCP tool reported an error",
                metadata={"transport": "mcp_stdio", "remote_tool": name},
            )
        output: Any
        if "structuredContent" in result:
            output = _bounded_value(result.get("structuredContent"))
        else:
            output = _safe_content(result.get("content", []))
        return ToolResult(
            ok=True,
            output=output,
            metadata={"transport": "mcp_stdio", "remote_tool": name},
        )

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            self._messages.put(None)
            return
        try:
            for line in process.stdout:
                self._messages.put(line)
        finally:
            self._messages.put(None)

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._request_lock:
            self._request_id += 1
            request_id = self._request_id
            self._write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            )
            deadline = time.monotonic() + self.timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MCPRuntimeError("MCP request timed out")
                message = self._next_message(remaining)
                if message.get("id") != request_id:
                    # Notifications and unrelated messages cannot satisfy the
                    # active synchronous request.
                    continue
                if "error" in message:
                    error = message.get("error")
                    code = error.get("code") if isinstance(error, dict) else None
                    suffix = f" (code {code})" if isinstance(code, int) else ""
                    raise MCPRuntimeError(f"MCP request failed{suffix}")
                result = message.get("result")
                if not isinstance(result, dict):
                    raise MCPRuntimeError("MCP response result must be an object")
                return result

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def _write(self, message: dict[str, Any]) -> None:
        self._require_running()
        process = self._process
        assert process is not None and process.stdin is not None
        serialized = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        if len(serialized) > _MAX_MESSAGE_CHARS:
            raise MCPRuntimeError("MCP outbound message exceeded the size limit")
        try:
            process.stdin.write(serialized + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise MCPRuntimeError("MCP process closed its input stream") from None

    def _next_message(self, timeout_seconds: float) -> dict[str, Any]:
        try:
            raw = self._messages.get(timeout=timeout_seconds)
        except queue.Empty:
            raise MCPRuntimeError("MCP request timed out") from None
        if raw is None:
            raise MCPRuntimeError("MCP process exited before responding")
        if len(raw) > _MAX_MESSAGE_CHARS:
            raise MCPRuntimeError("MCP inbound message exceeded the size limit")
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            raise MCPRuntimeError("MCP process emitted invalid JSON") from None
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise MCPRuntimeError("MCP process emitted an invalid JSON-RPC message")
        return message

    def _require_running(self) -> None:
        if not self.is_running:
            raise MCPRuntimeError("MCP session is not running")


def attach_mcp_tools(
    registry: ToolRegistry,
    session: MCPStdioSession,
    bindings: Mapping[str, ToolSpec],
) -> list[dict[str, str]]:
    """Bind remote names to authoritative local specs and guarded handlers."""

    if not session.is_running:
        raise MCPRuntimeError("MCP session must be started before attaching tools")
    remote_definitions = {tool.name: tool for tool in session.list_tools()}
    manifest: list[dict[str, str]] = []
    local_names: set[str] = set()
    for remote_name, local_spec in bindings.items():
        if remote_name not in remote_definitions:
            raise MCPRuntimeError("Configured MCP remote tool was not advertised")
        if local_spec.name in local_names:
            raise ValueError("MCP bindings contain duplicate local tool names")
        local_names.add(local_spec.name)
        definition = remote_definitions[remote_name]

        def handler(params: dict[str, Any], *, bound_name: str = remote_name) -> ToolResult:
            return session.call_tool(bound_name, params)

        registry.register(local_spec, handler)
        manifest.append(
            {
                "local_name": local_spec.name,
                "remote_name": remote_name,
                "remote_description_sha256": definition.description_fingerprint,
                "remote_input_schema_sha256": definition.input_schema_fingerprint,
            }
        )
    return manifest


def _fingerprint(value: Any) -> str:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _bounded_value(value: Any) -> Any:
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if len(serialized) <= _MAX_TEXT_CHARS:
        return value
    return {
        "truncated": True,
        "original_chars": len(serialized),
        "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    }


def _safe_content(content: Any) -> list[dict[str, Any]]:
    if not isinstance(content, list):
        raise MCPRuntimeError("MCP tool content must be a list")
    safe: list[dict[str, Any]] = []
    retained_chars = 0
    for item in content:
        if not isinstance(item, dict):
            continue
        content_type = item.get("type")
        if content_type == "text":
            raw_text = item.get("text", "")
            text = raw_text if isinstance(raw_text, str) else str(raw_text)
            remaining = max(0, _MAX_TEXT_CHARS - retained_chars)
            safe.append({"type": "text", "text": text[:remaining]})
            retained_chars += min(len(text), remaining)
        elif content_type in {"image", "audio"}:
            data = item.get("data", "")
            serialized = data if isinstance(data, str) else str(data)
            safe.append(
                {
                    "type": content_type,
                    "mimeType": str(item.get("mimeType", ""))[:256],
                    "data_omitted": True,
                    "data_sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                }
            )
        else:
            safe.append(
                {
                    "type": "unsupported",
                    "payload_sha256": _fingerprint(item),
                }
            )
    return safe


def _minimal_subprocess_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    return {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed
    }
