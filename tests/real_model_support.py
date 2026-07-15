from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Callable, TypeVar
from urllib.parse import urlsplit

from agentguard.model_config import load_model_config


ROOT = Path(__file__).resolve().parents[1]
_OPTIONAL_MODULES = ("langgraph", "langchain_core", "langchain_openai", "openai")
_T = TypeVar("_T")


def real_model_config_path() -> Path:
    """Select an explicit config, then a matching local provider config."""

    explicit = os.getenv("AGENTGUARD_REAL_MODEL_CONFIG", "").strip()
    if explicit:
        path = Path(explicit)
        return path if path.is_absolute() else ROOT / path

    if os.getenv("ANTHROPIC_AUTH_TOKEN"):
        base_url = os.getenv("ANTHROPIC_BASE_URL", "")
        if _is_kimi_code_url(base_url):
            return ROOT / "configs" / "kimi-code.example.json"
        if _is_siliconflow_url(base_url):
            return ROOT / "configs" / "siliconflow-claude-code.example.json"
    return ROOT / "configs" / "openai-compatible.example.json"


def real_model_enabled(gate_env: str) -> bool:
    if os.getenv(gate_env) != "1":
        return False

    missing_modules = [
        name for name in _OPTIONAL_MODULES if importlib.util.find_spec(name) is None
    ]
    if missing_modules:
        raise RuntimeError(
            f"{gate_env}=1 but real-model dependencies are missing: "
            f"{', '.join(missing_modules)}"
        )

    config_path = real_model_config_path()
    try:
        load_model_config(config_path).resolve_api_key()
    except (OSError, ValueError, RuntimeError) as exc:
        raise RuntimeError(
            f"{gate_env}=1 but the real-model config or API key could not be resolved "
            f"from {config_path}: {type(exc).__name__}"
        ) from exc
    return True


def _is_kimi_code_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname == "api.kimi.com"


def _is_siliconflow_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname == "api.siliconflow.cn"


def run_provider_call(operation: Callable[[], _T]) -> _T:
    """Run one provider operation without echoing provider response bodies."""

    try:
        return operation()
    except Exception as exc:
        module_root = type(exc).__module__.partition(".")[0]
        status_code = getattr(exc, "status_code", None)
        if module_root in {"openai", "httpx", "httpcore"} or isinstance(
            status_code, int
        ):
            summary = type(exc).__name__
            if isinstance(status_code, int) and 100 <= status_code <= 599:
                summary += f" (HTTP {status_code})"
            raise RuntimeError(f"Real-model provider call failed: {summary}") from None
        raise
