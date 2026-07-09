from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .adapters import LangGraphAdapterError


DEFAULT_API_KEY_ENVS = ("AGENTGUARD_OPENAI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_AUTH_TOKEN")


@dataclass(frozen=True)
class ModelConfig:
    """Runtime-only configuration for provider-backed chat models."""

    provider: str
    model: str
    base_url: str | None = None
    api_key_env: str = "AGENTGUARD_OPENAI_API_KEY"
    timeout_ms: int = 600_000
    temperature: float = 0.0
    max_retries: int = 2
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ModelConfig":
        provider = str(raw.get("provider", "openai")).strip().lower()
        model = str(raw.get("model", "")).strip()
        if not model:
            raise ValueError("Model config requires a non-empty 'model'.")
        known = {"provider", "model", "base_url", "api_key_env", "timeout_ms", "temperature", "max_retries"}
        return cls(
            provider=provider,
            model=model,
            base_url=_optional_str(raw.get("base_url")),
            api_key_env=str(raw.get("api_key_env", "AGENTGUARD_OPENAI_API_KEY")).strip(),
            timeout_ms=int(raw.get("timeout_ms", 600_000)),
            temperature=float(raw.get("temperature", 0.0)),
            max_retries=int(raw.get("max_retries", 2)),
            extra={key: value for key, value in raw.items() if key not in known},
        )

    @classmethod
    def from_json(cls, path: str | Path) -> "ModelConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Model config JSON must be an object.")
        return cls.from_dict(payload)

    def resolve_api_key(self, env: Mapping[str, str] | None = None) -> str:
        source = env or os.environ
        names = _candidate_env_names(self.api_key_env)
        for name in names:
            value = source.get(name)
            if value:
                return value
        raise LangGraphAdapterError(
            "Missing API key for model config. Set one of: " + ", ".join(names)
        )

    def redacted_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "timeout_ms": self.timeout_ms,
            "temperature": self.temperature,
            "max_retries": self.max_retries,
            "extra": self.extra,
        }


def load_model_config(path: str | Path) -> ModelConfig:
    return ModelConfig.from_json(path)


def load_chat_model_from_config(config_or_path: ModelConfig | str | Path) -> Any:
    config = (
        config_or_path
        if isinstance(config_or_path, ModelConfig)
        else load_model_config(config_or_path)
    )
    if config.provider != "openai":
        raise LangGraphAdapterError(f"Unsupported model provider in config: {config.provider}")
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:  # pragma: no cover - depends on optional dependency state
        raise LangGraphAdapterError(
            "OpenAI-compatible model config requires langchain-openai. "
            "Install with: python -m pip install -e .[langgraph,openai]"
        ) from exc

    kwargs: dict[str, Any] = {
        "model": config.model,
        "api_key": config.resolve_api_key(),
        "temperature": config.temperature,
        "timeout": max(config.timeout_ms / 1000.0, 0.001),
        "max_retries": config.max_retries,
        **config.extra,
    }
    if config.base_url:
        kwargs["base_url"] = _normalize_openai_base_url(config.base_url)
    return ChatOpenAI(**kwargs)


def _candidate_env_names(primary: str) -> list[str]:
    names: list[str] = []
    if primary:
        names.append(primary)
    for fallback in DEFAULT_API_KEY_ENVS:
        if fallback not in names:
            names.append(fallback)
    return names


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_openai_base_url(value: str) -> str:
    base = value.strip().rstrip("/")
    suffix = "/chat/completions"
    if base.endswith(suffix):
        base = base[: -len(suffix)]
    if base == "https://api.siliconflow.cn":
        return base + "/v1"
    return base
