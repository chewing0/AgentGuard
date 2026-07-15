from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from .adapters import LangGraphAdapterError


DEFAULT_API_KEY_ENVS = ("AGENTGUARD_OPENAI_API_KEY", "OPENAI_API_KEY")

_ENVIRONMENT_VARIABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RESERVED_EXTRA_KEYS = frozenset(
    {
        "api_key",
        "api_key_env",
        "auth_token",
        "authorization",
        "base_url",
        "max_retries",
        "model",
        "model_name",
        "openai_api_base",
        "openai_api_key",
        "password",
        "provider",
        "request_timeout",
        "secret",
        "temperature",
        "timeout",
        "timeout_ms",
        "token",
    }
)
_SENSITIVE_HEADER_NAMES = frozenset(
    {"api-key", "authorization", "openai-api-key", "proxy-authorization", "x-api-key"}
)
_SENSITIVE_QUERY_NAMES = frozenset(
    {"access_token", "api_key", "apikey", "authorization", "key", "token"}
)


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

    def __post_init__(self) -> None:
        _validate_api_key_env(self.api_key_env)
        _validate_extra_keys(self.extra)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ModelConfig":
        provider = str(raw.get("provider", "openai")).strip().lower()
        model = str(raw.get("model", "")).strip()
        if not model:
            raise ValueError("Model config requires a non-empty 'model'.")
        api_key_env = raw.get("api_key_env", "AGENTGUARD_OPENAI_API_KEY")
        if not isinstance(api_key_env, str):
            raise ValueError("Model config 'api_key_env' must be a valid environment variable name.")
        known = {"provider", "model", "base_url", "api_key_env", "timeout_ms", "temperature", "max_retries"}
        return cls(
            provider=provider,
            model=model,
            base_url=_optional_str(raw.get("base_url")),
            api_key_env=api_key_env.strip(),
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
        source = os.environ if env is None else env
        names = _candidate_env_names(self.api_key_env)
        for name in names:
            value = source.get(name)
            if value:
                return value
        raise LangGraphAdapterError(
            "Missing API key for model config. Set one of: " + ", ".join(names)
        )

    def redacted_dict(self) -> dict[str, Any]:
        payload = {
            "provider": self.provider,
            "model": self.model,
            "base_url": _sanitize_base_url_metadata(self.base_url),
            "api_key_env": self.api_key_env,
            "timeout_ms": self.timeout_ms,
            "temperature": self.temperature,
            "max_retries": self.max_retries,
            "extra_keys": sorted(self.extra),
        }
        # Metadata is still untrusted input: a malicious model name or option
        # key can contain a credential-shaped value. Import lazily to keep the
        # model-config module independent of detector initialization order.
        from .detectors import SensitiveDataDetector

        redacted, _ = SensitiveDataDetector().redact(payload)
        return dict(redacted)


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
    _validate_runtime_extra(config.extra)
    try:
        from langchain_openai import ChatOpenAI
    except ImportError as exc:  # pragma: no cover - depends on optional dependency state
        raise LangGraphAdapterError(
            "OpenAI-compatible model config requires langchain-openai. "
            "Install with: python -m pip install -e .[langgraph,openai]"
        ) from exc

    # Provider-specific options are applied first, then trusted core values are
    # written last so they cannot be replaced even if ``extra`` is mutated
    # after this frozen dataclass was created.
    kwargs: dict[str, Any] = {
        **config.extra,
        "model": config.model,
        "api_key": config.resolve_api_key(),
        "temperature": config.temperature,
        "timeout": max(config.timeout_ms / 1000.0, 0.001),
        "max_retries": config.max_retries,
    }
    if config.base_url:
        kwargs["base_url"] = _normalize_openai_base_url(config.base_url)
    return ChatOpenAI(**kwargs)


def _candidate_env_names(primary: str) -> list[str]:
    names = [primary]
    # Only the two conventional OpenAI variable names are aliases for each
    # other. A provider-specific variable must never fall back to an unrelated
    # credential, otherwise that credential could be sent to the wrong host.
    if primary in DEFAULT_API_KEY_ENVS:
        for fallback in DEFAULT_API_KEY_ENVS:
            if fallback not in names:
                names.append(fallback)
    return names


def _validate_api_key_env(value: Any) -> None:
    if not isinstance(value, str) or _ENVIRONMENT_VARIABLE_NAME.fullmatch(value) is None:
        raise ValueError("Model config 'api_key_env' must be a valid environment variable name.")


def _validate_extra_keys(extra: Mapping[str, Any]) -> None:
    if not isinstance(extra, Mapping):
        raise ValueError("Model config extra options must be a mapping.")
    non_string_keys = [key for key in extra if not isinstance(key, str)]
    if non_string_keys:
        raise ValueError("Model config extra option names must be strings.")
    reserved = sorted(key for key in extra if key.casefold() in _RESERVED_EXTRA_KEYS)
    if reserved:
        raise ValueError(
            "Model config extra options cannot override reserved parameters: "
            + ", ".join(reserved)
        )


def _validate_runtime_extra(extra: Mapping[str, Any]) -> None:
    _validate_extra_keys(extra)
    for field_name in ("default_headers", "headers", "extra_headers"):
        value = extra.get(field_name)
        if isinstance(value, Mapping) and any(
            str(key).strip().casefold() in _SENSITIVE_HEADER_NAMES for key in value
        ):
            raise ValueError(
                f"Model config extra option '{field_name}' cannot supply authentication headers."
            )
    for field_name in ("default_query", "query"):
        value = extra.get(field_name)
        if isinstance(value, Mapping) and any(
            str(key).strip().casefold() in _SENSITIVE_QUERY_NAMES for key in value
        ):
            raise ValueError(
                f"Model config extra option '{field_name}' cannot supply authentication query parameters."
            )


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


def _sanitize_base_url_metadata(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    except (TypeError, ValueError):
        return "[INVALID_URL]"
