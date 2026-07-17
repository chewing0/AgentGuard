from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from functools import cached_property
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
    input_cost_per_million_usd: float | None = None
    output_cost_per_million_usd: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_api_key_env(self.api_key_env)
        _validate_optional_price(
            self.input_cost_per_million_usd,
            "input_cost_per_million_usd",
        )
        _validate_optional_price(
            self.output_cost_per_million_usd,
            "output_cost_per_million_usd",
        )
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
        known = {
            "provider",
            "model",
            "base_url",
            "api_key_env",
            "timeout_ms",
            "temperature",
            "max_retries",
            "input_cost_per_million_usd",
            "output_cost_per_million_usd",
        }
        return cls(
            provider=provider,
            model=model,
            base_url=_optional_str(raw.get("base_url")),
            api_key_env=api_key_env.strip(),
            timeout_ms=int(raw.get("timeout_ms", 600_000)),
            temperature=float(raw.get("temperature", 0.0)),
            max_retries=int(raw.get("max_retries", 2)),
            input_cost_per_million_usd=_optional_float(
                raw.get("input_cost_per_million_usd")
            ),
            output_cost_per_million_usd=_optional_float(
                raw.get("output_cost_per_million_usd")
            ),
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
                self._validate_credential_origin(source, name)
                return value
        raise LangGraphAdapterError(
            "Missing API key for model config. Set one of: " + ", ".join(names)
        )

    def _validate_credential_origin(
        self,
        source: Mapping[str, str],
        resolved_name: str,
    ) -> None:
        if resolved_name != "ANTHROPIC_AUTH_TOKEN":
            return
        configured_origin = source.get("ANTHROPIC_BASE_URL", "").strip()
        if not configured_origin:
            raise LangGraphAdapterError(
                "ANTHROPIC_AUTH_TOKEN requires ANTHROPIC_BASE_URL so the credential "
                "origin can be matched to the model endpoint."
            )
        if not self.base_url or not _same_https_host(configured_origin, self.base_url):
            raise LangGraphAdapterError(
                "ANTHROPIC_BASE_URL does not match the model config host; refusing "
                "to send a provider credential across hosts."
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
            "input_cost_per_million_usd": self.input_cost_per_million_usd,
            "output_cost_per_million_usd": self.output_cost_per_million_usd,
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
    _validate_runtime_extra(config.extra)
    if config.provider == "openai":
        return _load_openai_chat_model(config)
    if config.provider == "anthropic":
        return _load_anthropic_chat_model(config)
    raise LangGraphAdapterError(f"Unsupported model provider in config: {config.provider}")


def _load_openai_chat_model(config: ModelConfig) -> Any:
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


def _load_anthropic_chat_model(config: ModelConfig) -> Any:
    try:
        from langchain_anthropic import ChatAnthropic
    except ImportError as exc:  # pragma: no cover - depends on optional dependency state
        raise LangGraphAdapterError(
            "Anthropic Messages model config requires langchain-anthropic. "
            "Install with: python -m pip install -e .[langgraph,anthropic]"
        ) from exc

    class BearerChatAnthropic(ChatAnthropic):
        @cached_property
        def _client_params(self) -> dict[str, Any]:
            params = dict(super()._client_params)
            params["auth_token"] = params.pop("api_key")
            return params

    api_key = config.resolve_api_key()
    extra = dict(config.extra)
    configured_headers = extra.pop("default_headers", None)
    default_headers = dict(configured_headers or {})
    kwargs: dict[str, Any] = {
        **extra,
        "model": config.model,
        "api_key": api_key,
        "default_headers": default_headers,
        "temperature": config.temperature,
        "timeout": max(config.timeout_ms / 1000.0, 0.001),
        "max_retries": config.max_retries,
    }
    if config.base_url:
        kwargs["base_url"] = _normalize_anthropic_base_url(config.base_url)
    return BearerChatAnthropic(**kwargs)


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


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("Model pricing values must be numeric, not boolean.")
    return float(value)


def _validate_optional_price(value: Any, name: str) -> None:
    if value is None:
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"Model config '{name}' must be finite and non-negative.")


def _normalize_openai_base_url(value: str) -> str:
    base = value.strip().rstrip("/")
    suffix = "/chat/completions"
    if base.endswith(suffix):
        base = base[: -len(suffix)]
    if base == "https://api.siliconflow.cn":
        return base + "/v1"
    return base


def _normalize_anthropic_base_url(value: str) -> str:
    base = value.strip().rstrip("/")
    suffix = "/v1/messages"
    if base.endswith(suffix):
        base = base[: -len(suffix)]
    if base == "https://api.siliconflow.cn/v1":
        return "https://api.siliconflow.cn"
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


def _same_https_host(left: str, right: str) -> bool:
    try:
        left_url = urlsplit(left)
        right_url = urlsplit(right)
    except ValueError:
        return False
    return (
        left_url.scheme == "https"
        and right_url.scheme == "https"
        and bool(left_url.hostname)
        and left_url.hostname == right_url.hostname
        and left_url.port == right_url.port
    )
