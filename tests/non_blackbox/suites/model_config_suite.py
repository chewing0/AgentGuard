"""Shared implementations for model configuration tests."""

from __future__ import annotations

import json
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from agentguard.adapters import LangGraphAdapterError
from agentguard.model_config import ModelConfig, load_chat_model_from_config


class ModelConfigTests(unittest.TestCase):
    def test_resolves_primary_and_fallback_api_key_envs(self) -> None:
        config = ModelConfig.from_dict({"provider": "openai", "model": "demo-model"})

        self.assertEqual(
            config.resolve_api_key({"AGENTGUARD_OPENAI_API_KEY": "primary"}),
            "primary",
        )
        self.assertEqual(config.resolve_api_key({"OPENAI_API_KEY": "fallback"}), "fallback")

        kimi = ModelConfig.from_dict(
            {
                "provider": "openai",
                "model": "kimi-for-coding",
                "base_url": "https://api.kimi.com/coding/v1",
                "api_key_env": "ANTHROPIC_AUTH_TOKEN",
            }
        )
        self.assertEqual(
            kimi.resolve_api_key(
                {
                    "ANTHROPIC_AUTH_TOKEN": "kimi-key",
                    "ANTHROPIC_BASE_URL": "https://api.kimi.com/coding",
                }
            ),
            "kimi-key",
        )
        with self.assertRaisesRegex(LangGraphAdapterError, "requires ANTHROPIC_BASE_URL"):
            kimi.resolve_api_key({"ANTHROPIC_AUTH_TOKEN": "kimi-key"})
        with self.assertRaisesRegex(LangGraphAdapterError, "across hosts"):
            kimi.resolve_api_key(
                {
                    "ANTHROPIC_AUTH_TOKEN": "kimi-key",
                    "ANTHROPIC_BASE_URL": "https://api.siliconflow.cn",
                }
            )
        with self.assertRaisesRegex(LangGraphAdapterError, "ANTHROPIC_AUTH_TOKEN"):
            kimi.resolve_api_key({"OPENAI_API_KEY": "wrong-provider-key"})
        with self.assertRaisesRegex(LangGraphAdapterError, "Missing API key"):
            ModelConfig.from_dict(
                {"provider": "openai", "model": "demo-model"}
            ).resolve_api_key({"ANTHROPIC_AUTH_TOKEN": "wrong-provider-key"})

    def test_explicit_empty_environment_does_not_fall_back_to_host(self) -> None:
        config = ModelConfig.from_dict(
            {"provider": "openai", "model": "demo-model", "api_key_env": "CUSTOM_KEY"}
        )

        with patch.dict("os.environ", {"CUSTOM_KEY": "host-secret"}, clear=True):
            with self.assertRaisesRegex(LangGraphAdapterError, "Missing API key"):
                config.resolve_api_key({})

    def test_api_key_env_requires_a_strict_environment_variable_name(self) -> None:
        for invalid in (None, 123, "", "1KEY", "BAD-NAME", "BAD NAME", "KEY=value"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "valid environment variable name"):
                    ModelConfig.from_dict(
                        {
                            "provider": "openai",
                            "model": "demo-model",
                            "api_key_env": invalid,
                        }
                    )
        with self.assertRaisesRegex(ValueError, "numeric, not boolean"):
            ModelConfig.from_dict(
                {
                    "provider": "openai",
                    "model": "demo-model",
                    "input_cost_per_million_usd": True,
                }
            )

    def test_extra_cannot_override_sensitive_or_core_parameters(self) -> None:
        for reserved_key in ("api_key", "model_name", "timeout", "authorization"):
            with self.subTest(reserved_key=reserved_key):
                with self.assertRaisesRegex(ValueError, "reserved parameters"):
                    ModelConfig.from_dict(
                        {
                            "provider": "openai",
                            "model": "demo-model",
                            reserved_key: "untrusted-value",
                        }
                    )

    def test_runtime_revalidates_mutated_extra_options(self) -> None:
        config = ModelConfig.from_dict({"provider": "openai", "model": "demo-model"})
        config.extra["api_key"] = "injected-secret"

        with self.assertRaisesRegex(ValueError, "reserved parameters"):
            load_chat_model_from_config(config)

    def test_authentication_headers_and_query_values_are_not_accepted_at_runtime(self) -> None:
        unsafe_options = (
            {"default_headers": {"Authorization": "Bearer embedded-secret"}},
            {"default_query": {"api_key": "embedded-secret"}},
        )
        for options in unsafe_options:
            with self.subTest(options=tuple(options)):
                config = ModelConfig.from_dict(
                    {"provider": "openai", "model": "demo-model", **options}
                )
                with self.assertRaisesRegex(ValueError, "cannot supply authentication"):
                    load_chat_model_from_config(config)

    def test_redacted_dict_does_not_include_secret_value(self) -> None:
        config = ModelConfig.from_dict(
            {
                "provider": "openai",
                "model": "sk-example-secret-value-1234567890",
                "base_url": "https://user:password@example.test/v1?api_key=secret",
                "organization": "secret-organization-value",
                "default_headers": {"X-Trace": "secret-header-value"},
            }
        )
        redacted = config.redacted_dict()
        serialized = json.dumps(redacted)

        self.assertEqual(redacted["api_key_env"], "AGENTGUARD_OPENAI_API_KEY")
        self.assertNotIn("api_key", redacted)
        self.assertNotIn("extra", redacted)
        self.assertEqual(redacted["extra_keys"], ["default_headers", "organization"])
        self.assertNotIn("secret-organization-value", serialized)
        self.assertNotIn("secret-header-value", serialized)
        self.assertNotIn("password", serialized)
        self.assertNotIn("api_key=secret", serialized)
        self.assertNotIn("sk-example-secret-value", serialized)
        self.assertEqual(redacted["base_url"], "https://example.test/v1")

    def test_loads_openai_compatible_model_with_mocked_provider(self) -> None:
        class FakeChatOpenAI:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_module = types.ModuleType("langchain_openai")
        fake_module.ChatOpenAI = FakeChatOpenAI
        payload = {
            "provider": "openai",
            "model": "Pro/zai-org/GLM-5.1",
            "base_url": "https://api.siliconflow.cn",
            "api_key_env": "CUSTOM_KEY",
            "timeout_ms": 123000,
            "temperature": 0.2,
            "max_retries": 4,
            "input_cost_per_million_usd": 1.25,
            "output_cost_per_million_usd": 5.0,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.dict(sys.modules, {"langchain_openai": fake_module}):
                with patch.dict("os.environ", {"CUSTOM_KEY": "secret-value"}, clear=True):
                    model = load_chat_model_from_config(path)

        self.assertIsInstance(model, FakeChatOpenAI)
        self.assertEqual(model.kwargs["model"], "Pro/zai-org/GLM-5.1")
        self.assertEqual(model.kwargs["api_key"], "secret-value")
        self.assertEqual(model.kwargs["base_url"], "https://api.siliconflow.cn/v1")
        self.assertEqual(model.kwargs["timeout"], 123.0)
        self.assertEqual(model.kwargs["temperature"], 0.2)
        self.assertEqual(model.kwargs["max_retries"], 4)
        self.assertNotIn("input_cost_per_million_usd", model.kwargs)
        self.assertNotIn("output_cost_per_million_usd", model.kwargs)

    def test_loads_anthropic_messages_model_with_runtime_bearer_header(self) -> None:
        class FakeChatAnthropic:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_module = types.ModuleType("langchain_anthropic")
        fake_module.ChatAnthropic = FakeChatAnthropic
        payload = {
            "provider": "anthropic",
            "model": "Pro/zai-org/GLM-5.1",
            "base_url": "https://api.siliconflow.cn/v1/messages",
            "api_key_env": "CUSTOM_KEY",
            "timeout_ms": 123000,
            "temperature": 0.2,
            "max_retries": 1,
            "default_headers": {"X-Trace-Mode": "safe"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "model.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with patch.dict(sys.modules, {"langchain_anthropic": fake_module}):
                with patch.dict("os.environ", {"CUSTOM_KEY": "secret-value"}, clear=True):
                    model = load_chat_model_from_config(path)

        self.assertIsInstance(model, FakeChatAnthropic)
        self.assertEqual(model.kwargs["model"], "Pro/zai-org/GLM-5.1")
        self.assertEqual(model.kwargs["api_key"], "secret-value")
        self.assertNotIn("Authorization", model.kwargs["default_headers"])
        self.assertEqual(model.kwargs["base_url"], "https://api.siliconflow.cn")
        self.assertEqual(model.kwargs["timeout"], 123.0)
        self.assertEqual(model.kwargs["temperature"], 0.2)
        self.assertEqual(model.kwargs["max_retries"], 1)
        self.assertEqual(model.kwargs["default_headers"]["X-Trace-Mode"], "safe")

        if importlib.util.find_spec("langchain_anthropic") is None:
            self.skipTest("langchain-anthropic is not installed")

        import httpx

        observed = {}

        def handler(request):
            observed["path"] = request.url.path
            observed["authorization"] = request.headers.get("authorization")
            observed["x_api_key"] = request.headers.get("x-api-key")
            observed["anthropic_version"] = request.headers.get("anthropic-version")
            return httpx.Response(
                200,
                json={
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "model": "Pro/zai-org/GLM-5.1",
                    "content": [{"type": "text", "text": "OK"}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )

        client = httpx.Client(
            base_url="https://api.siliconflow.cn",
            transport=httpx.MockTransport(handler),
        )
        real_payload = {
            "provider": "anthropic",
            "model": "Pro/zai-org/GLM-5.1",
            "base_url": "https://api.siliconflow.cn",
            "api_key_env": "ANTHROPIC_AUTH_TOKEN",
            "temperature": 0,
            "max_retries": 0,
        }
        with patch.dict(
            "os.environ",
            {
                "ANTHROPIC_AUTH_TOKEN": "test-only-provider-token",
                "ANTHROPIC_BASE_URL": "https://api.siliconflow.cn",
            },
            clear=False,
        ):
            real_model = load_chat_model_from_config(ModelConfig.from_dict(real_payload))
            with patch(
                "langchain_anthropic.chat_models._get_default_httpx_client",
                return_value=client,
            ):
                response = real_model.invoke("Reply OK", max_tokens=1)

        self.assertEqual(response.text, "OK")
        self.assertEqual(observed["path"], "/v1/messages")
        self.assertEqual(
            observed["authorization"],
            "Bearer test-only-provider-token",
        )
        self.assertIsNone(observed["x_api_key"])
        self.assertTrue(observed["anthropic_version"])


if __name__ == "__main__":
    unittest.main()
