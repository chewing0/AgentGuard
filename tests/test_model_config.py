from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from agentguard.model_config import ModelConfig, load_chat_model_from_config


class ModelConfigTests(unittest.TestCase):
    def test_resolves_primary_and_fallback_api_key_envs(self) -> None:
        config = ModelConfig.from_dict({"provider": "openai", "model": "demo-model", "api_key_env": "CUSTOM_KEY"})

        self.assertEqual(config.resolve_api_key({"CUSTOM_KEY": "primary"}), "primary")
        self.assertEqual(config.resolve_api_key({"ANTHROPIC_AUTH_TOKEN": "anthropic-compatible"}), "anthropic-compatible")

    def test_redacted_dict_does_not_include_secret_value(self) -> None:
        config = ModelConfig.from_dict({"provider": "openai", "model": "demo-model"})
        redacted = config.redacted_dict()

        self.assertEqual(redacted["api_key_env"], "AGENTGUARD_OPENAI_API_KEY")
        self.assertNotIn("api_key", redacted)

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


if __name__ == "__main__":
    unittest.main()
