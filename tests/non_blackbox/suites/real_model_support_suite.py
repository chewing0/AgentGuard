"""Shared implementations for provider gate and error handling tests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests import real_model_support


class RealModelGateTests(unittest.TestCase):
    gate_env = "AGENTGUARD_TEST_ONLY_REAL_MODEL_GATE"

    def test_selects_siliconflow_config_for_explicit_claude_code_environment(self) -> None:
        env = {
            "ANTHROPIC_AUTH_TOKEN": "test-placeholder",
            "ANTHROPIC_BASE_URL": "https://api.siliconflow.cn",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            selected = real_model_support.real_model_config_path()

        self.assertEqual(selected.name, "siliconflow-claude-code.example.json")

    def test_does_not_reuse_anthropic_token_for_an_unrecognized_host(self) -> None:
        env = {
            "ANTHROPIC_AUTH_TOKEN": "test-placeholder",
            "ANTHROPIC_BASE_URL": "https://unrecognized-provider.example",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            selected = real_model_support.real_model_config_path()

        self.assertEqual(selected.name, "openai-compatible.example.json")

    def test_disabled_gate_is_a_normal_skip_without_preflight(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            real_model_support.importlib.util,
            "find_spec",
            side_effect=AssertionError("preflight must not run for a disabled gate"),
        ):
            self.assertFalse(real_model_support.real_model_enabled(self.gate_env))

    def test_enabled_gate_fails_when_optional_dependencies_are_missing(self) -> None:
        with mock.patch.dict(os.environ, {self.gate_env: "1"}, clear=True), mock.patch.object(
            real_model_support.importlib.util, "find_spec", return_value=None
        ):
            with self.assertRaisesRegex(RuntimeError, "dependencies are missing"):
                real_model_support.real_model_enabled(self.gate_env)

    def test_enabled_gate_fails_when_configured_key_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = self._write_config(Path(tmp) / "model.json")
            env = {
                self.gate_env: "1",
                "AGENTGUARD_REAL_MODEL_CONFIG": str(config_path),
            }
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                real_model_support.importlib.util, "find_spec", return_value=object()
            ):
                with self.assertRaisesRegex(RuntimeError, "could not be resolved"):
                    real_model_support.real_model_enabled(self.gate_env)

    def test_enabled_gate_passes_only_after_full_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = self._write_config(Path(tmp) / "model.json")
            env = {
                self.gate_env: "1",
                "AGENTGUARD_REAL_MODEL_CONFIG": str(config_path),
                "AGENTGUARD_TEST_ONLY_API_KEY": "test-placeholder",
            }
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                real_model_support.importlib.util, "find_spec", return_value=object()
            ):
                self.assertTrue(real_model_support.real_model_enabled(self.gate_env))

    def test_provider_failure_body_is_not_rethrown(self) -> None:
        class ProviderError(RuntimeError):
            status_code = 402

        def fail() -> None:
            raise ProviderError("server echoed Bearer secret and the complete prompt")

        with self.assertRaisesRegex(
            RuntimeError, r"Real-model provider call failed: ProviderError \(HTTP 402\)"
        ) as caught:
            real_model_support.run_provider_call(fail)

        self.assertNotIn("Bearer secret", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_non_provider_failure_keeps_original_diagnostic(self) -> None:
        error = ValueError("local schema diagnostic")

        def fail() -> None:
            raise error

        with self.assertRaises(ValueError) as caught:
            real_model_support.run_provider_call(fail)

        self.assertIs(caught.exception, error)

    @staticmethod
    def _write_config(path: Path) -> Path:
        path.write_text(
            json.dumps(
                {
                    "provider": "openai",
                    "model": "test-model",
                    "api_key_env": "AGENTGUARD_TEST_ONLY_API_KEY",
                }
            ),
            encoding="utf-8",
        )
        return path


if __name__ == "__main__":
    unittest.main()
