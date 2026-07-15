"""Shared implementations for CLI tests."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agentguard.cli import _safe_exception_summary


class CliFailureRedactionTests(unittest.TestCase):
    def test_module_entrypoint_propagates_cli_failure_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_config = Path(tmp) / "missing-model-config.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agentguard",
                    "autonomous-agent",
                    "safe diagnostic",
                    "--model-config",
                    str(missing_config),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )

        self.assertEqual(completed.returncode, 1)
        self.assertIn("Autonomous agent failed: FileNotFoundError", completed.stderr)
        self.assertNotIn(str(missing_config), completed.stderr)

    def test_provider_error_body_is_not_in_safe_summary(self) -> None:
        class ProviderError(RuntimeError):
            status_code = 402

        error = ProviderError(
            "server echoed Bearer secret-token and the complete user prompt"
        )

        summary = _safe_exception_summary(error)

        self.assertEqual(summary, "ProviderError (HTTP 402)")
        self.assertNotIn("secret-token", summary)
        self.assertNotIn("user prompt", summary)

    def test_non_http_error_uses_only_exception_type(self) -> None:
        error = ValueError("private path and sensitive request content")

        self.assertEqual(_safe_exception_summary(error), "ValueError")


if __name__ == "__main__":
    unittest.main()
