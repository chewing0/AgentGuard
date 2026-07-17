"""Shared implementation for isolated expression sandbox tests."""

from __future__ import annotations

import time
import unittest
from pathlib import Path

from agentguard.sandbox_runtime import IsolatedExpressionSandbox
from agentguard.tools.builtin import DemoToolEnvironment


ROOT = Path(__file__).resolve().parents[3]


class SandboxRuntimeTests(unittest.TestCase):
    def test_expression_executes_in_isolated_bounded_subprocess(self) -> None:
        sandbox = IsolatedExpressionSandbox(timeout_seconds=1)
        self.assertEqual(sandbox.execute("sum([13, 21, 34])"), 68)

        started = time.perf_counter()
        with self.assertRaises(ValueError):
            sandbox.execute("10 ** 1000000")
        self.assertLess(time.perf_counter() - started, 0.5)
        with self.assertRaises(ValueError):
            sandbox.execute("__import__('os').environ")

        result = DemoToolEnvironment(ROOT).code_python({"code": "max([8, 5, 13])"})
        self.assertTrue(result.ok)
        self.assertEqual(result.output, {"result": 13})
        self.assertEqual(result.metadata["sandbox"], "isolated_subprocess")
