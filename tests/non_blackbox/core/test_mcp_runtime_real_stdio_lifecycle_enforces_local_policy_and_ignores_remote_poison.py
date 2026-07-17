"""One-test entry point for the MCP stdio lifecycle test."""

import unittest

from tests.non_blackbox.suites import mcp_runtime_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "MCPRuntimeTests.test_real_stdio_lifecycle_enforces_local_policy_and_ignores_remote_poison",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
