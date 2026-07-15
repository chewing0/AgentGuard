"""One-test entry point for AgentMemoryTests.test_memory_records_blocked_tool_and_retry_stop."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AgentMemoryTests.test_memory_records_blocked_tool_and_retry_stop", suite)


if __name__ == "__main__":
    unittest.main()
