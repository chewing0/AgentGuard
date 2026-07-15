"""One-test entry point for AgentTests.test_demo_agent_writes_report."""

import unittest

from tests.non_blackbox.suites import agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AgentTests.test_demo_agent_writes_report", suite)


if __name__ == "__main__":
    unittest.main()
