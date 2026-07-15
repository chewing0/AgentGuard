"""One-test entry point for AgentTests.test_security_operations_agent_blocks_poisoned_followup."""

import unittest

from tests.non_blackbox.suites import agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AgentTests.test_security_operations_agent_blocks_poisoned_followup", suite)


if __name__ == "__main__":
    unittest.main()
