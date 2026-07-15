"""One-test entry point for LangGraphAutonomousAgentTests.test_attacked_autonomous_agent_blocks_poisoned_followup."""

import unittest

from tests.non_blackbox.suites import langgraph_autonomous_agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAutonomousAgentTests.test_attacked_autonomous_agent_blocks_poisoned_followup", suite)


if __name__ == "__main__":
    unittest.main()
