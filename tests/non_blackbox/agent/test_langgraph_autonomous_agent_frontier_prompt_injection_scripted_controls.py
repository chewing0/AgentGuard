"""One-test entry point for LangGraphAutonomousAgentTests.test_frontier_prompt_injection_scripted_controls."""

import unittest

from tests.non_blackbox.suites import langgraph_autonomous_agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAutonomousAgentTests.test_frontier_prompt_injection_scripted_controls", suite)


if __name__ == "__main__":
    unittest.main()
