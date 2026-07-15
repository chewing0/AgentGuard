"""One-test entry point for LangGraphAutonomousAgentTests.test_untrusted_task_becomes_default_initial_provenance."""

import unittest

from tests.non_blackbox.suites import langgraph_autonomous_agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAutonomousAgentTests.test_untrusted_task_becomes_default_initial_provenance", suite)


if __name__ == "__main__":
    unittest.main()
