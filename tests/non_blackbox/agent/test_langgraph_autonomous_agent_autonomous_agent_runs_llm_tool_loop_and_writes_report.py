"""One-test entry point for LangGraphAutonomousAgentTests.test_autonomous_agent_runs_llm_tool_loop_and_writes_report."""

import unittest

from tests.non_blackbox.suites import langgraph_autonomous_agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAutonomousAgentTests.test_autonomous_agent_runs_llm_tool_loop_and_writes_report", suite)


if __name__ == "__main__":
    unittest.main()
