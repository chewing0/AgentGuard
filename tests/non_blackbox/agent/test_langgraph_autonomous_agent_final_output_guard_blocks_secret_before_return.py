"""One-test entry point for the autonomous-agent final output guard."""

import unittest

from tests.non_blackbox.suites import langgraph_autonomous_agent_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "LangGraphAutonomousAgentTests.test_final_output_guard_blocks_secret_before_return",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
