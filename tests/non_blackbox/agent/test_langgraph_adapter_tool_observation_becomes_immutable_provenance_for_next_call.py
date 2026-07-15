"""One-test entry point for LangGraphAdapterTests.test_tool_observation_becomes_immutable_provenance_for_next_call."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_tool_observation_becomes_immutable_provenance_for_next_call", suite)


if __name__ == "__main__":
    unittest.main()
