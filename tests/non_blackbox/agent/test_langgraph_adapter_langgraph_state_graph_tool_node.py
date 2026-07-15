"""One-test entry point for LangGraphAdapterTests.test_langgraph_state_graph_tool_node."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_langgraph_state_graph_tool_node", suite)


if __name__ == "__main__":
    unittest.main()
