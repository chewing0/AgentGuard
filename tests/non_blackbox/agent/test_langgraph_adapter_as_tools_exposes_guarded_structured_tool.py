"""One-test entry point for LangGraphAdapterTests.test_as_tools_exposes_guarded_structured_tool."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_as_tools_exposes_guarded_structured_tool", suite)


if __name__ == "__main__":
    unittest.main()
