"""One-test entry point for LangGraphAdapterTests.test_adapter_executes_framework_tool_name_through_gateway."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_adapter_executes_framework_tool_name_through_gateway", suite)


if __name__ == "__main__":
    unittest.main()
