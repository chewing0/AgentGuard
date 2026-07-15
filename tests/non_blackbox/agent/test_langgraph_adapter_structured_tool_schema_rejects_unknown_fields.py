"""One-test entry point for LangGraphAdapterTests.test_structured_tool_schema_rejects_unknown_fields."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_structured_tool_schema_rejects_unknown_fields", suite)


if __name__ == "__main__":
    unittest.main()
