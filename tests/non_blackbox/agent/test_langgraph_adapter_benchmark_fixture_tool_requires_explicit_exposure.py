"""One-test entry point for LangGraphAdapterTests.test_benchmark_fixture_tool_requires_explicit_exposure."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_benchmark_fixture_tool_requires_explicit_exposure", suite)


if __name__ == "__main__":
    unittest.main()
