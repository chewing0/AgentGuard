"""One-test entry point for GatewayTests.test_allows_knowledge_base_search."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_allows_knowledge_base_search", suite)


if __name__ == "__main__":
    unittest.main()
