"""One-test entry point for GatewayTests.test_mcp_metadata_poisoning_fixture_has_benign_backend."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_mcp_metadata_poisoning_fixture_has_benign_backend", suite)


if __name__ == "__main__":
    unittest.main()
