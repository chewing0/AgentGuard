"""One-test entry point for GatewayTests.test_allows_threat_intel_lookup."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_allows_threat_intel_lookup", suite)


if __name__ == "__main__":
    unittest.main()
