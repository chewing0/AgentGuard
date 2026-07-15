"""One-test entry point for GatewayTests.test_file_read_rejects_oversized_observation."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_file_read_rejects_oversized_observation", suite)


if __name__ == "__main__":
    unittest.main()
