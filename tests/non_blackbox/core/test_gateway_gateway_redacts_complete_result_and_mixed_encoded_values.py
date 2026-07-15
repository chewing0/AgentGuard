"""One-test entry point for GatewayTests.test_gateway_redacts_complete_result_and_mixed_encoded_values."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_gateway_redacts_complete_result_and_mixed_encoded_values", suite)


if __name__ == "__main__":
    unittest.main()
