"""One-test entry point for GatewayTests.test_blocks_base64_encoded_sensitive_network_flow."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_blocks_base64_encoded_sensitive_network_flow", suite)


if __name__ == "__main__":
    unittest.main()
