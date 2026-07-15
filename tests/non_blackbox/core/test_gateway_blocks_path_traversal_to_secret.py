"""One-test entry point for GatewayTests.test_blocks_path_traversal_to_secret."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_blocks_path_traversal_to_secret", suite)


if __name__ == "__main__":
    unittest.main()
