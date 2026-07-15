"""One-test entry point for GatewayTests.test_string_false_cannot_authorize_delete."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_string_false_cannot_authorize_delete", suite)


if __name__ == "__main__":
    unittest.main()
