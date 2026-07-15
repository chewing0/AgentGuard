"""One-test entry point for GatewayTests.test_requires_confirmation_for_unconfirmed_code."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_requires_confirmation_for_unconfirmed_code", suite)


if __name__ == "__main__":
    unittest.main()
