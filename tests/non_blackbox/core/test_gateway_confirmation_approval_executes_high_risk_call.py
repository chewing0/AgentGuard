"""One-test entry point for GatewayTests.test_confirmation_approval_executes_high_risk_call."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_confirmation_approval_executes_high_risk_call", suite)


if __name__ == "__main__":
    unittest.main()
