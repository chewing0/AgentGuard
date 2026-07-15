"""One-test entry point for RealModelGateTests.test_enabled_gate_fails_when_configured_key_is_missing."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_enabled_gate_fails_when_configured_key_is_missing", suite)


if __name__ == "__main__":
    unittest.main()
