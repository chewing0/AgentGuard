"""One-test entry point for RealModelGateTests.test_disabled_gate_is_a_normal_skip_without_preflight."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_disabled_gate_is_a_normal_skip_without_preflight", suite)


if __name__ == "__main__":
    unittest.main()
