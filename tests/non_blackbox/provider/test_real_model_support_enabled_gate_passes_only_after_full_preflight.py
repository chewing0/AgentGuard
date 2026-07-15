"""One-test entry point for RealModelGateTests.test_enabled_gate_passes_only_after_full_preflight."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_enabled_gate_passes_only_after_full_preflight", suite)


if __name__ == "__main__":
    unittest.main()
