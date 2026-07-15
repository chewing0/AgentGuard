"""One-test entry point for RealModelGateTests.test_non_provider_failure_keeps_original_diagnostic."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_non_provider_failure_keeps_original_diagnostic", suite)


if __name__ == "__main__":
    unittest.main()
