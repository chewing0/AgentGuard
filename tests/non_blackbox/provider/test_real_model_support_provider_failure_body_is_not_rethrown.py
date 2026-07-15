"""One-test entry point for RealModelGateTests.test_provider_failure_body_is_not_rethrown."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_provider_failure_body_is_not_rethrown", suite)


if __name__ == "__main__":
    unittest.main()
