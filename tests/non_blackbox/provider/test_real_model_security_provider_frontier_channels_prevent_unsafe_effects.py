"""One-test entry point for RealModelFrontierSecurityTests.test_provider_frontier_channels_prevent_unsafe_effects."""

import unittest

from tests.non_blackbox.suites import real_model_security_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelFrontierSecurityTests.test_provider_frontier_channels_prevent_unsafe_effects", suite)


if __name__ == "__main__":
    unittest.main()
