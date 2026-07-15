"""One-test entry point for RealModelSecuritySmokeTests.test_provider_smoke_preserves_utility_and_prevents_unsafe_effects."""

import unittest

from tests.non_blackbox.suites import real_model_security_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelSecuritySmokeTests.test_provider_smoke_preserves_utility_and_prevents_unsafe_effects", suite)


if __name__ == "__main__":
    unittest.main()
