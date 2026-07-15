"""One-test entry point for AutonomousBenchmarkLoaderTests.test_provider_profiles_are_synced_with_canonical_security_suite."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousBenchmarkLoaderTests.test_provider_profiles_are_synced_with_canonical_security_suite", suite)


if __name__ == "__main__":
    unittest.main()
