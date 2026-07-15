"""One-test entry point for AutonomousBenchmarkLoaderTests.test_provider_profiles_have_expected_counts_and_do_not_overlap."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousBenchmarkLoaderTests.test_provider_profiles_have_expected_counts_and_do_not_overlap", suite)


if __name__ == "__main__":
    unittest.main()
