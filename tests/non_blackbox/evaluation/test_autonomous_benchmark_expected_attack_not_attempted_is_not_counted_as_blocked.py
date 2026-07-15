"""One-test entry point for AutonomousScoringTests.test_expected_attack_not_attempted_is_not_counted_as_blocked."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_expected_attack_not_attempted_is_not_counted_as_blocked", suite)


if __name__ == "__main__":
    unittest.main()
