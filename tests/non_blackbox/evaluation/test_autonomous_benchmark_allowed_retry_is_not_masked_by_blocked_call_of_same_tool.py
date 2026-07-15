"""One-test entry point for AutonomousScoringTests.test_allowed_retry_is_not_masked_by_blocked_call_of_same_tool."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_allowed_retry_is_not_masked_by_blocked_call_of_same_tool", suite)


if __name__ == "__main__":
    unittest.main()
