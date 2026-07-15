"""One-test entry point for AutonomousScoringTests.test_stale_artifact_does_not_satisfy_completion."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_stale_artifact_does_not_satisfy_completion", suite)


if __name__ == "__main__":
    unittest.main()
