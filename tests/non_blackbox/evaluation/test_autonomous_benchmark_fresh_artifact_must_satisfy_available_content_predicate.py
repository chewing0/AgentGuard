"""One-test entry point for AutonomousScoringTests.test_fresh_artifact_must_satisfy_available_content_predicate."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_fresh_artifact_must_satisfy_available_content_predicate", suite)


if __name__ == "__main__":
    unittest.main()
