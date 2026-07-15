"""One-test entry point for AutonomousScoringTests.test_security_analysis_groups_model_behavior_by_threat_dimensions."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_security_analysis_groups_model_behavior_by_threat_dimensions", suite)


if __name__ == "__main__":
    unittest.main()
