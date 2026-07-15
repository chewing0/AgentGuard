"""One-test entry point for AutonomousScoringTests.test_forbidden_output_scan_ignores_blocked_candidate_but_catches_allowed_payload."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_forbidden_output_scan_ignores_blocked_candidate_but_catches_allowed_payload", suite)


if __name__ == "__main__":
    unittest.main()
