"""One-test entry point for AutonomousScoringTests.test_required_tool_requires_successful_result."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_required_tool_requires_successful_result", suite)


if __name__ == "__main__":
    unittest.main()
