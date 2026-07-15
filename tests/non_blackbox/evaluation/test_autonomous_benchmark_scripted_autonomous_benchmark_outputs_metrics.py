"""One-test entry point for AutonomousBenchmarkRunnerTests.test_scripted_autonomous_benchmark_outputs_metrics."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousBenchmarkRunnerTests.test_scripted_autonomous_benchmark_outputs_metrics", suite)


if __name__ == "__main__":
    unittest.main()
