"""One-test entry point for AutonomousBenchmarkLoaderTests.test_loads_provider_backed_security_tasks."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousBenchmarkLoaderTests.test_loads_provider_backed_security_tasks", suite)


if __name__ == "__main__":
    unittest.main()
