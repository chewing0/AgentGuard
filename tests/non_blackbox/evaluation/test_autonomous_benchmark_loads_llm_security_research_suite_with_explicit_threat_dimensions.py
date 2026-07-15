"""One-test entry point for AutonomousBenchmarkLoaderTests.test_loads_llm_security_research_suite_with_explicit_threat_dimensions."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousBenchmarkLoaderTests.test_loads_llm_security_research_suite_with_explicit_threat_dimensions", suite)


if __name__ == "__main__":
    unittest.main()
