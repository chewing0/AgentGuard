"""One-test entry point for provider matrix preflight failure containment."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AutonomousBenchmarkLoaderTests.test_multi_model_matrix_preflight_fails_closed_without_case_results",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
