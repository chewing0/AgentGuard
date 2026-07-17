"""One-test entry point for the repeated multi-model black-box matrix."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AutonomousBenchmarkLoaderTests.test_multi_model_blackbox_matrix_repeats_full_suite_and_discards_output",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
