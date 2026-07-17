"""One-test entry point for the conservative four-model reference snapshot contract."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AutonomousBenchmarkLoaderTests.test_siliconflow_four_model_reference_snapshot_is_complete_and_conservative",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
