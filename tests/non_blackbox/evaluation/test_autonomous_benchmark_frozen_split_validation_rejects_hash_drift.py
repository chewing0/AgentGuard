"""One-test entry point for frozen benchmark hash drift rejection."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AutonomousBenchmarkLoaderTests.test_frozen_split_validation_rejects_hash_drift",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
