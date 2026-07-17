"""One-test entry point for frozen development/held-out split validation."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AutonomousBenchmarkLoaderTests.test_frozen_splits_are_disjoint_and_heldout_labels_match_gateway",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
