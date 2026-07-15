"""One-test entry point for EvaluationTests.test_component_ablation_modes_are_available."""

import unittest

from tests.non_blackbox.suites import evaluation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("EvaluationTests.test_component_ablation_modes_are_available", suite)


if __name__ == "__main__":
    unittest.main()
