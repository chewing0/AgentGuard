"""One-test entry point for EvaluationTests.test_benchmark_expected_gateway_decisions."""

import unittest

from tests.non_blackbox.suites import evaluation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("EvaluationTests.test_benchmark_expected_gateway_decisions", suite)


if __name__ == "__main__":
    unittest.main()
