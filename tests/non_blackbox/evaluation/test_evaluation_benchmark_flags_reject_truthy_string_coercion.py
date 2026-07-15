"""One-test entry point for EvaluationTests.test_benchmark_flags_reject_truthy_string_coercion."""

import unittest

from tests.non_blackbox.suites import evaluation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("EvaluationTests.test_benchmark_flags_reject_truthy_string_coercion", suite)


if __name__ == "__main__":
    unittest.main()
