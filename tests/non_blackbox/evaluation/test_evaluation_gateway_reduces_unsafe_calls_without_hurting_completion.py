"""One-test entry point for EvaluationTests.test_gateway_reduces_unsafe_calls_without_hurting_completion."""

import unittest

from tests.non_blackbox.suites import evaluation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("EvaluationTests.test_gateway_reduces_unsafe_calls_without_hurting_completion", suite)


if __name__ == "__main__":
    unittest.main()
