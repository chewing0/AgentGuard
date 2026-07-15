"""One-test entry point for EvaluationTests.test_completion_excludes_tasks_without_required_steps_and_reports_utility."""

import unittest

from tests.non_blackbox.suites import evaluation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("EvaluationTests.test_completion_excludes_tasks_without_required_steps_and_reports_utility", suite)


if __name__ == "__main__":
    unittest.main()
