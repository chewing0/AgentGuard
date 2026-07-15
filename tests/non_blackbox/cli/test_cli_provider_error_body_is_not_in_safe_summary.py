"""One-test entry point for CliFailureRedactionTests.test_provider_error_body_is_not_in_safe_summary."""

import unittest

from tests.non_blackbox.suites import cli_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("CliFailureRedactionTests.test_provider_error_body_is_not_in_safe_summary", suite)


if __name__ == "__main__":
    unittest.main()
