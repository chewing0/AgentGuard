"""One-test entry point for CliFailureRedactionTests.test_non_http_error_uses_only_exception_type."""

import unittest

from tests.non_blackbox.suites import cli_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("CliFailureRedactionTests.test_non_http_error_uses_only_exception_type", suite)


if __name__ == "__main__":
    unittest.main()
