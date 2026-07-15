"""One-test entry point for CliFailureRedactionTests.test_module_entrypoint_propagates_cli_failure_exit_code."""

import unittest

from tests.non_blackbox.suites import cli_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("CliFailureRedactionTests.test_module_entrypoint_propagates_cli_failure_exit_code", suite)


if __name__ == "__main__":
    unittest.main()
