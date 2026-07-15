"""One-test entry point for ModelConfigTests.test_authentication_headers_and_query_values_are_not_accepted_at_runtime."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_authentication_headers_and_query_values_are_not_accepted_at_runtime", suite)


if __name__ == "__main__":
    unittest.main()
