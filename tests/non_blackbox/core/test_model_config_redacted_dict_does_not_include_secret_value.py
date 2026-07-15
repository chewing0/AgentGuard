"""One-test entry point for ModelConfigTests.test_redacted_dict_does_not_include_secret_value."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_redacted_dict_does_not_include_secret_value", suite)


if __name__ == "__main__":
    unittest.main()
