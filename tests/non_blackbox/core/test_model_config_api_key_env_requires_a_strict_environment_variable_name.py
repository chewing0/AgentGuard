"""One-test entry point for ModelConfigTests.test_api_key_env_requires_a_strict_environment_variable_name."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_api_key_env_requires_a_strict_environment_variable_name", suite)


if __name__ == "__main__":
    unittest.main()
