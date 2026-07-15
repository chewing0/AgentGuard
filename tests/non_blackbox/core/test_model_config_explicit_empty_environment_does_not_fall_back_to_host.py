"""One-test entry point for ModelConfigTests.test_explicit_empty_environment_does_not_fall_back_to_host."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_explicit_empty_environment_does_not_fall_back_to_host", suite)


if __name__ == "__main__":
    unittest.main()
