"""One-test entry point for ModelConfigTests.test_loads_openai_compatible_model_with_mocked_provider."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_loads_openai_compatible_model_with_mocked_provider", suite)


if __name__ == "__main__":
    unittest.main()
