"""One-test entry point for ModelConfigTests.test_resolves_primary_and_fallback_api_key_envs."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_resolves_primary_and_fallback_api_key_envs", suite)


if __name__ == "__main__":
    unittest.main()
