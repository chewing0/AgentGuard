"""One-test entry point for ModelConfigTests.test_extra_cannot_override_sensitive_or_core_parameters."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_extra_cannot_override_sensitive_or_core_parameters", suite)


if __name__ == "__main__":
    unittest.main()
