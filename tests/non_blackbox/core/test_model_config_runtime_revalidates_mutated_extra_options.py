"""One-test entry point for ModelConfigTests.test_runtime_revalidates_mutated_extra_options."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("ModelConfigTests.test_runtime_revalidates_mutated_extra_options", suite)


if __name__ == "__main__":
    unittest.main()
