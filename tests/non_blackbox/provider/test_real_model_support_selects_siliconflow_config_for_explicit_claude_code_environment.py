"""One-test entry point for RealModelGateTests.test_selects_siliconflow_config_for_explicit_claude_code_environment."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_selects_siliconflow_config_for_explicit_claude_code_environment", suite)


if __name__ == "__main__":
    unittest.main()
