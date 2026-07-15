"""One-test entry point for RealModelGateTests.test_does_not_reuse_anthropic_token_for_an_unrecognized_host."""

import unittest

from tests.non_blackbox.suites import real_model_support_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelGateTests.test_does_not_reuse_anthropic_token_for_an_unrecognized_host", suite)


if __name__ == "__main__":
    unittest.main()
