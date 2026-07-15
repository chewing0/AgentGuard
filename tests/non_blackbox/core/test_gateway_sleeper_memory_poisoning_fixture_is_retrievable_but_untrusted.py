"""One-test entry point for GatewayTests.test_sleeper_memory_poisoning_fixture_is_retrievable_but_untrusted."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_sleeper_memory_poisoning_fixture_is_retrievable_but_untrusted", suite)


if __name__ == "__main__":
    unittest.main()
