"""One-test entry point for GatewayTests.test_peer_agent_prompt_infection_fixture_is_returned_as_observation."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("GatewayTests.test_peer_agent_prompt_infection_fixture_is_returned_as_observation", suite)


if __name__ == "__main__":
    unittest.main()
