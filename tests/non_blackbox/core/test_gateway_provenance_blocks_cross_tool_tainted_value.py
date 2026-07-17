"""One-test entry point for GatewayTests.test_provenance_blocks_cross_tool_tainted_value."""

import unittest

from tests.non_blackbox.suites import gateway_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "GatewayTests.test_provenance_blocks_cross_tool_tainted_value",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
