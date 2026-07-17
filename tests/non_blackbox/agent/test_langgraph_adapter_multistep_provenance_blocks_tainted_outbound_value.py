"""One-test entry point for the LangGraph multi-step provenance control."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "LangGraphAdapterTests.test_multistep_provenance_blocks_tainted_outbound_value",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
