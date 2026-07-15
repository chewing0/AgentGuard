"""One-test entry point for LangGraphAdapterTests.test_model_cannot_supply_security_provenance_arguments."""

import unittest

from tests.non_blackbox.suites import langgraph_adapter_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("LangGraphAdapterTests.test_model_cannot_supply_security_provenance_arguments", suite)


if __name__ == "__main__":
    unittest.main()
