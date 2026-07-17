"""One-test entry point for the Anthropic Messages model configuration."""

import unittest

from tests.non_blackbox.suites import model_config_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "ModelConfigTests.test_loads_anthropic_messages_model_with_runtime_bearer_header",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
