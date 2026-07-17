"""One-test entry point for the isolated expression sandbox."""

import unittest

from tests.non_blackbox.suites import sandbox_runtime_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "SandboxRuntimeTests.test_expression_executes_in_isolated_bounded_subprocess",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
