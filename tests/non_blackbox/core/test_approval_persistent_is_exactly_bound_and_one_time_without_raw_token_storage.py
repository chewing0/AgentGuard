"""One-test entry point for persistent one-time approvals."""

import unittest

from tests.non_blackbox.suites import approval_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "ApprovalTests.test_persistent_approval_is_exactly_bound_and_one_time_without_raw_token_storage",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
