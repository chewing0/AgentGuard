"""One-test entry point for cross-session persistent memory."""

import unittest

from tests.non_blackbox.suites import persistent_memory_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "PersistentMemoryTests.test_cross_session_memory_redacts_secrets_and_quarantines_injection",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
