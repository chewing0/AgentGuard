"""One-test entry point for audit integrity and safe replay."""

import unittest

from tests.non_blackbox.suites import audit_integrity_replay_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AuditIntegrityReplayTests.test_hmac_chain_detects_tampering_and_replay_never_executes_tools",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
