"""One-test entry point for AuditLoggerTests.test_redacts_secrets_from_every_audit_section."""

import unittest

from tests.non_blackbox.suites import audit_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AuditLoggerTests.test_redacts_secrets_from_every_audit_section", suite)


if __name__ == "__main__":
    unittest.main()
