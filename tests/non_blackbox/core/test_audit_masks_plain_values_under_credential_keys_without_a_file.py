"""One-test entry point for AuditLoggerTests.test_masks_plain_values_under_credential_keys_without_a_file."""

import unittest

from tests.non_blackbox.suites import audit_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AuditLoggerTests.test_masks_plain_values_under_credential_keys_without_a_file", suite)


if __name__ == "__main__":
    unittest.main()
