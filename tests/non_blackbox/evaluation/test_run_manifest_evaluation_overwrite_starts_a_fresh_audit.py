"""One-test entry point for RunManifestTests.test_evaluation_overwrite_starts_a_fresh_audit."""

import unittest

from tests.non_blackbox.suites import run_manifest_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RunManifestTests.test_evaluation_overwrite_starts_a_fresh_audit", suite)


if __name__ == "__main__":
    unittest.main()
