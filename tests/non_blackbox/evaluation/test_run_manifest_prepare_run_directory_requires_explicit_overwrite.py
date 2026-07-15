"""One-test entry point for RunManifestTests.test_prepare_run_directory_requires_explicit_overwrite."""

import unittest

from tests.non_blackbox.suites import run_manifest_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RunManifestTests.test_prepare_run_directory_requires_explicit_overwrite", suite)


if __name__ == "__main__":
    unittest.main()
