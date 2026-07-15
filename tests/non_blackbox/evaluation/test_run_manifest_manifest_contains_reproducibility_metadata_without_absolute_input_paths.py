"""One-test entry point for RunManifestTests.test_manifest_contains_reproducibility_metadata_without_absolute_input_paths."""

import unittest

from tests.non_blackbox.suites import run_manifest_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RunManifestTests.test_manifest_contains_reproducibility_metadata_without_absolute_input_paths", suite)


if __name__ == "__main__":
    unittest.main()
