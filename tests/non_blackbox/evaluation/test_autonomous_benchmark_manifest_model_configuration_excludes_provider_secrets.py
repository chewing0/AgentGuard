"""One-test entry point for AutonomousScoringTests.test_manifest_model_configuration_excludes_provider_secrets."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("AutonomousScoringTests.test_manifest_model_configuration_excludes_provider_secrets", suite)


if __name__ == "__main__":
    unittest.main()
