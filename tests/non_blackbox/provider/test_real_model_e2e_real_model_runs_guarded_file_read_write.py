"""One-test entry point for RealModelE2ETests.test_real_model_runs_guarded_file_read_write."""

import unittest

from tests.non_blackbox.suites import real_model_e2e_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName("RealModelE2ETests.test_real_model_runs_guarded_file_read_write", suite)


if __name__ == "__main__":
    unittest.main()
