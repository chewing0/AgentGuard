"""One-test entry point for the InjecAgent external corpus adapter."""

import unittest

from tests.non_blackbox.suites import autonomous_benchmark_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "AutonomousBenchmarkLoaderTests.test_injecagent_adapter_reports_paired_tpr_fpr_without_raw_text",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
