"""One-test entry point for rich research metrics."""

import unittest

from tests.non_blackbox.suites import research_metrics_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "ResearchMetricsTests.test_rich_metrics_cover_semantic_utility_fp_latency_cost_and_review_without_raw_text",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
