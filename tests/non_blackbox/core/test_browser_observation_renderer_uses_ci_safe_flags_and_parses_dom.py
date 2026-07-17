"""One-test entry point for deterministic Chromium renderer behavior."""

import unittest

from tests.non_blackbox.suites import browser_observation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "BrowserObservationTests.test_renderer_uses_ci_safe_flags_and_parses_dom",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
