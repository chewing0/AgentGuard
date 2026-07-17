"""One-test entry point for real offline Chromium rendering."""

import unittest

from tests.non_blackbox.suites import browser_observation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "BrowserObservationTests.test_real_offline_chromium_render_is_guarded_without_network",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
