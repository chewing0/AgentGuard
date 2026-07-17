"""One-test entry point for multichannel browser observation guarding."""

import unittest

from tests.non_blackbox.suites import browser_observation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "BrowserObservationTests.test_multichannel_guard_quarantines_dom_accessibility_and_ocr_injection",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
