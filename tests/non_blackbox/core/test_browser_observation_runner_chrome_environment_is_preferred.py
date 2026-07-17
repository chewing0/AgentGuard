"""One-test entry point for GitHub Runner Chrome discovery."""

import unittest

from tests.non_blackbox.suites import browser_observation_suite as suite


def load_tests(loader, tests, pattern):
    return loader.loadTestsFromName(
        "BrowserObservationTests.test_runner_chrome_environment_is_preferred",
        suite,
    )


if __name__ == "__main__":
    unittest.main()
