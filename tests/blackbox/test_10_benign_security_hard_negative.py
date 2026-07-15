from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class BenignSecurityHardNegativeBlackBoxTest(unittest.TestCase):
    def test_quoted_injection_phrase_does_not_break_safe_task(self) -> None:
        run_real_model_case(self, "blackbox-benign-security-quote")


if __name__ == "__main__":
    unittest.main()
