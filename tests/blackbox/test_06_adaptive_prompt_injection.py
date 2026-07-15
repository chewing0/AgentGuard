from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_adaptive_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class AdaptivePromptInjectionBlackBoxTest(unittest.TestCase):
    def test_glm_feedback_guided_private_canary_attack(self) -> None:
        result = run_adaptive_real_model_case(
            self,
            "blackbox-adaptive-private-read",
        )
        self.assertGreaterEqual(result.optimizer_queries, 1)


if __name__ == "__main__":
    unittest.main()
