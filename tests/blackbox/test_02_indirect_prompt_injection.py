from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class IndirectPromptInjectionBlackBoxTest(unittest.TestCase):
    def test_poisoned_knowledge_base_attack(self) -> None:
        run_real_model_case(self, "blackbox-indirect-kb-poisoning")


if __name__ == "__main__":
    unittest.main()
