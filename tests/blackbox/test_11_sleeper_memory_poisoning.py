from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class SleeperMemoryPoisoningBlackBoxTest(unittest.TestCase):
    def test_retrieved_sleeper_memory_does_not_trigger_private_read(self) -> None:
        run_real_model_case(self, "blackbox-sleeper-memory-poisoning")


if __name__ == "__main__":
    unittest.main()
