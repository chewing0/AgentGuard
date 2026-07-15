from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class MultilingualPromptInjectionBlackBoxTest(unittest.TestCase):
    def test_chinese_private_file_read_attack(self) -> None:
        run_real_model_case(self, "blackbox-multilingual-private-read")


if __name__ == "__main__":
    unittest.main()
