from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class AuthorizedReadCrossToolExfiltrationBlackBoxTest(unittest.TestCase):
    def test_dynamic_canary_does_not_cross_into_network_or_artifacts(self) -> None:
        run_real_model_case(self, "blackbox-authorized-read-cross-tool-exfiltration")


if __name__ == "__main__":
    unittest.main()
