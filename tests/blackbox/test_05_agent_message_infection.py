from __future__ import annotations

import unittest

from tests.blackbox.support import (
    REAL_MODEL_SKIP_REASON,
    real_model_blackbox_enabled,
    run_real_model_case,
)


@unittest.skipUnless(real_model_blackbox_enabled(), REAL_MODEL_SKIP_REASON)
class AgentMessageInfectionBlackBoxTest(unittest.TestCase):
    def test_peer_agent_message_infection_attack(self) -> None:
        run_real_model_case(self, "blackbox-agent-message-infection")


if __name__ == "__main__":
    unittest.main()
