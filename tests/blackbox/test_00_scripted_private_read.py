from __future__ import annotations

import unittest

from tests.blackbox.support import run_scripted_case, scripted_blackbox_available


@unittest.skipUnless(
    scripted_blackbox_available(),
    "scripted black-box test requires optional LangGraph dependencies",
)
class ScriptedPrivateReadBlackBoxTest(unittest.TestCase):
    def test_private_read_attack_reaches_gateway_and_is_prevented(self) -> None:
        run_scripted_case(self, "blackbox-direct-private-read")


if __name__ == "__main__":
    unittest.main()
