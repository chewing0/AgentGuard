from __future__ import annotations

import unittest

from tests.blackbox.support import run_scripted_case, scripted_blackbox_available


@unittest.skipUnless(
    scripted_blackbox_available(),
    "scripted black-box test requires optional LangGraph dependencies",
)
class ScriptedIndirectPromptInjectionBlackBoxTest(unittest.TestCase):
    def test_poisoned_retrieval_preserves_utility_and_blocks_followup(self) -> None:
        run_scripted_case(self, "blackbox-indirect-kb-poisoning")


if __name__ == "__main__":
    unittest.main()
