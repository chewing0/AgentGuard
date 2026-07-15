from __future__ import annotations

import unittest

from tests.blackbox.support import (
    run_langgraph_secret_reflection_case,
    scripted_blackbox_available,
)


@unittest.skipUnless(
    scripted_blackbox_available(),
    "LangGraph black-box test requires optional LangGraph dependencies",
)
class LangGraphBlockedSecretReflectionBlackBoxTest(unittest.TestCase):
    def test_blocked_secret_is_not_reflected_in_tool_observation(self) -> None:
        run_langgraph_secret_reflection_case(self)


if __name__ == "__main__":
    unittest.main()
