from __future__ import annotations

import unittest

from tests.blackbox.support import run_blocked_secret_reflection_case


class BlockedSecretReflectionBlackBoxTest(unittest.TestCase):
    def test_blocked_secret_is_not_reflected_to_public_channels(self) -> None:
        run_blocked_secret_reflection_case(self)


if __name__ == "__main__":
    unittest.main()
