"""Verify every shared suite test has exactly one independent entry file."""

from __future__ import annotations

import ast
import unittest
from collections import Counter
from pathlib import Path


NON_BLACKBOX_ROOT = Path(__file__).resolve().parents[1]
SUITES_ROOT = NON_BLACKBOX_ROOT / "suites"


class TestLayoutContract(unittest.TestCase):
    def test_suite_methods_and_entry_files_are_one_to_one(self) -> None:
        suite_methods: set[tuple[str, str, str]] = set()
        for path in SUITES_ROOT.glob("*_suite.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name.startswith("test_"):
                        suite_methods.add((path.stem, node.name, item.name))

        entries: list[tuple[str, str, str]] = []
        for path in NON_BLACKBOX_ROOT.glob("*/test_*.py"):
            if path.resolve() == Path(__file__).resolve():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            suite_name = self._imported_suite_name(tree)
            targets = self._load_targets(tree)
            self.assertEqual(targets and len(targets), 1, str(path))
            class_name, method_name = targets[0].split(".", 1)
            entries.append((suite_name, class_name, method_name))

        counts = Counter(entries)
        self.assertEqual(set(entries), suite_methods)
        self.assertEqual(
            [entry for entry, count in counts.items() if count != 1],
            [],
        )

    @staticmethod
    def _imported_suite_name(tree: ast.Module) -> str:
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module == "tests.non_blackbox.suites":
                return node.names[0].name
        raise AssertionError("entry file must import exactly one shared suite")

    @staticmethod
    def _load_targets(tree: ast.Module) -> list[str]:
        return [
            str(node.args[0].value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "loadTestsFromName"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ]


if __name__ == "__main__":
    unittest.main()
