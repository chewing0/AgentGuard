"""Shared implementations for run manifest tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentguard.evaluation import run_evaluation
from agentguard.run_manifest import build_run_manifest, prepare_run_directory


ROOT = Path(__file__).resolve().parents[3]
BENCHMARKS = ROOT / "data" / "benchmarks"


class RunManifestTests(unittest.TestCase):
    def test_prepare_run_directory_requires_explicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            prepare_run_directory(out)
            (out / "metrics.json").write_text("{}", encoding="utf-8")
            (out / "keep.txt").write_text("user-owned", encoding="utf-8")
            audit = out / "audit"
            audit.mkdir()
            (audit / "gateway_audit.jsonl").write_text("old\n", encoding="utf-8")
            workspace = out / "workspaces" / "task-1"
            workspace.mkdir(parents=True)
            (workspace / "artifact.md").write_text("old", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                prepare_run_directory(out)

            prepare_run_directory(out, overwrite=True)
            self.assertFalse((out / "metrics.json").exists())
            self.assertFalse(audit.exists())
            self.assertFalse((out / "workspaces").exists())
            self.assertEqual((out / "keep.txt").read_text(encoding="utf-8"), "user-owned")

    def test_manifest_contains_reproducibility_metadata_without_absolute_input_paths(self) -> None:
        manifest = build_run_manifest(
            run_type="test",
            project_root=ROOT,
            tasks_path=BENCHMARKS / "benchmark_tasks.jsonl",
            tools_path=ROOT / "data" / "tools.json",
            configuration={"mode": "gateway"},
        )
        self.assertEqual(
            manifest["inputs"]["tasks"]["path"],
            "data/benchmarks/benchmark_tasks.jsonl",
        )
        self.assertEqual(len(manifest["inputs"]["tasks"]["sha256"]), 64)
        self.assertIn("commit", manifest["git"])
        self.assertIn("python", manifest["environment"])
        self.assertEqual(manifest["configuration"]["mode"], "gateway")

    def test_evaluation_overwrite_starts_a_fresh_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "run"
            kwargs = {
                "tasks_path": BENCHMARKS / "benchmark_tasks.jsonl",
                "tools_path": ROOT / "data" / "tools.json",
                "workspace_root": ROOT,
                "output_dir": out,
                "modes": ["gateway"],
            }
            run_evaluation(**kwargs)
            with self.assertRaises(FileExistsError):
                run_evaluation(**kwargs)
            run_evaluation(**kwargs, overwrite=True)

            events = (out / "audit" / "gateway_audit.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(events), 44)
            manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["configuration"]["modes"], ["gateway"])


if __name__ == "__main__":
    unittest.main()
