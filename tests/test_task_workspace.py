#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"


class TaskWorkspaceTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def test_task_init_creates_workspace_manifest_and_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            result = self.run_relay("task", "init", "Example Title Smoke", base_dir=base, json_mode=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            run_dir = pathlib.Path(payload["run_dir"])
            self.assertTrue(run_dir.is_dir())
            self.assertEqual(payload["status"], "initialized")
            self.assertTrue((run_dir / "task.md").is_file())
            self.assertTrue((run_dir / "manifest.json").is_file())
            self.assertTrue((run_dir / "scripts" / "final.py").is_file())
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(manifest["schema"], "chip-relay-run-manifest-v1")
            self.assertEqual(manifest["task"]["title"], "Example Title Smoke")
            self.assertEqual(manifest["task"]["brief_schema"], "chip-relay-agent-brief-v2")
            self.assertIn("agent_instructions", manifest["task"]["brief"])
            self.assertIn("success_metrics", manifest["task"]["brief"])
            self.assertIn("known_frictions", manifest["task"]["brief"])
            self.assertIn("verification_questions", manifest["task"]["brief"])
            task_md = (run_dir / "task.md").read_text(encoding="utf-8")
            self.assertIn("## Agent Instructions", task_md)
            self.assertIn("## Success Metrics", task_md)
            self.assertIn("## Known Frictions", task_md)
            self.assertIn("## Verification Questions", task_md)
            self.assertEqual(manifest["status"], "initialized")
            self.assertEqual(manifest["verification"]["strength"], "not-run")

    def test_task_list_and_show_return_existing_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_relay("task", "init", "List Show Smoke", base_dir=base, json_mode=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            run_id = json.loads(created.stdout)["run_id"]

            listed = self.run_relay("task", "list", base_dir=base, json_mode=True)
            self.assertEqual(listed.returncode, 0, listed.stderr)
            runs = json.loads(listed.stdout)["runs"]
            self.assertEqual([r["run_id"] for r in runs], [run_id])

            shown = self.run_relay("task", "show", run_id, base_dir=base, json_mode=True)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            payload = json.loads(shown.stdout)
            self.assertEqual(payload["run_id"], run_id)
            self.assertEqual(payload["task"]["title"], "List Show Smoke")


if __name__ == "__main__":
    unittest.main()
