#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"


class TaskRunPackTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        env["CHIP_RELAY_CDP_URL"] = "http://127.0.0.1:18800"
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def create_run(self, base: pathlib.Path, title: str = "Run Smoke") -> tuple[str, pathlib.Path]:
        created = self.run_relay("task", "init", title, base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def test_task_run_executes_final_script_without_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base)

            ran = self.run_relay("task", "run", run_id, base_dir=base, json_mode=True)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            payload = json.loads(ran.stdout)
            self.assertEqual(payload["status"], "ran")
            self.assertEqual(payload["run_id"], run_id)
            self.assertEqual(payload["exit_code"], 0)
            self.assertTrue((run_dir / "logs" / "run.log").is_file())
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "ran")

    def test_task_pack_refuses_unverified_run_then_packs_verified_script_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Pack Smoke")

            rejected = self.run_relay("task", "pack", run_id, "--name", "pack-smoke", base_dir=base, json_mode=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(json.loads(rejected.stdout)["failed_gate"], "run_not_verified")

            verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            packed = self.run_relay("task", "pack", run_id, "--name", "pack-smoke", base_dir=base, json_mode=True)
            self.assertEqual(packed.returncode, 0, packed.stderr)
            payload = json.loads(packed.stdout)
            recipe_dir = pathlib.Path(payload["recipe_dir"])
            self.assertEqual(payload["status"], "packed")
            self.assertTrue((recipe_dir / "final.py").is_file())
            self.assertTrue((recipe_dir / "recipe.json").is_file())
            self.assertFalse((recipe_dir / "logs").exists())
            self.assertFalse((recipe_dir / "screenshots").exists())

    def test_doctor_webwright_reports_playwright_cdp_workspace_and_hygiene(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            checked = self.run_relay("doctor", "webwright", base_dir=base, json_mode=True)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            payload = json.loads(checked.stdout)
            self.assertEqual(payload["status"], "ok")
            checks = payload["checks"]
            self.assertIn("python", checks)
            self.assertIn("playwright_import", checks)
            self.assertIn("cdp", checks)
            self.assertIn("workspace_writable", checks)
            self.assertIn("hygiene_scanner", checks)


if __name__ == "__main__":
    unittest.main()
