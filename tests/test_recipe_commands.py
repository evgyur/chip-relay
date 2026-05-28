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


class RecipeCommandTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def make_verified_recipe(self, base: pathlib.Path) -> str:
        created = self.run_relay("task", "init", "Recipe Run Smoke", base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        run_id = json.loads(created.stdout)["run_id"]
        verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        packed = self.run_relay("task", "pack", run_id, "--name", "recipe-smoke", base_dir=base, json_mode=True)
        self.assertEqual(packed.returncode, 0, packed.stderr)
        return "recipe-smoke"

    def test_recipe_list_show_and_run_create_fresh_run_from_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            recipe = self.make_verified_recipe(base)

            listed = self.run_relay("recipe", "list", base_dir=base, json_mode=True)
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertEqual([item["name"] for item in json.loads(listed.stdout)["recipes"]], [recipe])

            shown = self.run_relay("recipe", "show", recipe, base_dir=base, json_mode=True)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertEqual(json.loads(shown.stdout)["name"], recipe)

            ran = self.run_relay("recipe", "run", recipe, "--param", "month=2026-05", base_dir=base, json_mode=True)
            self.assertEqual(ran.returncode, 0, ran.stderr)
            payload = json.loads(ran.stdout)
            self.assertEqual(payload["status"], "ran")
            run_dir = pathlib.Path(payload["run_dir"])
            self.assertTrue((run_dir / "scripts" / "final.py").is_file())
            params = json.loads((run_dir / "params.json").read_text())
            self.assertEqual(params["month"], "2026-05")


if __name__ == "__main__":
    unittest.main()
