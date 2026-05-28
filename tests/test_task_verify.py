#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"


class TaskVerifyTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def create_run(self, base: pathlib.Path, title: str = "Verify Smoke") -> tuple[str, pathlib.Path]:
        created = self.run_relay("task", "init", title, base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def test_task_verify_runs_final_script_and_marks_manifest_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base)

            verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            payload = json.loads(verified.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["verification_strength"], "same-rail")
            self.assertTrue((run_dir / "logs" / "verify.log").is_file())
            self.assertTrue((run_dir / "logs" / "final.log").is_file())
            self.assertTrue((run_dir / "results" / "result.json").is_file())
            self.assertTrue((run_dir / "verification" / "verify-result.json").is_file())
            self.assertTrue((run_dir / "verification" / "hygiene-report.json").is_file())
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "verified")
            self.assertEqual(manifest["verification"]["strength"], "same-rail")
            self.assertGreaterEqual(len(manifest["artifacts"]), 3)

    def test_task_verify_fails_closed_on_secret_like_log_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Secret Hygiene Smoke")
            final_script = run_dir / "scripts" / "final.py"
            final_script.write_text(textwrap.dedent('''
                #!/usr/bin/env python3
                from pathlib import Path
                root = Path(__file__).resolve().parents[1]
                (root / "logs").mkdir(exist_ok=True)
                (root / "results").mkdir(exist_ok=True)
                leak = "Authorization: " + "Bearer " + "sk-" + "testsecret"
                (root / "logs" / "final.log").write_text(leak, encoding="utf-8")
                (root / "results" / "result.json").write_text("{}", encoding="utf-8")
            '''), encoding="utf-8")

            verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertNotEqual(verified.returncode, 0)
            payload = json.loads(verified.stdout)
            self.assertEqual(payload["status"], "failed")
            self.assertEqual(payload["failed_gate"], "hygiene_scan")
            report = json.loads((run_dir / "verification" / "hygiene-report.json").read_text())
            self.assertEqual(report["status"], "failed")
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "failed")


if __name__ == "__main__":
    unittest.main()
