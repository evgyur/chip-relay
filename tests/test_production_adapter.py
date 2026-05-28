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


class ProductionAdapterTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def create_verified_run(self, base: pathlib.Path) -> tuple[str, pathlib.Path]:
        created = self.run_relay("task", "init", "Adapter Evidence Smoke", base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        verified = self.run_relay("task", "verify", payload["run_id"], base_dir=base, json_mode=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def test_task_show_non_json_is_operator_evidence_not_manifest_dump(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_verified_run(base)

            shown = self.run_relay("task", "show", run_id, base_dir=base)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertIn("run: " + run_id, shown.stdout)
            self.assertIn("rail: default", shown.stdout)
            self.assertIn("cdp: local-only", shown.stdout)
            self.assertIn("verification: verified", shown.stdout)
            self.assertIn("hygiene: ok", shown.stdout)
            self.assertIn("artifact_policy: private-local/no-auto-send", shown.stdout)
            self.assertIn("blocker: none", shown.stdout)
            self.assertIn(str(run_dir), shown.stdout)
            self.assertNotIn('"schema"', shown.stdout)
            self.assertNotIn('"artifacts"', shown.stdout)

    def test_artifacts_command_returns_metadata_only_without_file_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_verified_run(base)
            private_text = "PRIVATE_CONTENT_SHOULD_NOT_APPEAR"
            (run_dir / "logs" / "manual-private.log").write_text(private_text, encoding="utf-8")

            artifacts = self.run_relay("artifacts", run_id, base_dir=base, json_mode=True)
            self.assertEqual(artifacts.returncode, 0, artifacts.stderr)
            payload = json.loads(artifacts.stdout)
            self.assertEqual(payload["run_id"], run_id)
            self.assertEqual(payload["artifact_policy"], "private-local/no-auto-send")
            self.assertEqual(payload["delivery"], "metadata-only")
            paths = [item["path"] for item in payload["artifacts"]]
            self.assertIn("logs/manual-private.log", paths)
            for item in payload["artifacts"]:
                self.assertEqual(item["sensitivity"], "private-local")
                self.assertIn("size_bytes", item)
                self.assertNotIn("content", item)
            self.assertNotIn(private_text, artifacts.stdout)


if __name__ == "__main__":
    unittest.main()
