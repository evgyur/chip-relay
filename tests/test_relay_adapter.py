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


class RelayAdapterTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def test_relay_task_init_verify_show_flow_uses_operator_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_relay("relay", "/relay", "task", "init", "Telegram Adapter Smoke", base_dir=base, json_mode=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            init_payload = json.loads(created.stdout)
            self.assertEqual(init_payload["schema"], "chip-relay-adapter-response-v1")
            self.assertEqual(init_payload["command"], "task.init")
            self.assertEqual(init_payload["status"], "initialized")
            run_id = init_payload["run_id"]

            verified = self.run_relay("relay", "/relay", "task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            verify_payload = json.loads(verified.stdout)
            self.assertEqual(verify_payload["command"], "task.verify")
            self.assertEqual(verify_payload["status"], "verified")
            self.assertEqual(verify_payload["evidence"]["verification"]["status"], "verified")
            self.assertEqual(verify_payload["evidence"]["artifact_policy"], "private-local/no-auto-send")

            shown = self.run_relay("relay", "/relay", "task", "show", run_id, base_dir=base)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertIn("run: " + run_id, shown.stdout)
            self.assertIn("verification: verified", shown.stdout)
            self.assertIn("artifact_policy: private-local/no-auto-send", shown.stdout)

    def test_relay_artifacts_returns_metadata_only_and_rejects_unknown_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_relay("relay", "task", "init", "Artifact Adapter Smoke", base_dir=base, json_mode=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            run_id = json.loads(created.stdout)["run_id"]
            run_dir = base / "runs" / run_id
            (run_dir / "logs" / "private.log").write_text("PRIVATE_CONTENT_SHOULD_NOT_APPEAR", encoding="utf-8")

            artifacts = self.run_relay("relay", "artifacts", run_id, base_dir=base, json_mode=True)
            self.assertEqual(artifacts.returncode, 0, artifacts.stderr)
            payload = json.loads(artifacts.stdout)
            self.assertEqual(payload["command"], "artifacts")
            self.assertEqual(payload["artifacts"]["delivery"], "metadata-only")
            self.assertNotIn("PRIVATE_CONTENT_SHOULD_NOT_APPEAR", artifacts.stdout)

            bad = self.run_relay("relay", "send", "artifacts", run_id, base_dir=base, json_mode=True)
            self.assertNotEqual(bad.returncode, 0)
            error_payload = json.loads(bad.stdout)
            self.assertEqual(error_payload["status"], "failed")
            self.assertEqual(error_payload["failed_gate"], "unknown_relay_command")


if __name__ == "__main__":
    unittest.main()
