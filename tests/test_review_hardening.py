#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))

from chip_relay.reports import _local_cdp_label

SCRIPT = ROOT / "scripts" / "chip-relay"


class ReviewHardeningTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def create_run(self, base: pathlib.Path, title: str = "Hardening Smoke") -> tuple[str, pathlib.Path]:
        created = self.run_relay("task", "init", title, base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def test_task_init_rejects_run_id_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            outside = base.parent / "outside"
            if outside.exists():
                shutil.rmtree(outside)
            created = self.run_relay("task", "init", "Traversal", "--id", "../../outside", base_dir=base, json_mode=True)
            self.assertNotEqual(created.returncode, 0)
            self.assertFalse(outside.exists())
            self.assertIn("invalid_run_id", created.stderr + created.stdout)

    def test_verify_rejects_stale_artifacts_after_final_script_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Stale Artifact Smoke")
            first = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            (run_dir / "scripts" / "final.py").write_text("raise SystemExit(0)\n", encoding="utf-8")

            second = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertNotEqual(second.returncode, 0)
            payload = json.loads(second.stdout)
            self.assertIn(payload["failed_gate"], {"final_log_missing", "required_artifact_missing"})

    def test_hygiene_blocks_cookie_profile_database_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Cookie Dump Smoke")
            (run_dir / "scripts" / "final.py").write_text(textwrap.dedent('''
                from pathlib import Path
                root = Path(__file__).resolve().parents[1]
                (root / "logs").mkdir(exist_ok=True)
                (root / "results").mkdir(exist_ok=True)
                (root / "logs" / "final.log").write_text("ok", encoding="utf-8")
                (root / "results" / "result.json").write_text("{}", encoding="utf-8")
                (root / "results" / "Cookies").write_bytes(b"SQLite format 3\\0cookie dump")
            '''), encoding="utf-8")

            verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertNotEqual(verified.returncode, 0)
            payload = json.loads(verified.stdout)
            self.assertEqual(payload["failed_gate"], "hygiene_scan")

    def test_hygiene_blocks_hidden_har_and_directory_symlink_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Hidden Artifact Smoke")
            external = base / "external-profile"
            external.mkdir()
            (run_dir / "scripts" / "final.py").write_text(textwrap.dedent(f'''
                from pathlib import Path
                root = Path(__file__).resolve().parents[1]
                (root / "logs").mkdir(exist_ok=True)
                (root / "results").mkdir(exist_ok=True)
                (root / "logs" / "final.log").write_text("ok", encoding="utf-8")
                (root / "results" / "result.json").write_text("{{}}", encoding="utf-8")
                (root / "results" / ".session.har").write_text("{{}}", encoding="utf-8")
                (root / "results" / "profile-link").symlink_to({str(external)!r}, target_is_directory=True)
            '''), encoding="utf-8")

            verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertNotEqual(verified.returncode, 0)
            payload = json.loads(verified.stdout)
            self.assertEqual(payload["failed_gate"], "hygiene_scan")

    def test_verify_log_redacts_secret_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Redacted Stdout Smoke")
            (run_dir / "scripts" / "final.py").write_text(textwrap.dedent('''
                from pathlib import Path
                root = Path(__file__).resolve().parents[1]
                (root / "logs").mkdir(exist_ok=True)
                (root / "results").mkdir(exist_ok=True)
                raw = "sentinel-token"
                print("Auth" + "orization: Bearer " + raw)
                (root / "logs" / "final.log").write_text("ok", encoding="utf-8")
                (root / "results" / "result.json").write_text("{}", encoding="utf-8")
            '''), encoding="utf-8")

            verified = self.run_relay("task", "verify", run_id, base_dir=base, json_mode=True)
            self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
            verify_log = (run_dir / "logs" / "verify.log").read_text(encoding="utf-8")
            self.assertNotIn("sk-testsecret", verify_log)
            self.assertIn("[REDACTED]", verify_log)

    def test_task_loop_missing_agent_returns_structured_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base, "Missing Agent Smoke")
            looped = self.run_relay("task", "loop", run_id, "--agent-command", "definitely-not-a-real-chip-relay-agent", base_dir=base, json_mode=True)
            self.assertNotEqual(looped.returncode, 0)
            self.assertEqual(looped.stderr, "")
            payload = json.loads(looped.stdout)
            self.assertEqual(payload["failed_gate"], "agent_command_not_found")

    def test_task_loop_supports_quoted_interpreter_agent_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base, "Quoted Agent Smoke")
            looped = self.run_relay("task", "loop", run_id, "--agent-command", "python3 scripts/chip-relay-agent-example", "--max-attempts", "1", base_dir=base, json_mode=True)
            self.assertEqual(looped.returncode, 0, looped.stderr + looped.stdout)
            self.assertEqual(json.loads(looped.stdout)["status"], "verified")

    def test_relay_loop_supports_quoted_full_agent_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base, "Relay Quoted Agent Smoke")
            looped = self.run_relay("relay", "/relay", "task", "loop", run_id, "--agent-command", "python3 scripts/chip-relay-agent-example", "--max-attempts", "1", base_dir=base, json_mode=True)
            self.assertEqual(looped.returncode, 0, looped.stderr + looped.stdout)
            self.assertEqual(json.loads(looped.stdout)["status"], "verified")

    def test_relay_loop_bad_integer_returns_structured_usage_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base, "Bad Integer Smoke")
            bad = self.run_relay("relay", "/relay", "task", "loop", run_id, "--agent-command", "scripts/chip-relay-agent-example", "--max-attempts", "nope", base_dir=base, json_mode=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertEqual(bad.stderr, "")
            payload = json.loads(bad.stdout)
            self.assertEqual(payload["failed_gate"], "usage")

    def test_unimplemented_verification_strength_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base, "Strength Smoke")
            result = self.run_relay("task", "verify", run_id, "--strength", "fresh-context", base_dir=base, json_mode=True)
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["failed_gate"], "verification_strength_not_implemented")

    def test_cdp_local_label_parses_hostname_exactly(self) -> None:
        self.assertEqual(_local_cdp_label("http://127.0.0.1:18800"), "local-only")
        self.assertEqual(_local_cdp_label("http://localhost:18800"), "local-only")
        self.assertEqual(_local_cdp_label("http://[::1]:18800"), "local-only")
        self.assertEqual(_local_cdp_label("https://localhost.evil.example"), "configured")
        self.assertEqual(_local_cdp_label("https://example.com/?next=localhost"), "configured")


if __name__ == "__main__":
    unittest.main()
