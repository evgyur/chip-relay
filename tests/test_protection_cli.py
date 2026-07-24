#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from chip_relay.protection import classify_blocker

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"


class ProtectionCliTests(unittest.TestCase):
    def run_cli(self, *args: str, base_dir: pathlib.Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run([str(SCRIPT), "--json", *args], cwd=ROOT, env=env, text=True, capture_output=True)

    def create_run(self, base: pathlib.Path) -> tuple[str, pathlib.Path]:
        created = self.run_cli("task", "init", "Protection CLI fixture", base_dir=base)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def test_direct_cli_add_diagnose_show_and_context_are_metadata_only(self) -> None:
        sentinel = "SENTINEL_CLI_PRIVATE_VALUE_42"
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base)
            network_file = base / "network.json"
            network_file.write_text(
                json.dumps(
                    {
                        "url": f"https://geo.captcha-delivery.com/captcha?token={sentinel}",
                        "status": 403,
                        "request_headers": {"Cookie": f"datadome={sentinel}"},
                        "response_headers": {"x-datadome-cid": sentinel},
                    }
                ),
                encoding="utf-8",
            )
            page_file = base / "page.json"
            page_file.write_text(
                json.dumps(
                    {
                        "final_url": f"https://example.com/challenge?token={sentinel}",
                        "status": 403,
                        "title_classification": "challenge",
                        "page_markers": [],
                        "window_keys": [],
                    }
                ),
                encoding="utf-8",
            )

            network_added = self.run_cli("task", "network", run_id, "add", "--json-file", str(network_file), base_dir=base)
            self.assertEqual(network_added.returncode, 0, network_added.stderr)
            added = self.run_cli("task", "protection", run_id, "add", "--json-file", str(page_file), base_dir=base)
            self.assertEqual(added.returncode, 0, added.stderr)
            diagnosed = self.run_cli("task", "protection", run_id, "diagnose", base_dir=base)
            self.assertEqual(diagnosed.returncode, 0, diagnosed.stderr)
            payload = json.loads(diagnosed.stdout)
            self.assertEqual(payload["status"], "diagnosed")
            self.assertEqual(payload["diagnosis"]["protections"][0]["provider"], "DataDome")
            self.assertEqual(payload["diagnosis"]["blocker"]["class"], "likely_profile_state")
            self.assertEqual(payload["diagnosis"]["blocker"]["certainty"], "hypothesis")
            self.assertTrue(payload["diagnosis"]["blocker"]["next_tests"])

            shown = self.run_cli("task", "protection", run_id, "show", base_dir=base)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            task_shown = self.run_cli("task", "show", run_id, base_dir=base)
            self.assertEqual(task_shown.returncode, 0, task_shown.stderr)
            context = self.run_cli("task", "context", run_id, base_dir=base)
            self.assertEqual(context.returncode, 0, context.stderr)
            artifacts = self.run_cli("task", "artifacts", run_id, base_dir=base)
            self.assertEqual(artifacts.returncode, 0, artifacts.stderr)

            combined = diagnosed.stdout + shown.stdout + task_shown.stdout + context.stdout + artifacts.stdout
            self.assertNotIn(sentinel, combined)
            self.assertEqual(json.loads(task_shown.stdout)["protection"]["provider"], "DataDome")
            self.assertEqual(json.loads(context.stdout)["protection"]["blocker_class"], "likely_profile_state")
            self.assertIn("protection/diagnosis.json", [item["path"] for item in json.loads(artifacts.stdout)["artifacts"]])
            self.assertEqual((run_dir / "protection" / "diagnosis.json").stat().st_mode & 0o777, 0o600)

    def test_relay_adapter_exposes_protection_show_and_structured_usage_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base)
            diagnosed = self.run_cli("relay", "/relay", "task", "protection", run_id, "diagnose", base_dir=base)
            self.assertEqual(diagnosed.returncode, 0, diagnosed.stderr)
            shown = self.run_cli("relay", "/relay", "task", "protection", run_id, "show", base_dir=base)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            payload = json.loads(shown.stdout)
            self.assertEqual(payload["command"], "task.protection.show")
            self.assertEqual(payload["protection"]["blocker_class"], "unknown")

            bad = self.run_cli("relay", "/relay", "task", "protection", run_id, "add", base_dir=base)
            self.assertNotEqual(bad.returncode, 0)
            error = json.loads(bad.stdout)
            self.assertEqual(error["failed_gate"], "usage")
            self.assertEqual(error["command"], "task.protection")

    def test_blocker_guidance_distinguishes_bounded_hypotheses(self) -> None:
        captcha = [{"provider": "Turnstile", "category": "captcha", "confidence": 90}]
        anti_bot = [{"provider": "DataDome", "category": "anti_bot", "confidence": 90}]
        cases = [
            ({"correlated_blockers": {"manual_captcha": True}}, captcha, "manual_captcha"),
            ({"correlated_blockers": {"rate_limit": True}}, [], "rate_limit"),
            ({"correlated_blockers": {"fingerprint_inconsistency": True}}, [], "fingerprint_inconsistency"),
            ({"correlated_blockers": {"likely_profile_state": True}}, anti_bot, "likely_profile_state"),
            ({"correlated_blockers": {"likely_ip_reputation": True}}, anti_bot, "likely_ip_reputation"),
            ({"correlated_blockers": {}}, [], "unknown"),
        ]
        for signals, protections, expected in cases:
            with self.subTest(expected=expected):
                result = classify_blocker(signals, protections)
                self.assertEqual(result["class"], expected)
                self.assertEqual(result["certainty"], "hypothesis")
                self.assertTrue(result["next_tests"])
                self.assertNotIn("guaranteed", json.dumps(result).lower())


if __name__ == "__main__":
    unittest.main()
