#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from chip_relay.protection import load_default_rule_pack

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"


class ProtectionEndToEndTests(unittest.TestCase):
    def run_cli(self, *args: str, base: pathlib.Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run([str(SCRIPT), "--json", *args], cwd=ROOT, env=env, text=True, capture_output=True)

    def new_run(self, base: pathlib.Path, title: str) -> tuple[str, pathlib.Path]:
        created = self.run_cli("task", "init", title, base=base)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def add_json(self, base: pathlib.Path, name: str, payload: dict[str, object]) -> pathlib.Path:
        path = base / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_verified_passive_run_emits_metadata_only_diagnosis_offline(self) -> None:
        sentinel = "SENTINEL_E2E_PRIVATE_704"
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.new_run(base, "offline passive protection fixture")
            network = self.add_json(
                base,
                "passive-network.json",
                {
                    "url": f"https://geo.captcha-delivery.com/captcha?token={sentinel}",
                    "status": 403,
                    "request_headers": {"Cookie": f"datadome={sentinel}"},
                    "response_headers": {"x-datadome-cid": sentinel},
                },
            )
            page = self.add_json(
                base,
                "passive-page.json",
                {"final_url": "https://example.test/challenge", "status": 403, "title_classification": "challenge"},
            )
            verified = self.run_cli("task", "verify", run_id, base=base)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["status"], "verified")
            for args in (
                ("task", "network", run_id, "add", "--json-file", str(network)),
                ("task", "protection", run_id, "add", "--json-file", str(page)),
                ("task", "protection", run_id, "diagnose"),
            ):
                result = self.run_cli(*args, base=base)
                self.assertEqual(result.returncode, 0, result.stderr)
            shown = self.run_cli("task", "show", run_id, base=base)
            payload = json.loads(shown.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["protection"]["provider"], "DataDome")
            diagnosis_text = (run_dir / "protection" / "diagnosis.json").read_text(encoding="utf-8")
            self.assertNotIn(sentinel, diagnosis_text + shown.stdout + verified.stdout)
            for forbidden in ("request_body", "response_body", "cookie_value", "raw_html", "storage_contents"):
                self.assertNotIn(forbidden, diagnosis_text)

    def test_instrumented_ambiguous_and_no_signal_fixtures_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)

            instrumented_id, _ = self.new_run(base, "offline instrumented fixture")
            observer = self.add_json(
                base,
                "observer.json",
                {
                    "schema": "chip-relay-fingerprint-observer-v1",
                    "mode": "instrumented",
                    "active": False,
                    "elapsed_ms": 10,
                    "counts": {"canvas.toDataURL": 2, "webgl.getParameter": 1},
                },
            )
            added = self.run_cli("task", "protection", instrumented_id, "add", "--json-file", str(observer), base=base)
            self.assertEqual(added.returncode, 0, added.stderr)
            instrumented = self.run_cli("task", "protection", instrumented_id, "diagnose", base=base)
            instrumented_payload = json.loads(instrumented.stdout)["diagnosis"]
            self.assertEqual(instrumented_payload["mode"], "instrumented")
            self.assertIn("instrumentation_notice", instrumented_payload)

            ambiguous_id, _ = self.new_run(base, "offline ambiguous fixture")
            ambiguous_network = self.add_json(
                base,
                "ambiguous.json",
                {
                    "url": "https://example.test/challenge",
                    "status": 403,
                    "response_headers": {"cf-mitigated": "challenge", "x-datadome-cid": "[REDACTED]"},
                },
            )
            self.assertEqual(
                self.run_cli("task", "network", ambiguous_id, "add", "--json-file", str(ambiguous_network), base=base).returncode,
                0,
            )
            ambiguous = self.run_cli("task", "protection", ambiguous_id, "diagnose", base=base)
            providers = [item["provider"] for item in json.loads(ambiguous.stdout)["diagnosis"]["protections"]]
            self.assertEqual(providers, ["Cloudflare", "DataDome"])

            empty_id, _ = self.new_run(base, "offline empty fixture")
            first = self.run_cli("task", "protection", empty_id, "diagnose", base=base)
            second = self.run_cli("task", "protection", empty_id, "diagnose", base=base)
            first_payload = json.loads(first.stdout)["diagnosis"]
            second_payload = json.loads(second.stdout)["diagnosis"]
            self.assertEqual(first_payload["protections"], [])
            self.assertEqual(first_payload["blocker"]["class"], "unknown")
            first_payload.pop("generated_at")
            second_payload.pop("generated_at")
            self.assertEqual(first_payload, second_payload)

    def test_documentation_and_clean_room_provenance_contract_are_complete(self) -> None:
        combined_docs = (ROOT / "README.md").read_text(encoding="utf-8") + (ROOT / "SKILL.md").read_text(encoding="utf-8")
        for text in (
            "task protection <run_id> add",
            "chip-relay-protection-diagnostic-v1",
            "passive",
            "instrumented",
            "Cloudflare",
            "DataDome",
            "no bypass",
        ):
            self.assertIn(text, combined_docs)

        pack = load_default_rule_pack()
        audit = json.loads((ROOT / "docs" / "protection-diagnostics-clean-room-audit.json").read_text(encoding="utf-8"))
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", workflow)
        self.assertEqual(audit["verdict"], "pass")
        self.assertEqual(audit["checks"]["exact_meaningful_line_matches"], 0)
        self.assertTrue(audit["checks"]["all_rules_have_independent_https_source"])
        self.assertGreaterEqual(len(pack["rules"]), 10)
        for rule in pack["rules"]:
            source = rule["source"]
            self.assertTrue(source["url"].startswith("https://"))
            self.assertNotIn("scrapfly", source["url"].lower())
            self.assertNotIn("antibot-detector", json.dumps(rule).lower())
            self.assertFalse(rule["id"].startswith("detect-"))

        production = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in [
                ROOT / "chip_relay" / "protection.py",
                ROOT / "chip_relay" / "protection_run.py",
                ROOT / "chip_relay" / "assets" / "protection-observer.js",
                ROOT / "chip_relay" / "rules" / "protections-v1.json",
            ]
        ).lower()
        self.assertNotIn("scrapfly", production)
        self.assertNotIn("antibot-detector", production)
        self.assertNotIn("nposl", production)


if __name__ == "__main__":
    unittest.main()
