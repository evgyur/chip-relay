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

import sys
sys.path.insert(0, str(ROOT))

from chip_relay.environment import cdp_binding
from chip_relay.network import record_observation, search_observations
from chip_relay.proxy import merge_proxy_server_arg, parse_proxy_config, redact_launch_arg
from chip_relay.uploads import validate_upload_paths


class StealthBrowserMcpAdoptionTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def create_run(self, base: pathlib.Path, title: str = "Adoption Smoke") -> tuple[str, pathlib.Path]:
        created = self.run_relay("task", "init", title, base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr + created.stdout)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def test_network_observer_records_metadata_and_redacts_sensitive_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            safe = record_observation(run_dir, {
                "url": "https://example.com/api?access_token=secret&x=1",
                "method": "post",
                "status": 200,
                "resource_type": "fetch",
                "request_headers": {"Authorization": "Bearer secret", "Cookie": "sid=secret", "Accept": "application/json"},
                "response_headers": {"Set-Cookie": "sid=secret"},
                "request_body": "PRIVATE_BODY",
                "response_body": "PRIVATE_RESPONSE",
            })
            self.assertEqual(safe["request_headers"]["Authorization"], "[REDACTED]")
            self.assertEqual(safe["request_headers"]["Cookie"], "[REDACTED]")
            self.assertNotIn("PRIVATE_BODY", json.dumps(safe))
            found = search_observations(run_dir, url_contains="example", method="POST")
            self.assertEqual(found["total"], 1)
            raw_file = (run_dir / "network" / "observations.jsonl").read_text(encoding="utf-8")
            self.assertNotIn("secret", raw_file)
            self.assertNotIn("PRIVATE_RESPONSE", raw_file)

    def test_network_search_filters_and_paginates_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            for idx, status in enumerate((200, 404, 200)):
                record_observation(run_dir, {
                    "url": f"https://example.com/api/item-{idx}?token=value-{idx}",
                    "method": "GET",
                    "status": status,
                    "resource_type": "fetch",
                })
            first_page = search_observations(run_dir, url_contains="/api/", status=200, limit=1)
            self.assertEqual(first_page["total"], 2)
            self.assertTrue(first_page["has_more"])
            second_page = search_observations(run_dir, url_contains="/api/", status=200, limit=1, offset=1)
            self.assertEqual(second_page["total"], 2)
            self.assertFalse(second_page["has_more"])
            self.assertNotEqual(first_page["results"][0]["url"], second_page["results"][0]["url"])
            self.assertNotIn("value-", json.dumps(first_page) + json.dumps(second_page))

    def test_task_network_cli_exports_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base)
            source = base / "request.json"
            source.write_text(json.dumps({"url": "https://example.com/?token=abc", "headers": {"Authorization": "Bearer abc"}, "body": "secret"}), encoding="utf-8")
            added = self.run_relay("task", "network", run_id, "add", "--json-file", str(source), base_dir=base, json_mode=True)
            self.assertEqual(added.returncode, 0, added.stderr + added.stdout)
            searched = self.run_relay("task", "network", run_id, "search", "--url", "example", base_dir=base, json_mode=True)
            self.assertEqual(searched.returncode, 0, searched.stderr)
            self.assertNotIn("Bearer abc", searched.stdout)
            exported = self.run_relay("task", "network", run_id, "export", base_dir=base, json_mode=True)
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertTrue((run_dir / "network" / "export.json").is_file())

    def test_init_script_cli_lists_names_and_hashes_and_template_loads_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, run_dir = self.create_run(base, "Init Script Smoke")
            script = base / "webdriver.js"
            script.write_text("Object.defineProperty(navigator, 'webdriver', {get: () => false});", encoding="utf-8")
            added = self.run_relay("task", "init-script", run_id, "add", "webdriver", "--file", str(script), base_dir=base, json_mode=True)
            self.assertEqual(added.returncode, 0, added.stderr + added.stdout)
            listed = self.run_relay("task", "init-script", run_id, "list", base_dir=base, json_mode=True)
            payload = json.loads(listed.stdout)
            self.assertEqual(payload["scripts"][0]["name"], "webdriver.js")
            self.assertIn("sha256", payload["scripts"][0])
            self.assertNotIn("Object.defineProperty", listed.stdout)
            final_text = (run_dir / "scripts" / "final.py").read_text(encoding="utf-8")
            self.assertIn("apply_init_scripts", final_text)

    def test_proxy_doctor_redacts_credentials_and_merge_keeps_single_arg(self) -> None:
        parsed = parse_proxy_config("http://user:pass@example.com:8080")
        self.assertEqual(parsed.server, "http://example.com:8080")
        args = merge_proxy_server_arg(["--foo", "--proxy-server=http://old:1"], parsed.server)
        self.assertEqual(args.count("--proxy-server=http://example.com:8080"), 1)
        self.assertNotIn("pass", redact_launch_arg("--proxy-server=http://user:pass@example.com:8080"))
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            checked = self.run_relay("doctor", "webwright", base_dir=base, json_mode=True, extra_env={"CHIP_RELAY_PROXY": "http://user:pass@example.com:8080"})
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
            self.assertNotIn("pass", checked.stdout)
            self.assertIn("proxy", json.loads(checked.stdout)["checks"])

    def test_proxy_invalid_errors_and_cdp_binding_is_exact_loopback_only(self) -> None:
        self.assertTrue(cdp_binding("http://localhost:18800")["ok"])
        self.assertTrue(cdp_binding("http://127.0.0.1:18800")["ok"])
        self.assertFalse(cdp_binding("http://localhost.example.com:18800")["ok"])
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            checked = self.run_relay("doctor", "webwright", base_dir=base, json_mode=True, extra_env={"CHIP_RELAY_PROXY": "http://user@example.com:8080"})
            self.assertNotEqual(checked.returncode, 0)
            payload = json.loads(checked.stdout)
            self.assertEqual(payload["status"], "failed")
            self.assertFalse(payload["checks"]["proxy"]["ok"])
            self.assertNotIn("user@example", checked.stdout)

    def test_shell_doctor_reports_proxy_redacted_without_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            checked = self.run_relay("doctor", base_dir=base, extra_env={"CHIP_RELAY_PROXY": "http://user:pass@example.com:8080"})
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
            self.assertIn("proxy:", checked.stdout)
            self.assertIn("example.com:8080", checked.stdout)
            self.assertNotIn("user", checked.stdout)
            self.assertNotIn("pass", checked.stdout)

    def test_cleanup_dry_run_and_execute_are_confined_to_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            profile = base / "profiles" / "orphan"
            profile.mkdir(parents=True)
            (base / "state.json").write_text(json.dumps({"pid": 99999999, "profileDir": str(profile)}), encoding="utf-8")
            dry = self.run_relay("cleanup", base_dir=base, json_mode=True)
            self.assertEqual(dry.returncode, 0, dry.stderr + dry.stdout)
            self.assertTrue(profile.exists())
            self.assertEqual(json.loads(dry.stdout)["mode"], "dry-run")
            executed = self.run_relay("cleanup", "--execute", base_dir=base, json_mode=True)
            self.assertEqual(executed.returncode, 0, executed.stderr + executed.stdout)
            self.assertFalse(profile.exists())

    def test_cleanup_blocks_outside_and_symlink_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp) / "base"
            outside = pathlib.Path(tmp) / "outside"
            base.mkdir(); outside.mkdir()
            outside_profile = outside / "profile"
            outside_profile.mkdir()
            (base / "state.json").write_text(json.dumps({"pid": 99999999, "profileDir": str(outside_profile)}), encoding="utf-8")
            blocked = self.run_relay("cleanup", base_dir=base, json_mode=True)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertEqual(json.loads(blocked.stdout)["status"], "blocked")
            self.assertTrue(outside_profile.exists())

            symlink_target = base / "profiles" / "target"
            symlink_target.mkdir(parents=True)
            symlink_profile = base / "profiles" / "linked"
            symlink_profile.symlink_to(symlink_target, target_is_directory=True)
            (base / "state.json").write_text(json.dumps({"pid": 99999999, "profileDir": str(symlink_profile)}), encoding="utf-8")
            symlink_blocked = self.run_relay("cleanup", base_dir=base, json_mode=True)
            self.assertNotEqual(symlink_blocked.returncode, 0)
            self.assertEqual(json.loads(symlink_blocked.stdout)["status"], "blocked")
            self.assertTrue(symlink_profile.is_symlink())

    def test_upload_allowlist_rejects_outside_relative_and_symlink_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            allowed = base / "allowed"
            outside = base / "outside"
            allowed.mkdir(); outside.mkdir()
            good = allowed / "file.txt"
            good.write_text("ok", encoding="utf-8")
            bad = outside / "file.txt"
            bad.write_text("no", encoding="utf-8")
            self.assertEqual(validate_upload_paths([str(good)], allowed_roots=[allowed]), [str(good.resolve())])
            with self.assertRaises(ValueError):
                validate_upload_paths(["relative.txt"], allowed_roots=[allowed])
            with self.assertRaises(ValueError):
                validate_upload_paths([str(bad)], allowed_roots=[allowed])
            link = allowed / "link.txt"
            link.symlink_to(good)
            with self.assertRaises(ValueError):
                validate_upload_paths([str(link)], allowed_roots=[allowed])

    def test_stealth_doctor_reports_diagnostics_not_guaranteed_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            sample = base / "sample.json"
            sample.write_text(json.dumps({
                "webdriver": False,
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome",
                "platform": "Win32",
                "languages": ["en-US", "en"],
                "timezone": "America/New_York",
                "webglVendor": "Google Inc.",
                "webglRenderer": "ANGLE",
                "challenge_passed": True,
            }), encoding="utf-8")
            checked = self.run_relay("stealth", "doctor", "--preset", "cf-sensitive", "--sample-json", str(sample), base_dir=base, json_mode=True)
            self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
            payload = json.loads(checked.stdout)
            self.assertEqual(payload["fingerprint"]["status"], "ok")
            self.assertEqual(payload["challenge"]["status"], "passed")
            self.assertEqual(payload["claim_policy"], "diagnostic-only/no-guaranteed-bypass")
            self.assertNotIn("98%", checked.stdout)


if __name__ == "__main__":
    unittest.main()
