#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from unittest import mock

import chip_relay
import chip_relay.protection_run as protection_run_module
from chip_relay.config import RelayConfig
from chip_relay.network import load_observations, record_observation, sanitize_observation
from chip_relay.protection import (
    diagnose_signals,
    fingerprint_observer_source,
    load_default_rule_pack,
    record_page_signals,
    sanitize_observer_snapshot,
    sanitize_page_signals,
    validate_rule_pack,
)
from chip_relay.protection_run import classify_blocker, diagnose_run, protection_summary
from chip_relay.verifier import verify_run
from chip_relay.workspace import (
    begin_execution_attempt,
    bound_attempt_id,
    execution_run_lock,
    init_run,
    load_manifest,
    update_execution_attempt,
    update_manifest,
    write_manifest,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "protection-rules-v1.json"


def config_for(base: pathlib.Path) -> RelayConfig:
    return RelayConfig(
        base_dir=base,
        runs_dir=base / "runs",
        recipes_dir=base / "recipes",
        host="127.0.0.1",
        port=18800,
        cdp_url="http://127.0.0.1:18800",
        profile="default",
        profile_dir=base / "profiles" / "default",
        proxy=None,
        upload_allowed_dirs=None,
    )


class ProtectionReviewRegressionTests(unittest.TestCase):
    def test_catastrophic_ambiguous_regex_is_rejected(self) -> None:
        pack = {
            "schema": "chip-relay-protection-rules-v1",
            "revision": "probe",
            "rules": [
                {
                    "id": "vendor.probe",
                    "provider": "Vendor",
                    "category": "anti_bot",
                    "source": {"title": "Source", "url": "https://example.com/source"},
                    "signals": [
                        {"method": "page_marker", "pattern": "^(a|aa)+$", "weight": 90, "strength": "strong"}
                    ],
                }
            ],
        }
        for unsafe_pattern in (
            "^(a|aa)+$",
            "^(a|aa){100}$",
            "^a{1000000}$",
            "^a{999999999999999999999999}$",
            "^((a|aa)){40}$",
            "^((a+)){40}$",
        ):
            pack["rules"][0]["signals"][0]["pattern"] = unsafe_pattern
            with self.subTest(pattern=unsafe_pattern), self.assertRaisesRegex(ValueError, "unsafe_rule_pattern"):
                validate_rule_pack(pack)

    def test_rule_pack_schema_and_public_source_url_are_strict(self) -> None:
        pack = {
            "schema": "chip-relay-protection-rules-v1",
            "revision": "strict",
            "rules": [{
                "id": "vendor.strict",
                "provider": "Vendor",
                "category": "anti_bot",
                "source": {"title": "Public source", "url": "https://example.test/source"},
                "signals": [{"method": "header_name", "pattern": "^x-vendor$", "weight": 80, "strength": "strong"}],
            }],
        }
        for location in ("pack", "rule", "source", "signal"):
            candidate = json.loads(json.dumps(pack))
            target = {
                "pack": candidate,
                "rule": candidate["rules"][0],
                "source": candidate["rules"][0]["source"],
                "signal": candidate["rules"][0]["signals"][0],
            }[location]
            target["unexpected"] = "private"
            with self.subTest(location=location), self.assertRaises(ValueError):
                validate_rule_pack(candidate)
        for url in (
            "http://example.test/source",
            "https://user:password@example.test/source",
            "https://example.test:8443/source",
            "https://example.test/source?token=private",
            "https://example.test/source#private",
            "https://127.0.0.1/source",
            "https://localhost/source",
        ):
            candidate = json.loads(json.dumps(pack))
            candidate["rules"][0]["source"]["url"] = url
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "invalid_rule_source_url"):
                validate_rule_pack(candidate)

    def test_one_physical_observation_scores_once(self) -> None:
        pack = {
            "schema": "chip-relay-protection-rules-v1",
            "revision": "probe",
            "rules": [
                {
                    "id": "vendor.probe",
                    "provider": "Vendor",
                    "category": "anti_bot",
                    "source": {"title": "Source", "url": "https://example.com/source"},
                    "signals": [
                        {"method": "header_name", "pattern": "^x-vendor", "weight": 60, "strength": "medium"},
                        {"method": "header_name", "pattern": "vendor$", "weight": 50, "strength": "strong"},
                    ],
                }
            ],
        }
        result = diagnose_signals({"header_names": ["x-vendor"]}, rule_pack=pack)
        self.assertEqual(len(result["protections"]), 1)
        self.assertEqual(len(result["protections"][0]["evidence"]), 1)
        self.assertLessEqual(result["protections"][0]["confidence"], 60)

    def test_passive_captcha_widget_on_normal_page_is_not_manual_blocker(self) -> None:
        blocker = classify_blocker(
            {"statuses": [200], "title_classifications": ["normal"], "page_markers": []},
            {"protections": [{"provider": "reCAPTCHA", "category": "captcha", "confidence": 80}]},
        )
        self.assertNotEqual(blocker["class"], "manual_captcha")

    def test_diagnosis_becomes_not_current_after_new_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            record_page_signals(run_dir, {"status": 200})
            diagnose_run(run_dir)
            self.assertEqual(protection_summary(run_dir)["status"], "diagnosed")
            record_page_signals(run_dir, {"status": 429, "title_classification": "rate_limited"})
            self.assertIn(protection_summary(run_dir)["status"], {"stale", "not_diagnosed"})

    def test_verify_result_and_artifact_include_compact_protection_feedback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp) / "base"
            created = init_run(config_for(base), "Verify protection feedback", template="placeholder")
            run_dir = created.run_dir
            final = run_dir / "scripts" / "final.py"
            final.write_text(
                textwrap.dedent(
                    """
                    import json
                    import pathlib
                    from chip_relay.network import record_observation
                    root = pathlib.Path(__file__).resolve().parents[1]
                    record_observation(root, {"url": "https://example.test/", "response_headers": {"Set-Cookie": "datadome=value"}, "status": 403})
                    (root / "logs" / "final.log").write_text("ok\\n", encoding="utf-8")
                    (root / "results" / "result.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
                    """
                ),
                encoding="utf-8",
            )
            result = verify_run(run_dir).as_dict()
            self.assertEqual(result["protection"]["provider"], "DataDome")
            artifact = json.loads((run_dir / "verification" / "verify-result.json").read_text(encoding="utf-8"))
            self.assertEqual(artifact["protection"]["provider"], "DataDome")
            self.assertNotIn("evidence", artifact["protection"])

    def test_network_schema_drops_polymorphic_values_and_all_header_values(self) -> None:
        sentinel = "SENTINEL_PRIVATE_9f3f"
        safe = sanitize_observation(
            {
                "url": f"https://example.com/reset/{sentinel}?token={sentinel}",
                "method": {"private": sentinel},
                "status": {"raw_dom": sentinel},
                "resource_type": {"storage": sentinel},
                "request_id": sentinel,
                "captured_at": sentinel,
                "headers": {"X-Amz-Security-Token": sentinel, "Content-Type": sentinel},
            }
        )
        rendered = json.dumps(safe, sort_keys=True)
        self.assertNotIn(sentinel, rendered)
        self.assertIsNone(safe["status"])
        self.assertEqual(set(safe["request_headers"].values()), {"[REDACTED]"})

    def test_url_matching_ignores_query_and_evidence_is_irreversibly_keyed(self) -> None:
        false_result = diagnose_signals(
            {"urls": ["https://example.test/?next=https://challenges.cloudflare.com/turnstile"]}
        )
        self.assertEqual(false_result["protections"], [])
        sentinel = "SENTINEL_PATH_SECRET_9f3f"
        result = diagnose_signals(
            {"urls": [f"https://challenges.cloudflare.com/reset/{sentinel}?token=query-secret"]}
        )
        rendered = json.dumps(result)
        self.assertNotIn(sentinel, rendered)
        self.assertNotIn("query-secret", rendered)
        self.assertNotIn("challenges.cloudflare.com", rendered)
        self.assertRegex(result["protections"][0]["evidence"][0]["key"], r"^sha256:[0-9a-f]{16}$")

    def test_forged_diagnosis_is_never_echoed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            protection = run_dir / "protection"
            protection.mkdir(parents=True)
            sentinel = "SENTINEL_FORGED_PRIVATE_9f3f"
            (protection / "diagnosis.json").write_text(
                json.dumps(
                    {
                        "schema": "chip-relay-protection-diagnosis-v1",
                        "provider": sentinel,
                        "protections": [{"provider": sentinel, "evidence": [sentinel]}],
                        "blocker": {"class": sentinel, "next_tests": [sentinel]},
                    }
                ),
                encoding="utf-8",
            )
            rendered = json.dumps(protection_summary(run_dir))
            self.assertNotIn(sentinel, rendered)
            self.assertIn(protection_summary(run_dir)["status"], {"stale", "not_diagnosed"})

    def test_every_shipped_rule_has_positive_and_negative_fixture(self) -> None:
        pack = load_default_rule_pack()
        fixtures = json.loads(FIXTURES.read_text(encoding="utf-8"))
        self.assertEqual(set(fixtures), {rule["id"] for rule in pack["rules"]})
        for rule in pack["rules"]:
            case = fixtures[rule["id"]]
            positive = diagnose_signals(case["positive"], rule_pack=pack)
            self.assertIn(rule["id"], {item["rule_id"] for item in positive["protections"]}, rule["id"])
            negative = diagnose_signals(case["negative"], rule_pack=pack)
            self.assertNotIn(rule["id"], {item["rule_id"] for item in negative["protections"]}, rule["id"])

    def test_observer_restores_wrappers_when_snapshot_publication_fails(self) -> None:
        fixture = r'''
globalThis.setTimeout = () => 1;
class HTMLCanvasElement { toDataURL() { return "original"; } }
Object.assign(globalThis, {HTMLCanvasElement});
const original = HTMLCanvasElement.prototype.toDataURL;
Object.preventExtensions(globalThis);
'''
        calls = r'''
process.stdout.write(JSON.stringify({restored: HTMLCanvasElement.prototype.toDataURL === original}));
'''
        completed = subprocess.run(
            ["node", "-"],
            input=fixture + fingerprint_observer_source() + calls,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertTrue(json.loads(completed.stdout)["restored"])

    def test_malformed_urls_never_survive_sanitization(self) -> None:
        sentinel = "SENTINEL_PRIVATE_7e21"
        malformed = f"https://[invalid/reset/{sentinel}?token={sentinel}#fragment-{sentinel}"
        network = sanitize_observation({"url": malformed})
        page = sanitize_page_signals({"final_url": malformed})
        self.assertNotIn(sentinel, json.dumps(network))
        self.assertNotIn(sentinel, json.dumps(page))

    def test_base_v1_network_rows_are_migrated_in_memory(self) -> None:
        sentinel = "SENTINEL_OLD_HEADER_9f3f"
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            path = run_dir / "network" / "observations.jsonl"
            path.parent.mkdir(parents=True)
            old_row = {
                "schema": "chip-relay-network-observation-v1",
                "captured_at": "2026-01-02T03:04:05Z",
                "request_id": "legacy-private-id",
                "url": "https://example.test/api/account?view=private",
                "method": "GET",
                "status": 200,
                "resource_type": None,
                "request_headers": {"x-safe": sentinel},
                "response_headers": {},
                "request_body": {"present": False, "bytes": 0, "policy": "omitted"},
                "response_body": {"present": False, "bytes": 0, "policy": "omitted"},
                "sensitivity": "private-local",
            }
            path.write_text(json.dumps(old_row) + "\n", encoding="utf-8")
            rows = load_observations(run_dir)
            self.assertEqual(len(rows), 1)
            self.assertNotIn(sentinel, json.dumps(rows))
            self.assertEqual(rows[0]["request_headers"]["x-safe"], "[REDACTED]")

    def test_network_symlink_and_malformed_record_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_dir = base / "run"
            network = run_dir / "network"
            network.mkdir(parents=True)
            outside = base / "outside.jsonl"
            outside.write_text("outside\n", encoding="utf-8")
            (network / "observations.jsonl").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe_network_path"):
                record_observation(run_dir, {"url": "https://example.test/"})
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            with self.assertRaisesRegex(ValueError, "unsafe_network_path"):
                load_observations(run_dir)

            (network / "observations.jsonl").unlink()
            (network / "observations.jsonl").write_text("{bad json}\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed_network_observation"):
                load_observations(run_dir)

    def test_fifo_json_input_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fifo = pathlib.Path(tmp) / "input.json"
            os.mkfifo(fifo)
            probe = (
                "from chip_relay.protection import read_bounded_json_object; "
                f"read_bounded_json_object({str(fifo)!r})"
            )
            completed = subprocess.run(
                ["python3", "-c", probe],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=1,
            )
            self.assertNotEqual(completed.returncode, 0)

    def test_attempt_generation_excludes_old_blockers_and_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "attempt freshness")
            record_page_signals(
                workspace.run_dir,
                {"status": 429, "title_classification": "rate_limited", "page_markers": ["cf-turnstile"]},
            )
            self.assertEqual(diagnose_run(workspace.run_dir)["blocker"]["class"], "rate_limit")
            begin_execution_attempt(
                workspace.run_dir,
                load_manifest(workspace.run_dir),
                source="test",
            )
            self.assertNotEqual(protection_summary(workspace.run_dir)["status"], "diagnosed")
            record_page_signals(
                workspace.run_dir,
                {"status": 200, "title_classification": "normal"},
            )
            with self.assertRaisesRegex(ValueError, "execution_attempt_in_progress"):
                diagnose_run(workspace.run_dir)
            manifest = load_manifest(workspace.run_dir)
            update_execution_attempt(
                workspace.run_dir,
                str(manifest["execution"]["attempt_id"]),
                lambda authoritative: None,
                phase="completed",
            )
            refreshed = diagnose_run(workspace.run_dir)
            self.assertNotEqual(refreshed["blocker"]["class"], "rate_limit")
            self.assertEqual(refreshed["signals_summary"]["status_codes"], [200])

    def test_diagnosis_snapshot_cannot_cross_into_a_running_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "diagnosis snapshot")
            record_page_signals(workspace.run_dir, {"status": 200, "title_classification": "normal"})
            original = protection_run_module.aggregate_run_signals
            aggregate_entered = threading.Event()
            allow_aggregate = threading.Event()
            begin_entered = threading.Event()
            begin_finished = threading.Event()

            def delayed_aggregate(run_dir: pathlib.Path):
                aggregate_entered.set()
                self.assertTrue(allow_aggregate.wait(2))
                return original(run_dir)

            def begin_attempt():
                begin_entered.set()
                result = begin_execution_attempt(
                    workspace.run_dir,
                    load_manifest(workspace.run_dir),
                    source="race-test",
                )
                begin_finished.set()
                return result

            with mock.patch.object(protection_run_module, "aggregate_run_signals", delayed_aggregate):
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    diagnosis_future = pool.submit(diagnose_run, workspace.run_dir)
                    self.assertTrue(aggregate_entered.wait(2))
                    begin_future = pool.submit(begin_attempt)
                    self.assertTrue(begin_entered.wait(2))
                    self.assertFalse(begin_finished.wait(0.05))
                    allow_aggregate.set()
                    diagnosis = diagnosis_future.result(timeout=2)
                    begun = begin_future.result(timeout=2)
            self.assertEqual(diagnosis["attempt_marker"]["attempt_id"], "attempt-000000000000")
            self.assertEqual(begun["execution"]["attempt_id"], "attempt-000000000001")
            self.assertNotEqual(protection_summary(workspace.run_dir)["status"], "diagnosed")

    def test_blocker_guidance_requires_same_observation_correlation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "correlation")
            record_observation(
                workspace.run_dir,
                {"url": "https://vendor.test/ok", "status": 200, "response_headers": {"x-datadome-cid": "value"}},
            )
            record_observation(
                workspace.run_dir,
                {"url": "https://unrelated.test/denied", "status": 403},
            )
            diagnosis = diagnose_run(workspace.run_dir)
            self.assertEqual(diagnosis["protections"][0]["provider"], "DataDome")
            self.assertEqual(diagnosis["blocker"]["class"], "unknown")

    def test_rate_limit_requires_same_row_status_and_provider_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            title_only = init_run(config_for(base), "title only")
            record_page_signals(title_only.run_dir, {"title_classification": "rate_limited"})
            self.assertEqual(diagnose_run(title_only.run_dir)["blocker"]["class"], "unknown")

            status_only = init_run(config_for(base), "status only")
            record_observation(status_only.run_dir, {"url": "https://public.test/wait", "status": 429})
            self.assertEqual(diagnose_run(status_only.run_dir)["blocker"]["class"], "unknown")

            correlated = init_run(config_for(base), "correlated rate limit")
            record_observation(
                correlated.run_dir,
                {
                    "url": "https://public.test/wait",
                    "status": 429,
                    "response_headers": {"x-datadome-cid": "opaque"},
                },
            )
            self.assertEqual(diagnose_run(correlated.run_dir)["blocker"]["class"], "rate_limit")

    def test_manifest_write_does_not_follow_predictable_temp_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "manifest symlink")
            outside = pathlib.Path(tmp) / "outside.json"
            outside.write_text("outside\n", encoding="utf-8")
            (workspace.run_dir / ".manifest.json.tmp").symlink_to(outside)
            begin_execution_attempt(workspace.run_dir, load_manifest(workspace.run_dir), source="test")
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            self.assertEqual(load_manifest(workspace.run_dir)["execution"]["generation"], 1)
            manifest_path = workspace.run_dir / "manifest.json"
            manifest_path.unlink()
            manifest_path.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe_manifest_path"):
                load_manifest(workspace.run_dir)
            write_manifest(workspace.run_dir, workspace.manifest)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")
            self.assertFalse(manifest_path.is_symlink())

    def test_manifest_and_execution_locks_reject_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "lock symlinks")
            outside = pathlib.Path(tmp) / "outside.lock"
            outside.write_text("outside\n", encoding="utf-8")
            manifest_lock = workspace.run_dir / ".manifest.lock"
            manifest_lock.unlink()
            manifest_lock.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe_manifest_lock"):
                begin_execution_attempt(workspace.run_dir, load_manifest(workspace.run_dir), source="test")
            manifest_lock.unlink()
            execution_lock = workspace.run_dir / ".execution.lock"
            execution_lock.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "unsafe_execution_lock"):
                verify_run(workspace.run_dir)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside\n")

    @unittest.skipUnless(sys.platform.startswith("linux"), "uses Linux abstract-socket lock authority")
    def test_lock_path_replacement_cannot_bypass_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "replacement safe locks")

            execution_started = threading.Event()
            execution_release = threading.Event()
            execution_contender_entered = threading.Event()

            def hold_execution() -> None:
                with execution_run_lock(workspace.run_dir):
                    execution_started.set()
                    self.assertTrue(execution_release.wait(2))

            def contend_execution() -> None:
                with execution_run_lock(workspace.run_dir):
                    execution_contender_entered.set()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                holder = pool.submit(hold_execution)
                self.assertTrue(execution_started.wait(2))
                (workspace.run_dir / ".execution.lock").unlink()
                contender = pool.submit(contend_execution)
                self.assertFalse(execution_contender_entered.wait(0.05))
                execution_release.set()
                holder.result(timeout=2)
                contender.result(timeout=2)
            self.assertTrue(execution_contender_entered.is_set())

            manifest_started = threading.Event()
            manifest_release = threading.Event()
            manifest_contender_entered = threading.Event()

            def blocking_update(_: dict[str, object]) -> None:
                manifest_started.set()
                self.assertTrue(manifest_release.wait(2))

            def contender_update(_: dict[str, object]) -> None:
                manifest_contender_entered.set()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                holder = pool.submit(update_manifest, workspace.run_dir, blocking_update)
                self.assertTrue(manifest_started.wait(2))
                (workspace.run_dir / ".manifest.lock").unlink()
                contender = pool.submit(update_manifest, workspace.run_dir, contender_update)
                self.assertFalse(manifest_contender_entered.wait(0.05))
                manifest_release.set()
                holder.result(timeout=2)
                contender.result(timeout=2)
            self.assertTrue(manifest_contender_entered.is_set())

    def test_malformed_execution_state_cannot_reissue_or_complete_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "malformed execution")
            first = begin_execution_attempt(workspace.run_dir, load_manifest(workspace.run_dir), source="test")
            token = str(first["execution"]["attempt_id"])
            update_execution_attempt(workspace.run_dir, token, lambda manifest: None, phase="completed")
            with self.assertRaisesRegex(ValueError, "execution_attempt_not_running"):
                update_execution_attempt(workspace.run_dir, token, lambda manifest: None, phase="completed")
            corrupted = load_manifest(workspace.run_dir)
            corrupted["execution"]["generation"] = "broken"
            write_manifest(workspace.run_dir, corrupted)
            with self.assertRaisesRegex(ValueError, "invalid_execution_state"):
                begin_execution_attempt(workspace.run_dir, corrupted, source="test")
            with self.assertRaisesRegex(ValueError, "invalid_execution_state"):
                update_execution_attempt(workspace.run_dir, token, lambda manifest: None, phase="completed")

            legacy = load_manifest(workspace.run_dir)
            legacy.pop("execution", None)
            write_manifest(workspace.run_dir, legacy)
            migrated = begin_execution_attempt(workspace.run_dir, legacy, source="legacy-test")
            self.assertEqual(migrated["execution"]["attempt_id"], "attempt-000000000001")

    def test_concurrent_attempt_allocation_and_completion_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "concurrent attempts")
            stale_manifest = load_manifest(workspace.run_dir)

            def allocate(_: int):
                return begin_execution_attempt(workspace.run_dir, stale_manifest, source="concurrency-test")

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                attempts = list(pool.map(allocate, range(8)))
            generations = sorted(int(item["execution"]["generation"]) for item in attempts)
            self.assertEqual(generations, list(range(1, 9)))
            current = load_manifest(workspace.run_dir)
            self.assertEqual(current["execution"]["generation"], 8)
            stale_attempt_id = min(
                str(item["execution"]["attempt_id"])
                for item in attempts
            )
            with self.assertRaisesRegex(ValueError, "stale_execution_attempt"):
                update_execution_attempt(workspace.run_dir, stale_attempt_id, lambda manifest: None, phase="failed")
            previous = os.environ.get("CHIP_RELAY_ATTEMPT_ID")
            os.environ["CHIP_RELAY_ATTEMPT_ID"] = stale_attempt_id
            try:
                with self.assertRaisesRegex(ValueError, "stale_execution_attempt"):
                    bound_attempt_id(workspace.run_dir)
            finally:
                if previous is None:
                    os.environ.pop("CHIP_RELAY_ATTEMPT_ID", None)
                else:
                    os.environ["CHIP_RELAY_ATTEMPT_ID"] = previous

    def test_concurrent_verify_calls_serialize_whole_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "concurrent verify")
            final = workspace.run_dir / "scripts" / "final.py"
            final.write_text(
                textwrap.dedent(
                    """
                    import json
                    import pathlib
                    import time
                    root = pathlib.Path(__file__).resolve().parents[1]
                    time.sleep(0.1)
                    (root / "logs" / "final.log").write_text("ok\\n", encoding="utf-8")
                    (root / "results" / "result.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
                    """
                ),
                encoding="utf-8",
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: verify_run(workspace.run_dir).status, range(2)))
            self.assertEqual(results, ["verified", "verified"])
            manifest = load_manifest(workspace.run_dir)
            self.assertEqual(manifest["execution"]["generation"], 2)
            self.assertEqual(manifest["execution"]["phase"], "completed")

    def test_compile_failure_starts_new_attempt_and_drops_old_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "compile failure")
            record_page_signals(
                workspace.run_dir,
                {"status": 429, "title_classification": "rate_limited"},
            )
            (workspace.run_dir / "scripts" / "final.py").write_text("def broken(:\n", encoding="utf-8")
            result = verify_run(workspace.run_dir).as_dict()
            manifest = load_manifest(workspace.run_dir)
            self.assertEqual(result["failed_gate"], "final_script_compile")
            self.assertEqual(manifest["execution"]["generation"], 1)
            self.assertEqual(manifest["execution"]["phase"], "failed")
            self.assertNotEqual(result["protection"]["blocker_class"], "rate_limit")

    def test_manifest_projection_and_evidence_keys_cannot_echo_private_values(self) -> None:
        sentinel = "SENTINEL_POLYMORPHIC_PRIVATE_9f3f"
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "manifest privacy")
            manifest = load_manifest(workspace.run_dir)
            manifest["status"] = {"private": sentinel}
            manifest["updated_at"] = {"private": sentinel}
            manifest["verification"]["last_result"] = {
                "status": {"private": sentinel},
                "failed_gate": [sentinel],
            }
            (workspace.run_dir / "manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            rendered = json.dumps(diagnose_run(workspace.run_dir))
            self.assertNotIn(sentinel, rendered)

        pack = {
            "schema": "chip-relay-protection-rules-v1",
            "revision": "probe",
            "rules": [{
                "id": "vendor.probe",
                "provider": "Vendor",
                "category": "anti_bot",
                "source": {"title": "Source", "url": "https://example.test/source"},
                "signals": [{
                    "method": "header_name",
                    "pattern": "^x-f5-",
                    "weight": 80,
                    "strength": "strong",
                }],
            }],
        }
        rendered = json.dumps(
            diagnose_signals({"header_names": [f"x-f5-{sentinel}"]}, rule_pack=pack)
        )
        self.assertNotIn(sentinel, rendered)

    def test_ambiguous_provider_candidates_are_preserved_without_duplicate_scoring(self) -> None:
        rules = []
        for rule_id, provider in (("vendor.one", "One"), ("vendor.two", "Two")):
            rules.append({
                "id": rule_id,
                "provider": provider,
                "category": "anti_bot",
                "source": {"title": "Source", "url": "https://example.test/source"},
                "signals": [
                    {"method": "header_name", "pattern": "^x-shared$", "weight": 70, "strength": "strong"},
                    {"method": "header_name", "pattern": "shared", "weight": 60, "strength": "medium"},
                ],
            })
        result = diagnose_signals(
            {"header_names": ["x-shared"]},
            rule_pack={"schema": "chip-relay-protection-rules-v1", "revision": "probe", "rules": rules},
        )
        self.assertEqual({item["provider"] for item in result["protections"]}, {"One", "Two"})
        self.assertTrue(all(len(item["evidence"]) == 1 for item in result["protections"]))

    def test_profile_cookie_prefixes_and_observer_snapshot_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = init_run(config_for(pathlib.Path(tmp)), "cookie prefix")
            record_observation(
                workspace.run_dir,
                {
                    "url": "https://example.test/",
                    "status": 403,
                    "response_headers": {"Set-Cookie": "visid_incap_456=value"},
                },
            )
            self.assertEqual(diagnose_run(workspace.run_dir)["blocker"]["class"], "likely_profile_state")
        blocker = classify_blocker(
            {
                "statuses": [403],
                "cookie_names": ["visid_incap_456"],
                "title_classifications": [],
                "correlated_blockers": {"likely_profile_state": True},
            },
            [{"provider": "Imperva", "category": "anti_bot", "confidence": 90}],
        )
        self.assertEqual(blocker["class"], "likely_profile_state")
        valid = {
            "schema": "chip-relay-fingerprint-observer-v1",
            "mode": "instrumented",
            "active": True,
            "elapsed_ms": 10,
            "counts": {},
        }
        for field, value in (("mode", "passive"), ("active", "yes"), ("elapsed_ms", [])):
            invalid = {**valid, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError):
                sanitize_observer_snapshot(invalid)

    def test_provenance_receipt_covers_full_feature_surface(self) -> None:
        receipt = json.loads(
            (ROOT / "docs" / "protection-diagnostics-clean-room-audit.json").read_text(
                encoding="utf-8"
            )
        )
        covered = set(receipt["audited_files"])
        for required in (
            "chip_relay/cli.py",
            "chip_relay/network.py",
            "chip_relay/verifier.py",
            "tests/test_protection_review_regressions.py",
            "README.md",
        ):
            self.assertIn(required, covered)
        self.assertEqual(receipt["checks"]["runtime_dependency_on_upstream"], False)

    def test_documented_rule_ids_and_release_version_match_sources(self) -> None:
        pack = load_default_rule_pack()
        documentation = (ROOT / "docs" / "protection-diagnostics-sources.md").read_text(encoding="utf-8")
        register = documentation.split("## Shipped source register", 1)[1]
        documented = {
            match.group(1)
            for match in re.finditer(r"^- `([a-z0-9._-]+)` ->", register, flags=re.MULTILINE)
        }
        self.assertEqual(documented, {rule["id"] for rule in pack["rules"]})
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn(f"version: {chip_relay.__version__}", skill)
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("unittest discover -s tests -p 'test_*.py'", workflow)
        self.assertIn("audit-protection-clean-room.py", workflow)


if __name__ == "__main__":
    unittest.main()
