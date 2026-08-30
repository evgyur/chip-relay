from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"
sys.path.insert(0, str(ROOT))

from chip_relay.benchmark import (  # noqa: E402
    BenchmarkContractError,
    atomic_write_result,
    compare_results,
    gate_results,
    read_result,
    validate_result,
)
from chip_relay.config import RelayConfig  # noqa: E402
from chip_relay.relay_adapter import relay_response  # noqa: E402


def result(
    run_id: str,
    *,
    check_ok: bool = True,
    status: str = "passed",
    identity: str = "chromium",
    elapsed_ms: int = 25,
    suite_id: str = "chip-relay-local",
) -> dict:
    return {
        "schema": "chip-relay-stealth-benchmark-v1",
        "run_id": run_id,
        "suite_id": suite_id,
        "suite_version": "1",
        "started_at": "2026-08-30T00:00:00+00:00",
        "completed_at": "2026-08-30T00:00:01+00:00",
        "claim_policy": "diagnostic-only/no-guaranteed-bypass",
        "artifact_policy": "private-local/no-auto-send",
        "results": [
            {
                "identity": identity,
                "requested": identity,
                "resolved": identity,
                "status": "completed",
                "browser": {"browser": "Chromium/1", "protocol_version": "1.3"},
                "preset": "normal",
                "headless": True,
                "proxy_configured": False,
                "ephemeral_profile": True,
                "cases": [
                    {
                        "name": "clean",
                        "status": status,
                        "elapsed_ms": elapsed_ms,
                        "repeat": 1,
                        "fingerprint_checks": [{"name": "webdriver", "ok": check_ok}],
                        "fingerprint_snapshot_sha256": "0" * 64,
                    }
                ],
            }
        ],
    }


class BenchmarkContractTests(unittest.TestCase):
    def test_valid_result_round_trip_is_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "private" / "result.json"
            atomic_write_result(path, result("baseline"))
            self.assertEqual(read_result(path)["run_id"], "baseline")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o077, 0)

    def test_result_reader_rejects_symlink_oversize_and_incompatible_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "target.json"
            target.write_text(json.dumps(result("baseline")), encoding="utf-8")
            link = root / "result.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(BenchmarkContractError, "benchmark_result_symlink"):
                read_result(link)
            huge = root / "huge.json"
            huge.write_bytes(b"x" * 1_048_577)
            with self.assertRaisesRegex(BenchmarkContractError, "benchmark_result_too_large"):
                read_result(huge)
            bad = result("bad")
            bad["schema"] = "future"
            with self.assertRaisesRegex(BenchmarkContractError, "benchmark_schema_incompatible"):
                validate_result(bad)

    def test_compare_and_gate_pass_for_equivalent_candidate(self) -> None:
        baseline = result("baseline")
        candidate = result("candidate")
        compared = compare_results(baseline, candidate)
        self.assertEqual(compared["schema"], "chip-relay-stealth-comparison-v1")
        gated = gate_results(baseline, candidate)
        self.assertEqual(gated.status, "passed")
        self.assertIsNone(gated.failed_gate)

    def test_gate_fails_new_fingerprint_regression(self) -> None:
        gated = gate_results(result("baseline"), result("candidate", check_ok=False))
        self.assertEqual(gated.status, "failed")
        self.assertEqual(gated.failed_gate, "fingerprint_regression")
        self.assertEqual(gated.regressions[0]["check"], "webdriver")

    def test_gate_fails_candidate_added_false_check_and_case(self) -> None:
        baseline = result("baseline")
        added_check = result("candidate-check")
        added_check["results"][0]["cases"][0]["fingerprint_checks"].append(
            {"name": "new_signal", "ok": False}
        )
        check_gate = gate_results(baseline, added_check)
        self.assertEqual(check_gate.status, "failed")
        self.assertIn(
            ("clean", "new_signal"),
            {(item.get("case"), item.get("check")) for item in check_gate.regressions},
        )

        added_case = result("candidate-case")
        added_case["results"][0]["cases"].append(
            {
                "name": "new-case",
                "status": "passed",
                "elapsed_ms": 25,
                "repeat": 1,
                "fingerprint_checks": [{"name": "new_signal", "ok": False}],
                "fingerprint_snapshot_sha256": "1" * 64,
            }
        )
        case_gate = gate_results(baseline, added_case)
        self.assertEqual(case_gate.status, "failed")
        self.assertIn(
            ("new-case", "new_signal"),
            {(item.get("case"), item.get("check")) for item in case_gate.regressions},
        )

    def test_local_latency_gate_has_explicit_noise_budget(self) -> None:
        within_budget = gate_results(
            result("baseline", elapsed_ms=100),
            result("candidate", elapsed_ms=600),
        )
        self.assertEqual(within_budget.status, "passed")
        regression = gate_results(
            result("baseline", elapsed_ms=100),
            result("candidate", elapsed_ms=601),
        )
        self.assertEqual(regression.status, "failed")
        self.assertEqual(regression.failed_gate, "latency_regression")
        self.assertEqual(regression.regressions[0]["limit_ms"], 600)

        public = gate_results(
            result("baseline", elapsed_ms=100, suite_id="chip-relay-public-detectors"),
            result(
                "candidate",
                check_ok=False,
                status="blocked",
                elapsed_ms=10_000,
                suite_id="chip-relay-public-detectors",
            ),
        )
        self.assertEqual(public.status, "passed")

    def test_missing_fingerprint_check_is_coverage_regression(self) -> None:
        candidate = result("candidate")
        candidate["results"][0]["cases"][0]["fingerprint_checks"] = []
        gated = gate_results(result("baseline"), candidate)
        self.assertEqual(gated.status, "failed")
        self.assertEqual(gated.failed_gate, "coverage_regression")
        self.assertEqual(gated.regressions[0]["check"], "webdriver")

    def test_gate_fails_outcome_and_coverage_regressions(self) -> None:
        outcome = gate_results(result("baseline"), result("candidate", status="blocked"))
        self.assertEqual(outcome.failed_gate, "outcome_regression")
        manual = gate_results(
            result("baseline"), result("candidate", status="captcha/manual")
        )
        self.assertEqual(manual.failed_gate, "outcome_regression")
        candidate = result("candidate")
        candidate["results"] = []
        with self.assertRaisesRegex(BenchmarkContractError, "benchmark_results_required"):
            gate_results(result("baseline"), candidate)

    def test_suite_and_backend_duplicates_fail_closed(self) -> None:
        candidate = result("candidate")
        candidate["suite_version"] = "2"
        with self.assertRaisesRegex(BenchmarkContractError, "benchmark_suite_incompatible"):
            compare_results(result("baseline"), candidate)
        duplicate = result("duplicate")
        duplicate["results"].append(dict(duplicate["results"][0]))
        with self.assertRaisesRegex(BenchmarkContractError, "benchmark_backend_duplicate"):
            validate_result(duplicate)

    def test_cli_gate_returns_structured_nonzero_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            baseline = base / "baseline.json"
            candidate = base / "candidate.json"
            atomic_write_result(baseline, result("baseline"))
            atomic_write_result(candidate, result("candidate", check_ok=False))
            env = os.environ.copy()
            env["PYTHONPATH"] = str(ROOT)
            completed = subprocess.run(
                [str(SCRIPT), "--json", "stealth", "gate", "--baseline", str(baseline), "--candidate", str(candidate)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["failed_gate"], "fingerprint_regression")
            self.assertNotIn("Traceback", completed.stderr + completed.stdout)

    def test_relay_gate_exposes_only_structured_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            baseline = base / "baseline.json"
            candidate = base / "candidate.json"
            atomic_write_result(baseline, result("baseline"))
            atomic_write_result(candidate, result("candidate"))
            cfg = RelayConfig(
                base_dir=base,
                runs_dir=base / "runs",
                recipes_dir=base / "recipes",
                host="127.0.0.1",
                port=18800,
                cdp_url="http://127.0.0.1:18800",
                profile="default",
                profile_dir=base / "profile",
                proxy=None,
                upload_allowed_dirs=None,
            )
            response = relay_response(
                cfg,
                ["stealth", "gate", "--baseline", str(baseline), "--candidate", str(candidate)],
            )
            self.assertEqual(response.exit_code, 0)
            self.assertEqual(response.payload["command"], "stealth.gate")
            self.assertEqual(response.payload["status"], "passed")

    def test_relay_stealth_usage_is_structured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            cfg = RelayConfig(
                base_dir=base,
                runs_dir=base / "runs",
                recipes_dir=base / "recipes",
                host="127.0.0.1",
                port=18800,
                cdp_url="http://127.0.0.1:18800",
                profile="default",
                profile_dir=base / "profile",
                proxy=None,
                upload_allowed_dirs=None,
            )
            response = relay_response(cfg, ["stealth"])
            self.assertEqual(response.exit_code, 1)
            self.assertEqual(response.payload["failed_gate"], "usage")


if __name__ == "__main__":
    unittest.main()
