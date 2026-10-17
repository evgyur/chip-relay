from __future__ import annotations

import copy
import json
import unittest

from chip_relay.benchmark import BenchmarkContractError, compare_results, gate_results, validate_result
from chip_relay.benchmark_probes import INPUT_TEXT, behavior_status, input_checks, tls_observation
from chip_relay.benchmark_runner import (
    _aggregate_attempts, _classify_case, _fingerprint_status, _page_status, _suite_cases,
)
from chip_relay.stealth import evaluate_fingerprint
from test_stealth_benchmark import result


class HonestClassificationTests(unittest.TestCase):
    def classify(self, evaluation, **kwargs):
        args = dict(response_status=200, title="Example Domain", url="https://example.com", text="Example")
        args.update(kwargs)
        return _classify_case(**args, evaluation=evaluation)

    def test_reproduced_false_pass_is_fixed(self):
        evaluation = evaluate_fingerprint({"webdriver": True, "userAgent": "HeadlessChrome/146.0", "platform": "Linux"})
        self.assertEqual(evaluation["status"], "needs_attention")
        self.assertEqual(self.classify(evaluation), "needs_attention")

    def test_missing_and_partial_measurement_are_not_passed(self):
        for evaluation in ({}, {"status": "ok"}, {"status": "not_run"},
                           {"status": "ok", "checks": [{"name": "webdriver", "ok": True}]}):
            self.assertEqual(self.classify(evaluation), "not_run")

    def test_complete_clean_sample_can_pass(self):
        evaluation = evaluate_fingerprint(dict(webdriver=False, userAgent="Chrome/146 Linux", platform="Linux",
            languages=["en-US"], timezone="UTC", webglVendor="fixture", webglRenderer="fixture"))
        self.assertEqual(self.classify(evaluation), "passed")
        self.assertEqual(self.classify(evaluation, response_status=None), "not_run")
        self.assertEqual(self.classify(evaluation, response_status=500), "error")

    def test_success_keyword_and_detector_url_are_not_bypass_evidence(self):
        bad = evaluate_fingerprint({"webdriver": True})
        self.assertEqual(self.classify(bad, title="success", url="https://nowsecure.nl"), "needs_attention")
        self.assertEqual(self.classify(bad, title="success CAPTCHA", response_status=403), "blocked")
        self.assertEqual(self.classify(bad, title="success CAPTCHA"), "captcha/manual")

    def test_accessibility_is_separate(self):
        self.assertEqual(_page_status(response_status=200, title="page", url="https://example.com", text="ok"), "accessible")

    def test_missing_attempt_cannot_disappear_from_check_aggregation(self):
        self.assertEqual(_aggregate_attempts([
            {"behavior_checks": [{"name": "input.trusted", "ok": True}]}, {"behavior_checks": []}
        ], "behavior_checks"), [{"name": "input.trusted", "ok": False}])

    def test_local_suite_is_only_loopback_and_covers_input_and_init(self):
        cases = dict(_suite_cases("local", "http://127.0.0.1:12345"))
        self.assertIn("input-events", cases)
        self.assertIn("init-script", cases)
        self.assertTrue(all(v.startswith("http://127.0.0.1:12345/") for v in cases.values()))


class ProbeContractTests(unittest.TestCase):
    def test_input_oracle_catches_js_untrusted_events_and_text_errors(self):
        sample = {"events": [{"type": t, "trusted": True, "target": "target"} for t in
            ["pointerdown", "mousedown", "pointerup", "mouseup", "click"]] +
            [{"type": t, "trusted": True, "target": "entry"} for t in ["keydown", "input", "keyup"] * len(INPUT_TEXT)],
            "clicks": 1, "value": INPUT_TEXT, "mutations": 0}
        self.assertTrue(all(c["ok"] for c in input_checks(sample)))
        sample["events"][0]["trusted"] = False
        sample["value"] = "wrong"
        sample["mutations"] = 1
        failures = {c["name"] for c in input_checks(sample) if not c["ok"]}
        self.assertEqual(failures, {"input.trusted_events", "input.exact_text", "input.no_dom_nodes"})

    def test_tls_parser_keeps_only_allowlisted_evidence(self):
        checks, evidence = tls_observation(json.dumps({"ip": "not-for-storage", "headers": ["private"],
            "http_version": "h2", "tls": {"ja3_hash": "a" * 32, "tls_version_negotiated": "772", "private": "discard"}}))
        self.assertTrue(all(c["ok"] for c in checks))
        self.assertEqual(set(evidence), {"http_version", "ja3_hash", "tls_version_negotiated"})
        self.assertFalse(any(c["ok"] for c in tls_observation("{}")[0]))

    def test_tls_bad_payload_is_not_success(self):
        for raw in ("null", "[]", '{"tls":null}', '{"http_version":[]}'):
            self.assertFalse(any(c["ok"] for c in tls_observation(raw)[0]))
        with self.assertRaises(ValueError):
            tls_observation("not json")

    def test_behavior_failures_and_missing_coverage_gate(self):
        base = result("baseline")
        base["results"][0]["cases"][0]["behavior_checks"] = [{"name": "init.before_page_script", "ok": True}]
        bad = copy.deepcopy(base)
        bad["run_id"] = "candidate"
        bad["results"][0]["cases"][0]["behavior_checks"][0]["ok"] = False
        self.assertIn("behavior_regression", {r["type"] for r in gate_results(base, bad).regressions})
        bad["results"][0]["cases"][0]["behavior_checks"] = []
        self.assertEqual(gate_results(base, bad).failed_gate, "coverage_regression")

    def test_behavior_measurement_requires_complete_boolean_checks(self):
        self.assertEqual(behavior_status("input-events", []), "not_run")
        self.assertEqual(behavior_status("init-script", [{"name": "init.before_page_script", "ok": True}]), "not_run")

    def test_new_failed_behavior_case_gates(self):
        base = result("baseline")
        bad = result("candidate")
        added = copy.deepcopy(bad["results"][0]["cases"][0])
        added.update(name="new-input", behavior_checks=[{"name": "input.trusted_events", "ok": False}])
        bad["results"][0]["cases"].append(added)
        self.assertIn("behavior_regression", {r["type"] for r in gate_results(base, bad).regressions})

    def test_dimension_regression_even_with_unchanged_top_status(self):
        base = result("baseline")
        base["results"][0]["cases"][0]["fingerprint_status"] = "passed"
        bad = copy.deepcopy(base)
        bad["results"][0]["cases"][0]["fingerprint_status"] = "not_run"
        self.assertEqual(gate_results(base, bad).failed_gate, "outcome_regression")

    def test_needs_attention_and_needs_proxy_are_regressions(self):
        for status in ("needs_attention", "needs_proxy"):
            self.assertEqual(gate_results(result("a"), result("b", status=status)).failed_gate, "outcome_regression")

    def test_duplicate_checks_fail_closed(self):
        for field in ("fingerprint_checks", "behavior_checks"):
            payload = result("a")
            payload["results"][0]["cases"][0][field] = [{"name": "x", "ok": True}] * 2
            with self.assertRaisesRegex(BenchmarkContractError, "benchmark_check_duplicate"):
                validate_result(payload)

    def test_browser_update_metadata_is_visible(self):
        candidate = result("b")
        candidate["results"][0]["browser"]["browser"] = "Chromium/2"
        diffs = compare_results(result("a"), candidate)["backend_diffs"][0]["environment_diffs"]
        self.assertEqual(diffs[0]["name"], "browser")

    def test_external_diagnostics_cannot_be_a_successful_release_gate(self):
        for suite in ("chip-relay-public-detectors", "chip-relay-tls-fingerprint"):
            gate = gate_results(result("a", suite_id=suite), result("b", suite_id=suite))
            self.assertEqual(gate.status, "not_run")
            self.assertEqual(gate.failed_gate, "external_diagnostic_only")

    def test_version_one_baseline_requires_explicit_new_baseline(self):
        candidate = result("b")
        candidate["suite_version"] = "2"
        with self.assertRaisesRegex(BenchmarkContractError, "benchmark_suite_incompatible"):
            compare_results(result("a"), candidate)


if __name__ == "__main__":
    unittest.main()
