import copy
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from chip_relay.fingerprint_coherence import CHECKS, evaluate, main

FIXTURE = Path(__file__).parent / "fixtures" / "fingerprint-desktop-v1.json"


class FingerprintCoherenceTests(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(FIXTURE.read_text())

    def assert_failed(self, check):
        result = evaluate(self.doc)
        self.assertEqual(result["status"], "needs_attention")
        self.assertEqual(result["checks"][check], "failed")

    def test_consistent_desktop(self):
        result = evaluate(self.doc)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(set(result["checks"]), set(CHECKS))
        self.assertFalse(result["browser_verified"])

    def test_other_desktop_profiles(self):
        for platform, navigator_platform, ua in [
            ("linux", "Linux x86_64", "Mozilla/5.0 (X11; Linux x86_64)"),
            ("macos", "MacIntel", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
        ]:
            with self.subTest(platform=platform):
                self.setUp()
                self.doc["expected"]["platform"] = platform
                self.doc["observed"]["navigator"].update(platform=navigator_platform, userAgent=ua)
                self.doc["observed"]["headers"].update({"user-agent": ua, "sec-ch-ua-platform": platform})
                self.assertEqual(evaluate(self.doc)["status"], "passed")

    def test_schema_and_section_type_errors(self):
        for version in [True, 1.0, "1", 2]:
            bad = copy.deepcopy(self.doc)
            bad["schema_version"] = version
            with self.assertRaises(ValueError):
                evaluate(bad)
        for value in [None, [], "invalid"]:
            bad = copy.deepcopy(self.doc)
            bad["observed"]["navigator"] = value
            with self.assertRaises(ValueError):
                evaluate(bad)
        bad = copy.deepcopy(self.doc)
        bad["expected"]["platform"] = []
        with self.assertRaises(ValueError):
            evaluate(bad)

    def test_platform_mismatches(self):
        for field, key, value, check in [
            ("navigator", "userAgent", "Mozilla/5.0 (X11; Linux x86_64)", "ua_platform"),
            ("navigator", "platform", "MacIntel", "navigator_platform"),
            ("headers", "sec-ch-ua-platform", '"Linux"', "client_hint_platform"),
        ]:
            with self.subTest(check=check):
                self.setUp()
                self.doc["observed"][field][key] = value
                self.assert_failed(check)

    def test_android_not_linux(self):
        self.doc["expected"]["platform"] = "linux"
        self.doc["observed"]["navigator"]["userAgent"] = "Mozilla/5.0 (Linux; Android 14)"
        self.assert_failed("ua_platform")

    def test_http_ua_mismatch(self):
        self.doc["observed"]["headers"]["user-agent"] += " extra"
        self.assert_failed("ua_matches_http")

    def test_language_mismatches(self):
        self.doc["observed"]["navigator"]["language"] = "fr-FR"
        self.assert_failed("language_matches_http")
        self.assert_failed("language_matches_profile")

    def test_language_q_weights_and_case(self):
        self.doc["observed"]["headers"]["accept-language"] = "fr;q=0.2,EN-us;q=0.9"
        self.assertEqual(evaluate(self.doc)["status"], "passed")

    def test_invalid_language_headers(self):
        for header in ["en-US;q=2", "en-US;q=0", "en-US;foo=1", "en-US;q=0.9;foo=1", "", "*"]:
            with self.subTest(header=header):
                self.doc["observed"]["headers"]["accept-language"] = header
                self.assert_failed("language_matches_http")

    def test_screen_and_scale_mismatches(self):
        for key, value in [("width", 1600), ("height", 900), ("device_scale_factor", 2)]:
            with self.subTest(key=key):
                self.setUp()
                self.doc["observed"]["screen"][key] = value
                self.assert_failed("screen_matches_profile")

    def test_viewport_exceeds_observed_screen(self):
        self.doc["observed"]["viewport"]["width"] = 2000
        self.assert_failed("viewport_fits_screen")

    def test_hardware_mismatches(self):
        for key, check in [("deviceMemory", "memory_matches_profile"),
                           ("hardwareConcurrency", "cores_match_profile"),
                           ("maxTouchPoints", "touch_matches_profile")]:
            with self.subTest(key=key):
                self.setUp()
                self.doc["observed"]["navigator"][key] = 2
                self.assert_failed(check)

    def test_invalid_numeric_measurements(self):
        for value in [True, -1, "8", [], {}, float("nan"), float("inf")]:
            with self.subTest(value=value):
                self.doc["observed"]["navigator"]["deviceMemory"] = value
                self.assert_failed("memory_matches_profile")

    def test_missing_never_passes(self):
        for section, values in self.doc["observed"].items():
            for key in values:
                with self.subTest(section=section, key=key):
                    partial = copy.deepcopy(self.doc)
                    del partial["observed"][section][key]
                    self.assertEqual(evaluate(partial)["status"], "not_run")

    def test_empty_and_null_observations(self):
        self.doc["observed"] = {}
        self.assertEqual(evaluate(self.doc)["status"], "not_run")
        self.doc["observed"] = {"navigator": {"userAgent": None}}
        self.assertEqual(evaluate(self.doc)["status"], "not_run")

    def test_failure_outweighs_missing(self):
        self.doc["observed"] = {"navigator": {"platform": "MacIntel"}}
        self.assert_failed("navigator_platform")

    def test_invalid_contracts(self):
        cases = [None, [], {}, {"schema_version": 1, "expected": {}, "observed": {}}]
        for path, value in [("platform", "android"), ("touch", 0), ("locale", "invalid_locale"),
                            ("hardware_concurrency", True), ("device_memory_gb", 0)]:
            bad = copy.deepcopy(self.doc)
            bad["expected"][path] = value
            cases.append(bad)
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    evaluate(bad)

    def test_cookie_or_unknown_fields_rejected(self):
        for section, key in [("headers", "cookie"), ("navigator", "password"), ("screen", "extra")]:
            with self.subTest(section=section):
                bad = copy.deepcopy(self.doc)
                bad["observed"][section][key] = "private-marker"
                with self.assertRaises(ValueError):
                    evaluate(bad)

    def test_no_source_values_in_output_or_mutation(self):
        before = copy.deepcopy(self.doc)
        self.doc["observed"]["navigator"]["userAgent"] = "private-marker"
        result = evaluate(self.doc)
        self.assertNotIn("private-marker", json.dumps(result))
        self.doc["observed"]["navigator"]["userAgent"] = before["observed"]["navigator"]["userAgent"]
        self.assertEqual(self.doc, before)

    def test_cli_exit_codes_and_redacted_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for content, code in [(json.dumps(self.doc), 0),
                                  (json.dumps({**self.doc, "observed": {}}), 1),
                                  ('{"private-marker":', 2)]:
                path.write_text(content)
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main([str(path)]), code)
                self.assertNotIn("private-marker", output.getvalue())
                json.loads(output.getvalue())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(path.parent / "missing")]), 2)
            self.assertNotIn(str(path.parent), output.getvalue())

    def test_offline_no_network(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(evaluate(self.doc)["status"], "passed")


if __name__ == "__main__":
    unittest.main()
