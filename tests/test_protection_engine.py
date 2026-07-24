#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest

from chip_relay.protection import diagnose_signals, load_default_rule_pack, validate_rule_pack


class ProtectionEngineTests(unittest.TestCase):
    def test_default_pack_covers_required_providers_with_independent_sources(self) -> None:
        pack = load_default_rule_pack()
        providers = {rule["provider"] for rule in pack["rules"]}
        self.assertTrue(
            {
                "Cloudflare",
                "Akamai",
                "DataDome",
                "HUMAN/PerimeterX",
                "Imperva",
                "Kasada",
                "AWS WAF",
                "F5/Shape",
                "reCAPTCHA",
                "hCaptcha",
                "Turnstile",
            }.issubset(providers)
        )
        for rule in pack["rules"]:
            source_url = rule["source"]["url"]
            self.assertTrue(source_url.startswith("https://"), rule["id"])
            self.assertNotIn("scrapfly", source_url.lower())

    def test_strong_passive_metadata_yields_explainable_deterministic_matches(self) -> None:
        signals = {
            "header_names": ["X-DataDome-CID", "cf-mitigated"],
            "cookie_names": ["datadome"],
            "urls": ["https://geo.captcha-delivery.com/captcha/?initialCid=redacted"],
        }
        first = diagnose_signals(signals)
        second = diagnose_signals(signals)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "chip-relay-protection-diagnostic-v1")
        self.assertEqual(first["mode"], "passive")
        self.assertEqual(first["claim_policy"], "diagnostic-only/no-guaranteed-bypass")
        providers = {item["provider"] for item in first["protections"]}
        self.assertIn("DataDome", providers)
        self.assertIn("Cloudflare", providers)
        datadome = next(item for item in first["protections"] if item["provider"] == "DataDome")
        self.assertGreaterEqual(datadome["confidence"], 80)
        self.assertEqual(datadome["rule_revision"], first["rule_revision"])
        self.assertTrue(datadome["evidence"])
        for evidence in datadome["evidence"]:
            self.assertEqual(set(evidence), {"type", "key", "strength", "weight"})
            self.assertNotIn("redacted", json.dumps(evidence).lower())

    def test_single_weak_signal_never_becomes_high_confidence(self) -> None:
        custom = validate_rule_pack(
            {
                "schema": "chip-relay-protection-rules-v1",
                "revision": "weak-test",
                "rules": [
                    {
                        "id": "vendor.generic-block",
                        "provider": "Vendor",
                        "category": "anti_bot",
                        "source": {"title": "Source", "url": "https://example.com/vendor"},
                        "signals": [
                            {"method": "page_marker", "pattern": "access denied", "weight": 95, "strength": "weak"}
                        ],
                    }
                ],
            }
        )
        result = diagnose_signals({"page_markers": ["access denied"]}, rule_pack=custom)
        self.assertEqual(len(result["protections"]), 1)
        self.assertLessEqual(result["protections"][0]["confidence"], 49)

    def test_conflicting_provider_evidence_remains_visible_and_sorted(self) -> None:
        result = diagnose_signals(
            {
                "header_names": ["x-datadome-cid", "cf-mitigated"],
                "cookie_names": ["datadome", "cf_clearance"],
            }
        )
        providers = [item["provider"] for item in result["protections"]]
        self.assertIn("DataDome", providers)
        self.assertIn("Cloudflare", providers)
        self.assertEqual(
            result["protections"],
            sorted(result["protections"], key=lambda item: (-item["confidence"], item["provider"], item["rule_id"])),
        )

    def test_no_signal_returns_an_honest_empty_diagnosis(self) -> None:
        result = diagnose_signals({})
        self.assertEqual(result["protections"], [])
        self.assertEqual(result["summary"], "no recognized protection metadata")


if __name__ == "__main__":
    unittest.main()
