#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import unittest

from chip_relay.network import sanitize_observation
from chip_relay.stealth import classify_challenge
from chip_relay.protection import (
    ALLOWED_SIGNAL_METHODS,
    DIAGNOSTIC_SCHEMA,
    validate_rule_pack,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ProtectionContractTests(unittest.TestCase):
    def _pack(self, rules: list[dict[str, object]]) -> dict[str, object]:
        return {
            "schema": "chip-relay-protection-rules-v1",
            "revision": "test-v1",
            "rules": rules,
        }

    def _rule(self, **overrides: object) -> dict[str, object]:
        rule: dict[str, object] = {
            "id": "vendor.strong-header",
            "provider": "Vendor",
            "category": "anti_bot",
            "source": {
                "title": "Independent public documentation",
                "url": "https://example.com/docs/header",
            },
            "signals": [
                {
                    "method": "header_name",
                    "pattern": "x-vendor-id",
                    "weight": 70,
                    "strength": "strong",
                }
            ],
        }
        rule.update(overrides)
        return rule

    def test_schema_allows_only_normalized_metadata_signal_types(self) -> None:
        self.assertEqual(DIAGNOSTIC_SCHEMA, "chip-relay-protection-diagnostic-v1")
        self.assertEqual(
            ALLOWED_SIGNAL_METHODS,
            {
                "url",
                "status",
                "header_name",
                "cookie_name",
                "page_marker",
                "window_key",
                "fingerprint_api",
            },
        )
        validated = validate_rule_pack(self._pack([self._rule()]))
        self.assertEqual(validated["revision"], "test-v1")

    def test_rule_validation_fails_closed(self) -> None:
        cases = [
            self._rule(signals=[{"method": "response_body", "pattern": "secret", "weight": 50, "strength": "strong"}]),
            self._rule(signals=[{"method": "url", "pattern": "(a+)+$", "weight": 50, "strength": "strong"}]),
            self._rule(signals=[{"method": "url", "pattern": "[", "weight": 50, "strength": "strong"}]),
            self._rule(signals=[{"method": "url", "pattern": "vendor", "weight": 101, "strength": "strong"}]),
        ]
        for index, rule in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ValueError):
                validate_rule_pack(self._pack([rule]))

        duplicate = self._rule()
        with self.assertRaises(ValueError):
            validate_rule_pack(self._pack([duplicate, dict(duplicate)]))

    def test_brownfield_network_and_challenge_contract_remains_characterized(self) -> None:
        secret = "SENTINEL_PRIVATE_VALUE"
        safe = sanitize_observation(
            {
                "url": f"https://example.com/?token={secret}",
                "headers": {"Authorization": f"Bearer {secret}"},
                "body": secret,
                "status": 403,
            }
        )
        self.assertNotIn(secret, repr(safe))
        self.assertEqual(safe["request_headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(classify_challenge({"status": 403})["status"], "blocked")

    def test_clean_room_provenance_policy_is_explicit(self) -> None:
        text = (ROOT / "docs" / "protection-diagnostics-sources.md").read_text(encoding="utf-8")
        for phrase in (
            "No copied detector JSON",
            "No copied source code",
            "No copied descriptions or confidence values",
            "No bundled Chrome extension",
            "independent public source",
        ):
            self.assertIn(phrase, text)


if __name__ == "__main__":
    unittest.main()
