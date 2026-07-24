#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from chip_relay.network import record_observation
from chip_relay.protection import load_page_signals, record_page_signals, sanitize_page_signals


class ProtectionCaptureTests(unittest.TestCase):
    def test_network_capture_keeps_only_cookie_names(self) -> None:
        sentinel = "SENTINEL_COOKIE_VALUE_9f3f"
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            safe = record_observation(
                run_dir,
                {
                    "url": f"https://example.com/challenge?token={sentinel}",
                    "request_headers": {
                        "Cookie": f"datadome={sentinel}; cf_clearance={sentinel}",
                        "Authorization": f"Bearer {sentinel}",
                    },
                    "response_headers": {
                        "Set-Cookie": f"aws-waf-token={sentinel}; Path=/; HttpOnly",
                        "x-datadome-cid": sentinel,
                    },
                    "request_body": sentinel,
                    "response_body": sentinel,
                },
            )
            self.assertEqual(safe["request_cookie_names"], ["cf_clearance", "datadome"])
            self.assertEqual(safe["response_cookie_names"], ["aws-waf-token"])
            text = (run_dir / "network" / "observations.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(sentinel, text)
            self.assertNotIn("Path=/", text)
            self.assertIn("datadome", text)

    def test_page_signal_record_is_allowlisted_bounded_and_metadata_only(self) -> None:
        sentinel = "SENTINEL_TOKEN_VALUE_7a2b"
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            safe = record_page_signals(
                run_dir,
                {
                    "final_url": f"https://example.com/challenge?token={sentinel}",
                    "status": 403,
                    "title_classification": "access_denied",
                    "page_markers": ["cf-turnstile", "cf-turnstile"],
                    "window_keys": ["turnstile"],
                },
            )
            self.assertEqual(safe["page_markers"], ["cf-turnstile"])
            self.assertEqual(safe["window_keys"], ["turnstile"])
            loaded = load_page_signals(run_dir)
            self.assertEqual(len(loaded), 1)
            text = (run_dir / "protection" / "signals.jsonl").read_text(encoding="utf-8")
            self.assertNotIn(sentinel, text)
            self.assertNotIn("body", text.lower())
            self.assertEqual((run_dir / "protection" / "signals.jsonl").stat().st_mode & 0o777, 0o600)

    def test_malformed_oversized_raw_and_token_like_payloads_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown_page_signal_field"):
            sanitize_page_signals({"raw_html": "<html>private</html>"})
        with self.assertRaisesRegex(ValueError, "invalid_page_marker"):
            sanitize_page_signals({"page_markers": ["token=SENTINEL_PRIVATE_VALUE"]})
        with self.assertRaisesRegex(ValueError, "invalid_page_marker"):
            sanitize_page_signals({"page_markers": ["token.SENTINELPRIVATEVALUE"]})
        with self.assertRaisesRegex(ValueError, "invalid_fingerprint_api"):
            sanitize_page_signals(
                {"fingerprint_apis": {"secret.SENTINELPRIVATEVALUE": 1}},
                mode="instrumented",
            )
        with self.assertRaisesRegex(ValueError, "page_signal_payload_too_large"):
            sanitize_page_signals({"page_markers": ["x"] * 70000})
        with self.assertRaisesRegex(ValueError, "invalid_page_signal_status"):
            sanitize_page_signals({"status": "403"})

    def test_url_userinfo_fragments_and_invalid_header_names_do_not_persist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            safe = record_observation(
                run_dir,
                {
                    "url": "https://private-user:private-pass@example.com/path?token=private-query#access_token=private-fragment",
                    "request_headers": {"x-safe": "ok"},
                },
            )
            text = json.dumps(safe)
            for private in ("private-user", "private-pass", "private-query", "private-fragment"):
                self.assertNotIn(private, text)
            with self.assertRaisesRegex(ValueError, "invalid_header_name"):
                record_observation(run_dir, {"request_headers": {"x-safe\nInjected": "value"}})

    def test_symlinked_run_or_signal_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            real_run = base / "real"
            real_run.mkdir()
            linked_run = base / "linked"
            linked_run.symlink_to(real_run, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "unsafe_run_dir"):
                record_page_signals(linked_run, {"status": 403})

            protection_dir = real_run / "protection"
            protection_dir.mkdir()
            target = base / "outside.jsonl"
            target.write_text("", encoding="utf-8")
            (protection_dir / "signals.jsonl").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "unsafe_signal_path"):
                record_page_signals(real_run, {"status": 403})


if __name__ == "__main__":
    unittest.main()
