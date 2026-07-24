#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
import unittest

from chip_relay.protection import (
    fingerprint_observer_source,
    install_fingerprint_observer,
    instrumentation_notice,
    sanitize_observer_snapshot,
)


class ProtectionInstrumentationTests(unittest.TestCase):
    def test_observer_is_disabled_by_default_for_normal_and_strict_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            for preset in ("normal", "strict"):
                result = install_fingerprint_observer(run_dir, enabled=False, preset=preset)
                self.assertEqual(result["status"], "disabled")
                self.assertFalse((run_dir / "init_scripts" / "protection-observer.js").exists())

    def test_explicit_opt_in_installs_document_start_source_with_bounded_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            run_dir.mkdir()
            result = install_fingerprint_observer(run_dir, enabled=True, preset="normal")
            self.assertEqual(result["status"], "installed")
            self.assertEqual(result["mode"], "instrumented")
            self.assertEqual(result["install_phase"], "document_start")
            path = run_dir / result["script"]["path"]
            self.assertTrue(path.is_file())
            source = path.read_text(encoding="utf-8")
            self.assertEqual(source, fingerprint_observer_source())
            for surface in (
                "canvas.toDataURL",
                "webgl.getParameter",
                "audio.getChannelData",
                "fonts.check",
                "webrtc.createOffer",
                "navigator.hardwareConcurrency",
                "storage.getItem",
                "performance.now",
                "screen.colorDepth",
            ):
                self.assertIn(surface, source)
            self.assertIn("MAX_TOTAL = 1000", source)
            self.assertIn("LIFETIME_MS = 10000", source)
            self.assertIn("restoreAll", source)

    def test_snapshot_accepts_names_and_bounded_counts_only(self) -> None:
        safe = sanitize_observer_snapshot(
            {
                "schema": "chip-relay-fingerprint-observer-v1",
                "mode": "instrumented",
                "active": True,
                "elapsed_ms": 10,
                "counts": {
                    "canvas.toDataURL": 2,
                    "webgl.getParameter": 1001,
                    "audio.getChannelData": 1,
                    "fonts.check": 1,
                    "webrtc.createOffer": 1,
                    "navigator.hardwareConcurrency": 1,
                    "storage.getItem": 1,
                    "performance.now": 1,
                    "screen.colorDepth": 1,
                },
            }
        )
        self.assertEqual(safe["mode"], "instrumented")
        self.assertEqual(safe["fingerprint_apis"]["canvas.toDataURL"], 2)
        self.assertEqual(safe["fingerprint_apis"]["webgl.getParameter"], 1000)
        self.assertNotIn("arguments", json.dumps(safe))
        self.assertNotIn("returns", json.dumps(safe))
        self.assertNotIn("stack", json.dumps(safe))
        with self.assertRaisesRegex(ValueError, "unknown_observer_snapshot_field"):
            sanitize_observer_snapshot({
                "schema": "chip-relay-fingerprint-observer-v1",
                "mode": "instrumented",
                "active": True,
                "elapsed_ms": 10,
                "counts": {},
                "arguments": ["private"],
            })

    def test_notice_is_honest_about_intrusion_and_no_bypass_proof(self) -> None:
        notice = instrumentation_notice()
        self.assertEqual(notice["default"], "disabled")
        self.assertIn("can affect detectability", notice["warning"])
        self.assertIn("cannot prove stealth or bypass", notice["claim_limit"])

    def test_observer_classifies_mocked_browser_calls_offline(self) -> None:
        fixture = r'''
globalThis.setTimeout = (callback) => { globalThis.__restoreObserver = callback; return 1; };
class HTMLCanvasElement { toDataURL() { return "canvas"; } toBlob() { return null; } }
class CanvasRenderingContext2D { getImageData() { return {}; } measureText() { return {}; } }
class WebGLRenderingContext { getParameter() { return 1; } getExtension() { return null; } readPixels() {} }
class AudioBuffer { getChannelData() { return []; } copyFromChannel() {} }
class AnalyserNode { getFloatFrequencyData() {} getByteFrequencyData() {} }
class FontFaceSet { check() { return true; } }
class RTCPeerConnection { createOffer() { return {}; } setLocalDescription() {} }
class Navigator {}
Object.defineProperty(Navigator.prototype, "hardwareConcurrency", {configurable: true, get() { return 4; }});
class Storage { getItem() { return null; } key() { return null; } }
class Performance { now() { return 1; } getEntriesByType() { return []; } }
class Screen {}
Object.defineProperty(Screen.prototype, "colorDepth", {configurable: true, get() { return 24; }});
Object.assign(globalThis, {HTMLCanvasElement, CanvasRenderingContext2D, WebGLRenderingContext, AudioBuffer, AnalyserNode, FontFaceSet, RTCPeerConnection, Navigator, Storage, Performance, Screen});
'''
        calls = r'''
new HTMLCanvasElement().toDataURL();
new WebGLRenderingContext().getParameter(1);
new AudioBuffer().getChannelData(0);
new FontFaceSet().check("12px sans");
new RTCPeerConnection().createOffer();
void new Navigator().hardwareConcurrency;
new Storage().getItem("name");
new Performance().now();
void new Screen().colorDepth;
const before = globalThis.__chipRelayProtectionSnapshot();
globalThis.__restoreObserver();
const after = globalThis.__chipRelayProtectionSnapshot();
process.stdout.write(JSON.stringify({before, after}));
'''
        completed = subprocess.run(
            ["node", "-"],
            input=fixture + fingerprint_observer_source() + calls,
            text=True,
            capture_output=True,
            check=True,
        )
        payload = json.loads(completed.stdout)
        expected = {
            "canvas.toDataURL",
            "webgl.getParameter",
            "audio.getChannelData",
            "fonts.check",
            "webrtc.createOffer",
            "navigator.hardwareConcurrency",
            "storage.getItem",
            "performance.now",
            "screen.colorDepth",
        }
        self.assertEqual(set(payload["before"]["counts"]), expected)
        self.assertTrue(payload["before"]["active"])
        self.assertFalse(payload["after"]["active"])


if __name__ == "__main__":
    unittest.main()
