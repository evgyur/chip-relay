#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import patch

from chip_relay import captcha as captcha_mod
from chip_relay.captcha import write_captcha_state
from chip_relay.captcha_visual import (
    CaptchaVisualError,
    _live_region,
    apply_captcha_visual_actions,
    capture_captcha_visual,
    parse_visual_points,
)
from chip_relay.config import RelayConfig
from chip_relay.relay_adapter import relay_response
from chip_relay.workspace import begin_execution_attempt, init_run, load_manifest

DOCUMENT_KEY = "fedcba9876543210"


def make_config(base: pathlib.Path) -> RelayConfig:
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


def seed_handoff(run_dir: pathlib.Path, *, page_key: str = "0123456789abcdef") -> None:
    write_captcha_state(
        run_dir,
        {
            "status": "human_required",
            "provider": "hCaptcha",
            "title_classification": "captcha",
            "interactive": True,
            "visible_widget_count": 1,
            "response_field_count": 1,
            "token_present": False,
            "next_action": "solve_in_visible_trusted_browser_then_resume",
            "human_handoff": True,
            "page_index": 0,
            "page_count": 1,
            "page_key": page_key,
            "checked_at": "2026-07-30T12:00:00Z",
        },
    )


class CaptchaVisualTests(unittest.TestCase):
    def test_live_region_must_be_fully_contained_and_bounded(self) -> None:
        valid = {"x": 10.0, "y": 20.0, "width": 300.0, "height": 200.0, "clip_x": 10.0, "clip_y": 20.0, "viewport_width": 800.0, "viewport_height": 600.0}
        bounds, clip = _live_region(valid)
        self.assertEqual(bounds["width"], 300.0)
        self.assertEqual(clip["x"], 10.0)
        for invalid in (
            {**valid, "x": -1.0},
            {**valid, "x": 700.0},
            {**valid, "width": 4096.0, "height": 4096.0},
            {**valid, "clip_x": -1.0},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(CaptchaVisualError):
                    _live_region(invalid)

    def test_capture_and_apply_are_attempt_bound_private_and_target_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha visual fixture")
            seed_handoff(run.run_dir)
            captured_keys: list[str] = []
            action_calls: list[tuple[str, list[tuple[float, float]]]] = []

            def capturer(_config: RelayConfig, page_key: str):
                captured_keys.append(page_key)
                return b"\x89PNG\r\n\x1a\nfixture", {"x": 10.0, "y": 20.0, "width": 300.0, "height": 200.0}, DOCUMENT_KEY

            capture = capture_captcha_visual(config, run.run_dir, capturer=capturer)
            screenshot = pathlib.Path(capture["artifact_path"])
            visual_state = run.run_dir / "protection" / "captcha-visual.json"
            self.assertEqual(captured_keys, ["0123456789abcdef"])
            self.assertEqual(capture["status"], "captured")
            self.assertEqual(capture["point_space"], "normalized-challenge-region")
            self.assertTrue(screenshot.is_file())
            self.assertEqual(screenshot.stat().st_mode & 0o777, 0o600)
            self.assertEqual(visual_state.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("fixture", visual_state.read_text())

            def actioner(
                _config: RelayConfig,
                page_key: str,
                _bounds: dict[str, float],
                expected_digest: str,
                document_key: str,
                points: list[tuple[float, float]],
            ) -> None:
                self.assertEqual(expected_digest, capture["sha256"])
                self.assertEqual(document_key, DOCUMENT_KEY)
                action_calls.append((page_key, points))

            def inspector(*_args, **_kwargs):
                self.assertEqual(_kwargs["page_key"], "0123456789abcdef")
                self.assertFalse(_kwargs["persist"])
                return {
                    "status": "clear",
                    "provider": "hCaptcha",
                    "title_classification": "normal",
                    "interactive": False,
                    "visible_widget_count": 1,
                    "response_field_count": 1,
                    "token_present": True,
                    "next_action": "continue_task",
                    "human_handoff": False,
                    "page_index": 0,
                    "page_count": 1,
                    "page_key": "0123456789abcdef",
                    "checked_at": "2026-07-30T12:00:01Z",
                }

            result = apply_captcha_visual_actions(
                config,
                run.run_dir,
                [(0.25, 0.75)],
                confidence=0.93,
                actioner=actioner,
                inspector=inspector,
            )
            self.assertEqual(action_calls, [("0123456789abcdef", [(0.25, 0.75)])])
            self.assertEqual(result["status"], "cleared")
            self.assertEqual(result["action_count"], 1)
            self.assertFalse(screenshot.exists())
            self.assertTrue(visual_state.exists())
            consumed_state = json.loads(visual_state.read_text())
            self.assertTrue(consumed_state["consumed"])
            self.assertEqual(consumed_state["authorization_status"], "consumed")
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_not_captured"):
                apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.25, 0.75)],
                    confidence=0.93,
                    actioner=actioner,
                    inspector=inspector,
                )

    def test_points_and_stale_attempt_fail_closed(self) -> None:
        self.assertEqual(parse_visual_points(["0.25,0.75", "0.5,0.5"]), [(0.25, 0.75), (0.5, 0.5)])
        for raw in ([], ["bad"], ["-0.1,0.5"], ["0.5,1.1"], ["nan,0.5"], ["0.5,inf"]):
            with self.subTest(raw=raw):
                with self.assertRaises(CaptchaVisualError):
                    parse_visual_points(raw)

        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha visual stale")
            seed_handoff(run.run_dir)
            capture_captcha_visual(
                config,
                run.run_dir,
                capturer=lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY),
            )
            begin_execution_attempt(run.run_dir, load_manifest(run.run_dir), source="test")
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_stale"):
                apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.5, 0.5)],
                    confidence=0.95,
                    actioner=lambda *_args: None,
                )

    def test_low_confidence_and_fourth_capture_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha visual bounds")
            seed_handoff(run.run_dir)
            fixture = lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY)
            first = capture_captcha_visual(config, run.run_dir, capturer=fixture)
            self.assertEqual(first["cycle"], 1)
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_confidence_too_low"):
                apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.5, 0.5)],
                    confidence=0.50,
                    actioner=lambda *_args: self.fail("low-confidence action clicked"),
                )
            self.assertEqual(capture_captcha_visual(config, run.run_dir, capturer=fixture)["cycle"], 2)
            self.assertEqual(capture_captcha_visual(config, run.run_dir, capturer=fixture)["cycle"], 3)
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_retry_limit"):
                capture_captcha_visual(config, run.run_dir, capturer=fixture)
            (run.run_dir / "protection" / "captcha-visual.json").unlink()
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_retry_limit"):
                capture_captcha_visual(config, run.run_dir, capturer=fixture)
            (run.run_dir / "protection" / "captcha-state.json").unlink()
            seed_handoff(run.run_dir)
            durable = captcha_mod.load_captcha_state(run.run_dir)
            assert durable is not None
            self.assertEqual(durable["visual_cycle"], 3)
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_retry_limit"):
                capture_captcha_visual(config, run.run_dir, capturer=fixture)

    def test_managed_wait_cannot_enter_visual_click_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha managed wait")
            write_captcha_state(
                run.run_dir,
                {
                    "status": "managed_wait",
                    "provider": "Cloudflare managed challenge",
                    "title_classification": "challenge",
                    "interactive": False,
                    "visible_widget_count": 0,
                    "response_field_count": 0,
                    "token_present": False,
                    "next_action": "wait_for_browser_native_clearance",
                    "human_handoff": False,
                    "page_index": 0,
                    "page_count": 1,
                    "page_key": "0123456789abcdef",
                    "checked_at": "2026-07-30T12:00:00Z",
                },
            )
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_gate_not_interactive"):
                capture_captcha_visual(
                    config,
                    run.run_dir,
                    capturer=lambda *_args: self.fail("managed wait captured for clicking"),
                )

    def test_concurrent_capture_is_serialized_by_retry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha concurrent capture")
            seed_handoff(run.run_dir)
            barrier = threading.Barrier(4)
            cycles: list[int] = []
            failures: list[str] = []

            def worker() -> None:
                barrier.wait()
                try:
                    result = capture_captcha_visual(
                        config,
                        run.run_dir,
                        capturer=lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY),
                    )
                    cycles.append(result["cycle"])
                except CaptchaVisualError as exc:
                    failures.append(str(exc))

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
            self.assertEqual(sorted(cycles), [1, 2, 3])
            self.assertEqual(failures, ["captcha_visual_retry_limit"])

    def test_state_rewrite_is_serialized_with_capture_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha state rewrite serialization")
            seed_handoff(run.run_dir)
            state = captcha_mod.load_captcha_state(run.run_dir)
            assert state is not None
            writer_entered = threading.Event()
            release_writer = threading.Event()
            capture_done = threading.Event()
            original_write = captcha_mod._write_private_state

            def blocking_write(run_dir: pathlib.Path, payload: dict[str, object]) -> None:
                if threading.current_thread().name == "captcha-state-writer":
                    writer_entered.set()
                    if not release_writer.wait(5):
                        raise RuntimeError("writer release timeout")
                original_write(run_dir, payload)

            captured: list[dict[str, object]] = []
            writer = threading.Thread(
                target=lambda: write_captcha_state(run.run_dir, state),
                name="captcha-state-writer",
            )
            capturer = threading.Thread(
                target=lambda: (
                    captured.append(capture_captcha_visual(
                        config,
                        run.run_dir,
                        capturer=lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY),
                    )),
                    capture_done.set(),
                ),
            )
            with patch.object(captcha_mod, "_write_private_state", side_effect=blocking_write):
                writer.start()
                self.assertTrue(writer_entered.wait(5))
                capturer.start()
                self.assertFalse(capture_done.wait(0.05))
                release_writer.set()
                writer.join(5)
                capturer.join(5)
            self.assertFalse(writer.is_alive())
            self.assertFalse(capturer.is_alive())
            self.assertEqual(captured[0]["cycle"], 1)
            durable = captcha_mod.load_captcha_state(run.run_dir)
            assert durable is not None
            self.assertEqual(durable["visual_cycle"], 1)

    def test_retry_budget_does_not_reset_when_page_target_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha target budget")
            seed_handoff(run.run_dir)
            fixture = lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY)
            first = capture_captcha_visual(config, run.run_dir, capturer=fixture)
            seed_handoff(run.run_dir, page_key="1111111111111111")
            second = capture_captcha_visual(config, run.run_dir, capturer=fixture)
            self.assertEqual((first["cycle"], second["cycle"]), (1, 2))

    def test_modified_visual_artifact_is_rejected_before_clicks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha visual tamper")
            seed_handoff(run.run_dir)
            capture = capture_captcha_visual(
                config,
                run.run_dir,
                capturer=lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY),
            )
            pathlib.Path(capture["artifact_path"]).write_bytes(b"tampered")
            pathlib.Path(capture["artifact_path"]).chmod(0o600)
            clicked: list[bool] = []
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_artifact_changed"):
                apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.5, 0.5)],
                    confidence=0.95,
                    actioner=lambda *_args: clicked.append(True),
                )
            self.assertEqual(clicked, [])

    def test_partial_or_failed_action_becomes_uncertain_and_cannot_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha uncertain")
            seed_handoff(run.run_dir)
            capture_captcha_visual(
                config,
                run.run_dir,
                capturer=lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY),
            )
            with self.assertRaisesRegex(RuntimeError, "partial click"):
                apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.5, 0.5)],
                    confidence=0.95,
                    actioner=lambda *_args: (_ for _ in ()).throw(RuntimeError("partial click")),
                )
            state = json.loads((run.run_dir / "protection" / "captcha-visual.json").read_text())
            self.assertEqual(state["authorization_status"], "uncertain")
            self.assertTrue(state["consumed"])
            with self.assertRaisesRegex(CaptchaVisualError, "captcha_visual_not_captured"):
                apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.5, 0.5)],
                    confidence=0.95,
                    actioner=lambda *_args: self.fail("uncertain authorization replayed"),
                )

    def test_private_visual_artifacts_never_appear_in_generic_relay_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha private projection")
            seed_handoff(run.run_dir)
            capture = capture_captcha_visual(
                config,
                run.run_dir,
                capturer=lambda *_args: (b"\x89PNG\r\n\x1a\nfixture", {"x": 0.0, "y": 0.0, "width": 100.0, "height": 100.0}, DOCUMENT_KEY),
            )
            for tokens in (
                ["artifacts", run.run_id],
                ["task", "artifacts", run.run_id],
                ["task", "context", run.run_id],
                ["task", "show", run.run_id],
            ):
                with self.subTest(tokens=tokens):
                    response = relay_response(config, tokens)
                    self.assertEqual(response.exit_code, 0)
                    projected = json.dumps(response.payload, ensure_ascii=False)
                    self.assertNotIn("captcha-visual.png", projected)
                    self.assertNotIn("captcha-visual.json", projected)
                    self.assertNotIn(capture["artifact_path"], projected)

    def test_relay_visual_projection_never_exposes_local_artifact_path(self) -> None:
        sentinel = "/private/SENTINEL-captcha.png"
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(pathlib.Path(tmp))
            run = init_run(config, "captcha relay visual")
            seed_handoff(run.run_dir)
            with patch(
                "chip_relay.relay_adapter.capture_captcha_visual",
                return_value={
                    "status": "captured",
                    "artifact_path": sentinel,
                    "sha256": "a" * 64,
                    "width": 300,
                    "height": 200,
                    "point_space": "normalized-challenge-region",
                    "artifact_policy": "private-local/no-auto-send",
                    "cycle": 1,
                },
            ):
                response = relay_response(config, ["task", "captcha", run.run_id, "capture"])
            self.assertEqual(response.exit_code, 0)
            self.assertEqual(response.payload["status"], "captured")
            encoded = json.dumps(response.payload)
            self.assertNotIn(sentinel, encoded)
            self.assertNotIn("artifact_path", encoded)
            self.assertNotIn("sha256", encoded)

            with (
                patch(
                    "chip_relay.relay_adapter.apply_captcha_visual_actions",
                    return_value={"status": "cleared", "action_count": 1, "visual_cycle": 2, "confidence": 0.91},
                ) as apply_mock,
                patch("chip_relay.relay_adapter.captcha_summary", return_value={"status": "cleared"}),
            ):
                acted = relay_response(
                    config,
                    ["task", "captcha", run.run_id, "act", "--confidence", "0.91", "--point", "0.5,0.5"],
                )
            self.assertEqual(acted.exit_code, 0)
            self.assertEqual(acted.payload["captcha"]["visual_cycle"], 2)
            self.assertEqual(acted.payload["captcha"]["confidence"], 0.91)
            apply_mock.assert_called_once_with(config, run.run_dir, [(0.5, 0.5)], confidence=0.91)

            missing_confidence = relay_response(
                config,
                ["task", "captcha", run.run_id, "act", "--point", "0.5,0.5"],
            )
            self.assertEqual(missing_confidence.exit_code, 1)
            self.assertEqual(missing_confidence.payload["failed_gate"], "usage")


if __name__ == "__main__":
    unittest.main()
