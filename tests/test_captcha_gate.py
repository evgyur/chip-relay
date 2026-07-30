#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from chip_relay import captcha as captcha_mod
from chip_relay.captcha import (
    CaptchaGateError,
    captcha_summary,
    classify_captcha_probe,
    load_captcha_state,
    wait_for_captcha_clearance,
    write_captcha_state,
)
from chip_relay.config import RelayConfig
from chip_relay.hermes_context import hermes_task_context
from chip_relay.playwright_runner import run_final_script
from chip_relay.relay_adapter import relay_response
from chip_relay.workspace import begin_execution_attempt, init_run, load_manifest


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


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


def page_probe(
    active_providers: dict[str, bool] | None = None,
    *,
    title: str = "normal",
    visible_widgets: int = 0,
    response_fields: int = 0,
    token_present: bool = False,
    interactive: bool = False,
) -> dict[str, object]:
    providers = {"recaptcha": False, "hcaptcha": False, "turnstile": False, "cloudflare": False}
    providers.update(active_providers or {})
    return {
        "providers": providers,
        "title_classification": title,
        "visible_widgets": visible_widgets,
        "response_fields": response_fields,
        "token_present": token_present,
        "interactive": interactive,
    }


class CaptchaGateTests(unittest.TestCase):
    def test_classifier_separates_clear_managed_wait_and_human_handoff(self) -> None:
        clear = classify_captcha_probe(
            page_probe(
                {"recaptcha": True},
                visible_widgets=1,
                response_fields=1,
                token_present=True,
            )
        )
        self.assertEqual(clear["status"], "clear")
        self.assertEqual(clear["provider"], "reCAPTCHA")

        managed = classify_captcha_probe(
            page_probe({"cloudflare": True}, title="challenge")
        )
        self.assertEqual(managed["status"], "managed_wait")
        self.assertFalse(managed["human_handoff"])

        cloudflare_turnstile = classify_captcha_probe(
            page_probe(
                {"cloudflare": True, "turnstile": True},
                title="challenge",
                visible_widgets=1,
                response_fields=1,
                interactive=True,
            )
        )
        self.assertEqual(cloudflare_turnstile["status"], "managed_wait")
        self.assertEqual(cloudflare_turnstile["provider"], "Cloudflare managed challenge")

        human = classify_captcha_probe(
            page_probe(
                {"hcaptcha": True},
                title="captcha",
                visible_widgets=1,
                response_fields=1,
                interactive=True,
            )
        )
        self.assertEqual(human["status"], "human_required")
        self.assertEqual(human["next_action"], "solve_in_visible_trusted_browser_then_resume")
        self.assertIn("token injection", human["forbidden"])

        hidden_pending = classify_captcha_probe(
            page_probe({"recaptcha": True}, response_fields=1)
        )
        self.assertEqual(hidden_pending["status"], "managed_wait")

        for malformed in ({}, {"providers": {}}, page_probe(visible_widgets=1)):
            with self.subTest(malformed=malformed):
                with self.assertRaisesRegex(CaptchaGateError, "invalid_captcha_probe"):
                    classify_captcha_probe(malformed)

    def test_wait_auto_resumes_after_browser_native_clearance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha wait fixture")
            probes = iter(
                [
                    {
                        "schema": "chip-relay-captcha-gate-v1",
                        "status": "managed_wait",
                        "provider": "Cloudflare managed challenge",
                        "human_handoff": False,
                    },
                    {
                        "schema": "chip-relay-captcha-gate-v1",
                        "status": "clear",
                        "provider": None,
                        "human_handoff": False,
                    },
                ]
            )
            clock = FakeClock()

            def inspector(*_args, **_kwargs):
                return next(probes)

            result = wait_for_captcha_clearance(
                config,
                run.run_dir,
                timeout=10,
                poll_interval=1,
                inspector=inspector,
                sleep=clock.sleep,
                monotonic=clock.monotonic,
            )
            self.assertEqual(result["status"], "cleared")
            self.assertEqual(result["checks"], 2)
            state = load_captcha_state(run.run_dir)
            self.assertIsNotNone(state)
            assert state is not None
            self.assertEqual(state["status"], "cleared")
            self.assertEqual((run.run_dir / "protection" / "captcha-state.json").stat().st_mode & 0o777, 0o600)

    def test_wait_sticks_to_the_initial_browser_target(self) -> None:
        calls: list[tuple[int, str | None]] = []

        def inspector(_config: RelayConfig, _run_dir: pathlib.Path, **kwargs: object) -> dict[str, object]:
            raw_page_index = kwargs.get("page_index", -1)
            page_index = raw_page_index if isinstance(raw_page_index, int) and not isinstance(raw_page_index, bool) else -1
            page_key = kwargs.get("page_key")
            calls.append((page_index, page_key if isinstance(page_key, str) else None))
            if len(calls) == 1:
                return {
                    "status": "human_required",
                    "provider": "hCaptcha",
                    "page_index": 0,
                    "page_count": 1,
                    "page_key": "0123456789abcdef",
                    "human_handoff": True,
                    "next_action": "solve_in_visible_trusted_browser_then_resume",
                    "checked_at": "2026-07-30T12:00:00Z",
                }
            return {
                "status": "clear",
                "provider": None,
                "page_index": 0,
                "page_count": 2,
                "page_key": "0123456789abcdef",
                "human_handoff": False,
                "next_action": "continue_task",
                "checked_at": "2026-07-30T12:00:01Z",
            }

        clock = FakeClock()
        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(pathlib.Path(tmp))
            run = init_run(config, "captcha sticky page fixture")
            result = wait_for_captcha_clearance(
                config,
                run.run_dir,
                timeout=5,
                poll_interval=1,
                inspector=inspector,
                sleep=clock.sleep,
                monotonic=clock.monotonic,
            )
        self.assertEqual(result["status"], "cleared")
        self.assertEqual(calls, [(-1, None), (0, "0123456789abcdef")])

    def test_resume_reuses_the_target_persisted_by_inspect(self) -> None:
        calls: list[tuple[int, str | None]] = []

        def inspector(_config: RelayConfig, _run_dir: pathlib.Path, **kwargs: object) -> dict[str, object]:
            raw_index = kwargs.get("page_index")
            raw_key = kwargs.get("page_key")
            calls.append((raw_index if isinstance(raw_index, int) else -1, raw_key if isinstance(raw_key, str) else None))
            return {
                "status": "clear",
                "provider": None,
                "page_index": 0,
                "page_count": 2,
                "page_key": "0123456789abcdef",
                "human_handoff": False,
                "next_action": "continue_task",
                "checked_at": "2026-07-30T12:00:01Z",
            }

        with tempfile.TemporaryDirectory() as tmp:
            config = make_config(pathlib.Path(tmp))
            run = init_run(config, "captcha persisted target fixture")
            write_captcha_state(
                run.run_dir,
                {
                    "status": "human_required",
                    "provider": "hCaptcha",
                    "page_index": 0,
                    "page_count": 1,
                    "page_key": "0123456789abcdef",
                    "human_handoff": True,
                    "next_action": "solve_in_visible_trusted_browser_then_resume",
                    "checked_at": "2026-07-30T12:00:00Z",
                },
            )
            result = wait_for_captcha_clearance(
                config,
                run.run_dir,
                timeout=0,
                inspector=inspector,
            )
        self.assertEqual(result["status"], "cleared")
        self.assertEqual(calls, [(0, "0123456789abcdef")])

    def test_wait_times_out_to_explicit_human_handoff_without_solver_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha handoff fixture")
            clock = FakeClock()

            def inspector(*_args, **_kwargs):
                return {
                    "schema": "chip-relay-captcha-gate-v1",
                    "status": "human_required",
                    "provider": "Turnstile",
                    "human_handoff": True,
                    "next_action": "solve_in_visible_trusted_browser_then_resume",
                }

            result = wait_for_captcha_clearance(
                config,
                run.run_dir,
                timeout=2,
                poll_interval=1,
                inspector=inspector,
                sleep=clock.sleep,
                monotonic=clock.monotonic,
            )
            self.assertEqual(result["status"], "human_required")
            self.assertEqual(result["next_action"], "solve_in_visible_trusted_browser_then_run_captcha_resume")
            self.assertNotIn("guaranteed", json.dumps(result).lower())
            self.assertNotIn("token", json.dumps(result).lower())

    def test_visible_cloudflare_timeout_persists_human_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "visible cloudflare handoff")
            clock = FakeClock()

            def inspector(*_args, **_kwargs):
                return {
                    "schema": "chip-relay-captcha-gate-v1",
                    "status": "managed_wait",
                    "provider": "Cloudflare managed challenge",
                    "title_classification": "challenge",
                    "interactive": True,
                    "visible_widget_count": 1,
                    "response_field_count": 1,
                    "token_present": False,
                    "human_handoff": False,
                    "next_action": "wait_for_browser_native_clearance",
                    "page_index": 0,
                    "page_count": 1,
                    "page_key": "0123456789abcdef",
                    "checked_at": "2026-07-30T12:00:00Z",
                }

            result = wait_for_captcha_clearance(
                config,
                run.run_dir,
                timeout=0,
                inspector=inspector,
                sleep=clock.sleep,
                monotonic=clock.monotonic,
            )
            state = load_captcha_state(run.run_dir)
            self.assertEqual(result["status"], "human_required")
            self.assertTrue(result["human_handoff"])
            self.assertIsNotNone(state)
            assert state is not None
            self.assertEqual(state["status"], "human_required")
            self.assertTrue(state["human_handoff"])

    def test_state_summary_context_and_relay_show_are_metadata_only(self) -> None:
        sentinel = "SENTINEL_CAPTCHA_PRIVATE_991"
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha context fixture")
            write_captcha_state(
                run.run_dir,
                {
                    "status": "human_required",
                    "provider": "hCaptcha",
                    "next_action": "solve_in_visible_trusted_browser_then_resume",
                    "human_handoff": True,
                    "checked_at": "2026-07-30T12:00:00Z",
                },
            )
            summary = captcha_summary(run.run_dir)
            context = hermes_task_context(config, run.run_dir)
            relayed = relay_response(config, ["task", "captcha", run.run_id, "show"])
            combined = json.dumps({"summary": summary, "context": context, "relay": relayed.payload})
            self.assertEqual(relayed.exit_code, 0)
            self.assertEqual(relayed.payload["command"], "task.captcha.show")
            self.assertEqual(context["captcha"]["status"], "human_required")
            self.assertEqual(
                context["commands"]["captcha_resume"],
                f"scripts/chip-relay task captcha {run.run_id} resume",
            )
            self.assertNotIn(sentinel, combined)

            with (
                patch(
                    "chip_relay.relay_adapter.inspect_captcha_gate",
                    return_value={"status": "clear", "url": sentinel, "page_key": sentinel},
                ),
                patch(
                    "chip_relay.relay_adapter.captcha_summary",
                    return_value={
                        "status": "clear",
                        "provider": None,
                        "next_action": "continue_task",
                        "human_handoff": False,
                    },
                ),
            ):
                inspected = relay_response(config, ["task", "captcha", run.run_id, "inspect"])
            self.assertNotIn(sentinel, json.dumps(inspected.payload))

            with (
                patch(
                    "chip_relay.relay_adapter.inspect_captcha_gate",
                    return_value={"status": "clear"},
                ),
                patch(
                    "chip_relay.relay_adapter.captcha_summary",
                    return_value={
                        "status": "stale",
                        "provider": None,
                        "next_action": "run_captcha_inspect",
                        "human_handoff": False,
                    },
                ),
            ):
                raced = relay_response(config, ["task", "captcha", run.run_id, "inspect"])
            self.assertEqual(raced.exit_code, 1)
            self.assertEqual(raced.payload["status"], "stale")

    def test_invalid_time_bounds_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha bounds fixture")
            with self.assertRaisesRegex(CaptchaGateError, "invalid_captcha_timeout"):
                wait_for_captcha_clearance(config, run.run_dir, timeout=3601)
            with self.assertRaisesRegex(CaptchaGateError, "invalid_captcha_timeout"):
                wait_for_captcha_clearance(config, run.run_dir, timeout=float("nan"))
            with self.assertRaisesRegex(CaptchaGateError, "invalid_captcha_poll_interval"):
                wait_for_captcha_clearance(config, run.run_dir, poll_interval=0)
            with self.assertRaisesRegex(CaptchaGateError, "invalid_captcha_poll_interval"):
                wait_for_captcha_clearance(config, run.run_dir, poll_interval=float("inf"))
            bad_index = relay_response(config, ["task", "captcha", run.run_id, "inspect", "--page-index", "bad"])
            self.assertEqual(bad_index.payload["failed_gate"], "usage")
            bad_timeout = relay_response(config, ["task", "captcha", run.run_id, "wait", "--timeout", "bad"])
            self.assertEqual(bad_timeout.payload["failed_gate"], "usage")

    def test_forged_state_is_not_echoed_by_operator_summary(self) -> None:
        sentinel = "SENTINEL_FORGED_CAPTCHA_STATE_73"
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha forged state fixture")
            with self.assertRaisesRegex(CaptchaGateError, "malformed_captcha_state"):
                write_captcha_state(
                    run.run_dir,
                    {
                        "status": "human_required",
                        "provider": sentinel,
                        "next_action": sentinel,
                        "human_handoff": True,
                    },
                )

            write_captcha_state(
                run.run_dir,
                {
                    "status": "human_required",
                    "provider": "hCaptcha",
                    "next_action": "solve_in_visible_trusted_browser_then_resume",
                    "human_handoff": True,
                    "private_extra": sentinel,
                    "url": f"https://private.invalid/{sentinel}",
                },
            )
            state_path = run.run_dir / "protection" / "captcha-state.json"
            self.assertNotIn(sentinel, state_path.read_text(encoding="utf-8"))
            forged = json.loads(state_path.read_text(encoding="utf-8"))
            forged["next_action"] = "continue_task"
            state_path.write_text(json.dumps(forged), encoding="utf-8")
            with self.assertRaisesRegex(CaptchaGateError, "malformed_captcha_state"):
                load_captcha_state(run.run_dir)
            summary = captcha_summary(run.run_dir)
            self.assertEqual(summary["status"], "stale")
            self.assertNotIn(sentinel, json.dumps(summary))

    def test_state_is_invalidated_by_a_new_task_execution_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha attempt binding fixture")
            write_captcha_state(
                run.run_dir,
                {
                    "status": "clear",
                    "provider": None,
                    "next_action": "continue_task",
                    "human_handoff": False,
                    "checked_at": "2026-07-30T12:00:00Z",
                },
            )
            initial_state = load_captcha_state(run.run_dir)
            self.assertIsNotNone(initial_state)
            assert initial_state is not None
            old_attempt_marker = initial_state["attempt_marker"]
            self.assertEqual(captcha_summary(run.run_dir)["status"], "clear")
            executed = run_final_script(run.run_dir, config=config)
            self.assertEqual(executed.status, "ran")
            self.assertEqual(captcha_summary(run.run_dir)["status"], "stale")
            with self.assertRaisesRegex(CaptchaGateError, "captcha_attempt_changed"):
                write_captcha_state(
                    run.run_dir,
                    {
                        "status": "clear",
                        "provider": None,
                        "next_action": "continue_task",
                        "human_handoff": False,
                    },
                    expected_attempt_marker=old_attempt_marker,
                )

    def test_attempt_change_during_private_write_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha state write race")
            write_captcha_state(
                run.run_dir,
                {
                    "status": "clear",
                    "provider": None,
                    "next_action": "continue_task",
                    "human_handoff": False,
                },
            )
            state = load_captcha_state(run.run_dir)
            self.assertIsNotNone(state)
            assert state is not None
            expected_marker = state["attempt_marker"]
            original_private_write = captcha_mod._write_private_state

            def racing_private_write(run_dir: pathlib.Path, payload: dict[str, object]) -> None:
                begin_execution_attempt(run_dir, load_manifest(run_dir), source="captcha_race_test")
                original_private_write(run_dir, payload)

            with patch.object(captcha_mod, "_write_private_state", side_effect=racing_private_write):
                with self.assertRaisesRegex(CaptchaGateError, "captcha_attempt_changed"):
                    write_captcha_state(
                        run.run_dir,
                        {
                            "status": "clear",
                            "provider": None,
                            "next_action": "continue_task",
                            "human_handoff": False,
                        },
                        expected_attempt_marker=expected_marker,
                    )
            self.assertEqual(captcha_summary(run.run_dir)["status"], "stale")

    def test_fifo_and_unsafe_permissions_fail_closed_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha state path safety")
            state_path = run.run_dir / "protection" / "captcha-state.json"
            write_captcha_state(
                run.run_dir,
                {
                    "status": "clear",
                    "provider": None,
                    "next_action": "continue_task",
                    "human_handoff": False,
                },
            )
            state_path.chmod(0o644)
            self.assertEqual(captcha_summary(run.run_dir)["status"], "stale")

            state_path.unlink()
            os.mkfifo(state_path, 0o600)
            self.assertEqual(captcha_summary(run.run_dir)["status"], "stale")

    def test_symlinked_protection_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha state directory safety")
            protection_dir = run.run_dir / "protection"
            if protection_dir.exists():
                protection_dir.rmdir()
            outside = base / "outside"
            outside.mkdir()
            protection_dir.symlink_to(outside, target_is_directory=True)

            self.assertEqual(captcha_summary(run.run_dir)["status"], "stale")
            with self.assertRaisesRegex(CaptchaGateError, "unsafe_captcha_state_path"):
                write_captcha_state(
                    run.run_dir,
                    {
                        "status": "clear",
                        "provider": None,
                        "next_action": "continue_task",
                        "human_handoff": False,
                    },
                )


if __name__ == "__main__":
    unittest.main()
