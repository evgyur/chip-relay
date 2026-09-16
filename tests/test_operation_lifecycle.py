#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest import mock

from chip_relay.captcha import (
    attempt_safe_captcha_activation,
    wait_for_captcha_clearance,
    write_captcha_state,
)
from chip_relay.captcha_visual import (
    CaptchaVisualError,
    apply_captcha_visual_actions,
    capture_captcha_visual,
)
from chip_relay.config import RelayConfig
from chip_relay.human_handoff import (
    HumanHandoffError,
    cancel_handoff,
    handoff_summary,
    request_handoff,
    resolve_handoff,
)
from chip_relay.operation_audit import OperationAuditError, audit_summary, begin_operation
from chip_relay.playwright_runner import run_final_script
from chip_relay.relay_adapter import relay_response
from chip_relay.workspace import begin_execution_attempt, init_run, load_manifest


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


def agent_captcha_state() -> dict[str, object]:
    return {
        "status": "agent_action",
        "provider": "hCaptcha",
        "title_classification": "captcha",
        "interactive": True,
        "visible_widget_count": 1,
        "response_field_count": 1,
        "token_present": False,
        "next_action": "attempt_safe_native_activation",
        "automation": "browser-native-then-agent-visual",
        "human_handoff": False,
        "claim_policy": "best-effort/no-guaranteed-solve",
        "page_index": 0,
        "page_count": 1,
        "page_key": "0123456789abcdef",
        "checked_at": "2026-09-16T12:00:00Z",
    }


class OperationLifecycleTests(unittest.TestCase):
    def test_audit_distinguishes_pre_dispatch_failure_unknown_and_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = init_run(make_config(pathlib.Path(tmp)), "operation audit")
            failed = begin_operation(run.run_dir, "browser.preflight", effect_class="browser-state")
            failed.finish("failed", error_class="target_unavailable")

            unknown = begin_operation(run.run_dir, "browser.click", effect_class="browser-state")
            unknown.mark_dispatched()
            with self.assertRaisesRegex(OperationAuditError, "dispatched_effect_must_not_be_failed"):
                unknown.finish("failed", error_class="timeout")
            unknown.finish("unknown", error_class="timeout")

            succeeded = begin_operation(
                run.run_dir,
                "browser.observe",
                effect_class="read-only",
                context={"origin": "https://example.com/private/path?secret=1"},
            )
            succeeded.mark_dispatched()
            succeeded.finish("succeeded", context={"origin": "https://example.com/another"})

            summary = audit_summary(run.run_dir)
            self.assertEqual(summary["terminal_counts"]["failed"], 1)
            self.assertEqual(summary["terminal_counts"]["unknown"], 1)
            self.assertEqual(summary["terminal_counts"]["succeeded"], 1)
            self.assertEqual(summary["pending_count"], 0)
            audit_path = run.run_dir / "audit" / "operations.jsonl"
            text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn("private/path", text)
            self.assertNotIn("secret=1", text)
            self.assertIn("https://example.com", text)
            self.assertEqual(audit_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(audit_path.parent.stat().st_mode & 0o777, 0o700)

    def test_pending_operation_is_reported_interrupted_and_context_is_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = init_run(make_config(pathlib.Path(tmp)), "pending operation")
            begin_operation(run.run_dir, "browser.pending", effect_class="external")
            summary = audit_summary(run.run_dir)
            self.assertEqual(summary["pending_count"], 1)
            self.assertEqual(summary["pending_effect_state"], "interrupted")
            with self.assertRaisesRegex(OperationAuditError, "invalid_operation_audit_context"):
                begin_operation(
                    run.run_dir,
                    "browser.bad_context",
                    effect_class="read-only",
                    context={"input_value": "SENTINEL_SECRET"},
                )

    def test_completed_audit_expires_after_thirty_days(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = init_run(make_config(pathlib.Path(tmp)), "audit retention")
            operation = begin_operation(run.run_dir, "browser.old", effect_class="read-only")
            operation.finish("succeeded")
            audit_path = run.run_dir / "audit" / "operations.jsonl"
            rewritten = []
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                event = json.loads(line)
                event["at"] = "2020-01-01T00:00:00Z"
                rewritten.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
            audit_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
            audit_path.chmod(0o600)
            summary = audit_summary(run.run_dir)
            self.assertEqual(summary["event_count"], 0)
            self.assertEqual(audit_path.stat().st_size, 0)

    def test_handoff_is_redacted_attempt_bound_and_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = init_run(make_config(pathlib.Path(tmp)), "human handoff")
            requested = request_handoff(
                run.run_dir,
                kind="two_factor",
                reason_code="second_factor_required",
                timeout_seconds=600,
                page_key="0123456789abcdef",
                provider="identity-provider",
            )
            self.assertEqual(requested["status"], "waiting")
            self.assertTrue(requested["human_required"])
            state_path = run.run_dir / "handoff" / "state.json"
            state = state_path.read_text(encoding="utf-8")
            self.assertNotIn("SENTINEL_OTP_123456", state)
            self.assertNotIn("input_value", state)
            self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)
            resolved = resolve_handoff(run.run_dir, requested["handoff_id"])
            self.assertEqual(resolved["status"], "resolved")
            self.assertFalse(resolved["human_required"])
            self.assertEqual(handoff_summary(run.run_dir)["status"], "resolved")
            self.assertEqual(audit_summary(run.run_dir)["handoff_counts"]["resolved"], 1)

            next_request = request_handoff(
                run.run_dir,
                kind="consent",
                reason_code="user_consent_required",
                timeout_seconds=600,
            )
            cancelled = cancel_handoff(run.run_dir, next_request["handoff_id"])
            self.assertEqual(cancelled["status"], "cancelled")

    def test_handoff_is_attempt_bound_and_stale_wait_does_not_block_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "handoff attempt binding")
            first = request_handoff(
                run.run_dir,
                kind="login",
                reason_code="credential_entry_required",
                timeout_seconds=600,
            )
            begin_execution_attempt(run.run_dir, load_manifest(run.run_dir), source="test")
            self.assertEqual(handoff_summary(run.run_dir)["status"], "stale")
            second = request_handoff(
                run.run_dir,
                kind="login",
                reason_code="credential_entry_required",
                timeout_seconds=600,
            )
            self.assertNotEqual(first["handoff_id"], second["handoff_id"])
            self.assertEqual(second["status"], "waiting")
            summary = audit_summary(run.run_dir)
            self.assertEqual(summary["handoff_counts"]["cancelled"], 1)
            self.assertEqual(summary["handoff_counts"]["waiting"], 2)

    def test_expired_handoffs_terminalize_consistently(self) -> None:
        base_time = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        for action in ("summary", "resolve", "cancel", "replace"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                run = init_run(make_config(pathlib.Path(tmp)), f"expired handoff {action}")
                with mock.patch("chip_relay.human_handoff._now", return_value=base_time):
                    requested = request_handoff(
                        run.run_dir,
                        kind="consent",
                        reason_code="user_consent_required",
                        timeout_seconds=30,
                    )
                expired_at = base_time + timedelta(seconds=31)
                with mock.patch("chip_relay.human_handoff._now", return_value=expired_at):
                    if action == "summary":
                        result = handoff_summary(run.run_dir)
                    elif action == "resolve":
                        result = resolve_handoff(run.run_dir, requested["handoff_id"])
                    elif action == "cancel":
                        result = cancel_handoff(run.run_dir, requested["handoff_id"])
                    else:
                        result = request_handoff(
                            run.run_dir,
                            kind="login",
                            reason_code="credential_entry_required",
                            timeout_seconds=30,
                        )
                if action == "replace":
                    self.assertEqual(result["status"], "waiting")
                    self.assertNotEqual(result["handoff_id"], requested["handoff_id"])
                else:
                    self.assertEqual(result["status"], "timed_out")
                self.assertEqual(audit_summary(run.run_dir)["handoff_counts"]["timed_out"], 1)

    def test_handoff_audit_outbox_recovers_without_reordering_or_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = init_run(make_config(pathlib.Path(tmp)), "handoff outbox")
            with mock.patch(
                "chip_relay.human_handoff.record_handoff_event",
                side_effect=RuntimeError("audit unavailable"),
            ):
                with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                    request_handoff(
                        run.run_dir,
                        kind="consent",
                        reason_code="user_consent_required",
                        timeout_seconds=600,
                    )
            recovered = request_handoff(
                run.run_dir,
                kind="consent",
                reason_code="user_consent_required",
                timeout_seconds=600,
            )
            resolved = resolve_handoff(run.run_dir, recovered["handoff_id"])
            self.assertEqual(resolved["status"], "resolved")
            audit_path = run.run_dir / "audit" / "operations.jsonl"
            transitions = [
                json.loads(line)["status"]
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if json.loads(line).get("event") == "human_handoff"
            ]
            self.assertEqual(transitions, ["waiting", "resolved"])

    def test_relay_projects_handoff_and_audit_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "relay lifecycle")
            requested = relay_response(
                config,
                [
                    "task",
                    "handoff",
                    run.run_id,
                    "request",
                    "--kind",
                    "consent",
                    "--reason-code",
                    "user_consent_required",
                ],
            )
            self.assertEqual(requested.exit_code, 0)
            self.assertEqual(requested.payload["handoff"]["status"], "waiting")
            audit = relay_response(config, ["task", "audit", run.run_id, "show"])
            self.assertEqual(audit.exit_code, 0)
            self.assertEqual(audit.payload["audit"]["handoff_counts"]["waiting"], 1)
            serialized = json.dumps({"requested": requested.payload, "audit": audit.payload})
            self.assertNotIn("input_value", serialized)
            self.assertNotIn("page_content", serialized)

    def test_captcha_native_no_candidate_moves_to_agent_visual_not_human(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha native")
            write_captcha_state(run.run_dir, agent_captcha_state())

            def inspector(*_args, **_kwargs):
                return dict(agent_captcha_state())

            result = attempt_safe_captcha_activation(
                config,
                run.run_dir,
                activator=lambda *_args: {
                    "attempted": False,
                    "reason_code": "activation_candidate_not_unique",
                },
                inspector=inspector,
            )
            self.assertEqual(result["status"], "agent_action")
            self.assertEqual(result["next_action"], "capture_and_solve_visually")
            self.assertFalse(result["human_handoff"])
            self.assertEqual(audit_summary(run.run_dir)["terminal_counts"]["succeeded"], 1)
            self.assertEqual(handoff_summary(run.run_dir)["status"], "none")
            repeated = attempt_safe_captcha_activation(
                config,
                run.run_dir,
                activator=lambda *_args: (_ for _ in ()).throw(AssertionError("must not retry native activation")),
                inspector=inspector,
            )
            self.assertEqual(repeated["reason_code"], "safe_activation_already_attempted")
            self.assertEqual(audit_summary(run.run_dir)["terminal_counts"]["succeeded"], 1)

    def test_captcha_partial_native_failure_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha native unknown")
            write_captcha_state(run.run_dir, agent_captcha_state())
            with self.assertRaisesRegex(RuntimeError, "partial"):
                attempt_safe_captcha_activation(
                    config,
                    run.run_dir,
                    activator=lambda *_args: (_ for _ in ()).throw(RuntimeError("partial")),
                )
            summary = audit_summary(run.run_dir)
            self.assertEqual(summary["terminal_counts"]["unknown"], 1)
            retry = attempt_safe_captcha_activation(
                config,
                run.run_dir,
                activator=lambda *_args: (_ for _ in ()).throw(
                    AssertionError("unknown native activation must not be retried")
                ),
            )
            self.assertEqual(retry["reason_code"], "safe_activation_already_attempted")
            self.assertEqual(audit_summary(run.run_dir)["terminal_counts"]["unknown"], 1)

    def test_concurrent_native_activation_dispatches_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha native concurrency")
            write_captcha_state(run.run_dir, agent_captcha_state())
            dispatch_count = 0
            count_lock = threading.Lock()

            def activator(*_args):
                nonlocal dispatch_count
                with count_lock:
                    dispatch_count += 1
                return {"attempted": False, "reason_code": "activation_candidate_not_unique"}

            def inspector(*_args, **_kwargs):
                return dict(agent_captcha_state())

            results: list[dict[str, Any]] = []
            failures: list[BaseException] = []

            def worker() -> None:
                try:
                    results.append(
                        attempt_safe_captcha_activation(
                            config,
                            run.run_dir,
                            activator=activator,
                            inspector=inspector,
                        )
                    )
                except BaseException as exc:  # pragma: no cover - asserted below
                    failures.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, [])
            self.assertEqual(dispatch_count, 1)
            self.assertEqual(len(results), 2)
            self.assertEqual(
                sorted(result["reason_code"] for result in results),
                ["activation_candidate_not_unique", "safe_activation_already_attempted"],
            )

    def test_stale_wait_observation_cannot_restore_native_allowance(self) -> None:
        for outcome in ("succeeded", "unknown"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                base = pathlib.Path(tmp)
                config = make_config(base)
                run = init_run(config, f"captcha stale wait {outcome}")
                write_captcha_state(run.run_dir, agent_captcha_state())
                dispatch_count = 0

                def activator(*_args):
                    nonlocal dispatch_count
                    dispatch_count += 1
                    if outcome == "unknown":
                        raise RuntimeError("post-dispatch-timeout")
                    return {"attempted": False, "reason_code": "activation_candidate_not_unique"}

                def stale_inspector(*_args, **_kwargs):
                    try:
                        attempt_safe_captcha_activation(
                            config,
                            run.run_dir,
                            activator=activator,
                            inspector=lambda *_args, **_kwargs: dict(agent_captcha_state()),
                        )
                    except RuntimeError:
                        pass
                    return dict(agent_captcha_state())

                waited = wait_for_captcha_clearance(
                    config,
                    run.run_dir,
                    timeout=0,
                    inspector=stale_inspector,
                )
                self.assertEqual(waited["status"], "agent_action")
                retry = attempt_safe_captcha_activation(
                    config,
                    run.run_dir,
                    activator=activator,
                )
                self.assertEqual(retry["reason_code"], "safe_activation_already_attempted")
                self.assertEqual(dispatch_count, 1)
                if outcome == "unknown":
                    self.assertEqual(audit_summary(run.run_dir)["terminal_counts"]["unknown"], 1)

    def test_stale_inspect_commit_cannot_restore_native_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha stale inspect")
            stale_observation = agent_captcha_state()
            write_captcha_state(run.run_dir, stale_observation)
            dispatch_count = 0

            def activator(*_args):
                nonlocal dispatch_count
                dispatch_count += 1
                return {"attempted": False, "reason_code": "activation_candidate_not_unique"}

            attempt_safe_captcha_activation(
                config,
                run.run_dir,
                activator=activator,
                inspector=lambda *_args, **_kwargs: dict(agent_captcha_state()),
            )
            write_captcha_state(run.run_dir, stale_observation)
            retry = attempt_safe_captcha_activation(
                config,
                run.run_dir,
                activator=activator,
            )
            self.assertEqual(retry["reason_code"], "safe_activation_already_attempted")
            self.assertEqual(dispatch_count, 1)

    def test_captcha_handoff_cannot_skip_self_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha handoff guard")
            write_captcha_state(run.run_dir, agent_captcha_state())
            with self.assertRaisesRegex(HumanHandoffError, "captcha_self_service_not_exhausted"):
                request_handoff(
                    run.run_dir,
                    kind="captcha",
                    reason_code="captcha_automation_exhausted",
                    timeout_seconds=600,
                )
            with self.assertRaisesRegex(HumanHandoffError, "captcha_self_service_not_exhausted"):
                request_handoff(
                    run.run_dir,
                    kind="captcha",
                    reason_code="captcha_visual_unavailable",
                    timeout_seconds=600,
                )
            visual_state = agent_captcha_state()
            visual_state.update(
                {
                    "native_attempts": 1,
                    "next_action": "capture_and_solve_visually",
                }
            )
            write_captcha_state(run.run_dir, visual_state)
            with self.assertRaisesRegex(CaptchaVisualError, "playwright_unavailable"):
                capture_captcha_visual(
                    config,
                    run.run_dir,
                    capturer=lambda *_args: (_ for _ in ()).throw(
                        CaptchaVisualError("playwright_unavailable")
                    ),
                )
            allowed = request_handoff(
                run.run_dir,
                kind="captcha",
                reason_code="captcha_visual_unavailable",
                timeout_seconds=600,
            )
            self.assertEqual(allowed["status"], "waiting")

    def test_captcha_human_handoff_starts_only_after_visual_budget_is_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "captcha visual exhaustion")
            initial = agent_captcha_state()
            initial.update({"native_attempts": 1, "next_action": "capture_and_solve_visually"})
            write_captcha_state(run.run_dir, initial)

            def inspector(*_args, **_kwargs):
                return dict(agent_captcha_state())

            for cycle in range(1, 4):
                capture_captcha_visual(
                    config,
                    run.run_dir,
                    capturer=lambda *_args: (
                        b"\x89PNG\r\n\x1a\nprivate-test",
                        {"x": 10, "y": 20, "width": 200, "height": 100},
                        "fedcba9876543210",
                    ),
                )
                result = apply_captcha_visual_actions(
                    config,
                    run.run_dir,
                    [(0.5, 0.5)],
                    confidence=0.95,
                    actioner=lambda *_args: None,
                    inspector=inspector,
                )
                if cycle < 3:
                    self.assertEqual(result["status"], "agent_action")
                    self.assertFalse(result["human_handoff"])
                    self.assertEqual(handoff_summary(run.run_dir)["status"], "none")
                else:
                    self.assertEqual(result["status"], "human_required")
                    self.assertTrue(result["human_handoff"])
                    self.assertEqual(result["handoff"]["status"], "waiting")
                    self.assertEqual(handoff_summary(run.run_dir)["kind"], "captcha")

    def test_final_script_exposes_effect_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            config = make_config(base)
            run = init_run(config, "final effect state")
            success = run_final_script(run.run_dir, config=config)
            self.assertEqual(success.effect_state, "succeeded")

            (run.run_dir / "scripts" / "final.py").write_text("raise SystemExit(3)\n", encoding="utf-8")
            failed = run_final_script(run.run_dir, config=config)
            self.assertEqual(failed.status, "failed")
            self.assertEqual(failed.effect_state, "unknown")
            summary = audit_summary(run.run_dir)
            self.assertEqual(summary["terminal_counts"]["succeeded"], 1)
            self.assertEqual(summary["terminal_counts"]["unknown"], 1)


if __name__ == "__main__":
    unittest.main()
