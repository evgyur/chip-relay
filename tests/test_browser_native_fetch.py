from __future__ import annotations

import base64
import contextlib
import json
import os
import pathlib
import stat
import tempfile
import threading
import types
import unittest
from unittest import mock

from chip_relay.artifacts import list_browser_fetch_artifacts
from chip_relay.browser_fetch import BrowserFetchError, browser_native_fetch
from chip_relay.capabilities import BrowserFetchPolicy, CapabilityContractError
from chip_relay.config import RelayConfig
from chip_relay.playwright_runner import _run_final_script_locked, browser_fetch_for_current_run
from chip_relay.reports import artifact_metadata
from chip_relay.workspace import read_private_body_artifact, write_manifest


class FakePage:
    def __init__(self, payload: dict, url: str = "https://example.test/app") -> None:
        self.url = url
        self.payload = payload
        self.calls: list[tuple[str, dict]] = []

    def evaluate(self, script: str, argument: dict) -> dict:
        self.calls.append((script, argument))
        return dict(self.payload)


def success_payload(body: bytes = b'{"ok":true}', *, content_type: str = "application/json") -> dict:
    return {
        "kind": "ok",
        "status": 200,
        "url": "https://example.test/api/items?limit=1",
        "contentType": content_type,
        "declaredLength": str(len(body)),
        "size": len(body),
        "bodyB64": base64.b64encode(body).decode("ascii"),
    }


class BrowserNativeFetchTests(unittest.TestCase):
    def _run_dir(self, root: pathlib.Path) -> pathlib.Path:
        run_dir = root / "run"
        run_dir.mkdir(mode=0o700)
        write_manifest(
            run_dir,
            {
                "run_id": "test-run",
                "artifacts": [],
                "execution": {
                    "generation": 0,
                    "attempt_id": "attempt-000000000000",
                    "phase": "initialized",
                    "source": "init",
                    "started_at": None,
                    "completed_at": None,
                    "captcha_visual_cycle": 0,
                },
            },
        )
        return run_dir

    def test_relative_get_returns_metadata_and_private_opaque_body(self) -> None:
        sentinel = b'cookie-and-header-sentinel:{"ok":true}'
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = FakePage(success_payload(sentinel))
            result = browser_native_fetch(page, run_dir, "/api/items?limit=1")

            public = result.as_public_dict()
            serialized = json.dumps(public, sort_keys=True)
            self.assertNotIn(sentinel.decode(), serialized)
            self.assertNotIn("bodyB64", serialized)
            self.assertNotIn("raw_body", serialized)
            self.assertNotIn("cookie", serialized.lower())
            self.assertEqual(public["status"], 200)
            self.assertTrue(public["body_handle"].startswith("body-"))

            token = result.body_handle.removeprefix("body-")
            body_path = run_dir / "artifacts" / "private" / "browser-fetch" / f"{token}.body"
            self.assertEqual(read_private_body_artifact(run_dir, result.body_handle), sentinel)
            self.assertEqual(stat.S_IMODE(body_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(body_path.parent.stat().st_mode), 0o700)

            records = list_browser_fetch_artifacts(run_dir)
            self.assertEqual(len(records), 1)
            records_text = json.dumps(records, sort_keys=True)
            self.assertNotIn(sentinel.decode(), records_text)
            self.assertNotIn(str(body_path), records_text)
            manifest_text = (run_dir / "manifest.json").read_text(encoding="utf-8")
            self.assertNotIn(sentinel.decode(), manifest_text)
            self.assertFalse(any("browser-fetch" in item["path"] for item in artifact_metadata(run_dir)))
            script, argument = page.calls[0]
            self.assertIn('credentials: "include"', script)
            self.assertIn('redirect: "manual"', script)
            self.assertEqual(argument["url"], "https://example.test/api/items?limit=1")
            self.assertEqual(argument["method"], "GET")

    def test_browser_rejections_abort_the_underlying_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = FakePage({"kind": "unsupported_type"})
            with self.assertRaisesRegex(BrowserFetchError, "fetch_content_type"):
                browser_native_fetch(page, run_dir, "/private")
            script = page.calls[0][0]
            rejection_helper = script.split("const rejectResponse = async", 1)
            self.assertEqual(len(rejection_helper), 2)
            self.assertIn("controller.abort();", rejection_helper[1])

    def test_head_is_allowed_without_materializing_a_body_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            payload = success_payload(b"")
            page = FakePage(payload)
            result = browser_native_fetch(page, run_dir, "/api/items?limit=1", method="HEAD")
            self.assertIsNone(result.body_handle)
            self.assertEqual(list_browser_fetch_artifacts(run_dir)[0]["body_handle"], None)
            self.assertEqual(page.calls[0][1]["method"], "HEAD")

    def test_absolute_scheme_relative_methods_and_protected_purposes_fail_before_browser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = FakePage(success_payload())
            for path in ("https://example.test/api", "//example.test/api", "/../admin"):
                with self.subTest(path=path), self.assertRaises(BrowserFetchError):
                    browser_native_fetch(page, run_dir, path)
            with self.assertRaises(BrowserFetchError):
                browser_native_fetch(page, run_dir, "/api", method="POST")
            with self.assertRaises(BrowserFetchError):
                browser_native_fetch(page, run_dir, "/api", purpose="captcha")
            self.assertFalse(page.calls)

    def test_redirect_type_timeout_oversize_and_origin_change_fail_without_artifacts(self) -> None:
        cases = [
            ({"kind": "redirect"}, "fetch_redirect"),
            ({"kind": "unsupported_type"}, "fetch_content_type"),
            ({"kind": "timeout"}, "fetch_timeout"),
            ({"kind": "oversize"}, "fetch_oversize"),
            ({"kind": "uncertain"}, "fetch_uncertain"),
            ({**success_payload(), "url": "https://other.test/api/items?limit=1"}, "fetch_origin_changed"),
        ]
        for payload, error in cases:
            with self.subTest(error=error), tempfile.TemporaryDirectory() as tmp:
                run_dir = self._run_dir(pathlib.Path(tmp))
                page = FakePage(payload)
                with self.assertRaisesRegex(BrowserFetchError, error):
                    browser_native_fetch(page, run_dir, "/api/items?limit=1")
                self.assertEqual(list_browser_fetch_artifacts(run_dir), [])

    def test_malformed_or_mismatched_body_fails_closed(self) -> None:
        payloads = [
            {**success_payload(), "bodyB64": "not-base64"},
            {**success_payload(), "size": 999},
            {**success_payload(), "status": 99},
        ]
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                run_dir = self._run_dir(pathlib.Path(tmp))
                with self.assertRaises(BrowserFetchError):
                    browser_native_fetch(FakePage(payload), run_dir, "/api/items?limit=1")
                self.assertEqual(list_browser_fetch_artifacts(run_dir), [])

    def test_symlinked_private_artifact_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            run_dir = self._run_dir(pathlib.Path(tmp))
            os.symlink(outside, run_dir / "artifacts")
            with self.assertRaises(BrowserFetchError):
                browser_native_fetch(FakePage(success_payload()), run_dir, "/api/items?limit=1")
            self.assertEqual(list(pathlib.Path(outside).iterdir()), [])

    def test_concurrency_is_fail_closed_at_one(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class BlockingPage(FakePage):
            def evaluate(self, script: str, argument: dict) -> dict:
                entered.set()
                release.wait(5)
                return super().evaluate(script, argument)

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = BlockingPage(success_payload())
            failures: list[Exception] = []

            def first() -> None:
                try:
                    browser_native_fetch(page, run_dir, "/api/items?limit=1")
                except Exception as exc:
                    failures.append(exc)

            worker = threading.Thread(target=first)
            worker.start()
            self.assertTrue(entered.wait(2))
            with self.assertRaisesRegex(BrowserFetchError, "fetch_concurrency"):
                browser_native_fetch(page, run_dir, "/api/items?limit=1")
            release.set()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])

    def test_policy_caps_are_forwarded_to_browser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = FakePage(success_payload(b"ok", content_type="text/plain"))
            policy = BrowserFetchPolicy(max_bytes=8, timeout_ms=250, content_types=("text/plain",))
            browser_native_fetch(page, run_dir, "/api/items?limit=1", policy=policy)
            argument = page.calls[0][1]
            self.assertEqual(argument["maxBytes"], 8)
            self.assertEqual(argument["timeoutMs"], 250)
            self.assertEqual(argument["contentTypes"], ["text/plain"])

    def test_runner_adapter_binds_the_current_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = FakePage(success_payload())
            old = os.environ.get("CHIP_RELAY_RUN_DIR")
            try:
                os.environ["CHIP_RELAY_RUN_DIR"] = str(run_dir)
                result = browser_fetch_for_current_run(page, "/api/items?limit=1")
                self.assertEqual(read_private_body_artifact(run_dir, result.body_handle or ""), b'{"ok":true}')
            finally:
                if old is None:
                    os.environ.pop("CHIP_RELAY_RUN_DIR", None)
                else:
                    os.environ["CHIP_RELAY_RUN_DIR"] = old

    def test_manifest_failure_removes_body_or_reports_cleanup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = self._run_dir(pathlib.Path(tmp))
            page = FakePage(success_payload())
            with mock.patch("chip_relay.browser_fetch.record_browser_fetch_artifact", side_effect=OSError("manifest")):
                with self.assertRaisesRegex(BrowserFetchError, "fetch_artifact"):
                    browser_native_fetch(page, run_dir, "/api/items?limit=1")
            body_dir = run_dir / "artifacts" / "private" / "browser-fetch"
            self.assertEqual(list(body_dir.glob("*.body")), [])

            with (
                mock.patch("chip_relay.browser_fetch.record_browser_fetch_artifact", side_effect=OSError("manifest")),
                mock.patch("chip_relay.browser_fetch.remove_private_body_artifact", side_effect=OSError("cleanup")),
                self.assertRaisesRegex(BrowserFetchError, "fetch_artifact_cleanup_failed"),
            ):
                browser_native_fetch(FakePage(success_payload()), run_dir, "/api/items?limit=1")

    def test_task_runner_overwrites_stale_parent_run_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "authoritative-run"
            (run_dir / "scripts").mkdir(parents=True)
            (run_dir / "logs").mkdir()
            (run_dir / "scripts" / "final.py").write_text("pass\n", encoding="utf-8")
            captured: dict[str, object] = {}

            def fake_run(*args: object, **kwargs: object) -> types.SimpleNamespace:
                del args
                captured.update(kwargs)
                return types.SimpleNamespace(stdout="", stderr="", returncode=0)

            base = pathlib.Path(tmp) / "base"
            config = RelayConfig(
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
                proxy_auth=None,
            )
            manifest = {"run_id": "authoritative-run"}
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        "CHIP_RELAY_RUN_DIR": "/tmp/stale-run",
                        "CHIP_RELAY_CDP_URL": "http://127.0.0.1:19999",
                        "CHIP_RELAY_PROXY_SECRET_FILE": "/tmp/stale-secret",
                    },
                    clear=False,
                ),
                mock.patch("chip_relay.playwright_runner.load_manifest", return_value=manifest),
                mock.patch("chip_relay.playwright_runner.begin_execution_attempt", return_value=manifest),
                mock.patch("chip_relay.playwright_runner.execution_marker", return_value={"attempt_id": "attempt-1"}),
                mock.patch("chip_relay.playwright_runner._update_run_manifest"),
                mock.patch("chip_relay.playwright_runner.subprocess.run", side_effect=fake_run),
            ):
                result = _run_final_script_locked(run_dir, config=config, timeout=1)
            self.assertEqual(result.status, "ran")
            child_env = captured["env"]
            assert isinstance(child_env, dict)
            self.assertEqual(child_env["CHIP_RELAY_RUN_DIR"], str(run_dir))
            self.assertEqual(child_env["CHIP_RELAY_CDP_URL"], config.cdp_url)
            self.assertNotIn("CHIP_RELAY_PROXY_SECRET_FILE", child_env)

    def test_task_runner_rejects_success_after_proxy_auth_runtime_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = pathlib.Path(tmp) / "run"
            (run_dir / "scripts").mkdir(parents=True)
            (run_dir / "logs").mkdir()
            (run_dir / "scripts" / "final.py").write_text("pass\n", encoding="utf-8")
            base = pathlib.Path(tmp) / "base"
            config = RelayConfig(
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
                proxy_auth=None,
            )
            manifest = {"run_id": "run"}

            @contextlib.contextmanager
            def failed_proxy_session(*_args: object, **_kwargs: object):
                yield object()
                raise CapabilityContractError("proxy_auth_runtime")

            completed = types.SimpleNamespace(returncode=0, stdout="ok", stderr="")
            with (
                mock.patch("chip_relay.playwright_runner.load_manifest", return_value=manifest),
                mock.patch("chip_relay.playwright_runner.begin_execution_attempt", return_value=manifest),
                mock.patch("chip_relay.playwright_runner.execution_marker", return_value={"attempt_id": "attempt-1"}),
                mock.patch("chip_relay.playwright_runner._update_run_manifest"),
                mock.patch("chip_relay.playwright_runner.proxy_auth_session", failed_proxy_session),
                mock.patch("chip_relay.playwright_runner.subprocess.run", return_value=completed),
            ):
                result = _run_final_script_locked(run_dir, config=config, timeout=1)
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.exit_code, 78)
            self.assertEqual(result.failed_gate, "proxy_auth_failed")
