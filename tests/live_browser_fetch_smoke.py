#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import http.server
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from typing import Any

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from chip_relay.browser_fetch import BrowserFetchError, browser_native_fetch
from chip_relay.capabilities import BrowserFetchPolicy
from chip_relay.playwright_runner import browser_fetch_for_current_run
from chip_relay.workspace import read_private_body_artifact, write_manifest


_COOKIE_VALUE = "browser-cookie-sentinel"
_PRIVATE_BODY = b'{"private":"browser-body-sentinel"}'


class OriginHandler(http.server.BaseHTTPRequestHandler):
    stream_bytes = 0
    stream_lock = threading.Lock()
    stream_disconnected = threading.Event()

    def do_GET(self) -> None:
        if self.path == "/seed":
            body = b"seeded"
            self.send_response(200)
            self.send_header("Set-Cookie", f"relay_session={_COOKIE_VALUE}; HttpOnly; SameSite=Strict; Path=/")
            self.send_header("Content-Type", "text/plain")
        elif self.path == "/private" and f"relay_session={_COOKIE_VALUE}" in self.headers.get("Cookie", ""):
            body = _PRIVATE_BODY
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/private")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif self.path == "/oversize":
            body = b'{"padding":"012345678901234567890123456789"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/html":
            body = b"<html>not allowed</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        elif self.path == "/slow":
            time.sleep(0.75)
            body = b'{"late":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/disconnect":
            with contextlib.suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            chunk = b"x" * 65536
            try:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    with type(self).stream_lock:
                        type(self).stream_bytes += len(chunk)
            except (BrokenPipeError, ConnectionResetError, OSError):
                type(self).stream_disconnected.set()
            return
        else:
            body = b"denied"
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args
        return


class ThreadingServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class OriginChangedPage:
    def __init__(self, page: Any) -> None:
        self._page = page
        self.url = page.url

    def evaluate(self, script: str, argument: dict[str, Any]) -> Any:
        self._page.goto("about:blank", wait_until="domcontentloaded", timeout=5_000)
        return self._page.evaluate(script, argument)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_cdp(cdp_url: str) -> dict:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(cdp_url + "/json/version", timeout=0.5) as response:
                return json.loads(response.read())
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("live_smoke_cdp_timeout")


def write_run_manifest(run_dir: pathlib.Path) -> None:
    run_dir.mkdir(mode=0o700)
    write_manifest(
        run_dir,
        {
            "run_id": "live-browser-fetch-smoke",
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


def browser_args(browser_path: pathlib.Path, profile: pathlib.Path, cdp_port: int) -> list[str]:
    switches_path = pathlib.Path(
        "/opt/cloakbrowser/venv/lib/python3.12/site-packages/playwright/driver/package/lib/server/chromium/chromiumSwitches.js"
    )
    node = shutil.which("node")
    if node is None or not switches_path.is_file():
        raise RuntimeError("live_smoke_playwright_switches_missing")
    script = f"console.log(JSON.stringify(require('{switches_path}').chromiumSwitches(false)))"
    switches = json.loads(subprocess.check_output([node, "-e", script], text=True))
    return [
        str(browser_path),
        *switches,
        "--headless",
        "--hide-scrollbars",
        "--mute-audio",
        "--no-sandbox",
        "--disable-dev-shm-usage",
        f"--remote-debugging-port={cdp_port}",
        f"--user-data-dir={profile}",
        "about:blank",
    ]


def navigate_and_prove(page: Any, url: str) -> None:
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=10_000)
    except PlaywrightError:
        pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if page.url == url and page.locator("body").inner_text(timeout=500) == "seeded":
                return
        except PlaywrightError:
            pass
        time.sleep(0.05)
    raise RuntimeError("live_smoke_seed_navigation")


def run_smoke() -> dict:
    browser_path = pathlib.Path.home() / ".cache/ms-playwright/chromium-1181/chrome-linux/chrome"
    if not browser_path.is_file():
        raise RuntimeError("live_smoke_browser_missing")
    OriginHandler.stream_bytes = 0
    OriginHandler.stream_disconnected.clear()
    origin = ThreadingServer(("127.0.0.1", 0), OriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    origin_port = int(origin.server_address[1])
    cdp_port = free_port()
    cdp_url = f"http://127.0.0.1:{cdp_port}"
    seed_url = f"http://127.0.0.1:{origin_port}/seed"
    profile = pathlib.Path(tempfile.mkdtemp(prefix="chip-relay-fetch-profile-"))
    run_root = pathlib.Path(tempfile.mkdtemp(prefix="chip-relay-fetch-run-"))
    run_dir = run_root / "run"
    write_run_manifest(run_dir)
    proc: subprocess.Popen[bytes] | None = None
    browser = None
    old_run_dir = os.environ.get("CHIP_RELAY_RUN_DIR")
    result_payload: dict = {}
    try:
        proc = subprocess.Popen(
            browser_args(browser_path, profile, cdp_port),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        version = wait_cdp(cdp_url)
        os.environ["CHIP_RELAY_RUN_DIR"] = str(run_dir)
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(cdp_url)
            context = browser.contexts[0]
            page = context.pages[0] if context.pages else context.new_page()
            navigate_and_prove(page, seed_url)
            session = context.new_cdp_session(page)
            target_info = session.send("Target.getTargetInfo").get("targetInfo", {})
            result = browser_fetch_for_current_run(page, "/private")
            private_body = read_private_body_artifact(run_dir, result.body_handle or "")
            negative_cases = (
                ("/redirect", None, "fetch_redirect"),
                ("/oversize", BrowserFetchPolicy(max_bytes=8), "fetch_oversize"),
                ("/html", BrowserFetchPolicy(content_types=("application/json",)), "fetch_content_type"),
                ("/slow", BrowserFetchPolicy(timeout_ms=250), "fetch_timeout"),
                ("/disconnect", None, "fetch_uncertain"),
                ("/stream", BrowserFetchPolicy(max_bytes=1024), "fetch_oversize"),
            )
            for path, policy, expected_error in negative_cases:
                try:
                    browser_fetch_for_current_run(page, path, policy=policy)
                except BrowserFetchError as exc:
                    if str(exc) != expected_error:
                        raise RuntimeError("live_smoke_negative_classification") from exc
                else:
                    raise RuntimeError(f"live_smoke_negative_accepted:{path}")
            with OriginHandler.stream_lock:
                stream_bytes_at_return = OriginHandler.stream_bytes
            if not OriginHandler.stream_disconnected.wait(0.5):
                raise RuntimeError("live_smoke_stream_not_aborted")
            with OriginHandler.stream_lock:
                stream_bytes_after_abort = OriginHandler.stream_bytes
            if stream_bytes_after_abort - stream_bytes_at_return > 2 * 1_048_576:
                raise RuntimeError(
                    f"live_smoke_stream_continued:{stream_bytes_at_return}:{stream_bytes_after_abort}"
                )
            try:
                browser_native_fetch(OriginChangedPage(page), run_dir, "/private")
            except BrowserFetchError as exc:
                if str(exc) != "fetch_origin_changed":
                    raise RuntimeError("live_smoke_origin_classification") from exc
            else:
                raise RuntimeError("live_smoke_origin_accepted")
            manifest_text = (run_dir / "manifest.json").read_text(encoding="utf-8")
            manifest_payload = json.loads(manifest_text)
            if private_body != _PRIVATE_BODY:
                raise RuntimeError("live_smoke_private_body")
            if _PRIVATE_BODY.decode() in manifest_text or _COOKIE_VALUE in manifest_text:
                raise RuntimeError("live_smoke_metadata_leak")
            if len(manifest_payload.get("artifacts", [])) != 1:
                raise RuntimeError("live_smoke_failure_artifact")
            result_payload = {
                "status": "ok",
                "tests_run": 1,
                "skipped": 0,
                "cookie_reused": result.status == 200,
                "negative_behaviors": True,
                "stream_abort_verified": True,
                "browser_pid": proc.pid,
                "browser_executable": str(browser_path.resolve()),
                "cdp_target_identity": str(target_info.get("targetId", "")),
                "cdp_browser": str(version.get("Browser", "")),
            }
            browser.close()
            browser = None
    finally:
        if old_run_dir is None:
            os.environ.pop("CHIP_RELAY_RUN_DIR", None)
        else:
            os.environ["CHIP_RELAY_RUN_DIR"] = old_run_dir
        if browser is not None:
            with contextlib.suppress(Exception):
                browser.close()
        if proc is not None and proc.poll() is None:
            proc.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=5)
        shutil.rmtree(profile, ignore_errors=True)
        shutil.rmtree(run_root, ignore_errors=True)
    result_payload["cleanup_verified"] = (
        proc is not None
        and proc.poll() is not None
        and not profile.exists()
        and not run_root.exists()
        and not origin_thread.is_alive()
    )
    return result_payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-live", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--expect-tests", type=int, default=1)
    parser.add_argument("--expect-skipped", type=int, default=0)
    args = parser.parse_args()
    try:
        payload = run_smoke()
        if payload.get("tests_run") != args.expect_tests or payload.get("skipped") != args.expect_skipped:
            raise RuntimeError("live_smoke_expectation")
        if (
            not payload.get("cookie_reused")
            or not payload.get("negative_behaviors")
            or not payload.get("stream_abort_verified")
            or not payload.get("cleanup_verified")
        ):
            raise RuntimeError("live_smoke_assertion")
    except Exception as exc:
        message = str(exc).splitlines()[0][:_MAX_ERROR] if str(exc) else type(exc).__name__
        message = message.replace(_COOKIE_VALUE, "[REDACTED]").replace(_PRIVATE_BODY.decode(), "[REDACTED]")
        payload = {"status": "failed", "tests_run": 0, "skipped": 0, "error": message}
        print(json.dumps(payload, sort_keys=True))
        return 1
    print(json.dumps(payload, sort_keys=True) if args.json else payload)
    return 0


_MAX_ERROR = 160


if __name__ == "__main__":
    raise SystemExit(main())
