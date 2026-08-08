from __future__ import annotations

import json
import os
import pathlib
import base64
import contextlib
import http.server
import select
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from unittest import mock

import websocket

from chip_relay.capabilities import CapabilityContractError, ProxyAuthDescriptor
from chip_relay.config import load_config
from chip_relay.proxy import parse_proxy_config
from chip_relay.proxy_auth import (
    ProxyAuthController,
    ProxyCredentials,
    _browser_websocket_url,
    load_proxy_credentials,
    proxy_auth_session,
)


_FIXTURE_USER = "fixture-user"
_FIXTURE_PASSWORD = "fixture-pass"
_FIXTURE_AUTH = "Basic " + base64.b64encode(f"{_FIXTURE_USER}:{_FIXTURE_PASSWORD}".encode()).decode()


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _AuthenticatedProxy(socketserver.StreamRequestHandler):
    tls_port = 0
    http_hits = 0
    connect_hits = 0
    auth_failures = 0

    def handle(self) -> None:
        request_line = self.rfile.readline(65537)
        if not request_line:
            return
        headers: dict[str, str] = {}
        while True:
            raw = self.rfile.readline(65537)
            if raw in {b"\r\n", b"\n", b""}:
                break
            name, _, value = raw.decode("latin1").partition(":")
            headers[name.lower().strip()] = value.strip()
        if headers.get("proxy-authorization") != _FIXTURE_AUTH:
            type(self).auth_failures += 1
            self.wfile.write(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"chip-relay-test\"\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
            return
        method, target, _ = request_line.decode("latin1").strip().split(" ", 2)
        if method == "CONNECT":
            host, _, raw_port = target.rpartition(":")
            if host != "127.0.0.1" or int(raw_port) != type(self).tls_port:
                self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
            upstream = socket.create_connection((host, int(raw_port)), timeout=3)
            try:
                type(self).connect_hits += 1
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                self.wfile.flush()
                sockets = [self.connection, upstream]
                deadline = time.monotonic() + 10
                try:
                    while time.monotonic() < deadline:
                        readable, _, _ = select.select(sockets, [], [], 0.25)
                        if not readable:
                            continue
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            destination = upstream if source is self.connection else self.connection
                            destination.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
            finally:
                upstream.close()
            return
        type(self).http_hits += 1
        body = b"proxy-http-ok"
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )


class _TLSOrigin(http.server.BaseHTTPRequestHandler):
    def handle(self) -> None:
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            return

    def do_GET(self) -> None:
        body = b"proxy-https-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args
        return


class _RawCDP:
    def __init__(self, websocket_url: str) -> None:
        self.ws = websocket.create_connection(websocket_url, timeout=5, suppress_origin=True)
        self.next_id = 0

    def close(self) -> None:
        self.ws.close()

    def request(self, method: str, params: dict | None = None, session_id: str | None = None) -> dict:
        self.next_id += 1
        wanted = self.next_id
        message: dict = {"id": wanted, "method": method, "params": params or {}}
        if session_id:
            message["sessionId"] = session_id
        self.ws.send(json.dumps(message))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            payload = json.loads(self.ws.recv())
            if payload.get("id") == wanted:
                if "error" in payload:
                    raise RuntimeError(payload["error"])
                return payload.get("result") or {}
        raise RuntimeError(f"CDP timeout: {method}")


class _TimeoutWebSocket:
    def __init__(self) -> None:
        self.closed = False

    def settimeout(self, value: float) -> None:
        del value

    def send(self, payload: str) -> None:
        del payload

    def recv(self) -> str:
        if self.closed:
            return ""
        time.sleep(0.01)
        raise websocket.WebSocketTimeoutException()

    def close(self) -> None:
        self.closed = True


class _ClosedWebSocket:
    def __init__(self) -> None:
        self.closed = False
        self.recv_count = 0

    def recv(self) -> str:
        self.recv_count += 1
        return ""

    def close(self) -> None:
        self.closed = True


class AuthenticatedProxyUnitTests(unittest.TestCase):
    def _secret(self, root: pathlib.Path, username: str = "fixture-user", password: str = "fixture-pass") -> pathlib.Path:
        path = root / "proxy-secret.json"
        path.write_text(json.dumps({"username": username, "password": password}), encoding="utf-8")
        path.chmod(0o600)
        return path

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    @staticmethod
    def _wait_cdp(cdp_url: str) -> dict:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(cdp_url + "/json/version", timeout=0.5) as response:
                    return json.loads(response.read())
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("CDP fixture did not start")

    @staticmethod
    def _body_text(client: _RawCDP, session_id: str, expected: str) -> str:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = client.request(
                "Runtime.evaluate",
                {"expression": "document.body ? document.body.innerText : ''", "returnByValue": True},
                session_id,
            )
            text = str(result.get("result", {}).get("value", ""))
            if text == expected:
                return text
            time.sleep(0.05)
        raise AssertionError(f"browser body did not become {expected!r}")

    def test_live_http_and_https_authenticated_proxy_on_attached_cdp(self) -> None:
        browser_path = pathlib.Path.home() / ".cache/ms-playwright/chromium-1181/chrome-linux/chrome"
        switches_path = pathlib.Path(
            "/opt/cloakbrowser/venv/lib/python3.12/site-packages/playwright/driver/package/lib/server/chromium/chromiumSwitches.js"
        )
        if not browser_path.is_file() or not switches_path.is_file():
            self.fail("matching local Chromium/Playwright fixture is required")

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            cert = root / "cert.pem"
            key = root / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-subj",
                    "/CN=localhost",
                    "-days",
                    "1",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            tls_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TLSOrigin)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(cert, key)
            tls_server.socket = tls_context.wrap_socket(tls_server.socket, server_side=True)
            tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
            tls_thread.start()

            _AuthenticatedProxy.tls_port = int(tls_server.server_address[1])
            _AuthenticatedProxy.http_hits = 0
            _AuthenticatedProxy.connect_hits = 0
            _AuthenticatedProxy.auth_failures = 0
            proxy_server = _ThreadingTCPServer(("127.0.0.1", 0), _AuthenticatedProxy)
            proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
            proxy_thread.start()
            proxy_port = int(proxy_server.server_address[1])

            cdp_port = self._free_port()
            cdp_url = f"http://127.0.0.1:{cdp_port}"
            node_expression = f"console.log(JSON.stringify(require('{switches_path}').chromiumSwitches(false)))"
            switches = json.loads(subprocess.check_output(["node", "-e", node_expression]))
            browser_args = [
                str(browser_path),
                *switches,
                "--headless",
                "--hide-scrollbars",
                "--mute-audio",
                "--no-sandbox",
                "--ignore-certificate-errors",
                f"--remote-debugging-port={cdp_port}",
                f"--user-data-dir={root / 'profile'}",
                f"--proxy-server=http://127.0.0.1:{proxy_port}",
                "--proxy-bypass-list=<-loopback>",
                "about:blank",
            ]
            self.assertNotIn(_FIXTURE_USER, " ".join(browser_args))
            self.assertNotIn(_FIXTURE_PASSWORD, " ".join(browser_args))
            browser = subprocess.Popen(
                browser_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            controller: ProxyAuthController | None = None
            client: _RawCDP | None = None
            try:
                version = self._wait_cdp(cdp_url)
                client = _RawCDP(version["webSocketDebuggerUrl"])
                created = client.request("Target.createTarget", {"url": "about:blank"})
                session_id = client.request(
                    "Target.attachToTarget",
                    {"targetId": created["targetId"], "flatten": True},
                )["sessionId"]
                client.request("Page.enable", session_id=session_id)

                failures_before = _AuthenticatedProxy.auth_failures
                bad_descriptor = ProxyAuthDescriptor.create(
                    f"http://127.0.0.1:{proxy_port}",
                    self._secret(root, "wrong-user", "wrong-password"),
                )
                controller = ProxyAuthController(cdp_url, bad_descriptor).start()
                client.request(
                    "Page.navigate",
                    {"url": "http://proxy-auth.invalid/invalid-credentials"},
                    session_id,
                )
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and controller.diagnostics()["auth_refused"] < 1:
                    time.sleep(0.05)
                self.assertGreater(_AuthenticatedProxy.auth_failures, failures_before)
                self.assertGreaterEqual(controller.diagnostics()["auth_refused"], 1)
                self.assertNotIn("wrong-password", json.dumps(controller.diagnostics()))
                controller.stop()
                self.assertFalse(controller.diagnostics()["active"])
                controller = None

                descriptor = ProxyAuthDescriptor.create(
                    f"http://127.0.0.1:{proxy_port}",
                    self._secret(root, _FIXTURE_USER, _FIXTURE_PASSWORD),
                )
                controller = ProxyAuthController(cdp_url, descriptor).start()
                http_nav = client.request(
                    "Page.navigate",
                    {"url": "http://proxy-auth.invalid/http"},
                    session_id,
                )
                self.assertFalse(http_nav.get("errorText"), http_nav)
                self.assertEqual(self._body_text(client, session_id, "proxy-http-ok"), "proxy-http-ok")

                https_nav = client.request(
                    "Page.navigate",
                    {"url": f"https://127.0.0.1:{_AuthenticatedProxy.tls_port}/https"},
                    session_id,
                )
                self.assertFalse(https_nav.get("errorText"), https_nav)
                self.assertEqual(self._body_text(client, session_id, "proxy-https-ok"), "proxy-https-ok")

                diagnostics = controller.diagnostics()
                self.assertGreaterEqual(_AuthenticatedProxy.http_hits, 1)
                self.assertGreaterEqual(_AuthenticatedProxy.connect_hits, 1)
                self.assertGreaterEqual(diagnostics["auth_provided"], 1)
                self.assertFalse(diagnostics["reader_failed"])
                self.assertNotIn(_FIXTURE_PASSWORD, json.dumps(diagnostics))

                controller.stop()
                self.assertFalse(controller.diagnostics()["active"])
                self.assertIsNone(controller._ws)
                self.assertEqual(controller._sessions, set())
                self.assertEqual(controller._auth_seen, {})
                controller = None
            finally:
                if client is not None:
                    client.close()
                if controller is not None:
                    controller.stop()
                browser.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    browser.wait(timeout=5)
                if browser.poll() is None:
                    browser.kill()
                    browser.wait(timeout=5)
                proxy_server.shutdown()
                proxy_server.server_close()
                tls_server.shutdown()
                tls_server.server_close()
                proxy_thread.join(timeout=5)
                tls_thread.join(timeout=5)
            self.assertIsNotNone(browser.poll())
            self.assertFalse(proxy_thread.is_alive())
            self.assertFalse(tls_thread.is_alive())

    def test_secret_file_is_owner_only_no_follow_bounded_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            secret = self._secret(root)
            descriptor = ProxyAuthDescriptor.create("http://127.0.0.1:8080", secret)
            credentials = load_proxy_credentials(descriptor)
            self.assertIsInstance(credentials, ProxyCredentials)
            self.assertEqual(credentials.username, "fixture-user")
            self.assertEqual(credentials.password, "fixture-pass")
            self.assertNotIn("fixture-user", repr(credentials))
            self.assertNotIn("fixture-pass", repr(credentials))

            secret.chmod(0o644)
            with self.assertRaisesRegex(CapabilityContractError, "secret_ref_mode"):
                load_proxy_credentials(descriptor)

            secret.chmod(0o600)
            symlink = root / "secret-link.json"
            symlink.symlink_to(secret)
            unsafe = object.__new__(ProxyAuthDescriptor)
            object.__setattr__(unsafe, "server", descriptor.server)
            object.__setattr__(unsafe, "secret_ref", symlink)
            with self.assertRaisesRegex(CapabilityContractError, "secret_ref_symlink"):
                load_proxy_credentials(unsafe)

    def test_secret_schema_is_exact_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            secret = self._secret(root)
            descriptor = ProxyAuthDescriptor.create("http://127.0.0.1:8080", secret)
            for payload in (
                {},
                {"username": "u"},
                {"username": "u", "password": "p", "token": "x"},
                {"username": "", "password": "p"},
                {"username": "u", "password": ""},
            ):
                secret.write_text(json.dumps(payload), encoding="utf-8")
                secret.chmod(0o600)
                with self.subTest(payload=payload), self.assertRaises(CapabilityContractError):
                    load_proxy_credentials(descriptor)
            secret.write_bytes(b"{" + b"x" * 20000 + b"}")
            secret.chmod(0o600)
            with self.assertRaisesRegex(CapabilityContractError, "secret_size"):
                load_proxy_credentials(descriptor)

    def test_fifo_descriptor_and_secret_fd_lifecycle_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fifo = root / "proxy-secret.fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(CapabilityContractError, "secret_ref_regular"):
                ProxyAuthDescriptor.create("http://127.0.0.1:8080", fifo)

            descriptor = ProxyAuthDescriptor.create("http://127.0.0.1:8080", self._secret(root))
            closed: list[int] = []
            real_close = os.close

            def tracked_close(fd: int) -> None:
                closed.append(fd)
                real_close(fd)

            with mock.patch("chip_relay.proxy_auth.os.close", side_effect=tracked_close):
                load_proxy_credentials(descriptor)
            self.assertEqual(len(closed), 1)

    def test_controller_timeout_browser_failure_and_teardown_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            descriptor = ProxyAuthDescriptor.create("http://127.0.0.1:8080", self._secret(root))
            timed_out_socket = _TimeoutWebSocket()
            with (
                mock.patch("chip_relay.proxy_auth._browser_websocket_url", return_value="ws://127.0.0.1:18800/devtools/browser/test"),
                mock.patch("websocket.create_connection", return_value=timed_out_socket) as create_connection,
                self.assertRaisesRegex(CapabilityContractError, "cdp_command_timeout"),
            ):
                ProxyAuthController(
                    "http://127.0.0.1:18800",
                    descriptor,
                    ready_timeout=0.05,
                ).start()
            self.assertTrue(timed_out_socket.closed)
            self.assertEqual(
                create_connection.call_args.kwargs.get("http_no_proxy"),
                ["127.0.0.1", "localhost", "::1"],
            )

            failed_controller = ProxyAuthController("http://127.0.0.1:18800", descriptor)
            with (
                mock.patch("chip_relay.proxy_auth._browser_websocket_url", return_value="ws://127.0.0.1:18800/devtools/browser/test"),
                mock.patch("websocket.create_connection", side_effect=OSError("browser gone")),
                self.assertRaisesRegex(CapabilityContractError, "cdp_websocket_connect"),
            ):
                failed_controller.start()
            self.assertFalse(failed_controller.diagnostics()["active"])
            self.assertIsNone(failed_controller._ws)

    def test_loopback_cdp_discovery_bypasses_inherited_proxy_environment(self) -> None:
        class DirectCDP(http.server.BaseHTTPRequestHandler):
            hits = 0

            def do_GET(self) -> None:
                type(self).hits += 1
                port = self.server.server_port  # type: ignore[attr-defined]
                body = json.dumps(
                    {"webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/devtools/browser/direct"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        class InterceptingProxy(http.server.BaseHTTPRequestHandler):
            hits = 0

            def do_GET(self) -> None:
                type(self).hits += 1
                parsed = urllib.parse.urlsplit(self.path)
                body = json.dumps(
                    {
                        "webSocketDebuggerUrl": (
                            f"ws://{parsed.hostname}:{parsed.port}/devtools/browser/forged"
                        )
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                del format, args

        direct = http.server.ThreadingHTTPServer(("127.0.0.1", 0), DirectCDP)
        intercept = http.server.ThreadingHTTPServer(("127.0.0.1", 0), InterceptingProxy)
        threads = [
            threading.Thread(target=direct.serve_forever, daemon=True),
            threading.Thread(target=intercept.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            direct_port = direct.server_address[1]
            intercept_port = intercept.server_address[1]
            clean_env = {
                key: value
                for key, value in os.environ.items()
                if key.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}
            }
            clean_env["HTTP_PROXY"] = f"http://127.0.0.1:{intercept_port}"
            clean_env["ALL_PROXY"] = f"http://127.0.0.1:{intercept_port}"
            with mock.patch.dict(os.environ, clean_env, clear=True):
                result = _browser_websocket_url(f"http://127.0.0.1:{direct_port}", timeout=2)
            self.assertEqual(result, f"ws://127.0.0.1:{direct_port}/devtools/browser/direct")
            self.assertEqual(DirectCDP.hits, 1)
            self.assertEqual(InterceptingProxy.hits, 0)
        finally:
            direct.shutdown()
            intercept.shutdown()
            direct.server_close()
            intercept.server_close()
            for thread in threads:
                thread.join(timeout=5)
            self.assertTrue(all(not thread.is_alive() for thread in threads))

    def test_graceful_cdp_eof_and_runtime_loss_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            descriptor = ProxyAuthDescriptor.create(
                "http://127.0.0.1:8080",
                self._secret(root, _FIXTURE_USER, _FIXTURE_PASSWORD),
            )
            controller = ProxyAuthController("http://127.0.0.1:18800", descriptor)
            closed_ws = _ClosedWebSocket()
            controller._ws = closed_ws
            reader = threading.Thread(target=controller._reader_loop, daemon=True)
            controller._thread = reader
            reader.start()
            try:
                reader.join(timeout=0.1)
                self.assertFalse(reader.is_alive())
                self.assertTrue(controller.diagnostics()["reader_failed"])
                self.assertLessEqual(closed_ws.recv_count, 1)
            finally:
                controller.stop()

            def fail_after_start(instance: ProxyAuthController) -> ProxyAuthController:
                instance._reader_error = "cdp_websocket_closed"
                return instance

            with mock.patch.object(ProxyAuthController, "start", fail_after_start):
                with self.assertRaisesRegex(CapabilityContractError, "proxy_auth_runtime"):
                    with proxy_auth_session("http://127.0.0.1:18800", descriptor):
                        pass

    def test_controller_state_is_bounded_and_cleared_on_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            descriptor = ProxyAuthDescriptor.create("http://127.0.0.1:8080", self._secret(root))
            controller = ProxyAuthController("http://127.0.0.1:18800", descriptor)
            controller._credentials = load_proxy_credentials(descriptor)
            sent: list[tuple[tuple[object, ...], dict[str, object]]] = []
            controller._send = lambda *args, **kwargs: sent.append((args, kwargs)) or len(sent)  # type: ignore[method-assign]
            for index in range(300):
                controller._enable_session(f"session-{index}", waiting=False)
            self.assertLessEqual(len(controller._sessions), 256)
            for index in range(2100):
                controller._handle_auth_required(
                    {
                        "requestId": f"request-{index}",
                        "authChallenge": {"source": "Proxy", "origin": descriptor.server},
                    },
                    "session-1",
                )
            self.assertLessEqual(len(controller._auth_seen), 2048)
            self.assertTrue(controller.diagnostics()["reader_failed"])
            controller.stop()
            self.assertTrue(
                any(args and args[0] == "Fetch.disable" for args, _kwargs in sent)
            )
            self.assertEqual(controller._sessions, set())
            self.assertEqual(controller._auth_seen, {})

    def test_config_accepts_nonsecret_reference_and_rejects_credential_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            secret = self._secret(root)
            env = {
                "HOME": str(root),
                "CHIP_RELAY_PROXY": "http://127.0.0.1:8080",
                "CHIP_RELAY_PROXY_SECRET_FILE": str(secret),
            }
            with mock.patch.dict(os.environ, env, clear=True):
                config = load_config()
            self.assertEqual(config.proxy, "http://127.0.0.1:8080")
            self.assertEqual(config.proxy_auth.secret_ref, secret.resolve())

            for unsafe in (
                {"CHIP_RELAY_PROXY": "http://u:p@127.0.0.1:8080"},
                {"CHIP_RELAY_PROXY_USERNAME": "u"},
                {"CHIP_RELAY_PROXY_PASSWORD": "p"},
            ):
                with self.subTest(unsafe=list(unsafe)), mock.patch.dict(os.environ, {"HOME": str(root), **unsafe}, clear=True):
                    with self.assertRaises(CapabilityContractError):
                        load_config()

    def test_legacy_proxy_parser_rejects_userinfo(self) -> None:
        with self.assertRaises(CapabilityContractError):
            parse_proxy_config("http://u:p@127.0.0.1:8080")

    def test_controller_diagnostics_and_context_are_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            secret = self._secret(root)
            descriptor = ProxyAuthDescriptor.create("http://127.0.0.1:8080", secret)
            controller = ProxyAuthController("http://127.0.0.1:18800", descriptor)
            text = repr(controller) + json.dumps(controller.diagnostics(), sort_keys=True)
            self.assertNotIn("fixture-user", text)
            self.assertNotIn("fixture-pass", text)
            with proxy_auth_session("http://127.0.0.1:18800", None) as inactive:
                self.assertIsNone(inactive)


if __name__ == "__main__":
    unittest.main()
