from __future__ import annotations

import contextlib
import json
import os
import pathlib
import stat
import threading
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator
from urllib.parse import urlsplit

from .capabilities import CapabilityContractError, ProxyAuthDescriptor, validate_secret_reference

_MAX_SECRET_BYTES = 16 * 1024
_MAX_SESSIONS = 256
_MAX_AUTH_REQUESTS = 2048


@dataclass(frozen=True)
class ProxyCredentials:
    username: str = field(repr=False)
    password: str = field(repr=False)


def _read_secret_bytes(path: pathlib.Path) -> bytes:
    validated = validate_secret_reference(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(validated, flags)
    except OSError as exc:
        raise CapabilityContractError("secret_open") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise CapabilityContractError("secret_ref_regular")
        if info.st_uid != os.geteuid():
            raise CapabilityContractError("secret_ref_owner")
        if info.st_mode & 0o077 or not info.st_mode & stat.S_IRUSR:
            raise CapabilityContractError("secret_ref_mode")
        if info.st_size > _MAX_SECRET_BYTES:
            raise CapabilityContractError("secret_size")
        opened_path = pathlib.Path(f"/proc/self/fd/{fd}")
        if opened_path.exists() and opened_path.resolve() != validated:
            raise CapabilityContractError("secret_ref_race")
        chunks: list[bytes] = []
        remaining = _MAX_SECRET_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_SECRET_BYTES:
            raise CapabilityContractError("secret_size")
        return payload
    finally:
        os.close(fd)


def load_proxy_credentials(descriptor: ProxyAuthDescriptor) -> ProxyCredentials:
    if descriptor.secret_ref is None:
        raise CapabilityContractError("secret_ref_required")
    raw = _read_secret_bytes(descriptor.secret_ref)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CapabilityContractError("secret_json") from exc
    if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
        raise CapabilityContractError("secret_schema")
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not username or len(username) > 256 or "\x00" in username:
        raise CapabilityContractError("secret_username")
    if not isinstance(password, str) or not password or len(password) > 4096 or "\x00" in password:
        raise CapabilityContractError("secret_password")
    return ProxyCredentials(username=username, password=password)


def _validate_cdp_url(cdp_url: str) -> tuple[str, int]:
    parsed = urlsplit(cdp_url)
    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None:
        raise CapabilityContractError("cdp_endpoint")
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise CapabilityContractError("cdp_loopback")
    try:
        port = parsed.port
    except ValueError as exc:
        raise CapabilityContractError("cdp_port") from exc
    if port is None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise CapabilityContractError("cdp_endpoint")
    return parsed.hostname, port


def _browser_websocket_url(cdp_url: str, timeout: float) -> str:
    host, port = _validate_cdp_url(cdp_url)
    endpoint = cdp_url.rstrip("/") + "/json/version"
    try:
        direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with direct_opener.open(endpoint, timeout=timeout) as response:
            payload = json.loads(response.read(64 * 1024).decode("utf-8"))
    except Exception as exc:
        raise CapabilityContractError("cdp_unavailable") from exc
    ws_url = payload.get("webSocketDebuggerUrl") if isinstance(payload, dict) else None
    if not isinstance(ws_url, str):
        raise CapabilityContractError("cdp_websocket")
    parsed = urlsplit(ws_url)
    if parsed.scheme not in {"ws", "wss"} or parsed.hostname not in {host, "127.0.0.1", "localhost", "::1"}:
        raise CapabilityContractError("cdp_websocket")
    if parsed.port != port:
        raise CapabilityContractError("cdp_websocket")
    return ws_url


class ProxyAuthController:
    """Bounded proxy-auth bridge for an already-running local Chromium CDP rail."""

    def __init__(
        self,
        cdp_url: str,
        descriptor: ProxyAuthDescriptor,
        *,
        connect_timeout: float = 3.0,
        ready_timeout: float = 5.0,
    ) -> None:
        _validate_cdp_url(cdp_url)
        if descriptor.secret_ref is None:
            raise CapabilityContractError("secret_ref_required")
        self.cdp_url = cdp_url.rstrip("/")
        self.descriptor = descriptor
        self.connect_timeout = connect_timeout
        self.ready_timeout = ready_timeout
        self._ws: Any | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._next_id = 1
        self._pending: dict[int, tuple[threading.Event, dict[str, Any]]] = {}
        self._callbacks: dict[int, Any] = {}
        self._sessions: set[str] = set()
        self._credentials: ProxyCredentials | None = None
        self._reader_error: str | None = None
        self._auth_seen: dict[str, int] = {}
        self._auth_challenges = 0
        self._auth_provided = 0
        self._auth_refused = 0

    def __repr__(self) -> str:
        state = self.diagnostics()
        return f"ProxyAuthController(active={state['active']}, proxy_server={state['proxy_server']!r})"

    def diagnostics(self) -> dict[str, Any]:
        return {
            "active": self._thread is not None and self._thread.is_alive(),
            "proxy_server": self.descriptor.server,
            "auth_challenges": self._auth_challenges,
            "auth_provided": self._auth_provided,
            "auth_refused": self._auth_refused,
            "reader_failed": self._reader_error is not None,
        }

    def raise_if_failed(self) -> None:
        thread = self._thread
        if self._reader_error is not None or (
            self._ws is not None and thread is not None and not thread.is_alive()
        ):
            raise CapabilityContractError("proxy_auth_runtime")

    def start(self) -> "ProxyAuthController":
        if self._thread is not None:
            raise RuntimeError("proxy auth controller already started")
        self._credentials = load_proxy_credentials(self.descriptor)
        try:
            ws_url = _browser_websocket_url(self.cdp_url, self.connect_timeout)
            import websocket

            self._ws = websocket.create_connection(
                ws_url,
                timeout=min(self.connect_timeout, 1.0),
                suppress_origin=True,
                http_no_proxy=["127.0.0.1", "localhost", "::1"],
            )
            self._ws.settimeout(0.25)
        except Exception as exc:
            if self._ws is not None:
                with contextlib.suppress(Exception):
                    self._ws.close()
                self._ws = None
            self._credentials = None
            raise CapabilityContractError("cdp_websocket_connect") from exc
        self._thread = threading.Thread(target=self._reader_loop, name="chip-relay-proxy-auth", daemon=True)
        self._thread.start()
        try:
            self._request("Target.setDiscoverTargets", {"discover": True})
            self._request(
                "Target.setAutoAttach",
                {
                    "autoAttach": True,
                    "waitForDebuggerOnStart": True,
                    "flatten": True,
                    "filter": [{"type": "page", "exclude": False}],
                },
            )
            targets = self._request("Target.getTargets").get("targetInfos", [])
            for target in targets:
                if target.get("type") != "page":
                    continue
                attached = self._request(
                    "Target.attachToTarget",
                    {"targetId": target["targetId"], "flatten": True},
                )
                session_id = attached.get("sessionId")
                if isinstance(session_id, str):
                    self._enable_session(session_id, waiting=False)
            if not self._ready.wait(self.ready_timeout):
                raise CapabilityContractError("proxy_auth_not_ready")
            if self._reader_error is not None:
                raise CapabilityContractError("proxy_auth_reader")
            return self
        except Exception:
            self.stop()
            raise

    def _send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
        callback: Any | None = None,
    ) -> int:
        with self._send_lock:
            ws = self._ws
            if ws is None:
                raise CapabilityContractError("proxy_auth_not_started")
            message_id = self._next_id
            self._next_id += 1
            payload: dict[str, Any] = {"id": message_id, "method": method, "params": params or {}}
            if session_id is not None:
                payload["sessionId"] = session_id
            if callback is not None:
                with self._state_lock:
                    self._callbacks[message_id] = callback
            ws.send(json.dumps(payload, separators=(",", ":")))
        return message_id

    def _request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        event = threading.Event()
        box: dict[str, Any] = {}
        with self._send_lock:
            ws = self._ws
            if ws is None:
                raise CapabilityContractError("proxy_auth_not_started")
            message_id = self._next_id
            self._next_id += 1
            with self._state_lock:
                self._pending[message_id] = (event, box)
            payload: dict[str, Any] = {"id": message_id, "method": method, "params": params or {}}
            if session_id is not None:
                payload["sessionId"] = session_id
            ws.send(json.dumps(payload, separators=(",", ":")))
        try:
            if not event.wait(self.ready_timeout):
                raise CapabilityContractError("cdp_command_timeout")
            if "error" in box:
                raise CapabilityContractError("cdp_command_failed")
            result = box.get("result")
            return result if isinstance(result, dict) else {}
        finally:
            with self._state_lock:
                self._pending.pop(message_id, None)

    def _enable_session(self, session_id: str, *, waiting: bool) -> None:
        if session_id in self._sessions:
            if waiting:
                self._send("Runtime.runIfWaitingForDebugger", session_id=session_id)
            return
        if len(self._sessions) >= _MAX_SESSIONS:
            self._reader_error = "session_limit"
            if waiting:
                self._send("Runtime.runIfWaitingForDebugger", session_id=session_id)
            return
        self._sessions.add(session_id)

        def enabled(message: dict[str, Any]) -> None:
            if "error" in message:
                self._reader_error = "fetch_enable"
                return
            if waiting:
                self._send("Runtime.runIfWaitingForDebugger", session_id=session_id)
            self._ready.set()

        self._send(
            "Fetch.enable",
            {
                "patterns": [{"urlPattern": "*", "requestStage": "Request"}],
                "handleAuthRequests": True,
            },
            session_id,
            callback=enabled,
        )

    def _reader_loop(self) -> None:
        try:
            import websocket

            while not self._stop.is_set() and self._ws is not None:
                try:
                    raw = self._ws.recv()
                except websocket.WebSocketTimeoutException:
                    continue
                except Exception as exc:
                    if not self._stop.is_set():
                        self._reader_error = type(exc).__name__
                    return
                if not raw:
                    if not self._stop.is_set():
                        self._reader_error = "cdp_websocket_closed"
                    return
                try:
                    message = json.loads(raw)
                except (TypeError, json.JSONDecodeError):
                    self._reader_error = "invalid_cdp_message"
                    return
                try:
                    self._handle_message(message)
                except Exception:
                    if not self._stop.is_set():
                        self._reader_error = "cdp_handler"
                    return
        finally:
            self._ready.set()

    def _handle_message(self, message: dict[str, Any]) -> None:
        message_id = message.get("id")
        if isinstance(message_id, int):
            callback = None
            pending = None
            with self._state_lock:
                callback = self._callbacks.pop(message_id, None)
                pending = self._pending.get(message_id)
            if callback is not None:
                callback(message)
            if pending is not None:
                event, box = pending
                box.update(message)
                event.set()
            return

        method = message.get("method")
        raw_params = message.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        session_id = message.get("sessionId")
        if method == "Target.attachedToTarget":
            raw_target_info = params.get("targetInfo")
            target_info: dict[str, Any] = raw_target_info if isinstance(raw_target_info, dict) else {}
            attached_session = params.get("sessionId")
            if target_info.get("type") == "page" and isinstance(attached_session, str):
                self._enable_session(attached_session, waiting=bool(params.get("waitingForDebugger")))
            return
        if not isinstance(session_id, str):
            return
        if method == "Fetch.requestPaused":
            request_id = params.get("requestId")
            if isinstance(request_id, str):
                self._send("Fetch.continueRequest", {"requestId": request_id}, session_id)
            return
        if method == "Fetch.authRequired":
            self._handle_auth_required(params, session_id)

    def _handle_auth_required(self, params: dict[str, Any], session_id: str) -> None:
        request_id = params.get("requestId")
        raw_challenge = params.get("authChallenge")
        challenge: dict[str, Any] = raw_challenge if isinstance(raw_challenge, dict) else {}
        if not isinstance(request_id, str):
            return
        self._auth_challenges += 1
        source = challenge.get("source")
        origin = str(challenge.get("origin", "")).rstrip("/")
        if request_id not in self._auth_seen and len(self._auth_seen) >= _MAX_AUTH_REQUESTS:
            count = 2
            self._reader_error = "auth_request_limit"
        else:
            count = self._auth_seen.get(request_id, 0) + 1
            self._auth_seen[request_id] = count
        credentials = self._credentials
        if source == "Proxy" and origin == self.descriptor.server and count == 1 and credentials is not None:
            response = {
                "response": "ProvideCredentials",
                "username": credentials.username,
                "password": credentials.password,
            }
            self._auth_provided += 1
        elif source == "Proxy":
            response = {"response": "CancelAuth"}
            self._auth_refused += 1
        else:
            response = {"response": "Default"}
            self._auth_refused += 1
        self._send(
            "Fetch.continueWithAuth",
            {"requestId": request_id, "authChallengeResponse": response},
            session_id,
        )

    def stop(self) -> None:
        with self._state_lock:
            sessions = tuple(self._sessions)
        for session_id in sessions:
            with contextlib.suppress(Exception):
                self._send("Fetch.disable", session_id=session_id)
        self._stop.set()
        ws = self._ws
        self._ws = None
        if ws is not None:
            with contextlib.suppress(Exception):
                ws.close()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._thread = None
        self._credentials = None
        with self._state_lock:
            for event, _ in self._pending.values():
                event.set()
            self._pending.clear()
            self._callbacks.clear()
            self._sessions.clear()
            self._auth_seen.clear()

    def __enter__(self) -> "ProxyAuthController":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.stop()


@contextmanager
def proxy_auth_session(
    cdp_url: str,
    descriptor: ProxyAuthDescriptor | None,
) -> Iterator[ProxyAuthController | None]:
    if descriptor is None or descriptor.secret_ref is None:
        yield None
        return
    controller = ProxyAuthController(cdp_url, descriptor)
    with controller:
        yield controller
        controller.raise_if_failed()
