from __future__ import annotations

import fcntl
import json
import os
import shutil
import socket
import stat
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import median
from typing import Any, Iterator
from urllib.parse import urlparse
from urllib.request import urlopen

from .benchmark import (
    BENCHMARK_SCHEMA,
    BenchmarkContractError,
    atomic_write_result,
    snapshot_sha256,
    utc_now,
    validate_result,
)
from .config import RelayConfig
from .stealth import FINGERPRINT_JS, classify_challenge, evaluate_fingerprint

SUITE_VERSION = "1"
PUBLIC_DETECTOR_CASES = (
    ("rebrowser-bot-detector", "https://bot-detector.rebrowser.net/"),
)
_CASE_PRECEDENCE = {
    "error": 6,
    "blocked": 5,
    "captcha/manual": 4,
    "needs_proxy": 3,
    "passed": 2,
    "not_run": 1,
}


class BenchmarkRunError(ValueError):
    pass


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        status = 200
        title = "chip-relay clean fixture"
        body = "benchmark fixture ready"
        if self.path == "/captcha":
            title = "Turnstile CAPTCHA challenge"
            body = "captcha manual challenge"
        elif self.path == "/blocked":
            status = 403
            title = "Access denied"
            body = "blocked by fixture"
        elif self.path != "/clean":
            status = 404
            title = "not found"
            body = "not found"
        encoded = (
            "<!doctype html><html><head><title>"
            + title
            + "</title></head><body>"
            + body
            + "</body></html>"
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def local_fixture_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _exact_loopback_cdp(cdp_url: str) -> str:
    parsed = urlparse(cdp_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise BenchmarkRunError("benchmark_cdp_loopback_required")
    if parsed.username is not None or parsed.password is not None:
        raise BenchmarkRunError("benchmark_cdp_userinfo_forbidden")
    try:
        port = parsed.port
    except ValueError as exc:
        raise BenchmarkRunError("benchmark_cdp_port_invalid") from exc
    if port is None:
        raise BenchmarkRunError("benchmark_cdp_port_required")
    return cdp_url.rstrip("/")


def _read_cdp_version(cdp_url: str) -> dict[str, Any]:
    endpoint = _exact_loopback_cdp(cdp_url) + "/json/version"
    try:
        with urlopen(endpoint, timeout=3) as response:  # noqa: S310 - exact loopback enforced
            raw = response.read(65537)
    except OSError as exc:
        raise BenchmarkRunError("benchmark_cdp_unavailable") from exc
    if len(raw) > 65536:
        raise BenchmarkRunError("benchmark_cdp_version_too_large")
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkRunError("benchmark_cdp_version_invalid") from exc
    if not isinstance(payload, dict):
        raise BenchmarkRunError("benchmark_cdp_version_invalid")
    user_agent = str(payload.get("User-Agent") or "")
    return {
        "browser": str(payload.get("Browser") or "unknown"),
        "protocol_version": str(payload.get("Protocol-Version") or "unknown"),
        "headless": "HeadlessChrome" in user_agent,
    }


def _suite_cases(suite: str, local_base: str | None) -> tuple[tuple[str, str], ...]:
    if suite == "local":
        if local_base is None:
            raise BenchmarkRunError("benchmark_local_fixture_missing")
        return (
            ("clean", f"{local_base}/clean"),
            ("captcha", f"{local_base}/captcha"),
            ("blocked", f"{local_base}/blocked"),
        )
    if suite == "public-detectors":
        return PUBLIC_DETECTOR_CASES
    raise BenchmarkRunError("benchmark_suite_unknown")


def _normalize_checks(evaluation: dict[str, Any]) -> list[dict[str, object]]:
    checks = evaluation.get("checks") or []
    return [
        {"name": str(item.get("name") or "unknown"), "ok": bool(item.get("ok"))}
        for item in checks
        if isinstance(item, dict)
    ]


def _classify_case(*, response_status: int | None, title: str, url: str, text: str, evaluation: dict[str, Any]) -> str:
    challenge = classify_challenge({
        "status": response_status,
        "title": title,
        "url": url,
        "text": text[:8000],
    })
    status = str(challenge.get("status") or "not_run")
    if status == "not_run":
        return "passed" if evaluation.get("status") == "ok" else "passed"
    return status


def _run_backend_probe(
    *,
    cdp_url: str,
    requested: str,
    resolved: str,
    suite: str,
    repeat: int,
    preset: str,
    proxy_configured: bool,
    ephemeral_profile: bool,
) -> dict[str, Any]:
    if not 1 <= repeat <= 3:
        raise BenchmarkRunError("benchmark_repeat_out_of_range")
    cdp_url = _exact_loopback_cdp(cdp_url)
    version = _read_cdp_version(cdp_url)
    headless = bool(version.pop("headless", False))
    fixture_context = local_fixture_server() if suite == "local" else _null_fixture()
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise BenchmarkRunError("benchmark_playwright_unavailable") from exc

    aggregate: dict[str, list[dict[str, Any]]] = {}
    with fixture_context as local_base:
        cases = _suite_cases(suite, local_base)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp(cdp_url, timeout=10_000)
                for _ in range(repeat):
                    context = browser.new_context()
                    try:
                        for name, target in cases:
                            page = context.new_page()
                            started = time.monotonic()
                            try:
                                response = page.goto(target, wait_until="domcontentloaded", timeout=20_000)
                                raw_sample = page.evaluate(FINGERPRINT_JS)
                                if not isinstance(raw_sample, dict):
                                    raise BenchmarkRunError("benchmark_fingerprint_invalid")
                                evaluation = evaluate_fingerprint(raw_sample)
                                title = page.title()[:512]
                                text = page.locator("body").inner_text(timeout=2_000)[:8000]
                                elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
                                status = _classify_case(
                                    response_status=response.status if response is not None else None,
                                    title=title,
                                    url=page.url,
                                    text=text,
                                    evaluation=evaluation,
                                )
                                item = {
                                    "status": status,
                                    "elapsed_ms": elapsed_ms,
                                    "fingerprint_checks": _normalize_checks(evaluation),
                                    "fingerprint_snapshot_sha256": snapshot_sha256(raw_sample),
                                }
                            except (PlaywrightError, BenchmarkRunError) as exc:
                                item = {
                                    "status": "error",
                                    "elapsed_ms": max(0, round((time.monotonic() - started) * 1000)),
                                    "fingerprint_checks": [],
                                    "fingerprint_snapshot_sha256": snapshot_sha256({"error": exc.__class__.__name__}),
                                }
                            finally:
                                page.close()
                            aggregate.setdefault(name, []).append(item)
                    finally:
                        try:
                            context.close()
                        except PlaywrightError:
                            pass
                # Never call browser.close() for a CDP attachment: it may terminate
                # an operator-owned active browser. Exiting Playwright disconnects
                # the client after the ephemeral context is closed.
        except PlaywrightError as exc:
            raise BenchmarkRunError("benchmark_cdp_connect_failed") from exc

    normalized_cases: list[dict[str, Any]] = []
    for name, attempts in aggregate.items():
        status = max((str(item["status"]) for item in attempts), key=lambda value: _CASE_PRECEDENCE.get(value, 0))
        check_names = sorted({str(check["name"]) for item in attempts for check in item["fingerprint_checks"]})
        checks = [
            {
                "name": check_name,
                "ok": all(
                    any(check["name"] == check_name and check["ok"] is True for check in item["fingerprint_checks"])
                    for item in attempts
                ),
            }
            for check_name in check_names
        ]
        normalized_cases.append({
            "name": name,
            "status": status,
            "elapsed_ms": round(median(item["elapsed_ms"] for item in attempts)),
            "repeat": len(attempts),
            "fingerprint_checks": checks,
            "fingerprint_snapshot_sha256": snapshot_sha256(
                [item["fingerprint_snapshot_sha256"] for item in attempts]
            ),
        })
    return {
        "identity": resolved,
        "requested": requested,
        "resolved": resolved,
        "status": "completed",
        "browser": version,
        "preset": preset,
        "headless": headless,
        "proxy_configured": proxy_configured,
        "ephemeral_profile": ephemeral_profile,
        "cases": normalized_cases,
    }


@contextmanager
def _null_fixture() -> Iterator[None]:
    yield None


def _safe_benchmark_root(config: RelayConfig, run_id: str) -> Path:
    root = config.base_dir / "benchmarks" / run_id
    benchmark_parent = config.base_dir / "benchmarks"
    benchmark_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if benchmark_parent.is_symlink():
        raise BenchmarkRunError("benchmark_root_symlink")
    benchmark_parent.chmod(0o700)
    root.mkdir(mode=0o700)
    if root.is_symlink() or root.resolve().parent != benchmark_parent.resolve():
        raise BenchmarkRunError("benchmark_root_unsafe")
    return root


@contextmanager
def _host_matrix_lock() -> Iterator[None]:
    runtime_dir = Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp"))
    if not runtime_dir.is_absolute() or runtime_dir.is_symlink():
        raise BenchmarkRunError("benchmark_lock_root_unsafe")
    path = runtime_dir / f"chip-relay-benchmark-{os.getuid()}.lock"
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BenchmarkRunError("benchmark_lock_open_failed") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
        ):
            raise BenchmarkRunError("benchmark_lock_unsafe")
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BenchmarkRunError("benchmark_matrix_busy") from exc
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _allocate_port(excluded: set[int]) -> int:
    for port in range(18810, 18830):
        if port in excluded:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            sock.close()
        return port
    raise BenchmarkRunError("benchmark_no_free_port")


def _read_state(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            return {}
        if metadata.st_size > 65_536:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _state_backend(config: RelayConfig) -> str:
    payload = _read_state(config.base_dir / "state.json")
    value = payload.get("backend")
    return value if isinstance(value, str) and value else "active"


def _unavailable_backend(name: str, reason: str) -> dict[str, Any]:
    return {
        "identity": name,
        "requested": name,
        "resolved": name,
        "status": "unavailable",
        "reason": reason,
        "browser": {"browser": "unavailable", "protocol_version": "unavailable"},
        "preset": "normal",
        "headless": os.environ.get("CHIP_RELAY_HEADLESS", "0") == "1",
        "proxy_configured": False,
        "ephemeral_profile": True,
        "cases": [],
    }


def _run_matrix_backend(
    *,
    config: RelayConfig,
    root: Path,
    backend: str,
    port: int,
    suite: str,
    repeat: int,
    preset: str,
) -> dict[str, Any]:
    script = Path(__file__).resolve().parents[1] / "scripts" / "chip-relay"
    runtime_root = root / "runtime" / backend
    profile_dir = runtime_root / "profile"
    log_dir = runtime_root / "logs"
    state_file = runtime_root / "state.json"
    for directory in (runtime_root, profile_dir, log_dir):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise BenchmarkRunError("benchmark_runtime_symlink")
    env = os.environ.copy()
    env.update({
        "CHIP_RELAY_BASE_DIR": str(runtime_root),
        "CHIP_RELAY_PROFILE_DIR": str(profile_dir),
        "CHIP_RELAY_LOG_DIR": str(log_dir),
        "CHIP_RELAY_STATE_FILE": str(state_file),
        "CHIP_RELAY_HOST": "127.0.0.1",
        "CHIP_RELAY_PORT": str(port),
        "CHIP_RELAY_BACKEND": backend,
        "CHIP_RELAY_PROFILE": f"benchmark-{backend}",
    })
    launch_attempted = False
    cdp_url = f"http://127.0.0.1:{port}"
    try:
        launch_attempted = True
        launch = subprocess.run(
            [str(script), "--json", "launch", "--backend", backend],
            cwd=script.parent.parent,
            env=env,
            text=True,
            capture_output=True,
            timeout=75,
        )
        if launch.returncode != 0:
            return _unavailable_backend(backend, "launch_failed")
        return _run_backend_probe(
            cdp_url=cdp_url,
            requested=backend,
            resolved=backend,
            suite=suite,
            repeat=repeat,
            preset=preset,
            proxy_configured=bool(config.proxy),
            ephemeral_profile=True,
        )
    except subprocess.TimeoutExpired:
        return _unavailable_backend(backend, "launch_timeout")
    finally:
        state = _read_state(state_file)
        needs_teardown = bool(state.get("pid"))
        if launch_attempted and not needs_teardown:
            try:
                _read_cdp_version(cdp_url)
            except BenchmarkRunError:
                pass
            else:
                needs_teardown = True
        if needs_teardown:
            stopped = subprocess.run(
                [str(script), "--json", "kill"],
                cwd=script.parent.parent,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
                check=False,
            )
            if stopped.returncode != 0:
                raise BenchmarkRunError("benchmark_teardown_failed")
        if runtime_root.exists():
            if runtime_root.is_symlink() or root not in runtime_root.parents:
                raise BenchmarkRunError("benchmark_runtime_cleanup_scope")
            shutil.rmtree(runtime_root)


def run_benchmark(
    config: RelayConfig,
    *,
    backends: list[str],
    suite: str,
    repeat: int,
    preset: str,
    required_backends: set[str] | None = None,
    output: str | None = None,
) -> tuple[dict[str, Any], Path]:
    if not backends:
        backends = ["active"]
    if any(name not in {"active", "chromium", "cloakbrowser", "browseros"} for name in backends):
        raise BenchmarkRunError("benchmark_backend_unknown")
    if len(set(backends)) != len(backends):
        raise BenchmarkRunError("benchmark_backend_duplicate")
    if "active" in backends and len(backends) != 1:
        raise BenchmarkRunError("benchmark_active_must_be_exclusive")
    if not 1 <= repeat <= 3:
        raise BenchmarkRunError("benchmark_repeat_out_of_range")
    if suite not in {"local", "public-detectors"}:
        raise BenchmarkRunError("benchmark_suite_unknown")
    if preset not in {"normal", "strict", "cf-sensitive"}:
        raise BenchmarkRunError("benchmark_preset_unknown")
    required_backends = required_backends or set()
    if not required_backends <= set(backends):
        raise BenchmarkRunError("benchmark_required_backend_not_requested")
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:8]
    started_at = utc_now()
    results: list[dict[str, Any]] = []
    with _host_matrix_lock():
        root = _safe_benchmark_root(config, run_id)
        if backends == ["active"]:
            resolved = _state_backend(config)
            results.append(_run_backend_probe(
                cdp_url=config.cdp_url,
                requested="active",
                resolved=resolved,
                suite=suite,
                repeat=repeat,
                preset=preset,
                proxy_configured=bool(config.proxy),
                ephemeral_profile=False,
            ))
        else:
            excluded = {config.port}
            for backend in backends:
                port = _allocate_port(excluded)
                excluded.add(port)
                results.append(_run_matrix_backend(
                    config=config,
                    root=root,
                    backend=backend,
                    port=port,
                    suite=suite,
                    repeat=repeat,
                    preset=preset,
                ))
    payload = {
        "schema": BENCHMARK_SCHEMA,
        "run_id": run_id,
        "suite_id": f"chip-relay-{suite}",
        "suite_version": SUITE_VERSION,
        "started_at": started_at,
        "completed_at": utc_now(),
        "claim_policy": "diagnostic-only/no-guaranteed-bypass",
        "artifact_policy": "private-local/no-auto-send",
        "results": results,
    }
    validate_result(payload)
    available = {item["requested"] for item in results if item["status"] == "completed"}
    missing_required = required_backends - available
    if missing_required:
        payload["required_backend_failure"] = sorted(missing_required)
    destination = Path(output).expanduser() if output else root / "benchmark-result.json"
    atomic_write_result(destination, payload)
    return payload, destination
