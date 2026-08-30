from __future__ import annotations

import ast
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"
sys.path.insert(0, str(ROOT))

from chip_relay.benchmark_runner import (  # noqa: E402
    BenchmarkRunError,
    _allocate_port,
    _exact_loopback_cdp,
    _host_matrix_lock,
    _safe_benchmark_root,
    local_fixture_server,
    run_benchmark,
)
from chip_relay.config import RelayConfig  # noqa: E402


def config(base: pathlib.Path, *, port: int = 18800) -> RelayConfig:
    return RelayConfig(
        base_dir=base,
        runs_dir=base / "runs",
        recipes_dir=base / "recipes",
        host="127.0.0.1",
        port=port,
        cdp_url=f"http://127.0.0.1:{port}",
        profile="default",
        profile_dir=base / "profiles" / "default",
        proxy=None,
        upload_allowed_dirs=None,
    )


def backend_result(identity: str, requested: str | None = None) -> dict:
    return {
        "identity": identity,
        "requested": requested or identity,
        "resolved": identity,
        "status": "completed",
        "browser": {"browser": "fixture", "protocol_version": "1.3"},
        "preset": "normal",
        "headless": True,
        "proxy_configured": False,
        "ephemeral_profile": identity != "active",
        "cases": [
            {
                "name": "clean",
                "status": "passed",
                "elapsed_ms": 1,
                "repeat": 1,
                "fingerprint_checks": [{"name": "webdriver", "ok": True}],
                "fingerprint_snapshot_sha256": "0" * 64,
            }
        ],
    }


class BenchmarkRunnerTests(unittest.TestCase):
    def test_cdp_requires_exact_loopback_and_explicit_port(self) -> None:
        self.assertEqual(_exact_loopback_cdp("http://127.0.0.1:18800/"), "http://127.0.0.1:18800")
        for invalid in (
            "http://localhost.evil.example:18800",
            "https://example.com:18800",
            "http://user:pass@localhost:18800",
            "http://localhost",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(BenchmarkRunError):
                _exact_loopback_cdp(invalid)

    def test_local_fixture_is_loopback_and_has_expected_outcomes(self) -> None:
        from urllib.error import HTTPError
        from urllib.request import urlopen

        with local_fixture_server() as base:
            self.assertTrue(base.startswith("http://127.0.0.1:"))
            with urlopen(base + "/clean", timeout=2) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(HTTPError) as blocked:
                urlopen(base + "/blocked", timeout=2)
            self.assertEqual(blocked.exception.code, 403)

    def test_port_allocator_excludes_default_and_fails_when_all_occupied(self) -> None:
        port = _allocate_port({18810, 18811})
        self.assertGreaterEqual(port, 18812)
        with self.assertRaisesRegex(BenchmarkRunError, "benchmark_no_free_port"):
            _allocate_port(set(range(18810, 18830)))

    def test_host_matrix_lock_serializes_across_base_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"XDG_RUNTIME_DIR": tmp}
        ):
            with _host_matrix_lock():
                with self.assertRaisesRegex(BenchmarkRunError, "benchmark_matrix_busy"):
                    with _host_matrix_lock():
                        self.fail("second lock unexpectedly acquired")
            lock = pathlib.Path(tmp) / f"chip-relay-benchmark-{os.getuid()}.lock"
            self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_benchmark_root_rejects_symlink_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp) / "base"
            outside = pathlib.Path(tmp) / "outside"
            base.mkdir()
            outside.mkdir()
            (base / "benchmarks").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(BenchmarkRunError, "benchmark_root_symlink"):
                _safe_benchmark_root(config(base), "run")

    def test_active_benchmark_writes_private_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            (base / "state.json").write_text('{"backend":"chromium"}', encoding="utf-8")
            active = backend_result("chromium", "active")
            active["ephemeral_profile"] = False
            with mock.patch("chip_relay.benchmark_runner._run_backend_probe", return_value=active):
                payload, path = run_benchmark(
                    config(base),
                    backends=["active"],
                    suite="local",
                    repeat=1,
                    preset="normal",
                )
            self.assertEqual(payload["results"][0]["resolved"], "chromium")
            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_matrix_is_sequential_and_required_unavailable_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            calls: list[str] = []

            def fake_matrix(**kwargs):
                backend = kwargs["backend"]
                calls.append(backend)
                if backend == "browseros":
                    return {
                        "identity": backend,
                        "requested": backend,
                        "resolved": backend,
                        "status": "unavailable",
                        "reason": "launch_failed",
                        "browser": {"browser": "unavailable", "protocol_version": "unavailable"},
                        "preset": "normal",
                        "headless": False,
                        "proxy_configured": False,
                        "ephemeral_profile": True,
                        "cases": [],
                    }
                return backend_result(backend)

            with mock.patch("chip_relay.benchmark_runner._run_matrix_backend", side_effect=fake_matrix):
                payload, _ = run_benchmark(
                    config(base),
                    backends=["chromium", "browseros"],
                    suite="local",
                    repeat=1,
                    preset="normal",
                    required_backends={"browseros"},
                )
            self.assertEqual(calls, ["chromium", "browseros"])
            self.assertEqual(payload["required_backend_failure"], ["browseros"])

    def test_active_cdp_runner_never_closes_operator_browser(self) -> None:
        source = (ROOT / "chip_relay" / "benchmark_runner.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        browser_close_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "browser"
            and node.func.attr == "close"
        ]
        self.assertEqual(browser_close_calls, [])

    def test_active_cannot_mix_with_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = config(pathlib.Path(tmp))
            with self.assertRaisesRegex(BenchmarkRunError, "benchmark_active_must_be_exclusive"):
                run_benchmark(
                    cfg,
                    backends=["active", "browseros"],
                    suite="local",
                    repeat=1,
                    preset="normal",
                )
            with self.assertRaisesRegex(BenchmarkRunError, "benchmark_backend_duplicate"):
                run_benchmark(
                    cfg,
                    backends=["browseros", "browseros"],
                    suite="local",
                    repeat=1,
                    preset="normal",
                )
            with self.assertRaisesRegex(BenchmarkRunError, "benchmark_required_backend_not_requested"):
                run_benchmark(
                    cfg,
                    backends=["browseros"],
                    suite="local",
                    repeat=1,
                    preset="normal",
                    required_backends={"chromium"},
                )

class RelayLifecycleTests(unittest.TestCase):
    def _fake_browser(self, root: pathlib.Path) -> pathlib.Path:
        script = root / "fake-chromium"
        script.write_text(
            """#!/usr/bin/env python3
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port = None
for arg in sys.argv[1:]:
    if arg.startswith('--remote-debugging-port='):
        port = int(arg.split('=', 1)[1])
if port is None:
    raise SystemExit(2)
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'Browser':'FakeChromium/1','Protocol-Version':'1.3'}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
HTTPServer(('127.0.0.1', port), Handler).serve_forever()
""",
            encoding="utf-8",
        )
        script.chmod(0o755)
        return script

    def _env(self, root: pathlib.Path, browser: pathlib.Path, port: int) -> dict[str, str]:
        env = os.environ.copy()
        env.update({
            "PYTHONPATH": str(ROOT),
            "CHIP_RELAY_BASE_DIR": str(root),
            "CHIP_RELAY_PROFILE_DIR": str(root / "profile"),
            "CHIP_RELAY_STATE_FILE": str(root / "state.json"),
            "CHIP_RELAY_LOG_DIR": str(root / "logs"),
            "CHIP_RELAY_CHROMIUM_BIN": str(browser),
            "CHIP_RELAY_BACKEND": "chromium",
            "CHIP_RELAY_HEADLESS": "1",
            "CHIP_RELAY_PORT": str(port),
            "CHIP_RELAY_LAUNCH_TIMEOUT": "5",
        })
        return env

    def test_launch_records_identity_and_kill_stops_exact_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            browser = self._fake_browser(root)
            port = _allocate_port(set())
            env = self._env(root, browser, port)
            launch = subprocess.run(
                [str(SCRIPT), "--json", "launch", "--backend", "chromium"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(launch.returncode, 0, launch.stderr + launch.stdout)
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            pid = state["pid"]
            self.assertEqual(state["processGroup"], pid)
            self.assertGreater(state["startTimeTicks"], 0)
            stopped = subprocess.run(
                [str(SCRIPT), "--json", "kill"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(stopped.returncode, 0, stopped.stderr + stopped.stdout)
            self.assertFalse(pathlib.Path(f"/proc/{pid}").exists())

    def test_kill_refuses_stale_start_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            browser = self._fake_browser(root)
            port = _allocate_port(set())
            env = self._env(root, browser, port)
            launch = subprocess.run(
                [str(SCRIPT), "--json", "launch", "--backend", "chromium"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(launch.returncode, 0, launch.stderr + launch.stdout)
            state_path = root / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            pid = state["pid"]
            state["startTimeTicks"] += 1
            state_path.write_text(json.dumps(state), encoding="utf-8")
            try:
                stopped = subprocess.run(
                    [str(SCRIPT), "--json", "kill"],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertNotEqual(stopped.returncode, 0)
                self.assertTrue(pathlib.Path(f"/proc/{pid}").exists())
                self.assertIn("ownership", stopped.stderr + stopped.stdout)
            finally:
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5
                while pathlib.Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
                    time.sleep(0.05)

    def test_kill_treats_unreaped_zombie_as_stopped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            browser = self._fake_browser(root)
            port = _allocate_port(set())
            env = self._env(root, browser, port)
            profile = root / "profile"
            profile.mkdir(parents=True, exist_ok=True)
            process = subprocess.Popen(
                [
                    str(browser),
                    f"--remote-debugging-port={port}",
                    f"--user-data-dir={profile}",
                ],
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        with urllib.request.urlopen(
                            f"http://127.0.0.1:{port}/json/version", timeout=1
                        ):
                            break
                    except OSError:
                        time.sleep(0.05)
                stat_fields = pathlib.Path(f"/proc/{process.pid}/stat").read_text().split()
                state_path = root / "state.json"
                state_path.write_text(
                    json.dumps(
                        {
                            "pid": process.pid,
                            "startTimeTicks": int(stat_fields[21]),
                            "port": port,
                            "profileDir": str(profile),
                        }
                    ),
                    encoding="utf-8",
                )
                state_path.chmod(0o600)
                stopped = subprocess.run(
                    [str(SCRIPT), "--json", "kill"],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(stopped.returncode, 0, stopped.stderr + stopped.stdout)
                self.assertEqual(process.poll(), -signal.SIGTERM)
                repeated = subprocess.run(
                    [str(SCRIPT), "--json", "kill"],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(repeated.returncode, 0, repeated.stderr + repeated.stdout)
                self.assertEqual(json.loads(repeated.stdout)["status"], "ok")
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)

    def test_launch_refuses_cdp_owned_by_another_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            browser = self._fake_browser(root)
            port = _allocate_port(set())
            first = root / "first"
            second = root / "second"
            first_env = self._env(first, browser, port)
            second_env = self._env(second, browser, port)
            launched = subprocess.run(
                [str(SCRIPT), "--json", "launch", "--backend", "chromium"],
                cwd=ROOT,
                env=first_env,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(launched.returncode, 0, launched.stderr + launched.stdout)
            state = json.loads((first / "state.json").read_text(encoding="utf-8"))
            pid = state["pid"]
            try:
                refused = subprocess.run(
                    [str(SCRIPT), "--json", "launch", "--backend", "chromium"],
                    cwd=ROOT,
                    env=second_env,
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn("ownership mismatch", refused.stderr)
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/json/version", timeout=2
                ) as response:
                    self.assertEqual(response.status, 200)
            finally:
                stopped = subprocess.run(
                    [str(SCRIPT), "--json", "kill"],
                    cwd=ROOT,
                    env=first_env,
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(stopped.returncode, 0, stopped.stderr + stopped.stdout)
                if pathlib.Path(f"/proc/{pid}").exists():
                    os.killpg(pid, signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
