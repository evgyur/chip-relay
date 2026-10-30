"""Optional owned-browser smoke; no saved profile, service or launcher is reused.

Run explicitly: python tests/smoke_attach_browser.py --browser /path/to/chrome
Add --public-network to compare a real browser IPv4 echo with a test expectation.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from chip_relay.attach.binding import BindingError, process_identity, verify_binding
from chip_relay.attach.profile_selection import resolve, write_selection

from chip_relay.attach.runner import run_checked
from chip_relay.attach.humanize import humanize_page

HTML = b"""<!doctype html><html><body><p id="identity">fixture-account</p>
<label>Search<input id="search"></label><button id="go">Search</button>
<script>window.clicks=0;window.trusted=[];
document.querySelector('#go').addEventListener('click',e=>{window.clicks++;window.trusted.push(e.isTrusted)});
document.querySelector('#search').addEventListener('input',e=>window.trusted.push(e.isTrusted));</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--public-network", action="store_true")
    args = parser.parse_args()
    executable = Path(args.browser).resolve(strict=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix="relay-attach-owned-") as tmp:
            root = Path(tmp).resolve()
            profile = root / "profile"
            profile.mkdir(mode=0o700)
            with socket.socket() as allocator:
                allocator.bind(("127.0.0.1", 0))
                port = allocator.getsockname()[1]
            flags = [
                str(executable),
                "--headless=new",
                "--no-sandbox",
                "--no-first-run",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--disable-dev-shm-usage",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=" + str(port),
                "--user-data-dir=" + str(profile),
                "about:blank",
            ]
            env = {
                key: os.environ[key]
                for key in ["HOME", "PATH", "TMPDIR", "LANG", "XDG_RUNTIME_DIR"]
                if key in os.environ
            }
            with (root / "browser.log").open("w") as log:
                child = subprocess.Popen(
                    flags, stdout=log, stderr=log, start_new_session=True, env=env
                )
                try:
                    deadline = time.monotonic() + 20
                    while True:
                        if child.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("owned_browser_unavailable")
                        try:
                            with socket.create_connection(
                                ("127.0.0.1", port), timeout=0.1
                            ):
                                break
                        except OSError:
                            time.sleep(0.1)
                    identity = process_identity(child.pid)
                    st = profile.stat()
                    entry = {
                        "lifecycle": "external",
                        "endpoint": f"http://127.0.0.1:{port}",
                        "uid": os.geteuid(),
                        "pid": child.pid,
                        "start_time": identity["start_time"],
                        "executable": str(executable),
                        "profile_path": str(profile),
                        "profile_inode": st.st_ino,
                        "profile_device": st.st_dev,
                        "profile_directory": "Default",
                        "capabilities": {
                            "authenticated": False,
                            "isolated_benchmark": True,
                        },
                    }
                    verify_binding(entry)
                    registry = {
                        "schema": "relay-external-binding-v1",
                        "profiles": {"fixture": entry},
                        "account_routes": {
                            "fixture-account": {
                                "profile": "fixture",
                                "evidence": "synthetic fixture, not provider login",
                            }
                        },
                        "routing": {
                            "schema": "relay-routing-v1",
                            "rules": [],
                            "networks": {
                                "inherit": {
                                    "kind": "unspecified",
                                    "expected_ips": [],
                                    "scope": "unknown",
                                    "evidence": "fixture unconstrained",
                                }
                            },
                            "profile_networks": {"fixture": "inherit"},
                            "inventory": {"fixture": {}},
                            "conflicts": [],
                        },
                    }
                    binding = root / "binding.json"
                    binding.write_text(json.dumps(registry))
                    binding.chmod(0o600)
                    origin = f"http://127.0.0.1:{server.server_port}"
                    selection = resolve(
                        registry,
                        site=origin,
                        account="fixture-account",
                        session="smoke",
                    )
                    pin = root / "pin.json"
                    write_selection(str(pin), selection)
                    from playwright.sync_api import sync_playwright

                    with sync_playwright() as driver:
                        browser = driver.chromium.connect_over_cdp(
                            entry["endpoint"], timeout=5000
                        )
                        page = browser.contexts[0].new_page()
                        try:
                            page.goto(origin, timeout=10000)

                            def action(bound, selected):
                                with humanize_page(
                                    page,
                                    expected_origin=selected["origin"],
                                    expected_account=selected["expected_account"],
                                    identity_check=lambda: (
                                        page.locator("#identity").inner_text()
                                        == "fixture-account"
                                    ),
                                    mode="careful",
                                ) as human:
                                    human.fill(
                                        page.get_by_label("Search"), "Hello Attach"
                                    )
                                    human.click(
                                        page.get_by_role(
                                            "button", name="Search", exact=True
                                        )
                                    )
                                assert (
                                    page.get_by_label("Search").input_value()
                                    == "Hello Attach"
                                )
                                assert page.evaluate("window.clicks") == 1
                                assert all(page.evaluate("window.trusted"))
                                return {
                                    "exact_text": True,
                                    "single_click": True,
                                    "trusted_input": True,
                                    "context_bound": True,
                                }

                            checks = run_checked(
                                binding, pin, action, session="smoke", target_url=origin
                            )
                            probes = 0
                            if args.public_network:
                                opener = urllib.request.build_opener(
                                    urllib.request.ProxyHandler({})
                                )
                                with opener.open(
                                    "https://api.ipify.org/?format=json", timeout=15
                                ) as response:
                                    expected = str(
                                        ipaddress.IPv4Address(json.load(response)["ip"])
                                    )
                                registry["routing"]["networks"]["exact"] = {
                                    "kind": "exact-ipv4",
                                    "expected_ips": [expected],
                                    "scope": "test IPv4 only",
                                    "evidence": "test expectation compared separately with actual browser response",
                                }
                                binding.write_text(json.dumps(registry))
                                network_pin = resolve(
                                    registry,
                                    site=origin,
                                    account="fixture-account",
                                    session="smoke",
                                    network="exact",
                                )
                                pending_path = root / "network-pending.json"
                                write_selection(str(pending_path), network_pin)
                                checked_path = root / "checked.json"
                                cli = [
                                    sys.executable,
                                    "-B",
                                    "-m",
                                    "chip_relay.attach",
                                    "--binding",
                                    str(binding),
                                    "--session",
                                    "smoke",
                                    "--selection",
                                    str(pending_path),
                                    "network-check",
                                    "--write",
                                    str(checked_path),
                                ]
                                cli_env = dict(
                                    env,
                                    PYTHONPATH=str(Path(__file__).resolve().parents[1]),
                                    PYTHONNOUSERSITE="1",
                                )
                                for attempt in range(2):
                                    probes += 1
                                    observed = subprocess.run(
                                        cli,
                                        env=cli_env,
                                        capture_output=True,
                                        text=True,
                                        timeout=40,
                                    )
                                    payload = json.loads(observed.stdout)
                                    if observed.returncode == 0:
                                        assert payload["status"] == "ipv4_exit_verified"
                                        break
                                    if (
                                        payload.get("failed_gate")
                                        != "routing_network_probe_failed"
                                        or attempt
                                    ):
                                        raise BindingError(
                                            "public_smoke_network_check_failed"
                                        )
                                run_checked(
                                    binding,
                                    checked_path,
                                    lambda *a: True,
                                    session="smoke",
                                    target_url=origin,
                                )
                                checks["actual_browser_ipv4_probe"] = True
                            report = {
                                "status": "verified",
                                "checks": checks,
                                "public_probe_attempts": probes,
                                "scope": "owned disposable synthetic profile",
                                "real_provider_login_proved": False,
                                "production_runtime_changed": False,
                            }
                        finally:
                            page.close()
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGTERM)
                        try:
                            child.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait(timeout=5)
                    assert child.poll() is not None
            report["owned_process_stopped"] = True
            print(json.dumps(report))
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


if __name__ == "__main__":
    main()
