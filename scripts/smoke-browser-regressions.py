#!/usr/bin/env python3
"""Explicit local-only smoke; owns a disposable browser, never attaches to a user profile."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from chip_relay.benchmark import gate_results
from chip_relay.benchmark_runner import local_fixture_server, run_benchmark
from chip_relay.benchmark_probes import input_checks
from chip_relay.config import RelayConfig


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--probe-binding", action="store_true", help="Observe CDP binding persistence on a task-owned local page")
    args = parser.parse_args()
    executable = Path(args.executable).resolve(strict=True)
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="relay-probe-smoke-") as tmp:
        root = Path(tmp)
        profile = root / "profile"
        profile.mkdir(mode=0o700)
        with (root / "browser.log").open("w") as log:
            process = subprocess.Popen([
                str(executable), "--headless=new", "--no-sandbox", "--disable-dev-shm-usage",
                "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                "--disable-component-update", "--disable-sync", "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0", f"--user-data-dir={profile}", "about:blank",
            ], stdout=log, stderr=log, start_new_session=True)
            try:
                deadline = time.monotonic() + 30
                port_file = profile / "DevToolsActivePort"
                while not port_file.exists():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("disposable_browser_start_failed")
                    time.sleep(0.1)
                port = int(port_file.read_text().splitlines()[0])
                cdp = f"http://127.0.0.1:{port}"
                config = RelayConfig(base_dir=output, runs_dir=output / "runs", recipes_dir=output / "recipes",
                    host="127.0.0.1", port=port, cdp_url=cdp, profile="disposable-smoke", profile_dir=profile,
                    proxy=None, upload_allowed_dirs=None)
                runs = []
                for name in ("baseline", "candidate"):
                    payload, path = run_benchmark(config, backends=["active"], suite="local", repeat=2,
                        preset="normal", output=str(output / f"{name}.json"))
                    runs.append(payload)
                    cases = {case["name"]: case for case in payload["results"][0]["cases"]}
                    assert len(cases) == 5, cases
                    assert cases["clean"]["page_status"] == "accessible", cases["clean"]
                    expected = "passed" if all(c["ok"] for c in cases["clean"]["fingerprint_checks"]) else "needs_attention"
                    assert cases["clean"]["status"] == expected, cases["clean"]
                    assert cases["blocked"]["status"] == "blocked", cases["blocked"]
                    assert cases["captcha"]["status"] == "captcha/manual", cases["captcha"]
                    for case in ("input-events", "init-script"):
                        assert cases[case]["behavior_checks"] and all(c["ok"] for c in cases[case]["behavior_checks"]), cases[case]
                gated = gate_results(*runs)
                assert gated.status == "passed", gated.as_dict()
                # Real negative controls: JavaScript click must not look like CDP input;
                # a page without pre-document initialization must not pass the init oracle.
                from playwright.sync_api import sync_playwright
                binding_probe = None
                context_cleanup = 'closed'
                with local_fixture_server() as base, sync_playwright() as pw:
                    browser = pw.chromium.connect_over_cdp(cdp)
                    context = browser.new_context()
                    try:
                        page = context.new_page()
                        page.goto(base + "/input-events")
                        page.evaluate("document.querySelector('#target').click()")
                        sample = page.evaluate("() => ({...window.__inputProbe, value: document.querySelector('#entry').value})")
                        negative = input_checks(sample)
                        assert any(c["name"] == "input.trusted_events" and c["ok"] is False for c in negative)
                        page.goto(base + "/init-script")
                        assert page.evaluate("window.__earlyProbe.ready") is False
                        from chip_relay.stealth import FINGERPRINT_JS, evaluate_fingerprint
                        from chip_relay.benchmark_runner import _classify_case
                        page.evaluate("Object.defineProperty(navigator, 'webdriver', {get: () => true})")
                        evaluation = evaluate_fingerprint(page.evaluate(FINGERPRINT_JS))
                        assert _classify_case(response_status=200, title=page.title(), url=page.url,
                            text="local fixture", evaluation=evaluation) == "needs_attention"
                        if args.probe_binding:
                            from chip_relay.cdp_binding_probe import probe_cdp_binding
                            binding_probe = probe_cdp_binding(context.new_page(), base + "/clean", base + "/init-script")
                    finally:
                        # All semantic assertions must finish before accepting an
                        # already-closed disposable context. Never mask their error.
                        if sys.exc_info()[0] is None:
                            from playwright._impl._errors import TargetClosedError
                            try:
                                context.close()
                            except TargetClosedError:
                                if process.poll() is not None:
                                    raise
                                context_cleanup = 'already_closed'
                receipt = {
                    "status": "verified", "package_root": str(ROOT),
                    "browser": runs[-1]["results"][0]["browser"],
                    "suite_version": runs[-1]["suite_version"], "local_only": True,
                    "gate_status": gated.status,
                    "cdp_binding_probe": binding_probe,
                    "disposable_context_cleanup": context_cleanup,
                    "negative_controls": {"js_click_rejected": True, "missing_init_rejected": True,
                                          "detected_webdriver_not_passed": True},
                    "cases": [{k: case[k] for k in ("name", "status", "page_status", "fingerprint_status", "behavior_checks", "repeat")}
                              for case in runs[-1]["results"][0]["cases"]],
                }
                path = output / "smoke-receipt.json"
                path.write_text(json.dumps(receipt, indent=2) + "\n")
                path.chmod(0o600)
                print(json.dumps(receipt, sort_keys=True))
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                assert process.poll() is not None


if __name__ == "__main__":
    main()
