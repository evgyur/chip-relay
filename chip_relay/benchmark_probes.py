"""Local, synthetic browser probes. Never inspect account pages or real input.

Original fixtures inspired by the test categories in Stealth Browser MCP (MIT),
not its browser lifecycle or input fallbacks. CDP events are not physical input.
"""
from __future__ import annotations

import json
import re
from typing import Any

INPUT_TEXT = "chip-relay input 42!"
INIT_SCRIPT = "window.__relayProbe = {ready: true, executions: (window.__relayProbe?.executions || 0) + 1};"
INPUT_HTML = """<!doctype html><html><head><title>relay input fixture</title></head>
<body><button id="target">Probe</button><textarea id="entry"></textarea>
<script>
window.__inputProbe = {events: [], clicks: 0, mutations: 0};
for (const type of ['pointerdown','pointerup','mousedown','mouseup','click','keydown','keyup','input']) {
  document.addEventListener(type, event => {
    if (__inputProbe.events.length < 300) __inputProbe.events.push({type, trusted: event.isTrusted, target: event.target.id});
  }, true);
}
document.querySelector('#target').addEventListener('click', () => __inputProbe.clicks++);
new MutationObserver(records => { __inputProbe.mutations += records.length; })
  .observe(document.documentElement, {childList:true, subtree:true});
</script></body></html>"""
INIT_HTML = """<!doctype html><html><head><script>
window.__earlyProbe = {ready: window.__relayProbe?.ready === true,
 executions: window.__relayProbe?.executions || 0};
</script><title>relay init fixture</title></head><body>local initialization probe</body></html>"""

REQUIRED_BEHAVIOR_CHECKS = {
    "input-events": {"input.trusted_events", "input.pointer_sequence", "input.keyboard_sequence",
                     "input.single_click", "input.exact_text", "input.no_dom_nodes"},
    "init-script": {"init.before_page_script", "init.after_navigation"},
    "tls-protocol": {"tls.version_observed", "tls.fingerprint_observed", "tls.http_version_observed"},
}


def behavior_status(name: str, checks: list[dict[str, Any]]) -> str:
    required = REQUIRED_BEHAVIOR_CHECKS.get(name)
    if required is None:
        return "not_applicable"
    if len(checks) != len(required) or {c.get("name") for c in checks} != required or any(type(c.get("ok")) is not bool for c in checks):
        return "not_run"
    return "passed" if all(c["ok"] for c in checks) else "needs_attention"


def input_checks(sample: dict[str, Any]) -> list[dict[str, Any]]:
    events = sample.get("events") or []
    button = [e.get("type") for e in events if e.get("target") == "target"]
    expected = ["pointerdown", "mousedown", "pointerup", "mouseup", "click"]
    typed = [e.get("type") for e in events if e.get("target") == "entry" and e.get("type") in {"keydown", "keyup", "input"}]
    values = {
        "input.trusted_events": bool(events) and all(e.get("trusted") is True for e in events),
        "input.pointer_sequence": button == expected,
        "input.keyboard_sequence": typed == ["keydown", "input", "keyup"] * len(INPUT_TEXT),
        "input.single_click": sample.get("clicks") == 1,
        "input.exact_text": sample.get("value") == INPUT_TEXT,
        "input.no_dom_nodes": sample.get("mutations") == 0,
    }
    return [{"name": key, "ok": value} for key, value in values.items()]


def run_input_probe(page: Any) -> list[dict[str, Any]]:
    # No JS .click(), fill(), insertText(), or fallback to a different input rail.
    page.locator("#target").click(timeout=3000)
    page.locator("#entry").click(timeout=3000)
    page.keyboard.type(INPUT_TEXT)
    sample = page.evaluate("""() => ({...window.__inputProbe,
      value: document.querySelector('#entry').value})""")
    return input_checks(sample)


def run_init_probe(page: Any, target: str) -> list[dict[str, Any]]:
    first = page.evaluate("window.__earlyProbe")
    page.goto(target + "?navigation=2", wait_until="load", timeout=5000)
    second = page.evaluate("window.__earlyProbe")
    return [
        {"name": "init.before_page_script", "ok": first == {"ready": True, "executions": 1}},
        {"name": "init.after_navigation", "ok": second == {"ready": True, "executions": 1}},
    ]


def tls_observation(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Allowlist only protocol evidence. Never retain provider IP/header payloads."""
    raw = json.loads(text) if len(text) <= 262144 else {}
    if not isinstance(raw, dict):
        raw = {}
    tls = raw.get("tls", {})
    if not isinstance(tls, dict):
        tls = {}
    evidence = {}
    for key in ("tls_version_negotiated", "ja3_hash", "ja4"):
        value = tls.get(key)
        pattern = {"tls_version_negotiated": r"[0-9]{3,4}", "ja3_hash": r"[0-9a-f]{32}",
                   "ja4": r"[a-zA-Z0-9_]{1,128}"}[key]
        if isinstance(value, str) and re.fullmatch(pattern, value):
            evidence[key] = value
    if isinstance(raw.get("http_version"), str) and raw["http_version"] in {"h2", "HTTP/2", "HTTP/1.1", "h3"}:
        evidence["http_version"] = raw["http_version"]
    checks = [
        {"name": "tls.version_observed", "ok": "tls_version_negotiated" in evidence},
        {"name": "tls.fingerprint_observed", "ok": bool(evidence.get("ja3_hash") or evidence.get("ja4"))},
        {"name": "tls.http_version_observed", "ok": "http_version" in evidence},
    ]
    return checks, evidence
