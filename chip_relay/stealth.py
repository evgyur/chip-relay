from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PRESETS: dict[str, dict[str, Any]] = {
    "normal": {
        "headless": "allowed-for-ci",
        "init_scripts": [],
        "notes": "Default diagnostic mode; no bypass claim.",
    },
    "strict": {
        "headless": "prefer-off",
        "init_scripts": ["webdriver", "language-timezone", "webgl-metadata"],
        "notes": "Consistency-first preset for automation-sensitive sites.",
    },
    "cf-sensitive": {
        "headless": "off-required-for-live-smoke",
        "init_scripts": ["webdriver", "language-timezone", "webgl-metadata", "ua-platform-consistency"],
        "notes": "Cloudflare-sensitive diagnostic preset; reports outcomes, never guarantees bypass.",
    },
}

FINGERPRINT_JS = """
(() => ({
  webdriver: navigator.webdriver,
  userAgent: navigator.userAgent,
  platform: navigator.platform,
  languages: navigator.languages,
  language: navigator.language,
  timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
  webglVendor: (() => {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    return ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null;
  })(),
  webglRenderer: (() => {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    return ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null;
  })()
}))()
""".strip()


def platform_consistent(user_agent: str, platform: str) -> bool:
    ua = user_agent.lower()
    value = platform.lower()
    if "windows" in ua:
        return value.startswith("win")
    if "mac os" in ua or "macintosh" in ua:
        return value.startswith("mac")
    if "linux" in ua:
        return "linux" in value or "x11" in ua
    return True


def evaluate_fingerprint(sample: dict[str, Any] | None) -> dict[str, Any]:
    if not sample:
        return {"status": "not_run", "checks": [], "script": FINGERPRINT_JS}
    ua = str(sample.get("userAgent") or sample.get("user_agent") or "")
    platform = str(sample.get("platform") or "")
    languages = sample.get("languages") or []
    checks = [
        {"name": "webdriver", "ok": sample.get("webdriver") in {False, None}, "value": sample.get("webdriver")},
        {"name": "headless_ua", "ok": "HeadlessChrome" not in ua, "value": "HeadlessChrome" in ua},
        {"name": "languages", "ok": bool(languages or sample.get("language")), "value": languages or sample.get("language")},
        {"name": "timezone", "ok": bool(sample.get("timezone")), "value": sample.get("timezone")},
        {"name": "webgl_vendor", "ok": bool(sample.get("webglVendor") or sample.get("webgl_vendor")), "value": sample.get("webglVendor") or sample.get("webgl_vendor")},
        {"name": "webgl_renderer", "ok": bool(sample.get("webglRenderer") or sample.get("webgl_renderer")), "value": sample.get("webglRenderer") or sample.get("webgl_renderer")},
        {"name": "ua_platform_consistency", "ok": platform_consistent(ua, platform), "value": {"userAgent": ua, "platform": platform}},
    ]
    return {"status": "ok" if all(item["ok"] for item in checks) else "needs_attention", "checks": checks, "script": FINGERPRINT_JS}


def classify_challenge(sample: dict[str, Any] | None) -> dict[str, Any]:
    if not sample:
        return {"status": "not_run", "evidence": "no live challenge sample supplied"}
    text = " ".join(str(sample.get(key, "")) for key in ("title", "url", "text", "body", "status_text")).lower()
    status = sample.get("status")
    if sample.get("challenge_passed") is True or "nowsecure" in text or "success" in text:
        return {"status": "passed", "evidence": "sample indicates challenge success"}
    if "captcha" in text or "turnstile" in text or sample.get("captcha"):
        return {"status": "captcha/manual", "evidence": "captcha/manual challenge detected"}
    if status in {403, 429} or "access denied" in text or "blocked" in text:
        return {"status": "blocked", "evidence": f"blocked signal status={status}"}
    if "proxy" in text or "ip reputation" in text:
        return {"status": "needs_proxy", "evidence": "proxy/ip reputation signal"}
    return {"status": "not_run", "evidence": "sample does not contain a recognized challenge outcome"}


def load_sample(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def stealth_doctor(*, preset: str = "normal", sample: dict[str, Any] | None = None) -> dict[str, Any]:
    if preset not in PRESETS:
        raise ValueError(f"unknown_stealth_preset: {preset}")
    return {
        "schema": "chip-relay-stealth-diagnostic-v1",
        "preset": preset,
        "preset_config": PRESETS[preset],
        "fingerprint": evaluate_fingerprint(sample),
        "challenge": classify_challenge(sample),
        "claim_policy": "diagnostic-only/no-guaranteed-bypass",
    }
