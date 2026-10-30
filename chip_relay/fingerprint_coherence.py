"""Offline consistency checks; no browser access, injection or network traffic.

Input is an explicitly supplied, minimized observation, not a cookie/storage dump.
The result contains check names and verdicts only, never source values.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re

PLATFORMS = {"windows", "macos", "linux"}
CHECKS = (
    "ua_platform", "navigator_platform", "client_hint_platform",
    "ua_matches_http", "language_matches_http", "language_matches_profile",
    "screen_matches_profile", "viewport_fits_screen", "memory_matches_profile",
    "cores_match_profile", "touch_matches_profile",
)


def _platform(value):
    if not isinstance(value, str):
        return None
    text = value.lower().strip('" ')
    if "android" in text or "iphone" in text or "ipad" in text:
        return None  # Desktop-only contract: do not mistake Android for Linux.
    if "windows" in text or text.startswith("win"):
        return "windows"
    if "macintosh" in text or "macintel" in text or text == "macos":
        return "macos"
    if "linux" in text:
        return "linux"
    return None


def _number(value, *, integer=False, minimum: float = 0):
    return (not isinstance(value, bool) and isinstance(value, (int, float))
            and math.isfinite(value) and value >= minimum
            and (not integer or isinstance(value, int)))


def _locale(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", value) is not None


def _first_language(value):
    if not isinstance(value, str):
        return None
    # First listed language is not necessarily preferred: honour q weights.
    choices = []
    for index, part in enumerate(value.split(",")):
        fields = part.strip().split(";")
        language = fields[0].strip()
        if not _locale(language) or len(fields) > 2:
            return None
        quality = 1.0
        if len(fields) == 2:
            match = re.fullmatch(r"q=(0(?:\.\d{1,3})?|1(?:\.0{1,3})?)", fields[1].strip())
            if not match:
                return None
            quality = float(match[1])
        if quality > 0:
            choices.append((quality, -index, language.lower()))
    return max(choices)[2] if choices else None


def evaluate(document):
    """Return passed only when every check ran and passed.

    Missing measurements are not_run, contradictory/invalid supplied values fail.
    Invalid top-level contracts raise ValueError; callers must not label them green.
    """
    if (not isinstance(document, dict)
            or set(document) != {"schema_version", "expected", "observed"}
            or type(document.get("schema_version")) is not int
            or document["schema_version"] != 1):
        raise ValueError("invalid_schema")
    expected = document.get("expected")
    observed = document.get("observed")
    if not isinstance(expected, dict) or not isinstance(observed, dict):
        raise ValueError("invalid_contract")
    required = {"platform", "locale", "screen", "device_memory_gb", "hardware_concurrency", "touch"}
    if (set(expected) != required or not isinstance(expected["platform"], str)
            or expected["platform"] not in PLATFORMS or not _locale(expected["locale"])):
        raise ValueError("invalid_expected_profile")
    screen = expected["screen"]
    if (not isinstance(screen, dict) or set(screen) != {"width", "height", "device_scale_factor"}
            or not all(_number(screen[k], integer=True, minimum=1) for k in ("width", "height"))
            or not _number(screen["device_scale_factor"], minimum=0.1)
            or not _number(expected["device_memory_gb"], minimum=0.1)
            or not _number(expected["hardware_concurrency"], integer=True, minimum=1)
            or not isinstance(expected["touch"], bool)):
        raise ValueError("invalid_expected_profile")
    allowed = {"headers", "navigator", "screen", "viewport"}
    if set(observed) - allowed or any(not isinstance(v, dict) for v in observed.values()):
        raise ValueError("invalid_observation")
    field_sets = {
        "headers": {"user-agent", "accept-language", "sec-ch-ua-platform"},
        "navigator": {"userAgent", "platform", "language", "deviceMemory", "hardwareConcurrency", "maxTouchPoints"},
        "screen": {"width", "height", "device_scale_factor"},
        "viewport": {"width", "height"},
    }
    for section, values in observed.items():
        if set(values) - field_sets[section]:
            raise ValueError("unexpected_observation_field")
    headers = observed.get("headers", {})
    nav = observed.get("navigator", {})
    actual_screen = observed.get("screen", {})
    viewport = observed.get("viewport", {})
    results = {name: "not_run" for name in CHECKS}

    def check(name, inputs, predicate):
        if all(value is not None for value in inputs):
            results[name] = "passed" if predicate() else "failed"

    for name, value in (("ua_platform", nav.get("userAgent")),
                        ("navigator_platform", nav.get("platform")),
                        ("client_hint_platform", headers.get("sec-ch-ua-platform"))):
        check(name, [value], lambda value=value: _platform(value) == expected["platform"])
    ua, http_ua = nav.get("userAgent"), headers.get("user-agent")
    check("ua_matches_http", [ua, http_ua], lambda: isinstance(ua, str) and ua == http_ua)
    language, http_language = nav.get("language"), headers.get("accept-language")
    check("language_matches_http", [language, http_language],
          lambda: _locale(language) and language.lower() == _first_language(http_language))
    check("language_matches_profile", [language],
          lambda: _locale(language) and language.lower() == expected["locale"].lower())
    check("screen_matches_profile", [actual_screen.get(k) for k in screen],
          lambda: all(_number(actual_screen[k], integer=k != "device_scale_factor", minimum=0.1)
                      and actual_screen[k] == screen[k] for k in screen))
    check("viewport_fits_screen", [viewport.get(k) for k in ("width", "height")]
          + [actual_screen.get(k) for k in ("width", "height")],
          lambda: all(_number(viewport[k], integer=True, minimum=1)
                      and _number(actual_screen[k], integer=True, minimum=1)
                      and viewport[k] <= actual_screen[k] for k in ("width", "height")))
    for name, actual, wanted, integer in (
        ("memory_matches_profile", nav.get("deviceMemory"), expected["device_memory_gb"], False),
        ("cores_match_profile", nav.get("hardwareConcurrency"), expected["hardware_concurrency"], True),
    ):
        check(name, [actual], lambda actual=actual, wanted=wanted, integer=integer:
              _number(actual, integer=integer, minimum=0.1) and actual == wanted)
    touch = nav.get("maxTouchPoints")
    check("touch_matches_profile", [touch], lambda: _number(touch, integer=True) and (touch > 0) == expected["touch"])
    status = ("needs_attention" if "failed" in results.values() else
              "not_run" if "not_run" in results.values() else "passed")
    return {"schema_version": 1, "status": status, "checks": results,
            "scope": "offline_consistency_only", "browser_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observation", type=Path)
    args = parser.parse_args(argv)
    try:
        result = evaluate(json.loads(args.observation.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, OverflowError):
        # Do not echo paths, private values or parser errors from input.
        print(json.dumps({"status": "blocked", "error": "invalid_input"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
