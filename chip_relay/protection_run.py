from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path
from typing import Any

from .network import load_observations, utc_now_text
from .protection import (
    DIAGNOSTIC_SCHEMA,
    _open_protection_dir_fd,
    _read_bounded_fd,
    _signal_values,
    _write_all,
    diagnose_signals,
    instrumentation_notice,
    load_default_rule_pack,
    load_page_signals,
    protection_dir,
)
from .workspace import _manifest_lock, current_attempt_id, execution_marker, load_manifest

PROTECTION_COOKIES = {
    "_abck",
    "_px3",
    "_pxvid",
    "ak_bmsc",
    "aws-waf-token",
    "bm_sz",
    "cf_clearance",
    "datadome",
    "f5avr",
    "incap_ses",
    "kp_uidz",
    "visid_incap",
}


def _has_protection_cookie(names: set[str]) -> bool:
    return bool(names & PROTECTION_COOKIES) or any(
        name.startswith(("incap_ses_", "visid_incap_")) or re.fullmatch(r"ts[0-9a-f]{6,}", name)
        for name in names
    )


def _compiled_rule_signals() -> list[tuple[str, list[tuple[str, re.Pattern[str]]]]]:
    pack = load_default_rule_pack()
    return [
        (
            str(rule["category"]).lower(),
            [(signal["method"], re.compile(signal["pattern"], re.IGNORECASE)) for signal in rule["signals"]],
        )
        for rule in pack["rules"]
    ]


def _matching_categories(
    signals: dict[str, Any],
    compiled_rules: list[tuple[str, list[tuple[str, re.Pattern[str]]]]],
) -> set[str]:
    return {
        category
        for category, rule_signals in compiled_rules
        if any(
            pattern.search(value)
            for method, pattern in rule_signals
            for value in _signal_values(signals, method)
        )
    }


def aggregate_run_signals(run_dir: Path) -> dict[str, Any]:
    attempt_id = current_attempt_id(run_dir)
    compiled_rules = _compiled_rule_signals()
    aggregate: dict[str, Any] = {
        "urls": [],
        "statuses": [],
        "header_names": [],
        "cookie_names": [],
        "page_markers": [],
        "window_keys": [],
        "fingerprint_apis": {},
        "title_classifications": [],
        "modes": [],
        "correlated_blockers": {
            "manual_captcha": False,
            "rate_limit": False,
            "fingerprint_inconsistency": False,
            "likely_profile_state": False,
            "likely_ip_reputation": False,
        },
    }
    for row in load_observations(run_dir):
        if row.get("attempt_id") != attempt_id:
            continue
        url = row.get("url")
        if isinstance(url, str) and url:
            aggregate["urls"].append(url)
        status = row.get("status")
        if isinstance(status, int) and not isinstance(status, bool):
            aggregate["statuses"].append(status)
        for field in ("request_headers", "response_headers"):
            headers = row.get(field)
            if isinstance(headers, dict):
                aggregate["header_names"].extend(str(name) for name in headers)
        for field in ("request_cookie_names", "response_cookie_names"):
            names = row.get(field)
            if isinstance(names, list):
                aggregate["cookie_names"].extend(str(name) for name in names if isinstance(name, str))
        row_headers = {
            str(name)
            for field in ("request_headers", "response_headers")
            for name in (row.get(field) or {})
            if isinstance(row.get(field), dict) and isinstance(name, str)
        }
        row_cookies = {
            str(name).lower()
            for field in ("request_cookie_names", "response_cookie_names")
            for name in (row.get(field) or [])
            if isinstance(row.get(field), list) and isinstance(name, str)
        }
        row_signals = {
            "urls": [url] if isinstance(url, str) and url else [],
            "statuses": [status] if isinstance(status, int) and not isinstance(status, bool) else [],
            "header_names": sorted(row_headers),
            "cookie_names": sorted(row_cookies),
        }
        row_categories = _matching_categories(row_signals, compiled_rules)
        correlated = aggregate["correlated_blockers"]
        if status == 429 and row_categories:
            correlated["rate_limit"] = True
        if status == 403 and _has_protection_cookie(row_cookies):
            correlated["likely_profile_state"] = True
        elif status == 403 and row_categories:
            correlated["likely_ip_reputation"] = True

    for row in load_page_signals(run_dir):
        if row.get("attempt_id") != attempt_id:
            continue
        url = row.get("final_url")
        if isinstance(url, str) and url:
            aggregate["urls"].append(url)
        status = row.get("status")
        if isinstance(status, int) and not isinstance(status, bool):
            aggregate["statuses"].append(status)
        for field in ("page_markers", "window_keys"):
            values = row.get(field)
            if isinstance(values, list):
                aggregate[field].extend(str(value) for value in values if isinstance(value, str))
        classification = row.get("title_classification")
        if isinstance(classification, str):
            aggregate["title_classifications"].append(classification)
        mode = row.get("mode")
        if isinstance(mode, str):
            aggregate["modes"].append(mode)
        counts = row.get("fingerprint_apis")
        if isinstance(counts, dict):
            for name, count in counts.items():
                if isinstance(name, str) and isinstance(count, int) and not isinstance(count, bool) and count > 0:
                    aggregate["fingerprint_apis"][name] = min(1000, aggregate["fingerprint_apis"].get(name, 0) + count)
        row_signals = {
            "urls": [url] if isinstance(url, str) and url else [],
            "statuses": [status] if isinstance(status, int) and not isinstance(status, bool) else [],
            "page_markers": row.get("page_markers", []),
            "window_keys": row.get("window_keys", []),
            "fingerprint_apis": counts if isinstance(counts, dict) else {},
            "title_classifications": [classification] if isinstance(classification, str) else [],
        }
        row_categories = _matching_categories(row_signals, compiled_rules)
        row_title = classification.lower() if isinstance(classification, str) else ""
        row_markers = {
            str(value).lower()
            for value in row.get("page_markers", [])
            if isinstance(value, str)
        }
        correlated = aggregate["correlated_blockers"]
        if row_title == "captcha" or (row_title == "challenge" and "captcha" in row_categories):
            correlated["manual_captcha"] = True
        if status == 429 and row_categories:
            correlated["rate_limit"] = True
        if "fingerprint-inconsistency" in row_markers:
            correlated["fingerprint_inconsistency"] = True
        if status == 403 and row_categories:
            correlated["likely_ip_reputation"] = True

    for field in (
        "urls",
        "statuses",
        "header_names",
        "cookie_names",
        "page_markers",
        "window_keys",
        "title_classifications",
        "modes",
    ):
        aggregate[field] = sorted(set(aggregate[field]), key=lambda value: str(value).lower())
    aggregate["fingerprint_apis"] = dict(sorted(aggregate["fingerprint_apis"].items(), key=lambda item: item[0].lower()))
    return aggregate


def classify_blocker(signals: dict[str, Any], protections: list[dict[str, Any]]) -> dict[str, Any]:
    title_classes = {str(value).lower() for value in signals.get("title_classifications", [])}
    categories = {str(item.get("category", "")).lower() for item in protections if isinstance(item, dict)}
    providers = [str(item.get("provider")) for item in protections if isinstance(item, dict) and item.get("provider")]
    correlated = signals.get("correlated_blockers")
    flags = correlated if isinstance(correlated, dict) else {}
    active_captcha = flags.get("manual_captcha") is True or (
        not flags and ("captcha" in title_classes or ("captcha" in categories and "captcha" in title_classes))
    )
    if active_captcha:
        blocker_class = "manual_captcha"
        label = "manual CAPTCHA"
        rationale = "An active normalized CAPTCHA/challenge page and CAPTCHA metadata were observed."
        next_tests = ["Complete the challenge manually in a trusted profile.", "Rerun a passive rendered smoke test."]
    elif flags.get("rate_limit") is True or (not flags and "rate_limited" in title_classes):
        blocker_class = "rate_limit"
        label = "rate limiting"
        rationale = "HTTP 429 or a normalized rate-limit page classification was observed."
        next_tests = ["Wait for the documented cooldown window.", "Reduce request rate and rerun one passive smoke test."]
    elif flags.get("fingerprint_inconsistency") is True:
        blocker_class = "fingerprint_inconsistency"
        label = "fingerprint inconsistency"
        rationale = "A normalized fingerprint-inconsistency marker was supplied by the run rail."
        next_tests = ["Compare the existing stealth doctor output with the selected preset.", "Rerun once in a fresh profile without instrumentation."]
    elif flags.get("likely_profile_state") is True:
        blocker_class = "likely_profile_state"
        label = "likely persistent profile state"
        rationale = "A denied response and protection-specific cookie names were observed on the same request."
        next_tests = ["Rerun the same target with a fresh ephemeral profile.", "Keep egress fixed so profile state is the only changed variable."]
    elif flags.get("likely_ip_reputation") is True:
        blocker_class = "likely_ip_reputation"
        label = "likely IP reputation or edge policy"
        rationale = "A denied response and provider signature were observed on the same request without protection-cookie state."
        next_tests = ["Rerun once with the same profile and an approved alternate egress.", "Compare status and provider evidence; do not automate rotation."]
    else:
        blocker_class = "unknown"
        label = "unknown blocker"
        rationale = "The available normalized metadata does not support a narrower blocker hypothesis."
        next_tests = ["Capture one passive rendered run with network metadata.", "Inspect the compact diagnosis before changing profile or egress."]

    return {
        "class": blocker_class,
        "label": label,
        "certainty": "hypothesis",
        "rationale": rationale,
        "providers": providers,
        "next_tests": next_tests,
        "claim_limit": "Diagnostic guidance only; no bypass, stealth, or success claim.",
    }


def diagnosis_path(run_dir: Path) -> Path:
    return protection_dir(run_dir) / "diagnosis.json"


def _attempt_marker(run_dir: Path) -> dict[str, Any]:
    try:
        manifest = load_manifest(run_dir)
    except (FileNotFoundError, ValueError, json.JSONDecodeError):
        return {"generation": 0, "attempt_id": "attempt-000000000000"}
    return execution_marker(manifest)


def _signals_digest(signals: dict[str, Any], marker: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"signals": signals, "attempt": marker},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _build_current_diagnosis_locked(run_dir: Path) -> dict[str, Any]:
    try:
        manifest = load_manifest(run_dir)
    except (OSError, ValueError, json.JSONDecodeError):
        manifest = None
    execution = manifest.get("execution") if isinstance(manifest, dict) else None
    if isinstance(execution, dict) and execution.get("phase") == "running":
        raise ValueError("execution_attempt_in_progress")
    signals = aggregate_run_signals(run_dir)
    mode = "instrumented" if "instrumented" in signals.get("modes", []) else "passive"
    marker = _attempt_marker(run_dir)
    diagnosis = diagnose_signals(signals, mode=mode)
    diagnosis.update(
        {
            "run_id": run_dir.name,
            "signals_digest": _signals_digest(signals, marker),
            "attempt_marker": marker,
            "signals_summary": {
                "url_count": len(signals["urls"]),
                "status_codes": signals["statuses"],
                "header_name_count": len(signals["header_names"]),
                "cookie_name_count": len(signals["cookie_names"]),
                "page_marker_count": len(signals["page_markers"]),
                "window_key_count": len(signals["window_keys"]),
                "fingerprint_api_count": len(signals["fingerprint_apis"]),
            },
        }
    )
    diagnosis["blocker"] = classify_blocker(signals, diagnosis["protections"])
    if mode == "instrumented":
        diagnosis["instrumentation_notice"] = instrumentation_notice()
    return diagnosis


def _write_private_json(run_dir: Path, payload: dict[str, Any]) -> None:
    root_fd = _open_protection_dir_fd(run_dir, create=True)
    if root_fd is None:
        raise ValueError("unsafe_diagnosis_path: protection directory unavailable")
    temporary = f".diagnosis-{os.getpid()}-{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(
                descriptor,
                (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, "diagnosis.json", src_dir_fd=root_fd, dst_dir_fd=root_fd)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass
        raise ValueError(f"unsafe_diagnosis_path: {exc}") from exc
    finally:
        os.close(root_fd)


def diagnose_run(run_dir: Path) -> dict[str, Any]:
    with _manifest_lock(run_dir):
        diagnosis = _build_current_diagnosis_locked(run_dir)
        diagnosis["generated_at"] = utc_now_text()
        _write_private_json(run_dir, diagnosis)
        return diagnosis


def _read_diagnosis_payload(run_dir: Path) -> dict[str, Any] | None:
    root_fd = _open_protection_dir_fd(run_dir, create=False)
    if root_fd is None:
        return None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open("diagnosis.json", flags, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError(f"unsafe_diagnosis_path: {exc}") from exc
        try:
            data = _read_bounded_fd(
                descriptor,
                max_bytes=1024 * 1024,
                too_large_gate="diagnosis_file_too_large",
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed_protection_diagnosis") from exc
    if not isinstance(payload, dict) or payload.get("schema") != DIAGNOSTIC_SCHEMA:
        raise ValueError("malformed_protection_diagnosis")
    return payload


def _load_protection_diagnosis_locked(run_dir: Path) -> dict[str, Any] | None:
    payload = _read_diagnosis_payload(run_dir)
    if payload is None:
        return None
    generated_at = payload.get("generated_at")
    digest = payload.get("signals_digest")
    if not isinstance(generated_at, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", generated_at):
        raise ValueError("malformed_protection_diagnosis")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("malformed_protection_diagnosis")
    expected = _build_current_diagnosis_locked(run_dir)
    comparable = dict(payload)
    comparable.pop("generated_at", None)
    if comparable != expected:
        raise ValueError("stale_or_untrusted_protection_diagnosis")
    return {**expected, "generated_at": generated_at}


def load_protection_diagnosis(run_dir: Path) -> dict[str, Any] | None:
    with _manifest_lock(run_dir):
        return _load_protection_diagnosis_locked(run_dir)


def _empty_summary(status: str) -> dict[str, Any]:
    next_test = (
        "Rerun task protection diagnose after the latest rendered task attempt."
        if status == "stale"
        else "Run task protection diagnose after a rendered task attempt."
    )
    return {
        "status": status,
        "mode": "passive",
        "provider": None,
        "confidence": 0,
        "blocker_class": "unknown",
        "next_test": next_test,
        "evidence_count": 0,
    }


def protection_summary(run_dir: Path) -> dict[str, Any]:
    try:
        diagnosis = load_protection_diagnosis(run_dir)
    except ValueError:
        return _empty_summary("stale")
    if diagnosis is None:
        return _empty_summary("not_diagnosed")
    protections = diagnosis["protections"]
    top: dict[str, Any] = protections[0] if protections else {}
    blocker = diagnosis["blocker"]
    next_tests = blocker["next_tests"]
    evidence_count = sum(len(item["evidence"]) for item in protections)
    return {
        "status": "diagnosed",
        "mode": diagnosis["mode"],
        "provider": top.get("provider"),
        "confidence": top.get("confidence", 0),
        "blocker_class": blocker["class"],
        "blocker_certainty": blocker["certainty"],
        "next_test": next_tests[0] if next_tests else None,
        "evidence_count": evidence_count,
        "artifact": "protection/diagnosis.json",
    }
