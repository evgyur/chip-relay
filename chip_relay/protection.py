from __future__ import annotations

import importlib
import hashlib
import ipaddress
import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit

DIAGNOSTIC_SCHEMA = "chip-relay-protection-diagnostic-v1"
RULE_PACK_SCHEMA = "chip-relay-protection-rules-v1"
ALLOWED_SIGNAL_METHODS = {
    "url",
    "status",
    "header_name",
    "cookie_name",
    "page_marker",
    "window_key",
    "fingerprint_api",
}
ALLOWED_CATEGORIES = {"anti_bot", "captcha", "fingerprinting"}
ALLOWED_STRENGTHS = {"weak", "medium", "strong"}
RULE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,100}$")
UNSAFE_REGEX_FEATURE = re.compile(r"\(\?(?!:)|\\[1-9]|\.\*|\.\+")
PAGE_SIGNAL_SCHEMA = "chip-relay-protection-page-signals-v1"
PAGE_SIGNAL_FIELDS = {
    "final_url",
    "status",
    "title_classification",
    "page_markers",
    "window_keys",
    "fingerprint_apis",
}
TITLE_CLASSIFICATIONS = {"challenge", "captcha", "access_denied", "rate_limited", "normal", "unknown"}
SAFE_MARKER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
PRIVATE_MARKER_HINT = re.compile(
    r"(?:^|[._:-])(?:authorization|bearer|cookie|password|secret|session|token)(?:[._:-]|$)",
    re.IGNORECASE,
)
MAX_PAGE_SIGNAL_BYTES = 65536
MAX_PAGE_SIGNAL_FILE_BYTES = 4 * 1024 * 1024
MAX_PAGE_SIGNAL_RECORDS = 5000
ATTEMPT_ID = re.compile(r"^attempt-\d{12}$")


def _require_text(value: Any, gate: str, *, max_length: int = 300) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"{gate}: expected non-empty bounded text")
    return value.strip()


def _regex_structure_is_safe(pattern: str) -> bool:
    parser = importlib.import_module("re._parser")
    constants = importlib.import_module("re._constants")
    try:
        parsed = parser.parse(pattern, 0)
    except (re.error, OverflowError, ValueError):
        return False

    repeat_ops = {constants.MAX_REPEAT, constants.MIN_REPEAT}
    possessive = getattr(constants, "POSSESSIVE_REPEAT", None)
    if possessive is not None:
        repeat_ops.add(possessive)
    unbounded_count = 0
    unsafe = False

    def walk(tokens: Any) -> tuple[bool, bool]:
        nonlocal unbounded_count, unsafe
        contains_branch = False
        contains_repeat = False
        for operation, argument in tokens:
            if operation in repeat_ops:
                minimum, maximum, child = argument
                child_branch, child_repeat = walk(child)
                if child_branch or child_repeat:
                    unsafe = True
                if maximum == constants.MAXREPEAT:
                    unbounded_count += 1
                elif minimum > 100 or maximum > 100:
                    unsafe = True
                contains_repeat = True
            elif operation is constants.SUBPATTERN:
                child_branch, child_repeat = walk(argument[-1])
                contains_branch = contains_branch or child_branch
                contains_repeat = contains_repeat or child_repeat
            elif operation is constants.BRANCH:
                contains_branch = True
                for branch in argument[1]:
                    branch_has_branch, branch_has_repeat = walk(branch)
                    contains_branch = contains_branch or branch_has_branch
                    contains_repeat = contains_repeat or branch_has_repeat
            elif operation in {
                constants.ASSERT,
                constants.ASSERT_NOT,
                constants.GROUPREF,
                constants.GROUPREF_EXISTS,
            }:
                unsafe = True
        return contains_branch, contains_repeat

    walk(parsed)
    return not unsafe and unbounded_count <= 1


def _validate_pattern(pattern: Any) -> str:
    value = _require_text(pattern, "invalid_rule_pattern", max_length=200)
    if UNSAFE_REGEX_FEATURE.search(value) or not _regex_structure_is_safe(value):
        raise ValueError("unsafe_rule_pattern: ambiguous or unbounded regex constructs are forbidden")
    try:
        re.compile(value, re.IGNORECASE)
    except (re.error, OverflowError, ValueError) as exc:
        raise ValueError(f"invalid_rule_pattern: {exc}") from exc
    return value


def _validate_source(source: Any) -> dict[str, str]:
    if not isinstance(source, dict):
        raise ValueError("invalid_rule_source: source metadata is required")
    if set(source) != {"title", "url"}:
        raise ValueError("invalid_rule_source: expected exactly title and url")
    title = _require_text(source.get("title"), "invalid_rule_source_title", max_length=200)
    url = _require_text(source.get("url"), "invalid_rule_source_url", max_length=500)
    parsed = urlparse(url)
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid_rule_source_url: malformed authority") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid_rule_source_url: expected a credential-free public HTTPS URL without query or fragment")
    lowered_host = hostname.lower().rstrip(".")
    if lowered_host == "localhost" or lowered_host.endswith((".localhost", ".local")) or "." not in lowered_host:
        raise ValueError("invalid_rule_source_url: public hostname required")
    try:
        address = ipaddress.ip_address(lowered_host)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("invalid_rule_source_url: public hostname required")
    return {"title": title, "url": url}


def validate_rule_pack(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema") != RULE_PACK_SCHEMA:
        raise ValueError(f"invalid_rule_pack_schema: expected {RULE_PACK_SCHEMA}")
    if set(payload) != {"schema", "revision", "rules"}:
        raise ValueError("invalid_rule_pack_schema: unexpected or missing fields")
    revision = _require_text(payload.get("revision"), "invalid_rule_pack_revision", max_length=100)
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("invalid_rule_pack_rules: at least one rule is required")

    seen: set[str] = set()
    validated_rules: list[dict[str, Any]] = []
    for raw_rule in rules:
        if not isinstance(raw_rule, dict):
            raise ValueError("invalid_rule: expected object")
        if set(raw_rule) != {"id", "provider", "category", "source", "signals"}:
            raise ValueError("invalid_rule: unexpected or missing fields")
        rule_id = _require_text(raw_rule.get("id"), "invalid_rule_id", max_length=100)
        if not RULE_ID.fullmatch(rule_id):
            raise ValueError(f"invalid_rule_id: {rule_id}")
        if rule_id in seen:
            raise ValueError(f"duplicate_rule_id: {rule_id}")
        seen.add(rule_id)

        provider = _require_text(raw_rule.get("provider"), "invalid_rule_provider", max_length=100)
        category = _require_text(raw_rule.get("category"), "invalid_rule_category", max_length=40)
        if category not in ALLOWED_CATEGORIES:
            raise ValueError(f"invalid_rule_category: {category}")
        source = _validate_source(raw_rule.get("source"))
        signals = raw_rule.get("signals")
        if not isinstance(signals, list) or not signals:
            raise ValueError(f"invalid_rule_signals: {rule_id}")

        validated_signals: list[dict[str, Any]] = []
        for raw_signal in signals:
            if not isinstance(raw_signal, dict):
                raise ValueError(f"invalid_rule_signal: {rule_id}")
            if set(raw_signal) != {"method", "pattern", "weight", "strength"}:
                raise ValueError(f"invalid_rule_signal: unexpected or missing fields for {rule_id}")
            method = _require_text(raw_signal.get("method"), "invalid_signal_method", max_length=40)
            if method not in ALLOWED_SIGNAL_METHODS:
                raise ValueError(f"invalid_signal_method: {method}")
            pattern = _validate_pattern(raw_signal.get("pattern"))
            weight = raw_signal.get("weight")
            if isinstance(weight, bool) or not isinstance(weight, int) or not 1 <= weight <= 100:
                raise ValueError(f"invalid_signal_weight: {rule_id}")
            strength = _require_text(raw_signal.get("strength"), "invalid_signal_strength", max_length=20)
            if strength not in ALLOWED_STRENGTHS:
                raise ValueError(f"invalid_signal_strength: {strength}")
            validated_signals.append({"method": method, "pattern": pattern, "weight": weight, "strength": strength})

        validated_rules.append(
            {
                "id": rule_id,
                "provider": provider,
                "category": category,
                "source": source,
                "signals": validated_signals,
            }
        )

    return {"schema": RULE_PACK_SCHEMA, "revision": revision, "rules": validated_rules}


def load_default_rule_pack() -> dict[str, Any]:
    path = Path(__file__).resolve().parent / "rules" / "protections-v1.json"
    return validate_rule_pack(json.loads(path.read_text(encoding="utf-8")))


def _signal_values(signals: dict[str, Any], method: str) -> list[str]:
    key_map = {
        "url": "urls",
        "status": "statuses",
        "header_name": "header_names",
        "cookie_name": "cookie_names",
        "page_marker": "page_markers",
        "window_key": "window_keys",
        "fingerprint_api": "fingerprint_apis",
    }
    raw = signals.get(key_map[method], {})
    if method == "fingerprint_api" and isinstance(raw, dict):
        values = [key for key, count in raw.items() if isinstance(count, int) and not isinstance(count, bool) and count > 0]
    elif isinstance(raw, list):
        values = raw
    else:
        values = []
    normalized: list[str] = []
    for value in values[:500]:
        text = str(value).strip()
        if method == "url":
            try:
                parsed = urlsplit(text if "://" in text else f"//{text}")
                text = f"{parsed.hostname or ''}{parsed.path}"
            except Exception:
                text = text.split("?", 1)[0].split("#", 1)[0]
        if text:
            normalized.append(text[:500])
    return normalized


def _evidence_key(method: str, value: str) -> str:
    digest = hashlib.sha256(f"{method}\0{value}".encode("utf-8", "ignore")).hexdigest()[:16]
    return f"sha256:{digest}"


def _confidence(evidence: list[dict[str, Any]]) -> int:
    raw = min(100, sum(int(item["weight"]) for item in evidence))
    strengths = [str(item["strength"]) for item in evidence]
    if "strong" in strengths:
        return raw
    if strengths.count("medium") >= 2:
        return min(raw, 79)
    return min(raw, 49)


def diagnose_signals(
    signals: dict[str, Any] | None,
    *,
    rule_pack: dict[str, Any] | None = None,
    mode: str = "passive",
) -> dict[str, Any]:
    if mode not in {"passive", "instrumented"}:
        raise ValueError(f"invalid_protection_mode: {mode}")
    safe_signals = signals if isinstance(signals, dict) else {}
    pack = validate_rule_pack(rule_pack) if rule_pack is not None else load_default_rule_pack()
    strength_rank = {"weak": 1, "medium": 2, "strong": 3}
    matched: dict[
        tuple[str, str, str],
        tuple[tuple[int, int, int], dict[str, Any], dict[str, Any]],
    ] = {}
    for rule_index, rule in enumerate(pack["rules"]):
        for signal in rule["signals"]:
            method = signal["method"]
            pattern = re.compile(signal["pattern"], re.IGNORECASE)
            for value in _signal_values(safe_signals, method):
                if not pattern.search(value):
                    continue
                key = _evidence_key(method, value)
                item = {
                    "type": method,
                    "key": key,
                    "strength": signal["strength"],
                    "weight": signal["weight"],
                }
                physical_key = (rule["id"], method, key.lower())
                priority = (strength_rank[signal["strength"]], int(signal["weight"]), -rule_index)
                current = matched.get(physical_key)
                if current is None or priority > current[0]:
                    matched[physical_key] = (priority, rule, item)

    evidence_by_rule: dict[str, list[dict[str, Any]]] = {}
    rules_by_id = {rule["id"]: rule for rule in pack["rules"]}
    for _, rule, item in matched.values():
        evidence_by_rule.setdefault(rule["id"], []).append(item)

    protections: list[dict[str, Any]] = []
    for rule_id, unsorted_evidence in evidence_by_rule.items():
        rule = rules_by_id[rule_id]
        evidence = sorted(
            unsorted_evidence,
            key=lambda item: (-int(item["weight"]), str(item["type"]), str(item["key"]).lower()),
        )
        protections.append(
            {
                "provider": rule["provider"],
                "category": rule["category"],
                "rule_id": rule["id"],
                "rule_revision": pack["revision"],
                "confidence": _confidence(evidence),
                "evidence": evidence,
                "source": rule["source"],
            }
        )

    protections.sort(key=lambda item: (-item["confidence"], item["provider"], item["rule_id"]))
    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "mode": mode,
        "rule_revision": pack["revision"],
        "protections": protections,
        "summary": "recognized protection metadata" if protections else "no recognized protection metadata",
        "claim_policy": "diagnostic-only/no-guaranteed-bypass",
        "artifact_policy": "metadata-only/private-local",
    }


def protection_dir(run_dir: Path) -> Path:
    return run_dir / "protection"


def page_signals_path(run_dir: Path) -> Path:
    return protection_dir(run_dir) / "signals.jsonl"


def _bounded_marker_list(raw: Any, gate: str, *, limit: int = 100) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > limit:
        raise ValueError(f"{gate}: expected at most {limit} normalized names")
    values: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not SAFE_MARKER.fullmatch(item) or PRIVATE_MARKER_HINT.search(item):
            raise ValueError(f"{gate}: expected normalized metadata name")
        values.add(item)
    return sorted(values, key=str.lower)


def _bounded_fingerprint_counts(raw: Any, mode: str) -> dict[str, int]:
    if raw is None or raw == "":
        return {}
    if mode != "instrumented":
        raise ValueError("fingerprint_apis_require_instrumented_mode")
    if not isinstance(raw, dict) or len(raw) > 100:
        raise ValueError("invalid_fingerprint_apis: expected bounded name/count map")
    values: dict[str, int] = {}
    for key, count in raw.items():
        if not isinstance(key, str) or not SAFE_MARKER.fullmatch(key) or PRIVATE_MARKER_HINT.search(key):
            raise ValueError("invalid_fingerprint_api: expected normalized API name")
        if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 1000:
            raise ValueError("invalid_fingerprint_api_count: expected integer 0..1000")
        if count:
            values[key] = count
    return dict(sorted(values.items(), key=lambda item: item[0].lower()))


def sanitize_page_signals(raw: Any, *, mode: str = "passive") -> dict[str, Any]:
    from .network import redact_url, utc_now_text

    if mode not in {"passive", "instrumented"}:
        raise ValueError(f"invalid_protection_mode: {mode}")
    if not isinstance(raw, dict):
        raise ValueError("invalid_page_signal_payload: expected object")
    try:
        serialized = json.dumps(raw, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_page_signal_payload: not JSON serializable") from exc
    if len(serialized.encode("utf-8")) > MAX_PAGE_SIGNAL_BYTES:
        raise ValueError("page_signal_payload_too_large")
    if any(not isinstance(key, str) for key in raw):
        raise ValueError("invalid_page_signal_field: expected text field names")
    unknown = sorted(set(raw) - PAGE_SIGNAL_FIELDS)
    if unknown:
        raise ValueError(f"unknown_page_signal_field: {unknown[0]}")

    status = raw.get("status")
    if status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599):
        raise ValueError("invalid_page_signal_status: expected integer 100..599")
    title_classification = raw.get("title_classification", "unknown")
    if title_classification not in TITLE_CLASSIFICATIONS:
        raise ValueError("invalid_title_classification")
    final_url = raw.get("final_url", "")
    if not isinstance(final_url, str) or len(final_url) > 2000:
        raise ValueError("invalid_page_signal_url")

    return {
        "schema": PAGE_SIGNAL_SCHEMA,
        "captured_at": utc_now_text(),
        "mode": mode,
        "final_url": redact_url(final_url)[:1000],
        "status": status,
        "title_classification": title_classification,
        "page_markers": _bounded_marker_list(raw.get("page_markers"), "invalid_page_marker"),
        "window_keys": _bounded_marker_list(raw.get("window_keys"), "invalid_window_key"),
        "fingerprint_apis": _bounded_fingerprint_counts(raw.get("fingerprint_apis"), mode),
        "artifact_policy": "metadata-only/private-local",
    }


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_protection_dir_fd(run_dir: Path, *, create: bool) -> int | None:
    try:
        run_fd = os.open(run_dir, _directory_flags())
    except OSError as exc:
        raise ValueError(f"unsafe_run_dir: {exc}") from exc
    try:
        if not stat.S_ISDIR(os.fstat(run_fd).st_mode):
            raise ValueError("unsafe_run_dir: expected a real run directory")
        if create:
            try:
                os.mkdir("protection", mode=0o700, dir_fd=run_fd)
            except FileExistsError:
                pass
        try:
            root_fd = os.open("protection", _directory_flags(), dir_fd=run_fd)
        except FileNotFoundError:
            if create:
                raise ValueError("unsafe_signal_path: protection directory disappeared")
            return None
        except OSError as exc:
            raise ValueError(f"unsafe_signal_path: {exc}") from exc
    finally:
        os.close(run_fd)
    if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
        os.close(root_fd)
        raise ValueError("unsafe_signal_path: protection path is not a directory")
    os.fchmod(root_fd, 0o700)
    return root_fd


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _read_bounded_fd(descriptor: int, *, max_bytes: int, too_large_gate: str) -> bytes:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("unsafe_file: expected regular file")
    if metadata.st_size > max_bytes:
        raise ValueError(too_large_gate)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise ValueError(too_large_gate)
    return b"".join(chunks)


def read_bounded_json_object(path_text: str, *, max_bytes: int = 65536) -> dict[str, Any]:
    path = Path(path_text).expanduser()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"unsafe_json_file: {exc}") from exc
    try:
        data = _read_bounded_fd(descriptor, max_bytes=max_bytes, too_large_gate="json_file_too_large")
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_json_file") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid_json_file: expected an object")
    return payload


def invalidate_protection_diagnosis(run_dir: Path) -> None:
    root_fd = _open_protection_dir_fd(run_dir, create=False)
    if root_fd is None:
        return
    try:
        try:
            os.unlink("diagnosis.json", dir_fd=root_fd)
        except FileNotFoundError:
            pass
    finally:
        os.close(root_fd)


def record_page_signals(run_dir: Path, raw: Any, *, mode: str = "passive") -> dict[str, Any]:
    from .workspace import bound_attempt_id

    safe = sanitize_page_signals(raw, mode=mode)
    safe["attempt_id"] = bound_attempt_id(run_dir)
    root_fd = _open_protection_dir_fd(run_dir, create=True)
    assert root_fd is not None
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        try:
            descriptor = os.open("signals.jsonl", flags, 0o600, dir_fd=root_fd)
        except OSError as exc:
            raise ValueError(f"unsafe_signal_path: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("unsafe_signal_path: signals file must be regular")
            encoded = (json.dumps(safe, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            if metadata.st_size + len(encoded) > MAX_PAGE_SIGNAL_FILE_BYTES:
                raise ValueError("page_signal_file_too_large")
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    invalidate_protection_diagnosis(run_dir)
    return safe


def load_page_signals(run_dir: Path) -> list[dict[str, Any]]:
    root_fd = _open_protection_dir_fd(run_dir, create=False)
    if root_fd is None:
        return []
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        try:
            descriptor = os.open("signals.jsonl", flags, dir_fd=root_fd)
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ValueError(f"unsafe_signal_path: {exc}") from exc
        try:
            data = _read_bounded_fd(
                descriptor,
                max_bytes=MAX_PAGE_SIGNAL_FILE_BYTES,
                too_large_gate="page_signal_file_too_large",
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("malformed_page_signal_record: invalid utf-8") from exc
    lines = text.splitlines()
    if len(lines) > MAX_PAGE_SIGNAL_RECORDS:
        raise ValueError("page_signal_record_limit_exceeded")
    rows: list[dict[str, Any]] = []
    stored_fields = {
        "schema", "attempt_id", "captured_at", "mode", "final_url", "status", "title_classification",
        "page_markers", "window_keys", "fingerprint_apis", "artifact_policy",
    }
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed_page_signal_record: line {line_number}") from exc
        if not isinstance(payload, dict) or payload.get("schema") != PAGE_SIGNAL_SCHEMA:
            raise ValueError(f"malformed_page_signal_record: line {line_number}")
        if set(payload) == stored_fields - {"attempt_id"}:
            payload["attempt_id"] = "attempt-000000000000"
        captured_at = payload.get("captured_at")
        if set(payload) != stored_fields or not isinstance(captured_at, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", captured_at
        ):
            raise ValueError(f"malformed_page_signal_record: line {line_number}")
        if not isinstance(payload.get("attempt_id"), str) or not ATTEMPT_ID.fullmatch(payload["attempt_id"]):
            raise ValueError(f"malformed_page_signal_record: line {line_number}")
        reconstructed_raw = {
            "final_url": payload.get("final_url"),
            "status": payload.get("status"),
            "title_classification": payload.get("title_classification"),
            "page_markers": payload.get("page_markers"),
            "window_keys": payload.get("window_keys"),
        }
        if payload.get("fingerprint_apis"):
            reconstructed_raw["fingerprint_apis"] = payload.get("fingerprint_apis")
        try:
            reconstructed = sanitize_page_signals(
                reconstructed_raw,
                mode=str(payload.get("mode")),
            )
        except ValueError as exc:
            raise ValueError(f"malformed_page_signal_record: line {line_number}") from exc
        for key in stored_fields - {"attempt_id", "captured_at"}:
            if payload.get(key) != reconstructed.get(key):
                raise ValueError(f"malformed_page_signal_record: line {line_number}")
        rows.append(payload)
    return rows


def instrumentation_notice() -> dict[str, str]:
    return {
        "default": "disabled",
        "mode": "instrumented",
        "warning": "Document-start API wrapping is intrusive and can affect detectability.",
        "claim_limit": "Observed calls cannot prove stealth or bypass.",
        "capture_policy": "API names and bounded call counts only; call payload data and browser contents are never recorded.",
    }


def fingerprint_observer_source() -> str:
    path = Path(__file__).resolve().parent / "assets" / "protection-observer.js"
    if not path.is_file() or path.is_symlink():
        raise ValueError("fingerprint_observer_missing_or_unsafe")
    return path.read_text(encoding="utf-8")


def install_fingerprint_observer(run_dir: Path, *, enabled: bool = False, preset: str = "normal") -> dict[str, Any]:
    if preset not in {"normal", "strict", "cf-sensitive"}:
        raise ValueError(f"unknown_stealth_preset: {preset}")
    if not enabled:
        return {
            "status": "disabled",
            "mode": "passive",
            "preset": preset,
            "preset_effect": "label_only",
            "notice": instrumentation_notice(),
        }
    from .init_scripts import add_init_script

    script = add_init_script(run_dir, "protection-observer", fingerprint_observer_source())
    return {
        "status": "installed",
        "mode": "instrumented",
        "preset": preset,
        "preset_effect": "label_only",
        "install_phase": "document_start",
        "script": script,
        "notice": instrumentation_notice(),
    }


def sanitize_observer_snapshot(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("invalid_observer_snapshot: expected object")
    allowed = {"schema", "mode", "active", "elapsed_ms", "counts"}
    if any(not isinstance(key, str) for key in raw):
        raise ValueError("invalid_observer_snapshot_field: expected text field names")
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"unknown_observer_snapshot_field: {unknown[0]}")
    if raw.get("schema") != "chip-relay-fingerprint-observer-v1":
        raise ValueError("invalid_observer_snapshot_schema")
    if raw.get("mode") != "instrumented":
        raise ValueError("invalid_observer_snapshot_mode")
    active = raw.get("active")
    if type(active) is not bool:
        raise ValueError("invalid_observer_snapshot_active")
    elapsed_ms = raw.get("elapsed_ms")
    if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 600_000:
        raise ValueError("invalid_observer_snapshot_elapsed_ms")
    counts = raw.get("counts")
    if not isinstance(counts, dict) or len(counts) > 100:
        raise ValueError("invalid_observer_snapshot_counts")
    normalized: dict[str, int] = {}
    for key, count in counts.items():
        if not isinstance(key, str) or not SAFE_MARKER.fullmatch(key) or PRIVATE_MARKER_HINT.search(key):
            raise ValueError("invalid_fingerprint_api: expected normalized API name")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("invalid_fingerprint_api_count")
        if count:
            normalized[key] = min(count, 1000)
    return {
        "schema": PAGE_SIGNAL_SCHEMA,
        "mode": "instrumented",
        "fingerprint_apis": dict(sorted(normalized.items(), key=lambda item: item[0].lower())),
        "observer_active": active,
        "observer_elapsed_ms": elapsed_ms,
        "notice": instrumentation_notice(),
        "artifact_policy": "metadata-only/private-local",
    }


# Run-level aggregation is split out to keep schema/rule evaluation independently testable.
# These lazy facades avoid a module-initialization cycle when protection_run is imported directly.
def aggregate_run_signals(run_dir: Path) -> dict[str, Any]:
    from .protection_run import aggregate_run_signals as implementation

    return implementation(run_dir)


def classify_blocker(signals: dict[str, Any], protections: list[dict[str, Any]]) -> dict[str, Any]:
    from .protection_run import classify_blocker as implementation

    return implementation(signals, protections)


def diagnose_run(run_dir: Path) -> dict[str, Any]:
    from .protection_run import diagnose_run as implementation

    return implementation(run_dir)


def diagnosis_path(run_dir: Path) -> Path:
    from .protection_run import diagnosis_path as implementation

    return implementation(run_dir)


def load_protection_diagnosis(run_dir: Path) -> dict[str, Any] | None:
    from .protection_run import load_protection_diagnosis as implementation

    return implementation(run_dir)


def protection_summary(run_dir: Path) -> dict[str, Any]:
    from .protection_run import protection_summary as implementation

    return implementation(run_dir)
