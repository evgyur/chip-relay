from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-datadome-cid",
    "x-kpsdk-cd",
    "x-kpsdk-cr",
    "x-kpsdk-ct",
    "x-xsrf-token",
}
TOKENISH = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,80}$")
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,100}$")
METHOD = re.compile(r"^[A-Z]{1,16}$")
ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
NETWORK_SCHEMA = "chip-relay-network-observation-v1"
MAX_NETWORK_FILE_BYTES = 8 * 1024 * 1024
ATTEMPT_ID = re.compile(r"^attempt-\d{12}$")
RESOURCE_TYPES = {
    "document", "eventsource", "fetch", "font", "image", "media", "other",
    "script", "stylesheet", "websocket", "xhr",
}
SAFE_PATH_SEGMENTS = {
    "api", "captcha", "cdn-cgi", "challenge", "challenge-platform", "hcaptcha",
    "kpsdk", "recaptcha", "turnstile", "v1", "v2", "v3",
}


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def network_dir(run_dir: Path) -> Path:
    return run_dir / "network"


def observations_path(run_dir: Path) -> Path:
    return network_dir(run_dir) / "observations.jsonl"


def export_path(run_dir: Path) -> Path:
    return network_dir(run_dir) / "export.json"


def _directory_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        flags |= getattr(os, name, 0)
    return flags


def _file_flags(base: int, *, nonblock: bool = False) -> int:
    flags = base | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if nonblock:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_network_dir_fd(run_dir: Path, *, create: bool) -> int | None:
    try:
        run_fd = os.open(run_dir, _directory_flags())
    except OSError as exc:
        raise ValueError("unsafe_run_dir: expected a real run directory") from exc
    try:
        if not stat.S_ISDIR(os.fstat(run_fd).st_mode):
            raise ValueError("unsafe_run_dir: expected a real run directory")
        if create:
            try:
                os.mkdir("network", 0o700, dir_fd=run_fd)
            except FileExistsError:
                pass
        try:
            root_fd = os.open("network", _directory_flags(), dir_fd=run_fd)
        except FileNotFoundError:
            if not create:
                return None
            raise
        except OSError as exc:
            raise ValueError("unsafe_network_path: expected a real private directory") from exc
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            os.close(root_fd)
            raise ValueError("unsafe_network_path: expected a real private directory")
        os.fchmod(root_fd, 0o700)
        return root_fd
    finally:
        os.close(run_fd)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _append_network_record(run_dir: Path, data: bytes) -> None:
    root_fd = _open_network_dir_fd(run_dir, create=True)
    if root_fd is None:
        raise ValueError("unsafe_network_path: directory creation failed")
    fd: int | None = None
    try:
        try:
            fd = os.open(
                "observations.jsonl",
                _file_flags(os.O_WRONLY | os.O_APPEND | os.O_CREAT),
                0o600,
                dir_fd=root_fd,
            )
        except OSError as exc:
            raise ValueError("unsafe_network_path: observations file is unsafe") from exc
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("unsafe_network_path: observations file must be regular")
        if metadata.st_size + len(data) > MAX_NETWORK_FILE_BYTES:
            raise ValueError("network_observations_too_large")
        os.fchmod(fd, 0o600)
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root_fd)


def _read_network_records(run_dir: Path) -> bytes | None:
    root_fd = _open_network_dir_fd(run_dir, create=False)
    if root_fd is None:
        return None
    fd: int | None = None
    try:
        try:
            fd = os.open(
                "observations.jsonl",
                _file_flags(os.O_RDONLY, nonblock=True),
                dir_fd=root_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ValueError("unsafe_network_path: observations file is unsafe") from exc
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("unsafe_network_path: observations file must be regular")
        if metadata.st_size > MAX_NETWORK_FILE_BYTES:
            raise ValueError("network_observations_too_large")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, MAX_NETWORK_FILE_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_NETWORK_FILE_BYTES:
                raise ValueError("network_observations_too_large")
        return b"".join(chunks)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root_fd)


def _atomic_write_network_export(run_dir: Path, data: bytes) -> None:
    root_fd = _open_network_dir_fd(run_dir, create=True)
    if root_fd is None:
        raise ValueError("unsafe_network_path: directory creation failed")
    temporary = f".export-{os.getpid()}-{secrets.token_hex(6)}.tmp"
    fd: int | None = None
    try:
        fd = os.open(
            temporary,
            _file_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
            dir_fd=root_fd,
        )
        _write_all(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.rename(temporary, "export.json", src_dir_fd=root_fd, dst_dir_fd=root_fd)
    except OSError as exc:
        raise ValueError("unsafe_network_path: export file is unsafe") from exc
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.close(root_fd)


def redact_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        port = parsed.port
        netloc = f"{hostname}:{port}" if hostname and port is not None else hostname
        safe_segments: list[str] = []
        for raw_segment in parsed.path.split("/"):
            segment = raw_segment.split(";", 1)[0]
            if not segment:
                safe_segments.append("")
            elif segment.lower() in SAFE_PATH_SEGMENTS or re.fullmatch(r"~[0-9a-f]{12}", segment):
                safe_segments.append(segment.lower())
            else:
                digest = hashlib.sha256(segment.encode("utf-8", "ignore")).hexdigest()[:12]
                safe_segments.append(f"~{digest}")
        safe_path = "/".join(safe_segments)
        safe_url = urlunsplit((parsed.scheme, netloc, safe_path, "", ""))
    except (TypeError, ValueError):
        return "invalid://redacted"
    return TOKENISH.sub(r"\1[REDACTED]", safe_url)


def redact_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    if len(headers) > 200:
        raise ValueError("too_many_headers")
    result: dict[str, str] = {}
    for raw_key, raw_value in headers.items():
        key = str(raw_key)
        if not HEADER_NAME.fullmatch(key):
            raise ValueError("invalid_header_name")
        result[key] = "[REDACTED]"
    return result


def _header_values(headers: Any, wanted: str) -> list[str]:
    if not isinstance(headers, dict):
        return []
    values: list[str] = []
    for key, raw_value in headers.items():
        if str(key).lower() != wanted:
            continue
        if isinstance(raw_value, list):
            values.extend(str(item) for item in raw_value)
        else:
            values.append(str(raw_value))
    return values


def extract_cookie_names(request_headers: Any, response_headers: Any) -> tuple[list[str], list[str]]:
    request_names: set[str] = set()
    for value in _header_values(request_headers, "cookie"):
        for item in value.split(";"):
            name = item.split("=", 1)[0].strip()
            if COOKIE_NAME.fullmatch(name):
                request_names.add(name)

    response_names: set[str] = set()
    for value in _header_values(response_headers, "set-cookie"):
        for match in re.finditer(r"(?:^|,\s*)([!#$%&'*+.^_`|~0-9A-Za-z-]{1,80})=", value):
            name = match.group(1)
            if COOKIE_NAME.fullmatch(name):
                response_names.add(name)
    return sorted(request_names, key=str.lower)[:200], sorted(response_names, key=str.lower)[:200]


def _body_metadata(value: Any) -> dict[str, Any]:
    if value is None:
        return {"present": False, "bytes": 0, "policy": "omitted"}
    if isinstance(value, bytes):
        size = len(value)
    else:
        size = len(str(value).encode("utf-8", "ignore"))
    return {"present": True, "bytes": size, "policy": "omitted"}


def sanitize_observation(raw: dict[str, Any]) -> dict[str, Any]:
    request_headers = raw.get("request_headers", raw.get("headers", {}))
    response_headers = raw.get("response_headers", {})
    body = raw.get("request_body", raw.get("post_data"))
    response_body = raw.get("response_body", raw.get("body"))
    request_cookie_names, response_cookie_names = extract_cookie_names(request_headers, response_headers)
    raw_method = raw.get("method")
    method = str(raw_method or "GET").upper() if isinstance(raw_method, str) or raw_method is None else "UNKNOWN"
    if not METHOD.fullmatch(method):
        method = "UNKNOWN"
    raw_status = raw.get("status")
    status = raw_status if type(raw_status) is int and 100 <= raw_status <= 599 else None
    raw_resource_type = raw.get("resource_type")
    resource_type = str(raw_resource_type).lower() if isinstance(raw_resource_type, str) else "other"
    if resource_type not in RESOURCE_TYPES:
        resource_type = "other"
    raw_captured_at = raw.get("captured_at")
    captured_at = raw_captured_at if isinstance(raw_captured_at, str) and ISO_UTC.fullmatch(raw_captured_at) else utc_now_text()
    raw_request_id = raw.get("request_id") or raw.get("id") or ""
    request_id = hashlib.sha256(str(raw_request_id).encode("utf-8", "ignore")).hexdigest()[:16] if raw_request_id else ""
    return {
        "schema": NETWORK_SCHEMA,
        "captured_at": captured_at,
        "request_id": request_id,
        "url": redact_url(str(raw.get("url") or "")),
        "method": method,
        "status": status,
        "resource_type": resource_type,
        "request_headers": redact_headers(request_headers),
        "response_headers": redact_headers(response_headers),
        "request_cookie_names": request_cookie_names,
        "response_cookie_names": response_cookie_names,
        "request_body": _body_metadata(body),
        "response_body": _body_metadata(response_body),
        "sensitivity": "private-local",
    }


def record_observation(run_dir: Path, raw: dict[str, Any]) -> dict[str, Any]:
    from .workspace import bound_attempt_id

    safe = sanitize_observation(raw)
    safe["attempt_id"] = bound_attempt_id(run_dir)
    data = (json.dumps(safe, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    _append_network_record(run_dir, data)
    from .protection import invalidate_protection_diagnosis

    invalidate_protection_diagnosis(run_dir)
    return safe


def _stored_observation_is_valid(payload: Any) -> bool:
    expected_fields = {
        "schema", "attempt_id", "captured_at", "request_id", "url", "method", "status", "resource_type",
        "request_headers", "response_headers", "request_cookie_names", "response_cookie_names",
        "request_body", "response_body", "sensitivity",
    }
    if not isinstance(payload, dict) or set(payload) != expected_fields or payload.get("schema") != NETWORK_SCHEMA:
        return False
    if not isinstance(payload.get("attempt_id"), str) or not ATTEMPT_ID.fullmatch(payload["attempt_id"]):
        return False
    if not isinstance(payload.get("captured_at"), str) or not ISO_UTC.fullmatch(payload["captured_at"]):
        return False
    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or (request_id and not re.fullmatch(r"[0-9a-f]{16}", request_id)):
        return False
    url = payload.get("url")
    if not isinstance(url, str) or len(url) > 2000 or redact_url(url) != url:
        return False
    if not isinstance(payload.get("method"), str) or not METHOD.fullmatch(payload["method"]):
        return False
    status = payload.get("status")
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        return False
    if payload.get("resource_type") not in RESOURCE_TYPES or payload.get("sensitivity") != "private-local":
        return False
    for field in ("request_headers", "response_headers"):
        headers = payload.get(field)
        if not isinstance(headers, dict) or len(headers) > 200:
            return False
        if any(not isinstance(key, str) or not HEADER_NAME.fullmatch(key) or value != "[REDACTED]" for key, value in headers.items()):
            return False
    for field in ("request_cookie_names", "response_cookie_names"):
        names = payload.get(field)
        if not isinstance(names, list) or len(names) > 200 or any(not isinstance(name, str) or not COOKIE_NAME.fullmatch(name) for name in names):
            return False
    for field in ("request_body", "response_body"):
        body = payload.get(field)
        if not isinstance(body, dict) or set(body) != {"present", "bytes", "policy"}:
            return False
        if type(body.get("present")) is not bool or type(body.get("bytes")) is not int or not 0 <= body["bytes"] <= 10**10:
            return False
        if body.get("policy") != "omitted":
            return False
    return True


def _normalize_stored_observation(payload: Any) -> dict[str, Any] | None:
    if _stored_observation_is_valid(payload):
        return payload
    if not isinstance(payload, dict) or payload.get("schema") != NETWORK_SCHEMA:
        return None
    candidate_fields = {
        "schema", "captured_at", "request_id", "url", "method", "status", "resource_type",
        "request_headers", "response_headers", "request_cookie_names", "response_cookie_names",
        "request_body", "response_body", "sensitivity",
    }
    if set(payload) == candidate_fields:
        migrated = {**payload, "attempt_id": "attempt-000000000000"}
        return migrated if _stored_observation_is_valid(migrated) else None
    base_fields = candidate_fields - {"request_cookie_names", "response_cookie_names"}
    if set(payload) != base_fields:
        return None
    try:
        migrated = sanitize_observation(payload)
    except (TypeError, ValueError):
        return None
    captured_at = payload.get("captured_at")
    if isinstance(captured_at, str) and ISO_UTC.fullmatch(captured_at):
        migrated["captured_at"] = captured_at
    migrated["attempt_id"] = "attempt-000000000000"
    return migrated if _stored_observation_is_valid(migrated) else None


def load_observations(run_dir: Path) -> list[dict[str, Any]]:
    data = _read_network_records(run_dir)
    if data is None:
        return []
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("malformed_network_observation: invalid UTF-8") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed_network_observation: line {line_number}") from exc
        normalized = _normalize_stored_observation(payload)
        if normalized is None:
            raise ValueError(f"malformed_network_observation: line {line_number}")
        rows.append(normalized)
    return rows


def search_observations(
    run_dir: Path,
    *,
    url_contains: str | None = None,
    method: str | None = None,
    status: int | None = None,
    resource_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    rows = load_observations(run_dir)
    matches: list[dict[str, Any]] = []
    for row in rows:
        if url_contains and url_contains.lower() not in str(row.get("url", "")).lower():
            continue
        if method and str(row.get("method", "")).upper() != method.upper():
            continue
        if status is not None and row.get("status") != status:
            continue
        if resource_type and resource_type.lower() not in str(row.get("resource_type", "")).lower():
            continue
        matches.append(row)
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    page = matches[offset : offset + limit]
    return {
        "schema": "chip-relay-network-search-v1",
        "total": len(matches),
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < len(matches),
        "results": page,
        "artifact_policy": "metadata-only/redacted",
    }


def export_network_metadata(run_dir: Path) -> dict[str, Any]:
    payload = {
        "schema": "chip-relay-network-export-v1",
        "run_dir": str(run_dir),
        "artifact_policy": "metadata-only/redacted",
        "observations": load_observations(run_dir),
    }
    path = export_path(run_dir)
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write_network_export(run_dir, data)
    payload["export_path"] = str(path)
    return payload
