from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
}
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "auth_token",
    "code",
    "id_token",
    "refresh_token",
    "session",
    "token",
}
TOKENISH = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
NETWORK_SCHEMA = "chip-relay-network-observation-v1"


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def network_dir(run_dir: Path) -> Path:
    return run_dir / "network"


def observations_path(run_dir: Path) -> Path:
    return network_dir(run_dir) / "observations.jsonl"


def export_path(run_dir: Path) -> Path:
    return network_dir(run_dir) / "export.json"


def redact_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    try:
        parsed = urlsplit(url)
    except Exception:
        return TOKENISH.sub(r"\1[REDACTED]", url)
    pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        pairs.append((key, "[REDACTED]" if key.lower() in SENSITIVE_QUERY_KEYS else value))
    query = urlencode(pairs, doseq=True)
    return TOKENISH.sub(r"\1[REDACTED]", urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment)))


def redact_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key)
        if name.lower() in SENSITIVE_HEADER_NAMES:
            redacted[name] = "[REDACTED]"
        else:
            redacted[name] = TOKENISH.sub(r"\1[REDACTED]", str(value))
    return redacted


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
    return {
        "schema": NETWORK_SCHEMA,
        "captured_at": str(raw.get("captured_at") or utc_now_text()),
        "request_id": str(raw.get("request_id") or raw.get("id") or ""),
        "url": redact_url(str(raw.get("url") or "")),
        "method": str(raw.get("method") or "GET").upper(),
        "status": raw.get("status"),
        "resource_type": raw.get("resource_type"),
        "request_headers": redact_headers(request_headers),
        "response_headers": redact_headers(response_headers),
        "request_body": _body_metadata(body),
        "response_body": _body_metadata(response_body),
        "sensitivity": "private-local",
    }


def record_observation(run_dir: Path, raw: dict[str, Any]) -> dict[str, Any]:
    safe = sanitize_observation(raw)
    path = observations_path(run_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(safe, ensure_ascii=False, sort_keys=True) + "\n")
    return safe


def load_observations(run_dir: Path) -> list[dict[str, Any]]:
    path = observations_path(run_dir)
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    payload["export_path"] = str(path)
    return payload
