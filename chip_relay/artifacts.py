from __future__ import annotations

from pathlib import Path
from typing import Any

from .workspace import load_manifest, update_manifest

_ALLOWED_KEYS = {
    "status",
    "url",
    "method",
    "content_type",
    "content_length",
    "body_handle",
}
_MAX_BROWSER_FETCH_RECORDS = 256


def record_browser_fetch_artifact(run_dir: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    if set(metadata) != _ALLOWED_KEYS:
        raise ValueError("browser_fetch_metadata_schema")
    handle = metadata.get("body_handle")
    if not isinstance(handle, str) and not (metadata.get("method") == "HEAD" and handle is None):
        raise ValueError("browser_fetch_metadata_handle")
    record = {"kind": "browser-fetch", "private": True, **metadata}

    def append(manifest: dict[str, Any]) -> None:
        artifacts = manifest.setdefault("artifacts", [])
        if not isinstance(artifacts, list) or len(artifacts) >= _MAX_BROWSER_FETCH_RECORDS:
            raise ValueError("browser_fetch_artifact_index")
        artifacts.append(record)

    update_manifest(run_dir, append)
    return dict(record)


def list_browser_fetch_artifacts(run_dir: Path) -> list[dict[str, Any]]:
    manifest = load_manifest(run_dir)
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        raise ValueError("browser_fetch_artifact_index")
    records: list[dict[str, Any]] = []
    for item in artifacts:
        if isinstance(item, dict) and item.get("kind") == "browser-fetch":
            records.append(dict(item))
    return records
