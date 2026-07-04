from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import RelayConfig
from .workspace import load_manifest
from .init_scripts import list_init_scripts
from .network import load_observations

ARTIFACT_POLICY = "private-local/no-auto-send"


def _local_cdp_label(cdp_url: str) -> str:
    hostname = urlparse(cdp_url).hostname
    if hostname in {"127.0.0.1", "::1", "localhost"}:
        return "local-only"
    return "configured"


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def artifact_metadata(run_dir: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for rel_root, kind in (
        ("agent", "agent"),
        ("init_scripts", "init_script"),
        ("logs", "log"),
        ("network", "network"),
        ("results", "result"),
        ("screenshots", "screenshot"),
        ("traces", "trace"),
        ("verification", "verification"),
    ):
        root = run_dir / rel_root
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            artifacts.append({
                "type": kind,
                "path": str(path.relative_to(run_dir)),
                "size_bytes": path.stat().st_size,
                "sensitivity": "private-local",
            })
    return artifacts


def hygiene_status(run_dir: Path) -> str:
    report = _load_json(run_dir / "verification" / "hygiene-report.json")
    if not report:
        return "not-run"
    return str(report.get("status", "unknown"))


def blocker_for(manifest: dict[str, Any]) -> str:
    status = manifest.get("status")
    if status == "verified":
        return "none"
    failed_gate = ((manifest.get("verification") or {}).get("last_result") or {}).get("failed_gate")
    if failed_gate:
        return str(failed_gate)
    return "not-verified"


def evidence_report(config: RelayConfig, run_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(run_dir)
    verification = manifest.get("verification") or {}
    last_result = verification.get("last_result") or {}
    artifacts = artifact_metadata(run_dir)
    return {
        "schema": "chip-relay-operator-evidence-v1",
        "run_id": manifest.get("run_id", run_dir.name),
        "run_dir": str(run_dir),
        "status": manifest.get("status", "unknown"),
        "title": (manifest.get("task") or {}).get("title", ""),
        "rail": {
            "id": (manifest.get("rail") or {}).get("rail_id", config.profile),
            "backend": (manifest.get("rail") or {}).get("backend", "unknown"),
            "cdp": _local_cdp_label((manifest.get("rail") or {}).get("cdp_url", config.cdp_url)),
        },
        "verification": {
            "status": last_result.get("status", manifest.get("status", "unknown") if manifest.get("status") == "verified" else "not-run"),
            "strength": verification.get("strength", "not-run"),
            "failed_gate": last_result.get("failed_gate"),
        },
        "hygiene": hygiene_status(run_dir),
        "artifacts": {
            "count": len(artifacts),
            "paths": [item["path"] for item in artifacts],
        },
        "init_scripts": list_init_scripts(run_dir),
        "network": {
            "count": len(load_observations(run_dir)),
            "artifact_policy": "metadata-only/redacted",
        },
        "artifact_policy": ARTIFACT_POLICY,
        "delivery": "metadata-only",
        "blocker": blocker_for(manifest),
        "recipe": "none",
    }


def artifacts_report(run_dir: Path) -> dict[str, Any]:
    manifest = load_manifest(run_dir)
    return {
        "schema": "chip-relay-artifact-index-v1",
        "run_id": manifest.get("run_id", run_dir.name),
        "run_dir": str(run_dir),
        "artifact_policy": ARTIFACT_POLICY,
        "delivery": "metadata-only",
        "artifacts": artifact_metadata(run_dir),
    }
