from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import RelayConfig
from .reports import ARTIFACT_POLICY, artifacts_report, evidence_report
from .workspace import load_manifest

SCHEMA = "chip-relay-hermes-workflow-context-v1"


def _last_verification(manifest: dict[str, Any]) -> dict[str, Any]:
    verification = manifest.get("verification") or {}
    last = verification.get("last_result") or {}
    return {
        "status": last.get("status", "not-run"),
        "strength": verification.get("strength", "not-run"),
        "failed_gate": last.get("failed_gate"),
    }


def _next_action(status: str, verification: dict[str, Any]) -> str:
    if status == "verified" or verification.get("status") == "verified":
        return "done_or_pack_recipe"
    return "edit_final_script_then_run_verify"


def hermes_task_context(config: RelayConfig, run_dir: Path, *, write: bool = False) -> dict[str, Any]:
    manifest = load_manifest(run_dir)
    run_id = str(manifest.get("run_id", run_dir.name))
    task = manifest.get("task", {})
    verification = _last_verification(manifest)
    evidence = evidence_report(config, run_dir)
    artifact_index = artifacts_report(run_dir)
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "model": "hermes-agent-uses-relay-tool",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "task": task,
        "task_brief": task.get("brief", {}),
        "status": manifest.get("status", "unknown"),
        "next_action": _next_action(str(manifest.get("status", "unknown")), verification),
        "editable_files": ["scripts/final.py"],
        "read_only_files": ["task.md", "manifest.json"],
        "artifact_policy": ARTIFACT_POLICY,
        "delivery": "metadata-only",
        "rail": {
            "cdp_url": config.cdp_url,
            "env": "CHIP_RELAY_CDP_URL",
            "profile_mode": (manifest.get("rail") or {}).get("profile_mode", "persistent"),
        },
        "contract": {
            "executor": "Hermes writes or patches scripts/final.py directly; relay verifies outcome.",
            "success_gate": "task verify must return status=verified on fresh artifacts.",
            "required_outputs": ["logs/final.log", "results/result.json or screenshots/*"],
            "forbidden_outputs": ["browser profile dumps", "cookies", "auth headers", "raw tokens", "HAR files", "SQLite browser databases"],
            "chat_boundary": "Never send artifact contents to chat by default; use metadata-only reports.",
        },
        "commands": {
            "run": f"scripts/chip-relay task run {run_id}",
            "verify": f"scripts/chip-relay task verify {run_id}",
            "show": f"scripts/chip-relay task show {run_id}",
            "artifacts": f"scripts/chip-relay task artifacts {run_id}",
            "pack": f"scripts/chip-relay task pack {run_id} --name <recipe-name>",
        },
        "verification": verification,
        "evidence": evidence,
        "artifacts": {
            "count": len(artifact_index.get("artifacts", [])),
            "paths": [item["path"] for item in artifact_index.get("artifacts", [])],
        },
    }
    if write:
        context_path = run_dir / "agent" / "hermes-context.json"
        context_path.parent.mkdir(parents=True, exist_ok=True)
        context_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        payload["context_path"] = str(context_path)
    return payload
