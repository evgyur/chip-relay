from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

from .config import RelayConfig


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _safe_path(path_value: str | None, base: Path) -> tuple[Path | None, str | None]:
    if not path_value:
        return None, "missing_path"
    path = Path(path_value).expanduser()
    try:
        resolved = path.resolve(strict=False)
    except OSError as exc:
        return None, f"path_error:{exc}"
    base_resolved = base.resolve()
    if not _is_relative_to(resolved, base_resolved):
        return resolved, "outside_base_dir"
    if path.is_symlink() or resolved.is_symlink():
        return resolved, "symlink_rejected"
    return resolved, None


def cleanup_candidates(config: RelayConfig) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    base = config.base_dir.resolve()
    state_file = base / "state.json"
    if state_file.is_file():
        try:
            state = json.loads(state_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            state = {}
        pid = int(state.get("pid") or state.get("browserPid") or 0)
        profile_value = state.get("profileDir") or state.get("profile_dir")
        profile, error = _safe_path(str(profile_value) if profile_value else None, base)
        if error:
            candidates.append({"kind": "profile", "path": str(profile) if profile else str(profile_value or ""), "action": "blocked", "reason": error})
        elif profile and profile.exists() and not _pid_running(pid):
            candidates.append({"kind": "profile", "path": str(profile), "action": "remove_dir", "reason": "tracked_pid_not_running", "pid": pid})
    tmp_root = base / "tmp"
    if tmp_root.exists():
        for path in sorted(tmp_root.glob("orphan-*")):
            resolved, error = _safe_path(str(path), base)
            if error:
                candidates.append({"kind": "tmp", "path": str(path), "action": "blocked", "reason": error})
            elif resolved and resolved.exists():
                candidates.append({"kind": "tmp", "path": str(resolved), "action": "remove_dir" if resolved.is_dir() else "remove_file", "reason": "orphan_marker"})
    return candidates


def run_cleanup(config: RelayConfig, *, execute: bool = False) -> dict[str, Any]:
    candidates = cleanup_candidates(config)
    actions: list[dict[str, Any]] = []
    for item in candidates:
        action = dict(item)
        if item.get("action") == "blocked" or not execute:
            action["executed"] = False
            actions.append(action)
            continue
        path = Path(str(item["path"]))
        try:
            if item["action"] == "remove_dir":
                shutil.rmtree(path)
            elif item["action"] == "remove_file":
                path.unlink()
            action["executed"] = True
        except OSError as exc:
            action["executed"] = False
            action["error"] = str(exc)
        actions.append(action)
    return {
        "schema": "chip-relay-cleanup-v1",
        "mode": "execute" if execute else "dry-run",
        "base_dir": str(config.base_dir),
        "status": "ok" if all(item.get("action") != "blocked" for item in candidates) else "blocked",
        "candidates": candidates,
        "actions": actions,
    }
