from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

INIT_SCRIPT_DIRNAME = "init_scripts"
INIT_SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


def init_script_dir(run_dir: Path) -> Path:
    return run_dir / INIT_SCRIPT_DIRNAME


def validate_init_script_name(name: str) -> str:
    if not isinstance(name, str) or not INIT_SCRIPT_NAME.fullmatch(name):
        raise ValueError("invalid_init_script_name: use letters, numbers, dot, underscore, and hyphen")
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError("invalid_init_script_name: path components are not allowed")
    return name if name.endswith(".js") else f"{name}.js"


def add_init_script(run_dir: Path, name: str, source: str) -> dict[str, Any]:
    safe_name = validate_init_script_name(name)
    root = init_script_dir(run_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = (root / safe_name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("invalid_init_script_name: resolved path escapes init_scripts directory")
    path.write_text(source, encoding="utf-8")
    return init_script_metadata(run_dir, path)


def init_script_metadata(run_dir: Path, path: Path) -> dict[str, Any]:
    root = init_script_dir(run_dir).resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("invalid_init_script_path: path escapes init_scripts directory")
    data = path.read_bytes()
    return {
        "name": path.name,
        "path": str(path.relative_to(run_dir)),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "sensitivity": "private-local",
    }


def list_init_scripts(run_dir: Path) -> list[dict[str, Any]]:
    root = init_script_dir(run_dir)
    if not root.exists():
        return []
    scripts: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.js")):
        if path.is_file() and not path.is_symlink():
            scripts.append(init_script_metadata(run_dir, path))
    return scripts


def iter_init_script_paths(run_dir: Path) -> list[Path]:
    root = init_script_dir(run_dir)
    if not root.exists():
        return []
    return [path for path in sorted(root.glob("*.js")) if path.is_file() and not path.is_symlink()]
