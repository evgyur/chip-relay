from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Sequence

UPLOAD_ALLOWED_DIRS_ENV = "CHIP_RELAY_UPLOAD_ALLOWED_DIRS"


def parse_allowed_upload_roots(value: str | None = None) -> list[Path]:
    raw = os.environ.get(UPLOAD_ALLOWED_DIRS_ENV) if value is None else value
    if raw is None or not raw.strip():
        return []
    roots: list[Path] = []
    for item in raw.split(os.pathsep):
        item = item.strip().strip('"')
        if not item:
            continue
        path = Path(item).expanduser()
        if not path.is_absolute():
            raise ValueError(f"upload_root_not_absolute: {item}")
        resolved = path.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError(f"upload_root_not_directory: {item}")
        roots.append(resolved)
    return roots


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def validate_upload_paths(paths: Sequence[str], *, allowed_roots: Iterable[Path] | None = None) -> list[str]:
    if not paths or isinstance(paths, (str, bytes)):
        raise ValueError("upload_paths_required")
    roots = [root.resolve(strict=True) for root in (allowed_roots if allowed_roots is not None else parse_allowed_upload_roots())]
    if not roots:
        raise ValueError(f"upload_roots_required: set {UPLOAD_ALLOWED_DIRS_ENV}")
    result: list[str] = []
    for value in paths:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("upload_path_empty")
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError(f"upload_path_not_absolute: {value}")
        if path.is_symlink():
            raise ValueError(f"upload_path_symlink_rejected: {value}")
        try:
            resolved = path.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError(f"upload_path_missing: {value}") from exc
        if not resolved.is_file():
            raise ValueError(f"upload_path_not_file: {value}")
        if not any(_is_relative_to(resolved, root) for root in roots):
            raise ValueError(f"upload_path_outside_allowed_roots: {resolved}")
        result.append(str(resolved))
    return result
