from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RelayConfig:
    base_dir: Path
    runs_dir: Path
    recipes_dir: Path
    host: str
    port: int
    cdp_url: str
    profile: str
    profile_dir: Path
    proxy: str | None
    upload_allowed_dirs: str | None


def _expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


def load_config() -> RelayConfig:
    base_dir = _expand(os.environ.get("CHIP_RELAY_BASE_DIR", "~/.local/share/chip-relay"))
    runs_dir = _expand(os.environ.get("CHIP_RELAY_RUNS_DIR", str(base_dir / "runs")))
    recipes_dir = _expand(os.environ.get("CHIP_RELAY_RECIPES_DIR", str(base_dir / "recipes")))
    host = os.environ.get("CHIP_RELAY_HOST", "127.0.0.1")
    port = int(os.environ.get("CHIP_RELAY_PORT", "18800"))
    cdp_url = os.environ.get("CHIP_RELAY_CDP_URL", f"http://{host}:{port}")
    profile = os.environ.get("CHIP_RELAY_PROFILE", "default")
    profile_dir = _expand(os.environ.get("CHIP_RELAY_PROFILE_DIR", str(base_dir / "profiles" / profile)))
    proxy = os.environ.get("CHIP_RELAY_PROXY")
    upload_allowed_dirs = os.environ.get("CHIP_RELAY_UPLOAD_ALLOWED_DIRS")
    return RelayConfig(
        base_dir=base_dir,
        runs_dir=runs_dir,
        recipes_dir=recipes_dir,
        host=host,
        port=port,
        cdp_url=cdp_url,
        profile=profile,
        profile_dir=profile_dir,
        proxy=proxy,
        upload_allowed_dirs=upload_allowed_dirs,
    )
