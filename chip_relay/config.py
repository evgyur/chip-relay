from __future__ import annotations

import os
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path

from .capabilities import ProxyAuthDescriptor, load_proxy_auth_descriptor


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
    proxy_auth: ProxyAuthDescriptor | None = None
    browser_use_command: str | None = None
    external_binding: dict | None = None


def _expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


BOUND_CONFIG: ContextVar[RelayConfig | None] = ContextVar('relay_bound_config', default=None)


def load_config() -> RelayConfig:
    bound = BOUND_CONFIG.get()
    if bound is not None:
        return bound
    base_dir = _expand(os.environ.get("CHIP_RELAY_BASE_DIR", "~/.local/share/chip-relay"))
    runs_dir = _expand(os.environ.get("CHIP_RELAY_RUNS_DIR", str(base_dir / "runs")))
    recipes_dir = _expand(os.environ.get("CHIP_RELAY_RECIPES_DIR", str(base_dir / "recipes")))
    host = os.environ.get("CHIP_RELAY_HOST", "127.0.0.1")
    port = int(os.environ.get("CHIP_RELAY_PORT", "18800"))
    cdp_url = os.environ.get("CHIP_RELAY_CDP_URL", f"http://{host}:{port}")
    profile = os.environ.get("CHIP_RELAY_PROFILE", "default")
    profile_dir = _expand(os.environ.get("CHIP_RELAY_PROFILE_DIR", str(base_dir / "profiles" / profile)))
    proxy_descriptor = load_proxy_auth_descriptor(os.environ)
    proxy = proxy_descriptor.server if proxy_descriptor is not None else None
    upload_allowed_dirs = os.environ.get("CHIP_RELAY_UPLOAD_ALLOWED_DIRS")
    browser_use_command = os.environ.get("CHIP_RELAY_BROWSER_USE_COMMAND")
    raw_binding = os.environ.get('RELAY_BOUND_ENTRY')
    if raw_binding:
        import json
        from .binding import validate_entry, verify_binding
        entry = json.loads(raw_binding)
        validate_entry(entry)
        verify_binding(entry)
        if entry['endpoint'] != cdp_url:
            raise ValueError('bound_endpoint_mismatch')
    else:
        entry = None
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
        proxy_auth=proxy_descriptor if proxy_descriptor is not None and proxy_descriptor.authenticated else None,
        browser_use_command=browser_use_command,
        external_binding=entry,
    )
