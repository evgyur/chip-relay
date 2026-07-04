from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def is_running_as_root() -> bool:
    return hasattr(os, "getuid") and os.getuid() == 0


def is_running_in_container() -> bool:
    indicators = [
        Path("/.dockerenv").exists(),
        os.environ.get("container") is not None,
        os.environ.get("KUBERNETES_SERVICE_HOST") is not None,
    ]
    try:
        indicators.append("docker" in Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        pass
    return any(indicators)


def find_browser_executable() -> str | None:
    names = [
        "cloakbrowser-chrome",
        "browseros",
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "microsoft-edge",
        "microsoft-edge-stable",
    ]
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    static_paths = [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/microsoft-edge",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
    ]
    for value in static_paths:
        path = Path(value)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def cdp_binding(cdp_url: str) -> dict[str, Any]:
    parsed = urlparse(cdp_url)
    hostname = parsed.hostname or ""
    local = hostname in {"127.0.0.1", "::1", "localhost"}
    return {
        "url": cdp_url,
        "hostname": hostname,
        "local_only": local,
        "label": "local-only" if local else "configured-nonlocal",
        "ok": local,
    }


def browser_environment(cdp_url: str) -> dict[str, Any]:
    root = is_running_as_root()
    container = is_running_in_container()
    warnings: list[str] = []
    if root:
        warnings.append("running-as-root-needs-no-sandbox")
    if container:
        warnings.append("container-may-need-disable-dev-shm-usage")
    binding = cdp_binding(cdp_url)
    if not binding["local_only"]:
        warnings.append("cdp-not-loopback")
    return {
        "ok": binding["ok"],
        "platform": platform.system(),
        "machine": platform.machine(),
        "is_root": root,
        "is_container": container,
        "browser_executable": find_browser_executable(),
        "cdp_binding": binding,
        "warnings": warnings,
    }
