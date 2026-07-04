from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import RelayConfig
from .environment import browser_environment
from .hygiene import redact_text, scan_path
from .proxy import ProxyConfigError, parse_proxy_config, redact_proxy_url
from .workspace import load_manifest, write_manifest


@dataclass(frozen=True)
class RunResult:
    status: str
    run_id: str
    run_dir: Path
    exit_code: int
    log_path: Path
    cdp_url: str
    failed_gate: str | None = None
    log_tail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "run_id": self.run_id,
            "run_dir": str(self.run_dir),
            "exit_code": self.exit_code,
            "log_path": str(self.log_path),
            "cdp_url": self.cdp_url,
        }
        if self.failed_gate:
            payload["failed_gate"] = self.failed_gate
        if self.log_tail:
            payload["log_tail"] = self.log_tail
        return payload


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def cdp_version(cdp_url: str, *, timeout: float = 2.0) -> dict[str, Any]:
    url = cdp_url.rstrip("/") + "/json/version"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "ignore"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return {}


def ensure_cdp(cdp_url: str) -> None:
    version = cdp_version(cdp_url)
    if not version:
        raise RuntimeError(f"CDP endpoint not reachable: {cdp_url}")


def run_final_script(run_dir: Path, *, config: RelayConfig, timeout: int = 180) -> RunResult:
    manifest = load_manifest(run_dir)
    final_script = run_dir / "scripts" / "final.py"
    log_path = run_dir / "logs" / "run.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    if not final_script.is_file():
        result = RunResult("failed", manifest.get("run_id", run_dir.name), run_dir, 1, log_path, config.cdp_url, "final_script_missing")
        _update_run_manifest(run_dir, manifest, result)
        return result

    env = os.environ.copy()
    env.setdefault("CHIP_RELAY_CDP_URL", config.cdp_url)
    env.setdefault("CHIP_RELAY_RUN_DIR", str(run_dir))
    env.setdefault("PYTHONUNBUFFERED", "1")

    try:
        proc = subprocess.run(
            [sys.executable, str(final_script)],
            cwd=run_dir,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if type(exc.stdout) is str else ""
        stderr = exc.stderr if type(exc.stderr) is str else ""
        combined = stdout + stderr
        log_path.write_text(redact_text(combined), encoding="utf-8")
        result = RunResult("failed", manifest.get("run_id", run_dir.name), run_dir, 124, log_path, config.cdp_url, "final_script_timeout", redact_text(combined))
        _update_run_manifest(run_dir, manifest, result)
        return result
    combined = (proc.stdout or "") + (proc.stderr or "")
    log_path.write_text(redact_text(combined), encoding="utf-8")

    status = "ran" if proc.returncode == 0 else "failed"
    failed_gate = None if proc.returncode == 0 else "final_script_exit"
    result = RunResult(
        status=status,
        run_id=manifest.get("run_id", run_dir.name),
        run_dir=run_dir,
        exit_code=proc.returncode,
        log_path=log_path,
        cdp_url=config.cdp_url,
        failed_gate=failed_gate,
        log_tail=redact_text(combined) if proc.returncode else None,
    )
    _update_run_manifest(run_dir, manifest, result)
    return result


def _update_run_manifest(run_dir: Path, manifest: dict[str, Any], result: RunResult) -> None:
    manifest["status"] = result.status
    manifest["updated_at"] = utc_now_text()
    manifest["run"] = {
        "last_result": result.as_dict(),
        "last_run_at": utc_now_text(),
    }
    write_manifest(run_dir, manifest)


def doctor_webwright(config: RelayConfig) -> dict[str, Any]:
    config.runs_dir.mkdir(parents=True, exist_ok=True)
    workspace_probe = config.runs_dir / ".write-test"
    writable = False
    try:
        workspace_probe.write_text("ok", encoding="utf-8")
        workspace_probe.unlink()
        writable = True
    except OSError:
        writable = False

    playwright_spec = importlib.util.find_spec("playwright")
    cdp = cdp_version(config.cdp_url)
    hygiene = scan_path(Path(__file__).resolve().parent)
    env_report = browser_environment(config.cdp_url)
    proxy_check: dict[str, Any] = {"ok": True, "configured": False, "server": None}
    if config.proxy:
        try:
            parsed_proxy = parse_proxy_config(config.proxy)
            proxy_check = {
                "ok": True,
                "configured": True,
                "server": parsed_proxy.server,
                "redacted": redact_proxy_url(config.proxy),
                "auth": parsed_proxy.username is not None,
            }
        except ProxyConfigError as exc:
            proxy_check = {"ok": False, "configured": True, "failed_gate": str(exc), "redacted": "[REDACTED]"}

    checks = {
        "python": {
            "ok": True,
            "executable": sys.executable,
            "version": sys.version.split()[0],
        },
        "playwright_import": {
            "ok": playwright_spec is not None,
        },
        "cdp": {
            "ok": bool(cdp),
            "url": config.cdp_url,
            "version": cdp,
        },
        "browser_environment": env_report,
        "proxy": proxy_check,
        "workspace_writable": {
            "ok": writable,
            "runs_dir": str(config.runs_dir),
        },
        "hygiene_scanner": {
            "ok": hygiene.get("status") == "ok",
            "patterns_active": True,
        },
    }
    # CDP and Playwright can be absent in CI/offline diagnostics; doctor reports them but stays usable.
    hard_ok = checks["python"]["ok"] and checks["workspace_writable"]["ok"] and checks["hygiene_scanner"]["ok"] and proxy_check["ok"]
    return {"status": "ok" if hard_ok else "failed", "checks": checks}
