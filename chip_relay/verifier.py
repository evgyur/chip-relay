from __future__ import annotations

import json
import py_compile
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hygiene import redact_text, scan_path
from .workspace import load_manifest, write_manifest


@dataclass(frozen=True)
class VerifyResult:
    status: str
    run_id: str
    run_dir: Path
    verification_strength: str
    failed_gate: str | None = None
    exit_code: int | None = None
    log_tail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "run_id": self.run_id,
            "run_dir": str(self.run_dir),
            "verification_strength": self.verification_strength,
        }
        if self.failed_gate:
            payload["failed_gate"] = self.failed_gate
        if self.exit_code is not None:
            payload["exit_code"] = self.exit_code
        if self.log_tail:
            payload["log_tail"] = self.log_tail
        return payload


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def artifact_index(run_dir: Path) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for rel_root, kinds in (("logs", "log"), ("results", "result"), ("screenshots", "screenshot"), ("traces", "trace"), ("verification", "verification")):
        root = run_dir / rel_root
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if path.is_file():
                artifacts.append({
                    "type": kinds,
                    "path": str(path.relative_to(run_dir)),
                    "sensitivity": "private-local",
                })
    return artifacts


def fail(run_dir: Path, manifest: dict[str, Any], gate: str, strength: str, exit_code: int | None = None, log_tail: str | None = None) -> VerifyResult:
    manifest["status"] = "failed"
    manifest["updated_at"] = utc_now_text()
    manifest.setdefault("verification", {})["strength"] = strength
    manifest["verification"]["last_result"] = {"status": "failed", "failed_gate": gate, "exit_code": exit_code}
    manifest["artifacts"] = artifact_index(run_dir)
    write_manifest(run_dir, manifest)
    result = VerifyResult("failed", manifest.get("run_id", run_dir.name), run_dir, strength, gate, exit_code, log_tail)
    write_json(run_dir / "verification" / "verify-result.json", result.as_dict())
    return result


def verify_run(run_dir: Path, *, strength: str = "same-rail") -> VerifyResult:
    manifest = load_manifest(run_dir)
    final_script = run_dir / "scripts" / "final.py"
    verify_log = run_dir / "logs" / "verify.log"
    verify_log.parent.mkdir(parents=True, exist_ok=True)

    if strength != "same-rail":
        return fail(run_dir, manifest, "verification_strength_not_implemented", strength)

    if not final_script.is_file():
        return fail(run_dir, manifest, "final_script_missing", strength)

    try:
        py_compile.compile(str(final_script), doraise=True)
    except py_compile.PyCompileError as exc:
        return fail(run_dir, manifest, "final_script_compile", strength, log_tail=redact_text(str(exc)))

    verify_started_at = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(final_script)],
            cwd=run_dir,
            text=True,
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if type(exc.stdout) is str else ""
        stderr = exc.stderr if type(exc.stderr) is str else ""
        combined = stdout + stderr
        verify_log.write_text(redact_text(combined), encoding="utf-8")
        return fail(run_dir, manifest, "final_script_timeout", strength, log_tail=redact_text(combined))
    combined = (proc.stdout or "") + (proc.stderr or "")
    verify_log.write_text(redact_text(combined), encoding="utf-8")
    if proc.returncode != 0:
        return fail(run_dir, manifest, "final_script_exit", strength, proc.returncode, redact_text(combined))

    final_log = run_dir / "logs" / "final.log"
    result_json = run_dir / "results" / "result.json"

    def fresh(path: Path) -> bool:
        return path.is_file() and path.stat().st_mtime >= verify_started_at

    has_fresh_log = fresh(final_log) or bool(verify_log.read_text(encoding="utf-8").strip())
    has_fresh_result_or_screenshot = fresh(result_json) or any(path.stat().st_mtime >= verify_started_at for path in (run_dir / "screenshots").glob("*") if path.is_file())
    if not has_fresh_log:
        return fail(run_dir, manifest, "final_log_missing", strength)
    if not has_fresh_result_or_screenshot:
        return fail(run_dir, manifest, "required_artifact_missing", strength)

    hygiene_report = scan_path(run_dir)
    write_json(run_dir / "verification" / "hygiene-report.json", hygiene_report)
    if hygiene_report["status"] != "ok":
        return fail(run_dir, manifest, "hygiene_scan", strength, log_tail=redact_text(json.dumps(hygiene_report, ensure_ascii=False)))

    result_payload = {
        "status": "verified",
        "run_id": manifest.get("run_id", run_dir.name),
        "verification_strength": strength,
        "verified_at": utc_now_text(),
    }
    write_json(run_dir / "verification" / "verify-result.json", result_payload)

    manifest["status"] = "verified"
    manifest["updated_at"] = utc_now_text()
    manifest.setdefault("verification", {})["strength"] = strength
    manifest["verification"]["last_result"] = result_payload
    manifest["artifacts"] = artifact_index(run_dir)
    write_manifest(run_dir, manifest)

    return VerifyResult("verified", manifest.get("run_id", run_dir.name), run_dir, strength)
