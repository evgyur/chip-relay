from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .config import RelayConfig

SCHEMA = "chip-relay-run-manifest-v1"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ATTEMPT_ID_PATTERN = re.compile(r"^attempt-(\d{12})$")
MAX_MANIFEST_BYTES = 1_048_576
KERNEL_LOCK_RETRY_SECONDS = 0.01


@dataclass(frozen=True)
class RunWorkspace:
    run_id: str
    run_dir: Path
    manifest: dict[str, Any]


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def slugify(title: str, max_len: int = 60) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title.strip().lower()).strip("-")
    slug = re.sub(r"-+", "-", slug)
    return (slug[:max_len].strip("-") or "browser-task")


def make_run_id(title: str, now: datetime | None = None) -> str:
    current = now or utc_now()
    stamp = current.strftime("%Y-%m-%dT%H%M%SZ")
    return f"{stamp}-{slugify(title)}"


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise ValueError("invalid_run_id: use only letters, numbers, dot, underscore, and hyphen")
    if ".." in run_id or "/" in run_id or "\\" in run_id:
        raise ValueError("invalid_run_id: path components are not allowed")
    return run_id


def default_manifest(config: RelayConfig, run_id: str, title: str, run_dir: Path, *, template: str = "placeholder") -> dict[str, Any]:
    now = utc_now().isoformat().replace("+00:00", "Z")
    brief = default_task_brief(title, template=template)
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "created_at": now,
        "updated_at": now,
        "task": {
            "title": title,
            "source": "cli",
            "sensitivity": "private-local",
            "brief_schema": "chip-relay-agent-brief-v2",
            "brief": brief,
        },
        "rail": {
            "rail_id": config.profile,
            "backend": "unknown",
            "cdp_url": config.cdp_url,
            "profile_mode": "persistent",
        },
        "workspace": {
            "path": str(run_dir),
            "artifact_policy": "private-local",
            "retention_days": 14,
        },
        "status": "initialized",
        "template": template,
        "artifacts": [],
        "execution": {
            "generation": 0,
            "attempt_id": "attempt-000000000000",
            "phase": "initialized",
            "source": "init",
            "started_at": None,
            "completed_at": None,
            "captcha_visual_cycle": 0,
        },
        "verification": {
            "required": ["final_script", "final_log", "hygiene_scan"],
            "strength": "not-run",
            "last_result": None,
        },
        "init_scripts": [],
    }


def default_task_brief(title: str, *, template: str = "placeholder") -> dict[str, Any]:
    return {
        "agent_instructions": [
            "Treat task.md and manifest.json as the source-of-truth brief before editing scripts/final.py.",
            "Make the smallest script change that satisfies the task and can be freshly verified.",
            "Keep secrets, cookies, browser profiles, HAR files, and raw private artifact contents out of chat output.",
        ],
        "success_metrics": [
            "scripts/final.py exits 0 under task verify.",
            "Verification produces fresh evidence from the current attempt.",
            "At least one useful result artifact exists under results/ or screenshots/.",
            "Hygiene scan passes with no forbidden browser/auth artifacts.",
        ],
        "known_frictions": [
            "CDP endpoint unavailable or bound to the wrong rail.",
            "Authentication, captcha, or rate-limit wall blocks the live site.",
            "DOM, selector, or navigation timing changed since the script was written.",
            "Artifacts may contain private data and must stay metadata-only by default.",
        ],
        "verification_questions": [
            "Did task verify run after the latest scripts/final.py edit?",
            "Do logs/results/screenshots come from the current verify attempt rather than stale files?",
            "Does the evidence prove the requested outcome, not just script execution?",
            "Did hygiene block forbidden profile, cookie, token, HAR, SQLite, or symlink artifacts?",
        ],
        "context": {
            "title": title,
            "template": template,
        },
    }


def task_markdown(title: str, *, template: str = "placeholder") -> str:
    brief = default_task_brief(title, template=template)

    def section(name: str, values: list[str]) -> str:
        lines = [f"## {name}", ""]
        lines.extend(f"- {value}" for value in values)
        return "\n".join(lines)

    return "\n\n".join([
        "# Task",
        title,
        "## Brief Schema\n\nchip-relay-agent-brief-v2",
        section("Agent Instructions", brief["agent_instructions"]),
        section("Success Metrics", brief["success_metrics"]),
        section("Known Frictions", brief["known_frictions"]),
        section("Verification Questions", brief["verification_questions"]),
        "",
    ])


def final_template(title: str, *, template: str = "placeholder") -> str:
    safe_title = json.dumps(title, ensure_ascii=False)
    if template == "example-title":
        return f'''#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import time

from playwright.sync_api import sync_playwright

RUN_DIR = pathlib.Path(__file__).resolve().parents[1]
LOG_DIR = RUN_DIR / "logs"
RESULT_DIR = RUN_DIR / "results"
SCREENSHOT_DIR = RUN_DIR / "screenshots"
INIT_SCRIPT_DIR = RUN_DIR / "init_scripts"
CDP_URL = os.environ.get("CHIP_RELAY_CDP_URL", "http://127.0.0.1:18800")

for directory in (LOG_DIR, RESULT_DIR, SCREENSHOT_DIR):
    directory.mkdir(parents=True, exist_ok=True)


def log(message: str) -> None:
    line = f"{{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}} {{message}}"
    print(line, flush=True)
    with open(LOG_DIR / "final.log", "a", encoding="utf-8") as handle:
        handle.write(line + "\\n")


def apply_init_scripts(context) -> None:
    if not INIT_SCRIPT_DIR.exists():
        return
    for script_path in sorted(INIT_SCRIPT_DIR.glob("*.js")):
        if script_path.is_file() and not script_path.is_symlink():
            context.add_init_script(path=str(script_path))
            log(f"loaded init script {{script_path.name}}")


def main() -> int:
    log(f"connecting to {{CDP_URL}}")
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP_URL)
        context = browser.contexts[0] if browser.contexts else browser.new_context()
        apply_init_scripts(context)
        page = context.new_page()
        page.goto("https://example.com", wait_until="domcontentloaded", timeout=30000)
        page.screenshot(path=str(SCREENSHOT_DIR / "999-final.png"), full_page=True)
        result = {{"task": {safe_title}, "title": page.title(), "url": page.url}}
        (RESULT_DIR / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        log("wrote result.json and final screenshot")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''
    return f'''#!/usr/bin/env python3
from __future__ import annotations

import json
import pathlib
import time

RUN_DIR = pathlib.Path(__file__).resolve().parents[1]
LOG_DIR = RUN_DIR / "logs"
RESULT_DIR = RUN_DIR / "results"
SCREENSHOT_DIR = RUN_DIR / "screenshots"
INIT_SCRIPT_DIR = RUN_DIR / "init_scripts"

for directory in (LOG_DIR, RESULT_DIR, SCREENSHOT_DIR):
    directory.mkdir(parents=True, exist_ok=True)


def log(message: str) -> None:
    line = f"{{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}} {{message}}"
    print(line, flush=True)
    with open(LOG_DIR / "final.log", "a", encoding="utf-8") as handle:
        handle.write(line + "\\n")


def apply_init_scripts(context) -> None:
    if not INIT_SCRIPT_DIR.exists():
        return
    for script_path in sorted(INIT_SCRIPT_DIR.glob("*.js")):
        if script_path.is_file() and not script_path.is_symlink():
            context.add_init_script(path=str(script_path))
            log(f"loaded init script {{script_path.name}}")


def main() -> int:
    result = {{"task": {safe_title}, "status": "template-ready"}}
    (RESULT_DIR / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    log("wrote placeholder result.json; use --template example-title for Playwright/CDP smoke")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def init_run(config: RelayConfig, title: str, *, run_id: str | None = None, template: str = "placeholder") -> RunWorkspace:
    config.runs_dir.mkdir(parents=True, exist_ok=True)
    rid = validate_run_id(run_id or make_run_id(title))
    run_dir = config.runs_dir / rid
    if run_dir.exists():
        raise FileExistsError(f"run already exists: {rid}")
    for rel in ("scripts", "logs", "screenshots", "traces", "results/downloads", "verification", "init_scripts", "network"):
        (run_dir / rel).mkdir(parents=True, exist_ok=True)
    (run_dir / "task.md").write_text(task_markdown(title, template=template), encoding="utf-8")
    (run_dir / "README.md").write_text(f"# {rid}\n\nStatus: initialized\n", encoding="utf-8")
    final_path = run_dir / "scripts" / "final.py"
    final_path.write_text(final_template(title, template=template), encoding="utf-8")
    final_path.chmod(0o755)
    manifest = default_manifest(config, rid, title, run_dir, template=template)
    write_manifest(run_dir, manifest)
    return RunWorkspace(run_id=rid, run_dir=run_dir, manifest=manifest)


@contextmanager
def _replacement_safe_lock(run_dir: Path, scope: str) -> Iterator[None]:
    if not sys.platform.startswith("linux"):
        yield
        return
    logical_path = os.path.normcase(os.path.abspath(os.fspath(run_dir)))
    digest = hashlib.sha256(f"{scope}\0{logical_path}".encode()).hexdigest()[:40]
    address = f"\0chip-relay-{scope}-{digest}"
    guard = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                guard.bind(address)
                break
            except OSError as exc:
                if exc.errno != errno.EADDRINUSE:
                    raise
                time.sleep(KERNEL_LOCK_RETRY_SECONDS)
        yield
    finally:
        guard.close()


@contextmanager
def execution_run_lock(run_dir: Path) -> Iterator[None]:
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    lock_flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        dir_fd = os.open(run_dir, dir_flags)
    except OSError as exc:
        raise ValueError("unsafe_execution_run_directory") from exc
    lock_fd: int | None = None
    try:
        lock_fd = os.open(".execution.lock", lock_flags, 0o600, dir_fd=dir_fd)
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("unsafe_execution_lock")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        with _replacement_safe_lock(run_dir, "execution"):
            yield
    except OSError as exc:
        raise ValueError("unsafe_execution_lock") from exc
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(dir_fd)


@contextmanager
def _manifest_lock(run_dir: Path) -> Iterator[None]:
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    lock_flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        dir_fd = os.open(run_dir, dir_flags)
    except OSError as exc:
        raise ValueError("unsafe_manifest_run_directory") from exc
    lock_fd: int | None = None
    try:
        lock_fd = os.open(".manifest.lock", lock_flags, 0o600, dir_fd=dir_fd)
        metadata = os.fstat(lock_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("unsafe_manifest_lock")
        os.fchmod(lock_fd, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        with _replacement_safe_lock(run_dir, "manifest"):
            yield
    except OSError as exc:
        raise ValueError("unsafe_manifest_lock") from exc
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(dir_fd)


def _write_manifest_unlocked(run_dir: Path, manifest: dict[str, Any]) -> None:
    data = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest_too_large")
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        dir_fd = os.open(run_dir, dir_flags)
    except OSError as exc:
        raise ValueError(f"unsafe_manifest_directory: {exc}") from exc
    tmp_name = f".manifest-{secrets.token_hex(12)}.tmp"
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_fd: int | None = None
    try:
        metadata = os.fstat(dir_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("unsafe_manifest_directory: not a directory")
        file_fd = os.open(tmp_name, file_flags, 0o600, dir_fd=dir_fd)
        os.fchmod(file_fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short manifest write")
            view = view[written:]
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.rename(tmp_name, "manifest.json", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        os.fsync(dir_fd)
    except OSError as exc:
        raise ValueError(f"unsafe_manifest_path: {exc}") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        os.close(dir_fd)


def write_manifest(run_dir: Path, manifest: dict[str, Any]) -> None:
    with _manifest_lock(run_dir):
        _write_manifest_unlocked(run_dir, manifest)


def update_manifest(run_dir: Path, updater: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with _manifest_lock(run_dir):
        manifest = load_manifest(run_dir)
        attempt_before = execution_marker(manifest)
        updater(manifest)
        if execution_marker(manifest) != attempt_before:
            raise ValueError("manifest_updater_changed_execution_identity")
        _write_manifest_unlocked(run_dir, manifest)
        return manifest


def load_manifest(run_dir: Path) -> dict[str, Any]:
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        dir_fd = os.open(run_dir, dir_flags)
        try:
            file_fd = os.open("manifest.json", file_flags, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
    except OSError as exc:
        raise ValueError(f"unsafe_manifest_path: {exc}") from exc
    try:
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_MANIFEST_BYTES:
            raise ValueError("unsafe_manifest_path: manifest must be a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(65_536, MAX_MANIFEST_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_MANIFEST_BYTES:
                raise ValueError("manifest_too_large")
    finally:
        os.close(file_fd)
    try:
        payload = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid_manifest_json: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid_manifest_json: top-level object required")
    return payload


def execution_marker(manifest: Any) -> dict[str, Any]:
    default = {"generation": 0, "attempt_id": "attempt-000000000000"}
    if not isinstance(manifest, dict):
        raise ValueError("invalid_execution_state")
    if "execution" not in manifest:
        return default
    execution = manifest["execution"]
    required_execution_fields = {
        "generation",
        "attempt_id",
        "phase",
        "source",
        "started_at",
        "completed_at",
    }
    execution_fields = set(execution) if isinstance(execution, dict) else set()
    if execution_fields not in {
        frozenset(required_execution_fields),
        frozenset(required_execution_fields | {"captcha_visual_cycle"}),
    }:
        raise ValueError("invalid_execution_state")
    generation = execution.get("generation")
    attempt_id = execution.get("attempt_id")
    phase = execution.get("phase")
    source = execution.get("source")
    started_at = execution.get("started_at")
    completed_at = execution.get("completed_at")
    captcha_visual_cycle = execution.get("captcha_visual_cycle", 0)
    if type(captcha_visual_cycle) is not int or not 0 <= captcha_visual_cycle <= 3:
        raise ValueError("invalid_execution_state")
    if type(generation) is not int or not 0 <= generation <= 999_999_999_999:
        raise ValueError("invalid_execution_state")
    if not isinstance(attempt_id, str):
        raise ValueError("invalid_execution_state")
    match = ATTEMPT_ID_PATTERN.fullmatch(attempt_id)
    if match is None or int(match.group(1)) != generation:
        raise ValueError("invalid_execution_state")
    timestamp = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
    if generation == 0:
        if (phase, source, started_at, completed_at) != ("initialized", "init", None, None):
            raise ValueError("invalid_execution_state")
    else:
        if phase not in {"running", "completed", "failed"}:
            raise ValueError("invalid_execution_state")
        if not isinstance(source, str) or re.fullmatch(r"[a-z0-9_-]{1,40}", source) is None:
            raise ValueError("invalid_execution_state")
        if not isinstance(started_at, str) or re.fullmatch(timestamp, started_at) is None:
            raise ValueError("invalid_execution_state")
        if phase == "running":
            if completed_at is not None:
                raise ValueError("invalid_execution_state")
        elif not isinstance(completed_at, str) or re.fullmatch(timestamp, completed_at) is None:
            raise ValueError("invalid_execution_state")
    return {"generation": generation, "attempt_id": attempt_id}


def current_attempt_id(run_dir: Path) -> str:
    try:
        manifest = load_manifest(run_dir)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return "attempt-000000000000"
    return str(execution_marker(manifest)["attempt_id"])


def bound_attempt_id(run_dir: Path) -> str:
    current = current_attempt_id(run_dir)
    expected = os.environ.get("CHIP_RELAY_ATTEMPT_ID")
    if expected is None:
        return current
    if not ATTEMPT_ID_PATTERN.fullmatch(expected):
        raise ValueError("invalid_bound_attempt_id")
    if expected != current:
        raise ValueError("stale_execution_attempt")
    return expected


def begin_execution_attempt(run_dir: Path, _manifest: dict[str, Any], *, source: str) -> dict[str, Any]:
    if not isinstance(source, str) or not re.fullmatch(r"[a-z0-9_-]{1,40}", source):
        raise ValueError("invalid_attempt_source")
    with _manifest_lock(run_dir):
        manifest = load_manifest(run_dir)
        current = execution_marker(manifest)
        generation = int(current["generation"]) + 1
        if generation > 999_999_999_999:
            raise ValueError("attempt_generation_exhausted")
        now = utc_now().isoformat().replace("+00:00", "Z")
        manifest["execution"] = {
            "generation": generation,
            "attempt_id": f"attempt-{generation:012d}",
            "phase": "running",
            "source": source,
            "started_at": now,
            "completed_at": None,
            "captcha_visual_cycle": 0,
        }
        manifest["status"] = "running"
        manifest["updated_at"] = now
        _write_manifest_unlocked(run_dir, manifest)
        from .protection import invalidate_protection_diagnosis

        invalidate_protection_diagnosis(run_dir)
        return manifest


def update_execution_attempt(
    run_dir: Path,
    attempt_id: str,
    updater: Callable[[dict[str, Any]], None],
    *,
    phase: str | None = None,
) -> dict[str, Any]:
    if not ATTEMPT_ID_PATTERN.fullmatch(attempt_id):
        raise ValueError("invalid_attempt_id")
    if phase not in {None, "completed", "failed"}:
        raise ValueError("invalid_attempt_phase")
    with _manifest_lock(run_dir):
        manifest = load_manifest(run_dir)
        if execution_marker(manifest)["attempt_id"] != attempt_id:
            raise ValueError("stale_execution_attempt")
        execution = manifest.get("execution")
        if not isinstance(execution, dict):
            raise ValueError("invalid_execution_state")
        if phase is not None and execution.get("phase") != "running":
            raise ValueError("execution_attempt_not_running")
        updater(manifest)
        if execution_marker(manifest)["attempt_id"] != attempt_id:
            raise ValueError("execution_attempt_identity_changed")
        if phase is not None:
            execution = manifest.get("execution")
            if not isinstance(execution, dict):
                raise ValueError("invalid_execution_attempt")
            execution["phase"] = phase
            execution["completed_at"] = utc_now().isoformat().replace("+00:00", "Z")
        execution_marker(manifest)
        _write_manifest_unlocked(run_dir, manifest)
        return manifest


def resolve_run(config: RelayConfig, run_id_or_path: str) -> Path:
    candidate = Path(run_id_or_path).expanduser()
    runs_root = config.runs_dir.resolve()
    if candidate.exists():
        resolved = candidate.resolve()
        if not resolved.is_relative_to(runs_root):
            raise ValueError("invalid_run_id: resolved path escapes runs_dir")
        return resolved
    run_id = validate_run_id(run_id_or_path)
    resolved = (config.runs_dir / run_id).resolve()
    if not resolved.is_relative_to(runs_root):
        raise ValueError("invalid_run_id: resolved path escapes runs_dir")
    return resolved


def list_runs(config: RelayConfig) -> list[dict[str, Any]]:
    if not config.runs_dir.exists():
        return []
    runs: list[dict[str, Any]] = []
    for manifest_path in sorted(config.runs_dir.glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        runs.append({
            "run_id": manifest.get("run_id", manifest_path.parent.name),
            "status": manifest.get("status", "unknown"),
            "title": (manifest.get("task") or {}).get("title", ""),
            "run_dir": str(manifest_path.parent),
            "created_at": manifest.get("created_at"),
            "updated_at": manifest.get("updated_at"),
        })
    return runs
