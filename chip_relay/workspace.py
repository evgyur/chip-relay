from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import RelayConfig

SCHEMA = "chip-relay-run-manifest-v1"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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


def write_manifest(run_dir: Path, manifest: dict[str, Any]) -> None:
    path = run_dir / "manifest.json"
    tmp = run_dir / ".manifest.json.tmp"
    tmp.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def load_manifest(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))


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
