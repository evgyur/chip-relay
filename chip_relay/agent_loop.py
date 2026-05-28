from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import RelayConfig
from .hygiene import redact_text
from .verifier import verify_run
from .workspace import load_manifest, write_manifest


@dataclass(frozen=True)
class AgentLoopResult:
    status: str
    run_id: str
    run_dir: Path
    attempts: int
    failed_gate: str | None = None
    verification: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "run_id": self.run_id,
            "run_dir": str(self.run_dir),
            "attempts": self.attempts,
        }
        if self.failed_gate:
            payload["failed_gate"] = self.failed_gate
        if self.verification is not None:
            payload["verification"] = self.verification
        return payload


def utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _agent_command_tokens(agent_command: str) -> list[str]:
    tokens = shlex.split(agent_command)
    if not tokens:
        return tokens
    caller_cwd = Path.cwd()
    resolved: list[str] = []
    for token in tokens:
        candidate = Path(token).expanduser()
        if not candidate.is_absolute() and ("/" in token or token.startswith(".")):
            from_caller = (caller_cwd / candidate).resolve()
            if from_caller.exists():
                resolved.append(str(from_caller))
                continue
        resolved.append(token)
    return resolved


def _update_manifest(run_dir: Path, result: AgentLoopResult) -> None:
    manifest = load_manifest(run_dir)
    manifest["updated_at"] = utc_now_text()
    manifest["agent_loop"] = {
        "status": result.status,
        "attempts": result.attempts,
        "failed_gate": result.failed_gate,
        "updated_at": utc_now_text(),
    }
    write_manifest(run_dir, manifest)


def _fail(run_dir: Path, run_id: str, attempts: int, gate: str, verification: dict[str, Any] | None = None) -> AgentLoopResult:
    result = AgentLoopResult("failed", run_id, run_dir, attempts, gate, verification)
    _write_json(run_dir / "agent" / "loop-result.json", result.as_dict())
    _update_manifest(run_dir, result)
    return result


def run_agent_loop(
    run_dir: Path,
    *,
    config: RelayConfig,
    agent_command: str | None,
    max_attempts: int = 3,
    timeout: int = 120,
) -> AgentLoopResult:
    manifest = load_manifest(run_dir)
    run_id = manifest.get("run_id", run_dir.name)
    agent_dir = run_dir / "agent"
    agent_dir.mkdir(parents=True, exist_ok=True)

    if not agent_command:
        return _fail(run_dir, run_id, 0, "agent_command_missing")
    if max_attempts < 1:
        return _fail(run_dir, run_id, 0, "max_attempts_invalid")

    previous: dict[str, Any] | None = None
    for attempt in range(1, max_attempts + 1):
        context = {
            "schema": "chip-relay-agent-context-v1",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "attempt": attempt,
            "max_attempts": max_attempts,
            "task": manifest.get("task", {}),
            "cdp_url": config.cdp_url,
            "artifact_contract": {
                "final_script": "scripts/final.py",
                "required_outputs": ["logs/final.log", "results/result.json or screenshots/*"],
                "forbidden": ["cookies", "auth headers", "raw tokens", "browser profile dumps"],
            },
            "previous_result": previous,
        }
        context_path = agent_dir / f"request-{attempt:03d}.json"
        _write_json(context_path, context)

        env = os.environ.copy()
        env["CHIP_RELAY_AGENT_CONTEXT"] = str(context_path)
        env["CHIP_RELAY_RUN_DIR"] = str(run_dir)
        env["CHIP_RELAY_CDP_URL"] = config.cdp_url
        try:
            proc = subprocess.run(
                _agent_command_tokens(agent_command),
                cwd=run_dir,
                env=env,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            previous = {"status": "failed", "failed_gate": "agent_command_not_found", "exit_code": 127}
            _write_json(agent_dir / f"feedback-{attempt:03d}.json", previous)
            (agent_dir / f"attempt-{attempt:03d}.log").write_text("agent command not found\n", encoding="utf-8")
            return _fail(run_dir, run_id, attempt, "agent_command_not_found", previous)
        except PermissionError:
            previous = {"status": "failed", "failed_gate": "agent_command_not_executable", "exit_code": 126}
            _write_json(agent_dir / f"feedback-{attempt:03d}.json", previous)
            (agent_dir / f"attempt-{attempt:03d}.log").write_text("agent command not executable\n", encoding="utf-8")
            return _fail(run_dir, run_id, attempt, "agent_command_not_executable", previous)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if type(exc.stdout) is str else ""
            stderr = exc.stderr if type(exc.stderr) is str else ""
            agent_log = stdout + stderr
            (agent_dir / f"attempt-{attempt:03d}.log").write_text(redact_text(agent_log), encoding="utf-8")
            previous = {"status": "failed", "failed_gate": "agent_command_timeout", "exit_code": None}
            _write_json(agent_dir / f"feedback-{attempt:03d}.json", previous)
            return _fail(run_dir, run_id, attempt, "agent_command_timeout", previous)
        agent_log = (proc.stdout or "") + (proc.stderr or "")
        (agent_dir / f"attempt-{attempt:03d}.log").write_text(redact_text(agent_log), encoding="utf-8")
        if proc.returncode != 0:
            previous = {"status": "failed", "failed_gate": "agent_command_exit", "exit_code": proc.returncode}
            _write_json(agent_dir / f"feedback-{attempt:03d}.json", previous)
            continue

        verification = verify_run(run_dir, strength="same-rail").as_dict()
        _write_json(agent_dir / f"feedback-{attempt:03d}.json", verification)
        if verification.get("status") == "verified":
            result = AgentLoopResult("verified", run_id, run_dir, attempt, verification=verification)
            _write_json(agent_dir / "loop-result.json", result.as_dict())
            _update_manifest(run_dir, result)
            return result
        previous = verification

    return _fail(run_dir, run_id, max_attempts, "verification_failed", previous)
