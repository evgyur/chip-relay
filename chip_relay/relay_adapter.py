from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent_loop import run_agent_loop
from .config import RelayConfig
from .hermes_context import hermes_task_context
from .recipes import list_recipes, load_recipe, pack_run, parse_params, prepare_recipe_run
from .reports import artifacts_report, evidence_report
from .verifier import verify_run
from .workspace import init_run, resolve_run
from .playwright_runner import run_final_script

SCHEMA = "chip-relay-adapter-response-v1"


@dataclass(frozen=True)
class RelayAdapterResult:
    exit_code: int
    payload: dict[str, Any]


def _ok(command: str, payload: dict[str, Any]) -> RelayAdapterResult:
    data = {"schema": SCHEMA, "command": command}
    data.update(payload)
    return RelayAdapterResult(0, data)


def _fail(gate: str, message: str, *, command: str = "unknown") -> RelayAdapterResult:
    return RelayAdapterResult(1, {
        "schema": SCHEMA,
        "command": command,
        "status": "failed",
        "failed_gate": gate,
        "message": message,
    })


def normalize_relay_tokens(tokens: list[str]) -> list[str]:
    if tokens and tokens[0].strip() == "/relay":
        return tokens[1:]
    return tokens


def relay_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    tokens = normalize_relay_tokens(tokens)
    if not tokens:
        return _fail("empty_relay_command", "relay command is required")

    head = tokens[0]
    if head == "task":
        return _task_response(config, tokens[1:])
    if head == "artifacts":
        if len(tokens) != 2:
            return _fail("usage", "usage: /relay artifacts <run_id>", command="artifacts")
        run_dir = resolve_run(config, tokens[1])
        payload = artifacts_report(run_dir)
        return _ok("artifacts", {"status": "ok", "artifacts": payload})
    if head == "recipe":
        return _recipe_response(config, tokens[1:])
    return _fail("unknown_relay_command", f"unknown relay command: {head}")


def relay_text_response(config: RelayConfig, text: str) -> RelayAdapterResult:
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        return _fail("parse_error", str(exc))
    return relay_response(config, tokens)


def _task_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    if not tokens:
        return _fail("usage", "usage: /relay task <init|context|verify|show|artifacts|run|loop|pack>", command="task")
    action = tokens[0]
    if action == "init":
        if len(tokens) < 2:
            return _fail("usage", "usage: /relay task init <task>", command="task.init")
        title = " ".join(tokens[1:]).strip()
        run = init_run(config, title)
        return _ok("task.init", {
            "status": run.manifest["status"],
            "run_id": run.run_id,
            "run_dir": str(run.run_dir),
            "final_script": str(run.run_dir / "scripts" / "final.py"),
            "artifact_policy": "private-local/no-auto-send",
        })
    if action == "context":
        if len(tokens) not in {2, 3}:
            return _fail("usage", "usage: /relay task context <run_id> [--write]", command="task.context")
        write = False
        if len(tokens) == 3:
            if tokens[2] != "--write":
                return _fail("usage", f"unknown task context arg: {tokens[2]}", command="task.context")
            write = True
        run_dir = resolve_run(config, tokens[1])
        context = hermes_task_context(config, run_dir, write=write)
        return _ok("task.context", {"status": "ok", "run_id": context["run_id"], "context": context})
    if action == "verify":
        if len(tokens) != 2:
            return _fail("usage", "usage: /relay task verify <run_id>", command="task.verify")
        run_dir = resolve_run(config, tokens[1])
        verify = verify_run(run_dir)
        evidence = evidence_report(config, run_dir)
        return RelayAdapterResult(0 if verify.status == "verified" else 1, {
            "schema": SCHEMA,
            "command": "task.verify",
            "status": verify.status,
            "run_id": verify.run_id,
            "failed_gate": verify.failed_gate,
            "evidence": evidence,
        })
    if action == "show":
        if len(tokens) != 2:
            return _fail("usage", "usage: /relay task show <run_id>", command="task.show")
        run_dir = resolve_run(config, tokens[1])
        evidence = evidence_report(config, run_dir)
        return _ok("task.show", {"status": evidence["status"], "run_id": evidence["run_id"], "evidence": evidence})
    if action == "artifacts":
        if len(tokens) != 2:
            return _fail("usage", "usage: /relay task artifacts <run_id>", command="task.artifacts")
        run_dir = resolve_run(config, tokens[1])
        return _ok("task.artifacts", {"status": "ok", "artifacts": artifacts_report(run_dir)})
    if action == "run":
        if len(tokens) != 2:
            return _fail("usage", "usage: /relay task run <run_id>", command="task.run")
        run_dir = resolve_run(config, tokens[1])
        result = run_final_script(run_dir, config=config)
        return RelayAdapterResult(0 if result.status == "ran" else 1, {"schema": SCHEMA, "command": "task.run", **result.as_dict()})
    if action == "loop":
        return _task_loop_response(config, tokens[1:])
    if action == "pack":
        return _task_pack_response(config, tokens[1:])
    return _fail("unknown_relay_command", f"unknown task command: {action}", command="task")


def _task_loop_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    if not tokens:
        return _fail("usage", "usage: /relay task loop <run_id> --agent-command <command>", command="task.loop")
    run_id = tokens[0]
    agent_command: str | None = None
    max_attempts = 3
    timeout = 120
    index = 1
    known_flags = {"--agent-command", "--max-attempts", "--timeout"}
    while index < len(tokens):
        item = tokens[index]
        if item == "--agent-command" and index + 1 < len(tokens):
            values: list[str] = []
            index += 1
            while index < len(tokens) and tokens[index] not in known_flags:
                values.append(tokens[index])
                index += 1
            if not values:
                return _fail("usage", "agent command is required", command="task.loop")
            agent_command = values[0] if len(values) == 1 else " ".join(shlex.quote(value) for value in values)
        elif item == "--max-attempts" and index + 1 < len(tokens):
            try:
                max_attempts = int(tokens[index + 1])
            except ValueError:
                return _fail("usage", "--max-attempts must be an integer", command="task.loop")
            index += 2
        elif item == "--timeout" and index + 1 < len(tokens):
            try:
                timeout = int(tokens[index + 1])
            except ValueError:
                return _fail("usage", "--timeout must be an integer", command="task.loop")
            index += 2
        else:
            return _fail("usage", f"unknown task loop arg: {item}", command="task.loop")
    run_dir = resolve_run(config, run_id)
    result = run_agent_loop(run_dir, config=config, agent_command=agent_command, max_attempts=max_attempts, timeout=timeout)
    return RelayAdapterResult(0 if result.status == "verified" else 1, {"schema": SCHEMA, "command": "task.loop", **result.as_dict()})


def _task_pack_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    if not tokens:
        return _fail("usage", "usage: /relay task pack <run_id> --name <recipe>", command="task.pack")
    run_id = tokens[0]
    name: str | None = None
    force = False
    index = 1
    while index < len(tokens):
        item = tokens[index]
        if item == "--name" and index + 1 < len(tokens):
            name = tokens[index + 1]
            index += 2
        elif item == "--force":
            force = True
            index += 1
        else:
            return _fail("usage", f"unknown task pack arg: {item}", command="task.pack")
    if not name:
        return _fail("usage", "recipe name is required", command="task.pack")
    run_dir = resolve_run(config, run_id)
    result = pack_run(config, run_dir, name=name, force=force)
    return RelayAdapterResult(0 if result.status == "packed" else 1, {"schema": SCHEMA, "command": "task.pack", **result.as_dict()})


def _recipe_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    if not tokens:
        return _fail("usage", "usage: /relay recipe <list|show|run|pack>", command="recipe")
    action = tokens[0]
    if action == "list":
        return _ok("recipe.list", {"status": "ok", "recipes": list_recipes(config)})
    if action == "show" and len(tokens) == 2:
        return _ok("recipe.show", {"status": "ok", "recipe": load_recipe(config, tokens[1])})
    if action == "run" and len(tokens) >= 2:
        name = tokens[1]
        params = parse_params([t for t in tokens[2:] if "=" in t])
        run_id, run_dir = prepare_recipe_run(config, name, params=params)
        result = run_final_script(run_dir, config=config)
        payload = result.as_dict()
        payload["run_id"] = run_id
        payload["params"] = params
        return RelayAdapterResult(0 if result.status == "ran" else 1, {"schema": SCHEMA, "command": "recipe.run", **payload})
    if action == "pack":
        return _task_pack_response(config, tokens[1:])
    return _fail("unknown_relay_command", f"unknown recipe command: {action}", command="recipe")


def format_evidence_lines(evidence: dict[str, Any]) -> list[str]:
    return [
        f"run: {evidence['run_id']}",
        f"status: {evidence['status']}",
        f"title: {evidence['title']}",
        f"path: {evidence['run_dir']}",
        f"rail: {evidence['rail']['id']}",
        f"cdp: {evidence['rail']['cdp']}",
        f"verification: {evidence['verification']['status']}",
        f"strength: {evidence['verification']['strength']}",
        f"artifacts: {evidence['artifacts']['count']}",
        f"hygiene: {evidence['hygiene']}",
        f"artifact_policy: {evidence['artifact_policy']}",
        f"blocker: {evidence['blocker']}",
    ]
