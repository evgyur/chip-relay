from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import Any

from .agent_loop import run_agent_loop
from .benchmark import compare_results, gate_results, read_result
from .benchmark_runner import run_benchmark
from .captcha import captcha_summary, inspect_captcha_gate, wait_for_captcha_clearance
from .captcha_visual import apply_captcha_visual_actions, capture_captcha_visual, parse_visual_points
from .config import RelayConfig
from .hermes_context import hermes_task_context
from .recipes import list_recipes, load_recipe, pack_run, parse_params, prepare_recipe_run
from .reports import artifacts_report, evidence_report
from .verifier import verify_run
from .workspace import init_run, resolve_run, update_manifest
from .playwright_runner import run_final_script
from .protection import (
    diagnose_run,
    install_fingerprint_observer,
    protection_summary,
    read_bounded_json_object,
    record_page_signals,
    sanitize_observer_snapshot,
)
from .init_scripts import list_init_scripts


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
    if head == "stealth":
        try:
            return _stealth_response(config, tokens[1:])
        except ValueError as exc:
            gate = str(exc).split(":", 1)[0] or "stealth_command_failed"
            return _fail(gate, str(exc), command="stealth")
    return _fail("unknown_relay_command", f"unknown relay command: {head}")


def _option_value(tokens: list[str], index: int, option: str) -> tuple[str, int]:
    if index + 1 >= len(tokens):
        raise ValueError(f"usage: {option} requires a value")
    return tokens[index + 1], index + 2


def _stealth_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    if not tokens:
        return _fail(
            "usage",
            "usage: /relay stealth <benchmark|compare|gate>",
            command="stealth",
        )
    action = tokens[0]
    if action == "benchmark":
        backends: list[str] = []
        required: set[str] = set()
        suite = "local"
        repeat = 1
        preset = "normal"
        index = 1
        while index < len(tokens):
            option = tokens[index]
            if option in {"--backend", "--require-backend", "--suite", "--repeat", "--preset"}:
                value, index = _option_value(tokens, index, option)
                if option == "--backend":
                    backends.append(value)
                elif option == "--require-backend":
                    required.add(value)
                elif option == "--suite":
                    suite = value
                elif option == "--repeat":
                    try:
                        repeat = int(value)
                    except ValueError as exc:
                        raise ValueError("benchmark_repeat_invalid: repeat must be 1, 2, or 3") from exc
                else:
                    preset = value
                continue
            raise ValueError(f"usage: unknown stealth benchmark arg: {option}")
        payload, path = run_benchmark(
            config,
            backends=backends or ["active"],
            suite=suite,
            repeat=repeat,
            preset=preset,
            required_backends=required,
        )
        failed = bool(payload.get("required_backend_failure"))
        return RelayAdapterResult(
            1 if failed else 0,
            {
                "schema": SCHEMA,
                "command": "stealth.benchmark",
                "status": "failed" if failed else "completed",
                "result_path": str(path),
                "artifact_policy": "private-local/no-auto-send",
                "delivery": "metadata-only",
                "summary": {
                    "run_id": payload["run_id"],
                    "suite_id": payload["suite_id"],
                    "backends": [
                        {"identity": item["identity"], "status": item["status"]}
                        for item in payload["results"]
                    ],
                    "required_backend_failure": payload.get("required_backend_failure", []),
                },
            },
        )
    if action in {"compare", "gate"}:
        baseline = None
        candidate = None
        index = 1
        while index < len(tokens):
            option = tokens[index]
            if option in {"--baseline", "--candidate"}:
                value, index = _option_value(tokens, index, option)
                if option == "--baseline":
                    baseline = value
                else:
                    candidate = value
                continue
            raise ValueError(f"usage: unknown stealth {action} arg: {option}")
        if not baseline or not candidate:
            return _fail(
                "usage",
                f"usage: /relay stealth {action} --baseline <path> --candidate <path>",
                command=f"stealth.{action}",
            )
        if action == "compare":
            comparison = compare_results(read_result(baseline), read_result(candidate))
            return _ok("stealth.compare", {"status": "completed", "comparison": comparison})
        gate = gate_results(read_result(baseline), read_result(candidate))
        return RelayAdapterResult(
            0 if gate.status == "passed" else 1,
            {"schema": SCHEMA, "command": "stealth.gate", **gate.as_dict()},
        )
    return _fail("usage", f"unknown stealth action: {action}", command="stealth")


def relay_text_response(config: RelayConfig, text: str) -> RelayAdapterResult:
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        return _fail("parse_error", str(exc))
    return relay_response(config, tokens)


def _task_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    if not tokens:
        return _fail("usage", "usage: /relay task <init|context|verify|show|artifacts|protection|captcha|run|loop|pack>", command="task")
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
            "protection": verify.protection,
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
    if action == "protection":
        try:
            return _task_protection_response(config, tokens[1:])
        except ValueError as exc:
            gate = str(exc).split(":", 1)[0] or "protection_command_failed"
            return _fail(gate, str(exc), command="task.protection")
    if action == "captcha":
        try:
            return _task_captcha_response(config, tokens[1:])
        except ValueError as exc:
            gate = str(exc).split(":", 1)[0] or "captcha_command_failed"
            return _fail(gate, str(exc), command="task.captcha")
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


def _read_protection_input(path_text: str) -> dict[str, Any]:
    return read_bounded_json_object(path_text)


def _task_protection_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    usage = "usage: /relay task protection <run_id> <add|diagnose|show|observer-enable>"
    if len(tokens) < 2:
        return _fail("usage", usage, command="task.protection")
    run_dir = resolve_run(config, tokens[0])
    action = tokens[1]
    if action == "diagnose" and len(tokens) == 2:
        diagnosis = diagnose_run(run_dir)
        return _ok("task.protection.diagnose", {"status": "diagnosed", "run_id": run_dir.name, "diagnosis": diagnosis})
    if action == "show" and len(tokens) == 2:
        summary = protection_summary(run_dir)
        return _ok(
            "task.protection.show",
            {
                "status": summary["status"],
                "run_id": run_dir.name,
                "protection": summary,
            },
        )
    if action == "add":
        if len(tokens) not in {4, 6} or tokens[2] != "--json-file":
            return _fail("usage", f"{usage}; add requires --json-file <path> [--mode passive|instrumented]", command="task.protection")
        mode = "passive"
        if len(tokens) == 6:
            if tokens[4] != "--mode" or tokens[5] not in {"passive", "instrumented"}:
                return _fail("usage", "--mode must be passive or instrumented", command="task.protection")
            mode = tokens[5]
        raw = _read_protection_input(tokens[3])
        if raw.get("schema") == "chip-relay-fingerprint-observer-v1":
            snapshot = sanitize_observer_snapshot(raw)
            signal = record_page_signals(run_dir, {"fingerprint_apis": snapshot["fingerprint_apis"]}, mode="instrumented")
        else:
            signal = record_page_signals(run_dir, raw, mode=mode)
        return _ok("task.protection.add", {"status": "recorded", "run_id": run_dir.name, "signal": signal})
    if action == "observer-enable" and len(tokens) in {2, 4}:
        preset = "normal"
        if len(tokens) == 4:
            if tokens[2] != "--preset" or tokens[3] not in {"normal", "strict", "cf-sensitive"}:
                return _fail("usage", "--preset must be normal, strict, or cf-sensitive", command="task.protection")
            preset = tokens[3]
        observer = install_fingerprint_observer(run_dir, enabled=True, preset=preset)
        update_manifest(run_dir, lambda manifest: manifest.__setitem__("init_scripts", list_init_scripts(run_dir)))
        return _ok("task.protection.observer-enable", {"status": "installed", "run_id": run_dir.name, "observer": observer})
    return _fail("usage", usage, command="task.protection")


def _task_captcha_response(config: RelayConfig, tokens: list[str]) -> RelayAdapterResult:
    usage = "usage: /relay task captcha <run_id> <inspect|wait|resume|capture|act|show>"
    if len(tokens) < 2:
        return _fail("usage", usage, command="task.captcha")
    run_dir = resolve_run(config, tokens[0])
    action = tokens[1]
    if action == "capture" and len(tokens) == 2:
        visual = capture_captcha_visual(config, run_dir)
        return _ok(
            "task.captcha.capture",
            {
                "status": visual["status"],
                "run_id": run_dir.name,
                "captcha_visual": {
                    "status": visual["status"],
                    "width": visual["width"],
                    "height": visual["height"],
                    "point_space": visual["point_space"],
                    "cycle": visual["cycle"],
                    "artifact_policy": visual["artifact_policy"],
                },
            },
        )
    if action == "act":
        raw_points: list[str] = []
        confidence: float | None = None
        index = 2
        while index < len(tokens):
            if index + 1 >= len(tokens):
                return _fail("usage", usage, command="task.captcha")
            flag, value = tokens[index], tokens[index + 1]
            if flag == "--point":
                raw_points.append(value)
            elif flag == "--confidence":
                try:
                    confidence = float(value)
                except ValueError:
                    return _fail("usage", "--confidence must be numeric", command="task.captcha")
            else:
                return _fail("usage", usage, command="task.captcha")
            index += 2
        if confidence is None:
            return _fail("usage", "--confidence is required", command="task.captcha")
        try:
            points = parse_visual_points(raw_points)
        except ValueError as exc:
            return _fail("usage", str(exc), command="task.captcha")
        captcha = apply_captcha_visual_actions(config, run_dir, points, confidence=confidence)
        summary = captcha_summary(run_dir)
        summary["action_count"] = captcha.get("action_count", len(points))
        summary["visual_cycle"] = captcha.get("visual_cycle")
        summary["confidence"] = captcha.get("confidence")
        return RelayAdapterResult(
            0 if summary["status"] == "cleared" else 1,
            {
                "schema": SCHEMA,
                "command": "task.captcha.act",
                "status": summary["status"],
                "run_id": run_dir.name,
                "captcha": summary,
            },
        )
    if action == "show" and len(tokens) == 2:
        captcha = captcha_summary(run_dir)
        return _ok("task.captcha.show", {"status": captcha["status"], "run_id": run_dir.name, "captcha": captcha})
    if action == "inspect" and len(tokens) in {2, 4}:
        page_index = -1
        if len(tokens) == 4:
            if tokens[2] != "--page-index":
                return _fail("usage", usage, command="task.captcha")
            try:
                page_index = int(tokens[3])
            except ValueError:
                return _fail("usage", "--page-index must be an integer", command="task.captcha")
        inspect_captcha_gate(config, run_dir, page_index=page_index)
        summary = captcha_summary(run_dir)
        return RelayAdapterResult(
            1 if summary["status"] == "stale" else 0,
            {
                "schema": SCHEMA,
                "command": "task.captcha.inspect",
                "status": summary["status"],
                "run_id": run_dir.name,
                "captcha": summary,
            },
        )
    if action in {"wait", "resume"}:
        timeout = 120.0 if action == "wait" else 30.0
        poll_interval = 2.0
        page_index = -1
        index = 2
        while index < len(tokens):
            if index + 1 >= len(tokens):
                return _fail("usage", usage, command="task.captcha")
            flag, value = tokens[index], tokens[index + 1]
            if flag == "--timeout":
                try:
                    timeout = float(value)
                except ValueError:
                    return _fail("usage", "--timeout must be numeric", command="task.captcha")
            elif flag == "--poll-interval":
                try:
                    poll_interval = float(value)
                except ValueError:
                    return _fail("usage", "--poll-interval must be numeric", command="task.captcha")
            elif flag == "--page-index":
                try:
                    page_index = int(value)
                except ValueError:
                    return _fail("usage", "--page-index must be an integer", command="task.captcha")
            else:
                return _fail("usage", usage, command="task.captcha")
            index += 2
        captcha = wait_for_captcha_clearance(
            config,
            run_dir,
            timeout=timeout,
            poll_interval=poll_interval,
            page_index=page_index,
        )
        summary = captcha_summary(run_dir)
        if isinstance(captcha.get("checks"), int):
            summary["checks"] = captcha["checks"]
        if isinstance(captcha.get("elapsed_seconds"), (int, float)):
            summary["elapsed_seconds"] = captcha["elapsed_seconds"]
        return RelayAdapterResult(
            0 if summary["status"] == "cleared" else 1,
            {
                "schema": SCHEMA,
                "command": f"task.captcha.{action}",
                "status": summary["status"],
                "run_id": run_dir.name,
                "captcha": summary,
            },
        )
    return _fail("usage", usage, command="task.captcha")


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
        f"protection: {evidence['protection']['provider'] or 'none'}",
        f"protection_confidence: {evidence['protection']['confidence']}",
        f"protection_blocker: {evidence['protection']['blocker_class']}",
        f"protection_next_test: {evidence['protection']['next_test']}",
        f"captcha: {evidence['captcha']['status']}",
        f"captcha_provider: {evidence['captcha']['provider'] or 'none'}",
        f"captcha_next_action: {evidence['captcha']['next_action']}",
    ]
