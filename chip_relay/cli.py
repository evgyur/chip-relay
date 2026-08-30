from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .agent_loop import run_agent_loop
from .benchmark import compare_results, gate_results, read_result
from .benchmark_runner import run_benchmark
from .browser_use import (
    BrowserUseUnavailable,
    browser_use_doctor,
    browser_use_plan,
    browser_use_summary,
    execute_browser_use,
)
from .captcha import captcha_summary, inspect_captcha_gate, wait_for_captcha_clearance
from .captcha_visual import (
    apply_captcha_visual_actions,
    capture_captcha_visual,
    parse_visual_points,
)
from .cleanup import run_cleanup
from .config import load_config
from .hermes_context import hermes_task_context
from .init_scripts import add_init_script, list_init_scripts
from .network import export_network_metadata, record_observation, search_observations
from .playwright_runner import doctor_webwright, run_final_script
from .protection import (
    diagnose_run,
    install_fingerprint_observer,
    protection_summary,
    read_bounded_json_object,
    record_page_signals,
    sanitize_observer_snapshot,
)
from .recipes import (
    list_recipes,
    load_recipe,
    pack_run,
    parse_params,
    prepare_recipe_run,
)
from .relay_adapter import format_evidence_lines, relay_response
from .reports import artifacts_report, evidence_report
from .stealth import load_sample, stealth_doctor
from .verifier import verify_run
from .workspace import init_run, list_runs, load_manifest, resolve_run, update_manifest


def emit(payload: object, *, json_mode: bool) -> None:
    if json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        if isinstance(payload, dict):
            for key, value in payload.items():
                print(f"{key}: {value}")
        else:
            print(payload)


def read_bounded_json_file(path_text: str, *, max_bytes: int = 65536) -> dict[str, Any]:
    return read_bounded_json_object(path_text, max_bytes=max_bytes)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chip-relay-python")
    parser.add_argument("--json", action="store_true", dest="json_mode")
    sub = parser.add_subparsers(dest="command", required=True)

    task = sub.add_parser("task")
    task_sub = task.add_subparsers(dest="task_command", required=True)

    init = task_sub.add_parser("init")
    init.add_argument("title", nargs="+")
    init.add_argument("--id", dest="run_id")
    init.add_argument("--template", choices=["placeholder", "example-title"], default="placeholder")

    task_sub.add_parser("list")

    show = task_sub.add_parser("show")
    show.add_argument("run")

    task_artifacts = task_sub.add_parser("artifacts")
    task_artifacts.add_argument("run")

    context = task_sub.add_parser("context")
    context.add_argument("run")
    context.add_argument("--write", action="store_true")

    verify = task_sub.add_parser("verify")
    verify.add_argument("run")
    verify.add_argument("--strength", choices=["same-rail", "fresh-context", "clean-ci"], default="same-rail")

    run = task_sub.add_parser("run")
    run.add_argument("run")
    run.add_argument("--verify", action="store_true")

    pack = task_sub.add_parser("pack")
    pack.add_argument("run")
    pack.add_argument("--name", required=True)
    pack.add_argument("--force", action="store_true")

    loop = task_sub.add_parser("loop")
    loop.add_argument("run")
    loop.add_argument("--agent-command", default=None)
    loop.add_argument("--max-attempts", type=int, default=3)
    loop.add_argument("--timeout", type=int, default=120)

    network = task_sub.add_parser("network")
    network.add_argument("run")
    network_sub = network.add_subparsers(dest="network_command", required=True)
    network_add = network_sub.add_parser("add")
    network_add.add_argument("--json-file", required=True)
    network_search = network_sub.add_parser("search")
    network_search.add_argument("--url", dest="url_contains")
    network_search.add_argument("--method")
    network_search.add_argument("--status", type=int)
    network_search.add_argument("--resource-type")
    network_search.add_argument("--limit", type=int, default=50)
    network_search.add_argument("--offset", type=int, default=0)
    network_sub.add_parser("export")

    protection = task_sub.add_parser("protection")
    protection.add_argument("run")
    protection_sub = protection.add_subparsers(dest="protection_command", required=True)
    protection_add = protection_sub.add_parser("add")
    protection_add.add_argument("--json-file", required=True)
    protection_add.add_argument("--mode", choices=["passive", "instrumented"], default="passive")
    protection_sub.add_parser("diagnose")
    protection_sub.add_parser("show")
    observer_enable = protection_sub.add_parser("observer-enable")
    observer_enable.add_argument("--preset", choices=["normal", "strict", "cf-sensitive"], default="normal")

    captcha = task_sub.add_parser("captcha")
    captcha.add_argument("run")
    captcha_sub = captcha.add_subparsers(dest="captcha_command", required=True)
    captcha_inspect = captcha_sub.add_parser("inspect")
    captcha_inspect.add_argument("--page-index", type=int, default=-1)
    captcha_wait = captcha_sub.add_parser("wait")
    captcha_wait.add_argument("--timeout", type=float, default=120)
    captcha_wait.add_argument("--poll-interval", type=float, default=2)
    captcha_wait.add_argument("--page-index", type=int, default=-1)
    captcha_resume = captcha_sub.add_parser("resume")
    captcha_resume.add_argument("--timeout", type=float, default=30)
    captcha_resume.add_argument("--poll-interval", type=float, default=2)
    captcha_resume.add_argument("--page-index", type=int, default=-1)
    captcha_sub.add_parser("capture")
    captcha_act = captcha_sub.add_parser("act")
    captcha_act.add_argument("--point", action="append", required=True)
    captcha_act.add_argument("--confidence", type=float, required=True)
    captcha_sub.add_parser("show")

    init_script = task_sub.add_parser("init-script")
    init_script.add_argument("run")
    init_script_sub = init_script.add_subparsers(dest="init_script_command", required=True)
    init_add = init_script_sub.add_parser("add")
    init_add.add_argument("name")
    init_add.add_argument("--file", required=True)
    init_script_sub.add_parser("list")

    browser_use = task_sub.add_parser("browser-use")
    browser_use.add_argument("run")
    browser_use_sub = browser_use.add_subparsers(dest="browser_use_command", required=True)
    browser_use_sub.add_parser("doctor")
    browser_use_plan_parser = browser_use_sub.add_parser("plan")
    browser_use_plan_parser.add_argument("--script", required=True)
    browser_use_execute = browser_use_sub.add_parser("execute")
    browser_use_execute.add_argument("--script", required=True)
    browser_use_execute.add_argument("--timeout", type=float, default=120)
    browser_use_sub.add_parser("show")

    doctor = sub.add_parser("doctor")
    doctor.add_argument("topic", nargs="?", default="webwright", choices=["webwright", "playwright"])

    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--execute", action="store_true")

    stealth = sub.add_parser("stealth")
    stealth_sub = stealth.add_subparsers(dest="stealth_command", required=True)
    stealth_doctor_parser = stealth_sub.add_parser("doctor")
    stealth_doctor_parser.add_argument("--preset", choices=["normal", "strict", "cf-sensitive"], default="normal")
    stealth_doctor_parser.add_argument("--sample-json")
    stealth_benchmark = stealth_sub.add_parser("benchmark")
    stealth_benchmark.add_argument(
        "--backend",
        action="append",
        choices=["active", "chromium", "cloakbrowser", "browseros"],
        dest="backends",
    )
    stealth_benchmark.add_argument("--require-backend", action="append", default=[])
    stealth_benchmark.add_argument("--suite", choices=["local", "public-detectors"], default="local")
    stealth_benchmark.add_argument("--repeat", type=int, choices=[1, 2, 3], default=1)
    stealth_benchmark.add_argument("--preset", choices=["normal", "strict", "cf-sensitive"], default="normal")
    stealth_benchmark.add_argument("--output")
    stealth_compare = stealth_sub.add_parser("compare")
    stealth_compare.add_argument("--baseline", required=True)
    stealth_compare.add_argument("--candidate", required=True)
    stealth_gate = stealth_sub.add_parser("gate")
    stealth_gate.add_argument("--baseline", required=True)
    stealth_gate.add_argument("--candidate", required=True)
    stealth_gate.add_argument("--policy", choices=["default"], default="default")

    artifacts = sub.add_parser("artifacts")
    artifacts.add_argument("run")

    relay = sub.add_parser("relay")
    relay.add_argument("tokens", nargs=argparse.REMAINDER)

    recipe = sub.add_parser("recipe")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    recipe_sub.add_parser("list")
    recipe_show = recipe_sub.add_parser("show")
    recipe_show.add_argument("name")
    recipe_run = recipe_sub.add_parser("run")
    recipe_run.add_argument("name")
    recipe_run.add_argument("--param", action="append", default=[])
    recipe_run.add_argument("--verify", action="store_true")
    return parser


def cmd_task_network(args: argparse.Namespace, config) -> int:
    run_dir = resolve_run(config, args.run)
    if args.network_command == "add":
        raw = read_bounded_json_file(args.json_file)
        payload = record_observation(run_dir, raw)
        emit({"status": "recorded", "run_id": run_dir.name, "observation": payload}, json_mode=args.json_mode)
        return 0
    if args.network_command == "search":
        payload = search_observations(
            run_dir,
            url_contains=args.url_contains,
            method=args.method,
            status=args.status,
            resource_type=args.resource_type,
            limit=args.limit,
            offset=args.offset,
        )
        emit(payload, json_mode=args.json_mode)
        return 0
    if args.network_command == "export":
        payload = export_network_metadata(run_dir)
        emit(payload, json_mode=args.json_mode)
        return 0
    raise SystemExit(f"unknown network command: {args.network_command}")


def cmd_task_protection(args: argparse.Namespace, config) -> int:
    run_dir = resolve_run(config, args.run)
    if args.protection_command == "add":
        raw = read_bounded_json_file(args.json_file)
        if isinstance(raw, dict) and raw.get("schema") == "chip-relay-fingerprint-observer-v1":
            snapshot = sanitize_observer_snapshot(raw)
            payload = record_page_signals(
                run_dir,
                {"fingerprint_apis": snapshot["fingerprint_apis"]},
                mode="instrumented",
            )
        else:
            payload = record_page_signals(run_dir, raw, mode=args.mode)
        emit({"status": "recorded", "run_id": run_dir.name, "signal": payload}, json_mode=args.json_mode)
        return 0
    if args.protection_command == "diagnose":
        diagnosis = diagnose_run(run_dir)
        emit({"status": "diagnosed", "run_id": run_dir.name, "diagnosis": diagnosis}, json_mode=args.json_mode)
        return 0
    if args.protection_command == "show":
        summary = protection_summary(run_dir)
        emit(
            {
                "status": summary["status"],
                "run_id": run_dir.name,
                "protection": summary,
            },
            json_mode=args.json_mode,
        )
        return 0
    if args.protection_command == "observer-enable":
        payload = install_fingerprint_observer(run_dir, enabled=True, preset=args.preset)
        update_manifest(run_dir, lambda manifest: manifest.__setitem__("init_scripts", list_init_scripts(run_dir)))
        emit({"status": "installed", "run_id": run_dir.name, "observer": payload}, json_mode=args.json_mode)
        return 0
    raise SystemExit(f"unknown protection command: {args.protection_command}")


def cmd_task_init_script(args: argparse.Namespace, config) -> int:
    run_dir = resolve_run(config, args.run)
    if args.init_script_command == "add":
        source = Path(args.file).read_text(encoding="utf-8")
        item = add_init_script(run_dir, args.name, source)
        manifest = update_manifest(
            run_dir,
            lambda authoritative: authoritative.__setitem__("init_scripts", list_init_scripts(run_dir)),
        )
        emit({"status": "added", "run_id": manifest.get("run_id", run_dir.name), "script": item}, json_mode=args.json_mode)
        return 0
    if args.init_script_command == "list":
        emit({"status": "ok", "run_id": run_dir.name, "scripts": list_init_scripts(run_dir)}, json_mode=args.json_mode)
        return 0
    raise SystemExit(f"unknown init-script command: {args.init_script_command}")


def cmd_task_browser_use(args: argparse.Namespace, config) -> int:
    run_dir = resolve_run(config, args.run)
    if args.browser_use_command == "doctor":
        payload = browser_use_doctor(config)
    elif args.browser_use_command == "plan":
        payload = browser_use_plan(config, run_dir, Path(args.script))
    elif args.browser_use_command == "execute":
        try:
            payload = execute_browser_use(
                config,
                run_dir,
                Path(args.script),
                timeout=args.timeout,
            )
        except BrowserUseUnavailable as exc:
            payload = {
                "schema": "chip-relay-browser-use-result-v1",
                "status": "blocked",
                "mode": "cooperative-read-only",
                "failure": str(exc),
                "artifact_policy": "private-local/metadata-only-report",
            }
    elif args.browser_use_command == "show":
        payload = browser_use_summary(run_dir)
    else:
        raise SystemExit(f"unknown browser-use command: {args.browser_use_command}")
    payload["run_id"] = run_dir.name
    emit(payload, json_mode=args.json_mode)
    return 0 if payload["status"] in {"ready", "succeeded", "not-run"} else 1


def cmd_task_captcha(args: argparse.Namespace, config) -> int:
    run_dir = resolve_run(config, args.run)
    if args.captcha_command == "capture":
        payload = capture_captcha_visual(config, run_dir)
        emit({"status": payload["status"], "run_id": run_dir.name, "captcha_visual": payload}, json_mode=args.json_mode)
        return 0
    if args.captcha_command == "act":
        points = parse_visual_points(args.point)
        payload = apply_captcha_visual_actions(config, run_dir, points, confidence=args.confidence)
        emit({"status": payload["status"], "run_id": run_dir.name, "captcha": payload}, json_mode=args.json_mode)
        return 0 if payload["status"] == "cleared" else 1
    if args.captcha_command == "inspect":
        payload = inspect_captcha_gate(config, run_dir, page_index=args.page_index)
        current = captcha_summary(run_dir)
        if current["status"] == "stale":
            emit({"status": "stale", "run_id": run_dir.name, "captcha": current}, json_mode=args.json_mode)
            return 1
        emit({"status": payload["status"], "run_id": run_dir.name, "captcha": payload}, json_mode=args.json_mode)
        return 0
    if args.captcha_command in {"wait", "resume"}:
        payload = wait_for_captcha_clearance(
            config,
            run_dir,
            timeout=args.timeout,
            poll_interval=args.poll_interval,
            page_index=args.page_index,
        )
        current = captcha_summary(run_dir)
        if current["status"] == "stale":
            emit({"status": "stale", "run_id": run_dir.name, "captcha": current}, json_mode=args.json_mode)
            return 1
        emit({"status": payload["status"], "run_id": run_dir.name, "captcha": payload}, json_mode=args.json_mode)
        return 0 if payload["status"] == "cleared" else 1
    if args.captcha_command == "show":
        payload = captcha_summary(run_dir)
        emit({"status": payload["status"], "run_id": run_dir.name, "captcha": payload}, json_mode=args.json_mode)
        return 0
    raise SystemExit(f"unknown captcha command: {args.captcha_command}")


def cmd_task(args: argparse.Namespace) -> int:
    config = load_config()
    if args.task_command == "init":
        title = " ".join(args.title).strip()
        if not title:
            raise SystemExit("task title is required")
        run = init_run(config, title, run_id=args.run_id, template=args.template)
        emit({
            "status": run.manifest["status"],
            "run_id": run.run_id,
            "run_dir": str(run.run_dir),
            "manifest": str(run.run_dir / "manifest.json"),
            "final_script": str(run.run_dir / "scripts" / "final.py"),
            "template": args.template,
        }, json_mode=args.json_mode)
        return 0
    if args.task_command == "list":
        emit({"runs": list_runs(config)}, json_mode=args.json_mode)
        return 0
    if args.task_command == "show":
        run_dir = resolve_run(config, args.run)
        report = evidence_report(config, run_dir)
        if args.json_mode:
            manifest = load_manifest(run_dir)
            manifest["protection"] = report["protection"]
            manifest["evidence"] = report
            print(json.dumps(manifest, ensure_ascii=False, indent=2))
        else:
            print(f"run: {report['run_id']}")
            print(f"status: {report['status']}")
            print(f"title: {report['title']}")
            print(f"path: {report['run_dir']}")
            print(f"rail: {report['rail']['id']}")
            print(f"cdp: {report['rail']['cdp']}")
            print(f"verification: {report['verification']['status']}")
            print(f"strength: {report['verification']['strength']}")
            print(f"artifacts: {report['artifacts']['count']}")
            print(f"hygiene: {report['hygiene']}")
            print(f"artifact_policy: {report['artifact_policy']}")
            print(f"blocker: {report['blocker']}")
            print(f"protection: {report['protection']['provider'] or 'none'}")
            print(f"protection_confidence: {report['protection']['confidence']}")
            print(f"protection_blocker: {report['protection']['blocker_class']}")
            print(f"protection_next_test: {report['protection']['next_test']}")
            print(f"captcha: {report['captcha']['status']}")
            print(f"captcha_provider: {report['captcha']['provider'] or 'none'}")
            print(f"captcha_next_action: {report['captcha']['next_action']}")
        return 0
    if args.task_command == "artifacts":
        run_dir = resolve_run(config, args.run)
        payload = artifacts_report(run_dir)
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"artifact_policy: {payload['artifact_policy']}")
            print(f"delivery: {payload['delivery']}")
            for item in payload["artifacts"]:
                print(f"- {item['path']} ({item['type']}, {item['size_bytes']} bytes, {item['sensitivity']})")
        return 0
    if args.task_command == "context":
        run_dir = resolve_run(config, args.run)
        payload = hermes_task_context(config, run_dir, write=args.write)
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"status: {payload['status']}")
            print(f"model: {payload['model']}")
            print(f"next_action: {payload['next_action']}")
            print("final_script: scripts/final.py")
            print(f"artifact_policy: {payload['artifact_policy']}")
            if payload.get("context_path"):
                print(f"context_path: {payload['context_path']}")
        return 0
    if args.task_command == "verify":
        run_dir = resolve_run(config, args.run)
        result = verify_run(run_dir, strength=args.strength)
        payload = result.as_dict()
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"status: {payload['status']}")
            print(f"verification: {payload['verification_strength']}")
            if payload.get("failed_gate"):
                print(f"failed_gate: {payload['failed_gate']}")
        return 0 if result.status == "verified" else 1
    if args.task_command == "run":
        run_dir = resolve_run(config, args.run)
        result = run_final_script(run_dir, config=config)
        payload = result.as_dict()
        if args.verify and result.status == "ran":
            verify_result = verify_run(run_dir, strength="same-rail")
            payload["verification"] = verify_result.as_dict()
            if verify_result.status == "verified":
                payload["status"] = "verified"
            else:
                payload["status"] = "failed"
                payload["failed_gate"] = verify_result.failed_gate
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"status: {payload['status']}")
            print(f"exit_code: {payload['exit_code']}")
            if payload.get("failed_gate"):
                print(f"failed_gate: {payload['failed_gate']}")
        return 0 if payload["status"] in {"ran", "verified"} else 1
    if args.task_command == "pack":
        run_dir = resolve_run(config, args.run)
        result = pack_run(config, run_dir, name=args.name, force=args.force)
        payload = result.as_dict()
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"status: {payload['status']}")
            print(f"recipe: {payload['recipe_name']}")
            if payload.get("recipe_dir"):
                print(f"recipe_dir: {payload['recipe_dir']}")
            if payload.get("failed_gate"):
                print(f"failed_gate: {payload['failed_gate']}")
        return 0 if result.status == "packed" else 1
    if args.task_command == "loop":
        run_dir = resolve_run(config, args.run)
        result = run_agent_loop(run_dir, config=config, agent_command=args.agent_command, max_attempts=args.max_attempts, timeout=args.timeout)
        payload = result.as_dict()
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"status: {payload['status']}")
            print(f"attempts: {payload['attempts']}")
            if payload.get("failed_gate"):
                print(f"failed_gate: {payload['failed_gate']}")
        return 0 if result.status == "verified" else 1
    if args.task_command == "network":
        return cmd_task_network(args, config)
    if args.task_command == "protection":
        return cmd_task_protection(args, config)
    if args.task_command == "captcha":
        return cmd_task_captcha(args, config)
    if args.task_command == "init-script":
        return cmd_task_init_script(args, config)
    if args.task_command == "browser-use":
        return cmd_task_browser_use(args, config)
    raise SystemExit(f"unknown task command: {args.task_command}")


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config()
    payload = doctor_webwright(config)
    if args.json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print("chip-relay doctor webwright")
        for name, check in payload["checks"].items():
            marker = "ok" if check.get("ok") else "fail"
            print(f"- {name}: {marker}")
    return 0 if payload["status"] == "ok" else 1


def cmd_cleanup(args: argparse.Namespace) -> int:
    config = load_config()
    payload = run_cleanup(config, execute=args.execute)
    emit(payload, json_mode=args.json_mode)
    return 0 if payload["status"] == "ok" else 1


def cmd_stealth(args: argparse.Namespace) -> int:
    if args.stealth_command == "doctor":
        payload = stealth_doctor(preset=args.preset, sample=load_sample(args.sample_json))
        emit(payload, json_mode=args.json_mode)
        return 0
    if args.stealth_command == "benchmark":
        payload, path = run_benchmark(
            load_config(),
            backends=args.backends or ["active"],
            suite=args.suite,
            repeat=args.repeat,
            preset=args.preset,
            required_backends=set(args.require_backend),
            output=args.output,
        )
        response = {
            "status": "failed" if payload.get("required_backend_failure") else "completed",
            "result_path": str(path),
            "benchmark": payload,
        }
        emit(response, json_mode=args.json_mode)
        return 1 if payload.get("required_backend_failure") else 0
    if args.stealth_command == "compare":
        payload = compare_results(read_result(args.baseline), read_result(args.candidate))
        emit(payload, json_mode=args.json_mode)
        return 0
    if args.stealth_command == "gate":
        result = gate_results(read_result(args.baseline), read_result(args.candidate))
        emit(result.as_dict(), json_mode=args.json_mode)
        return 0 if result.status == "passed" else 1
    raise SystemExit(f"unknown stealth command: {args.stealth_command}")


def cmd_artifacts(args: argparse.Namespace) -> int:
    config = load_config()
    run_dir = resolve_run(config, args.run)
    payload = artifacts_report(run_dir)
    if args.json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"run: {payload['run_id']}")
        print(f"artifact_policy: {payload['artifact_policy']}")
        print(f"delivery: {payload['delivery']}")
        for item in payload["artifacts"]:
            print(f"- {item['path']} ({item['type']}, {item['size_bytes']} bytes, {item['sensitivity']})")
    return 0


def cmd_relay(args: argparse.Namespace) -> int:
    config = load_config()
    result = relay_response(config, args.tokens)
    payload = result.payload
    if args.json_mode:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    elif "evidence" in payload:
        for line in format_evidence_lines(payload["evidence"]):
            print(line)
    elif payload.get("command") in {"artifacts", "task.artifacts"}:
        artifacts = payload["artifacts"]
        print(f"run: {artifacts['run_id']}")
        print(f"artifact_policy: {artifacts['artifact_policy']}")
        print(f"delivery: {artifacts['delivery']}")
        for item in artifacts["artifacts"]:
            print(f"- {item['path']} ({item['type']}, {item['size_bytes']} bytes, {item['sensitivity']})")
    else:
        emit(payload, json_mode=False)
    return result.exit_code


def cmd_recipe(args: argparse.Namespace) -> int:
    config = load_config()
    if args.recipe_command == "list":
        payload = {"recipes": list_recipes(config)}
        emit(payload, json_mode=args.json_mode)
        return 0
    if args.recipe_command == "show":
        payload = load_recipe(config, args.name)
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"recipe: {payload.get('name')}")
            print(f"recipe_dir: {payload.get('recipe_dir')}")
            print(f"source_run_id: {payload.get('source_run_id')}")
        return 0
    if args.recipe_command == "run":
        params = parse_params(args.param)
        run_id, run_dir = prepare_recipe_run(config, args.name, params=params)
        result = run_final_script(run_dir, config=config)
        payload = result.as_dict()
        payload["run_id"] = run_id
        payload["params"] = params
        if args.verify and result.status == "ran":
            verify_result = verify_run(run_dir, strength="same-rail")
            payload["verification"] = verify_result.as_dict()
            if verify_result.status == "verified":
                payload["status"] = "verified"
            else:
                payload["status"] = "failed"
                payload["failed_gate"] = verify_result.failed_gate
        if args.json_mode:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"run: {payload['run_id']}")
            print(f"status: {payload['status']}")
            print(f"run_dir: {payload['run_dir']}")
            if payload.get("failed_gate"):
                print(f"failed_gate: {payload['failed_gate']}")
        return 0 if payload["status"] in {"ran", "verified"} else 1
    raise SystemExit(f"unknown recipe command: {args.recipe_command}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "task":
            return cmd_task(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "cleanup":
            return cmd_cleanup(args)
        if args.command == "stealth":
            return cmd_stealth(args)
        if args.command == "artifacts":
            return cmd_artifacts(args)
        if args.command == "relay":
            return cmd_relay(args)
        if args.command == "recipe":
            return cmd_recipe(args)
    except ValueError as exc:
        message = str(exc)
        gate = message.split(":", 1)[0] or "value_error"
        if args.json_mode:
            print(json.dumps({"status": "failed", "failed_gate": gate, "message": message}, ensure_ascii=False, indent=2))
            return 1
        raise SystemExit(message) from exc
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
