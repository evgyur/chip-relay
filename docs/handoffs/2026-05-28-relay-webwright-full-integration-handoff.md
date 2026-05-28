# Relay Webwright Full Integration — Architect+ Handoff

> **For Hermes / implementer:** this is a full architect-level handoff for deep integration of the Webwright execution paradigm into `chip-relay` and Chip's production `/relay` stack. Do not treat this as a cosmetic command wrapper. The target is a reproducible browser-task factory: persistent authenticated rails + disposable verified execution + reusable recipes/tools.

**Date:** 2026-05-28  
**Repo inspected:** local `chip-relay` checkout  
**Production skill context:** `chip-browser-relay` (`/relay`)  
**Portable public repo context:** `chip-relay`  
**Primary inspiration:** Microsoft Webwright — terminal-native web agents

---

## 0. Executive thesis

`/relay` must evolve from a **persistent CDP browser rail** into a **browser automation operating layer**.

Current mental model:

```text
/relay = launch browser + expose CDP + open URLs + inspect tabs
```

Target mental model:

```text
/relay = persistent browser identity + reproducible task workspaces + verified browser programs + reusable recipes
```

The key shift from Webwright is not “use Playwright”. The key shift is:

```text
web task → code → artifacts → fresh verified rerun → reusable tool
```

A browser task is not complete when an agent says “done”. It is complete only when there is:

- a final executable script;
- a captured log;
- screenshots / trace / result artifacts where relevant;
- a verification run from a clean or controlled workspace;
- no leaked secrets in artifacts;
- an optional recipe/tool extracted for reuse.

---

## 1. Source facts already verified

### 1.1 Webwright core idea

Webwright describes itself as **terminal-native web agents**:

- model receives terminal + local workspace;
- model emits bash/code, often Playwright-backed scripts;
- browser sessions are disposable;
- code, logs, screenshots, outputs persist in workspace;
- successful task becomes a reusable program;
- final completion is gated by rerun + self-reflection.

Important phrasing from source:

```text
A terminal is all you need for web agents.
The output is not just a completed task, but a reusable program.
```

### 1.2 Current portable repo shape

Inspected files:

```text
chip-relay/
├── README.md
├── SKILL.md
├── scripts/
│   ├── chip-relay
│   ├── chip-relay.sh
│   ├── chip-relay-watchdog.sh
│   └── install-cloakbrowser.sh
├── tests/
│   ├── test_public_hygiene.py
│   └── test_shell_syntax.py
├── templates/
│   └── chip-relay.env.example
└── references/
    └── security.md
```

Current `scripts/chip-relay` supports:

```bash
scripts/chip-relay doctor
scripts/chip-relay status
scripts/chip-relay launch --backend cloakbrowser|browseros|chromium|auto
scripts/chip-relay open URL
scripts/chip-relay tabs
scripts/chip-relay health
scripts/chip-relay kill
```

Current backend model:

- CloakBrowser first;
- BrowserOS fallback;
- Chromium fallback;
- CDP via `http://127.0.0.1:18800` by default;
- persistent profile under `~/.local/share/chip-relay/profiles/default`.

### 1.3 Current `/relay` production context from skill

Production `/relay` (`chip-browser-relay`) has richer live concerns:

- production host/user setup;
- CloakBrowser primary backend;
- BrowserOS secondary fallback/MCP path;
- named profile rails / session rails;
- auth/cookie diagnostics through CDP, not raw SQLite dumps;
- Gmail, OAuth, Meta, Railway, provider screenshot workflows;
- fingerprint governance;
- anti-bot/captcha risk adapter with hard safety gates.

This matters because the full integration must preserve these operational constraints. The portable repo can receive the generic engine; production `/relay` can adopt it with Chip-specific policies.

---

## 2. Non-negotiable architecture decision

Do **not** merge these two concepts:

```text
persistent identity rail ≠ disposable execution workspace
```

They solve different problems.

### Persistent identity rail

Purpose:

- keep authenticated browser profile;
- maintain real SaaS sessions;
- provide stable CDP endpoint;
- carry fingerprint/persona policy;
- support manual Chip intervention when needed.

Examples:

```text
rail: default
profile: ~/.local/share/chip-relay/profiles/default
cdp: http://127.0.0.1:18800
backend: cloakbrowser
```

### Disposable execution workspace

Purpose:

- create isolated task folder;
- generate scripts;
- run browser automation;
- capture evidence;
- verify final script;
- package reusable recipe.

Examples:

```text
runs/2026-05-28T120000Z-stripe-invoices/
├── task.md
├── manifest.json
├── scripts/
│   ├── explore.py
│   └── final.py
├── logs/
├── screenshots/
├── traces/
├── results/
└── verification/
```

### Bridge between them

The bridge is a `RunContext`:

```json
{
  "run_id": "2026-05-28T120000Z-stripe-invoices",
  "rail_id": "default",
  "cdp_url": "http://127.0.0.1:18800",
  "profile_mode": "persistent|clone|clean|ephemeral",
  "backend": "cloakbrowser",
  "artifact_policy": "private-local",
  "risk_policy": "default"
}
```

The task runner may connect to the persistent rail via CDP, clone a profile into a temp dir, or launch a clean browser. It must never pretend these are the same thing.

---

## 3. Target system components

### 3.1 Layer map

```text
chip-relay
├── CLI layer
│   ├── launch/status/open/tabs/health/kill               existing
│   ├── task init/run/verify/pack/list/show/clean         new
│   ├── recipe run/list/show/export/import                new
│   └── doctor artifacts/security/playwright              new
│
├── backend layer
│   ├── CloakBrowser                                      existing
│   ├── BrowserOS                                         existing
│   └── Chromium                                          existing
│
├── rail layer
│   ├── rail config                                       new/grow
│   ├── named rails                                       production already has concepts
│   ├── CDP endpoint discovery                            grow
│   └── auth/fingerprint/risk policy binding              production integration
│
├── task workspace layer                                  new
│   ├── run ID generation
│   ├── manifest lifecycle
│   ├── file layout
│   ├── artifact indexing
│   └── retention/cleanup
│
├── Playwright execution layer                            new
│   ├── connect_over_cdp
│   ├── clean context runner
│   ├── persistent rail runner
│   ├── screenshot/trace/log hooks
│   └── result writer
│
├── verification layer                                    new
│   ├── final.py gate
│   ├── fresh rerun gate
│   ├── artifact presence checks
│   ├── domain-specific assertions
│   ├── self-reflection/evaluator hook
│   └── secret hygiene scan
│
├── recipe/tool layer                                     new
│   ├── recipe.yaml
│   ├── parameter schema
│   ├── entrypoint final.py
│   ├── environment requirements
│   ├── allowed rails/domains
│   └── import/export
│
└── policy/safety layer                                   grow
    ├── no cookie/header logging
    ├── raw DOM limits
    ├── screenshot sensitivity classes
    ├── public packaging scan
    └── authenticated rail restrictions
```

### 3.2 Architectural principle

The shell script should remain a thin operator wrapper. Complex behavior should move into Python modules.

Recommended split:

```text
scripts/chip-relay                 thin Bash CLI / backward compatibility
chip_relay/
├── __init__.py
├── cli.py                         argparse/subcommands
├── config.py                      env + defaults
├── rail.py                        backend/CDP/profile discovery
├── workspace.py                   run folders + manifests
├── playwright_runner.py           CDP + Playwright harness
├── verifier.py                    final-run gates
├── artifacts.py                   logs/screenshots/traces/index
├── recipes.py                     pack/run/import/export
├── hygiene.py                     secret/privacy scans
├── risk.py                        adapter interface, production can override
└── templates/
    ├── final.py.j2
    ├── explore.py.j2
    ├── recipe.yaml.j2
    └── README.task.md.j2
```

Why Python:

- Playwright integration is first-class;
- JSON manifests are easier and safer;
- artifact indexing/hygiene scans are easier;
- shell quoting around URLs/OAuth is already a known failure class;
- tests become straightforward.

The current shell can dispatch:

```bash
python3 -m chip_relay.cli "$@"
```

But do this gradually to avoid breaking existing `launch/open/status` flows.

---

## 4. New CLI contract

### 4.1 Existing commands must remain compatible

Do not break:

```bash
scripts/chip-relay doctor
scripts/chip-relay status
scripts/chip-relay launch --backend auto
scripts/chip-relay open https://example.com
scripts/chip-relay tabs
scripts/chip-relay health
scripts/chip-relay kill
```

### 4.2 New task commands

```bash
scripts/chip-relay task init "download May invoices from Stripe"
```

Creates a run workspace and returns path/ID.

```bash
scripts/chip-relay task run <run-id-or-path>
```

Runs exploration or final task script. In v1 this can run existing `scripts/final.py`; later this can call an agent loop.

```bash
scripts/chip-relay task verify <run-id-or-path>
```

Hard gate:

- `scripts/final.py` exists;
- final run exits 0;
- logs captured;
- required artifacts exist;
- hygiene scan passes;
- manifest status becomes `verified`.

```bash
scripts/chip-relay task pack <run-id-or-path> --name stripe-invoices
```

Creates a reusable recipe from verified run.

```bash
scripts/chip-relay task show <run-id-or-path>
scripts/chip-relay task list
scripts/chip-relay task clean --older-than 14d
```

### 4.3 New recipe commands

```bash
scripts/chip-relay recipe list
scripts/chip-relay recipe show stripe-invoices
scripts/chip-relay recipe run stripe-invoices --param month=2026-05
scripts/chip-relay recipe export stripe-invoices --public-safe ./dist/
scripts/chip-relay recipe import ./dist/stripe-invoices.recipe.tgz
```

### 4.4 New doctor commands

```bash
scripts/chip-relay doctor playwright
scripts/chip-relay doctor artifacts
scripts/chip-relay doctor security
scripts/chip-relay doctor webwright
```

`doctor webwright` should prove:

- Python available;
- Playwright import available;
- browser CDP reachable or launchable;
- workspace dir writable;
- hygiene scanner available;
- secret deny patterns active;
- optional trace support available.

---

## 5. Workspace contract

### 5.1 Default paths

Portable repo public-safe default:

```text
${CHIP_RELAY_BASE_DIR:-~/.local/share/chip-relay}/runs/
${CHIP_RELAY_BASE_DIR:-~/.local/share/chip-relay}/recipes/
```

Never default to repo-local `runs/` for production/auth tasks. Repo-local examples are okay only for tests/fixtures.

### 5.2 Run folder layout

```text
runs/<run_id>/
├── task.md
├── manifest.json
├── README.md
├── scripts/
│   ├── explore.py
│   ├── final.py
│   └── lib/
├── logs/
│   ├── explore.log
│   ├── final.log
│   ├── verify.log
│   └── cdp-events.ndjson              optional, redacted only
├── screenshots/
│   ├── 001-start.png
│   ├── 002-critical-state.png
│   └── 999-final.png
├── traces/
│   └── final-trace.zip                optional, private-local by default
├── results/
│   ├── result.json
│   ├── result.md
│   └── downloads/
├── verification/
│   ├── verify-result.json
│   ├── self-reflection.json           optional
│   └── hygiene-report.json
└── recipe/
    └── recipe.yaml                    generated after pack
```

### 5.3 Manifest schema v1

Create `templates/run-manifest.schema.json` and enforce in tests.

Minimal manifest:

```json
{
  "schema": "chip-relay-run-manifest-v1",
  "run_id": "2026-05-28T120000Z-stripe-invoices",
  "created_at": "2026-05-28T12:00:00Z",
  "updated_at": "2026-05-28T12:10:00Z",
  "task": {
    "title": "download May invoices from Stripe",
    "source": "cli",
    "sensitivity": "private-authenticated"
  },
  "rail": {
    "rail_id": "default",
    "backend": "cloakbrowser",
    "cdp_url": "http://127.0.0.1:18800",
    "profile_mode": "persistent"
  },
  "workspace": {
    "path": "/home/user/.local/share/chip-relay/runs/...",
    "artifact_policy": "private-local",
    "retention_days": 14
  },
  "status": "initialized|exploring|final-ready|verified|failed|packed",
  "artifacts": [],
  "verification": {
    "required": ["final_script", "final_log", "hygiene_scan"],
    "last_result": null
  }
}
```

### 5.4 Artifact index item

```json
{
  "type": "screenshot|log|trace|result|download",
  "path": "screenshots/999-final.png",
  "created_at": "2026-05-28T12:02:00Z",
  "sha256": "...",
  "sensitivity": "private|public-safe|secret-risk",
  "description": "Final confirmation screen"
}
```

---

## 6. Playwright runner design

### 6.1 Runner modes

#### Mode A — persistent CDP mode

Used when task requires logged-in profile.

```python
browser = p.chromium.connect_over_cdp(cdp_url)
context = browser.contexts[0]
page = context.new_page()
```

Pros:

- real auth state;
- minimal friction;
- matches `/relay` value.

Cons:

- not fully clean;
- sensitive screenshots/logs likely;
- task may mutate profile state;
- verification can be less deterministic.

Use for:

- Gmail access checks;
- SaaS dashboards;
- OAuth flows with Chip intervention;
- internal authenticated tasks.

#### Mode B — clean local browser mode

Used for public/reproducible tasks.

```python
browser = p.chromium.launch(headless=False)
context = browser.new_context()
```

Pros:

- deterministic;
- no auth leakage;
- ideal for public recipes.

Cons:

- no logged-in sessions.

Use for:

- public scraping;
- QA checks;
- docs extraction;
- non-auth website automation.

#### Mode C — profile clone mode

Used for “auth-seeded but disposable” tasks.

Concept:

- clone/copy profile into temp run profile;
- launch browser on run-specific port;
- execute task;
- destroy temp profile after retention window.

This is desirable but risky. Implement after V1.

Hard warning:

- browser profile copy while Chrome is running can corrupt or produce inconsistent data;
- must use lock detection and safe copy strategy;
- never package cloned profile.

#### Mode D — BrowserOS/MCP route

Used for BrowserOS-specific capabilities, not default V1.

Keep as adapter:

```text
runner = playwright_cdp | browseros_mcp | hybrid
```

Do not let BrowserOS-specific logic infect core task workspace design.

### 6.2 `final.py` skeleton

Generated `scripts/final.py` should be self-contained and runnable without the agent.

Template contract:

```python
#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import sys
import time
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

RUN_DIR = pathlib.Path(__file__).resolve().parents[1]
LOG_DIR = RUN_DIR / "logs"
SCREENSHOT_DIR = RUN_DIR / "screenshots"
RESULT_DIR = RUN_DIR / "results"

LOG_DIR.mkdir(exist_ok=True)
SCREENSHOT_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(exist_ok=True)

CDP_URL = os.environ.get("CHIP_RELAY_CDP_URL", "http://127.0.0.1:18800")


def log(message: str) -> None:
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {message}"
    print(line, flush=True)
    with open(LOG_DIR / "final.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.connect_over_cdp(CDP_URL)
        context = browser.contexts[0] if browser.contexts else browser.new_context()
        page = context.new_page()

        log("opened page")
        page.goto("https://example.com", wait_until="domcontentloaded", timeout=30000)
        page.screenshot(path=str(SCREENSHOT_DIR / "999-final.png"), full_page=True)

        result = {"title": page.title(), "url": page.url}
        (RESULT_DIR / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        log("wrote result.json")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

### 6.3 Log capture

`task verify` should execute:

```bash
python3 scripts/final.py > logs/verify.log 2>&1
```

Then copy/merge relevant log into `verification/verify-result.json`.

### 6.4 Trace capture

Playwright trace can be optional because traces may contain sensitive data.

Default:

```text
trace: disabled for private-authenticated tasks
trace: enabled only for public/clean tasks or explicit --trace
```

---

## 7. Verification layer

### 7.1 Completion gate

A task cannot be `verified` unless all required gates pass.

Gate list v1:

1. `scripts/final.py` exists.
2. `python3 -m py_compile scripts/final.py` passes.
3. `python3 scripts/final.py` exits 0 under `task verify`.
4. `logs/final.log` or `logs/verify.log` exists and is non-empty.
5. At least one final evidence artifact exists unless task type is explicitly `no_artifact`.
6. `verification/hygiene-report.json` exists and has `status=ok`.
7. Manifest status is updated atomically.

### 7.2 Domain-specific assertions

Recipes should define assertions:

```yaml
assertions:
  - type: file_exists
    path: results/result.json
  - type: json_path_exists
    path: results/result.json
    json_path: $.items[0].title
  - type: screenshot_exists
    path: screenshots/999-final.png
  - type: url_matches
    pattern: '^https://app\.example\.com/'
```

Avoid only relying on exit code. Exit code alone is not proof.

### 7.3 Self-reflection hook

Webwright uses self-reflection. In `/relay`, make it pluggable.

V1:

- deterministic checks only;
- optional `--self-reflect` writes JSON from LLM evaluator if available.

V2:

- evaluator prompt receives task, final log, artifact index, redacted screenshot descriptions if available;
- evaluator returns:

```json
{
  "status": "success|failure|uncertain",
  "critical_points": [],
  "evidence": [],
  "risks": [],
  "recommendation": "..."
}
```

Hard rule: self-reflection can fail a task, but cannot override missing deterministic gates.

### 7.4 Fresh rerun semantics

There are three verification strengths:

```text
level 1: same rail rerun
level 2: fresh browser context rerun
level 3: clean machine/CI rerun
```

Do not overclaim. For authenticated SaaS tasks, `level 1` may be the only realistic default.

Manifest should record:

```json
"verification_strength": "same-rail|fresh-context|clean-ci"
```

---

## 8. Recipe/tool extraction

### 8.1 Recipe purpose

A recipe turns a successful task into a reusable browser tool.

Example:

```bash
scripts/chip-relay recipe run stripe-invoices --param month=2026-05
```

### 8.2 Recipe layout

```text
recipes/<recipe_name>/
├── recipe.yaml
├── final.py
├── README.md
├── tests/
│   └── test_recipe_contract.py
└── fixtures/
```

### 8.3 `recipe.yaml` schema v1

```yaml
schema: chip-relay-recipe-v1
name: stripe-invoices
version: 0.1.0
description: Download Stripe invoices for a month from an authenticated browser rail.
created_from_run: 2026-05-28T120000Z-stripe-invoices
entrypoint: final.py

sensitivity: private-authenticated
allowed_modes:
  - persistent-cdp
allowed_rails:
  - default
allowed_domains:
  - dashboard.stripe.com

params:
  month:
    type: string
    required: true
    pattern: '^\\d{4}-\\d{2}$'

artifacts:
  required:
    - logs/final.log
    - results/result.json

assertions:
  - type: json_path_exists
    path: results/result.json
    json_path: $.invoices

security:
  allow_screenshots: true
  allow_trace: false
  forbid_cookie_logging: true
  forbid_auth_header_logging: true
  public_export: false
```

### 8.4 Public export

Public export must be opt-in and must strip:

- screenshots;
- traces;
- logs by default;
- downloads;
- profile data;
- `.env`;
- tokens;
- private hostnames/IPs;
- local absolute paths;
- cookies/localStorage/sessionStorage;
- raw DOM from authenticated pages.

Command:

```bash
scripts/chip-relay recipe export stripe-invoices --public-safe ./dist/
```

If recipe is `private-authenticated`, public export should fail unless a `--code-only` mode is used and hygiene passes.

---

## 9. Safety and privacy model

### 9.1 Artifact sensitivity classes

```text
public-safe
private-local
private-authenticated
secret-risk
blocked
```

Default for authenticated rail runs:

```text
private-authenticated
```

Default for clean public runs:

```text
private-local, can become public-safe after scan
```

### 9.2 Never collect classes

Do not collect and “redact later”:

- cookies;
- auth headers;
- OAuth codes/tokens;
- localStorage/sessionStorage dumps;
- raw HTML/DOM from authenticated apps unless explicit local-only debug mode;
- screenshots of password/token/payment/PII screens;
- browser profile folders.

### 9.3 Hygiene scan

Extend current `tests/test_public_hygiene.py` idea into runtime `chip_relay/hygiene.py`.

Scan artifacts for:

- known token patterns (`sk-`, `ghp_`, `gsk_`, `pplx-`, etc.);
- private absolute paths (`<browser-owner-home>`, `<agent-home>`, `<production-skill-runtime>`) in public packages;
- private IPs/hostnames outside allowlist;
- cookie-looking strings (`SID=`, `auth_token`, `ct0`, `sessionid`);
- Authorization headers;
- OAuth callback codes.

Output:

```json
{
  "status": "ok|failed",
  "scanned_files": 12,
  "findings": [
    {
      "severity": "high",
      "path": "logs/final.log",
      "pattern": "authorization header",
      "action": "block"
    }
  ]
}
```

### 9.4 Auth rail restrictions

Authenticated/persistent rails should default to:

- no public export;
- no external captcha brokers;
- no proxy switching;
- no fingerprint randomization per task;
- no raw DOM archive;
- screenshots allowed only if not password/token/payment/PII screens;
- task artifacts local-only by default.

This aligns with existing `/relay` risk adapter governance.

---

## 10. Integration with production `/relay`

### 10.1 Portable repo vs production skill

There are two surfaces:

1. `chip-relay` public portable repo — generic engine, no private paths/secrets.
2. `chip-browser-relay` production skill — Chip-specific deployment, production paths, watchdogs, named rails, risk policies.

Implementation should land generic parts in public repo first:

- workspace manager;
- Playwright runner;
- manifest/recipe schema;
- verification gate;
- hygiene scanner;
- CLI commands.

Production skill then adds:

- named rail mapping;
- HEL1 user execution wrappers;
- policy defaults;
- sync to `<production-skill-runtime>/...`;
- integration with existing `/relay` Telegram command adapter.

### 10.2 Production command adapter shape

Telegram `/relay` should expose high-level commands, not all internals.

Examples:

```text
/relay task init скачать инвойсы за май
/relay task verify <run_id>
/relay recipe list
/relay recipe run stripe-invoices month=2026-05
/relay task artifacts <run_id>
```

Operator response should show compact evidence:

```text
run: 2026-05-28T120000Z-stripe-invoices
status: verified
rail: default / cloakbrowser / 127.0.0.1:18800
final: scripts/final.py exited 0
artifacts: result.json, final.log, 3 screenshots
hygiene: ok
recipe: stripe-invoices v0.1.0
```

Never print secrets, cookies, raw tokens, or sensitive artifact content in chat.

### 10.3 production deployment concerns

From production skill:

- Hermes may run as `hermes`, browser profile owned by `chip`;
- use stdin execution pattern when needed:

```bash
sudo -n -u chip bash -s -- --json status < <editable-skill-source>/relay.sh
```

For task runner, avoid writing run artifacts under `<agent-home>` if the browser process runs as `chip` and needs access. Use chip-owned runtime home for production:

```text
~/.local/share/chip-relay/runs/
~/.local/share/chip-relay/recipes/
```

If Hermes needs to inspect summaries, expose redacted metadata through CLI JSON, not direct private file dumping.

---

## 11. Implementation phases

## Phase 0 — Design hardening and contracts

**Goal:** freeze the architecture contracts before code churn.

### Task 0.1: Add architecture docs

Files:

- Create: `docs/architecture/webwright-mode.md`
- Create: `docs/architecture/task-workspaces.md`
- Create: `docs/architecture/recipes.md`
- Create: `docs/architecture/artifact-security.md`

Content requirements:

- persistent rail vs disposable workspace distinction;
- run folder layout;
- manifest schema summary;
- verification gates;
- recipe lifecycle;
- safety defaults.

Verification:

```bash
python3 tests/test_public_hygiene.py
```

### Task 0.2: Add schemas

Files:

- Create: `templates/run-manifest.schema.json`
- Create: `templates/recipe.schema.json`
- Create: `templates/hygiene-report.schema.json`

Verification:

```bash
python3 -m json.tool templates/run-manifest.schema.json >/dev/null
python3 -m json.tool templates/recipe.schema.json >/dev/null
python3 -m json.tool templates/hygiene-report.schema.json >/dev/null
```

### Task 0.3: Add `.gitignore` runtime dirs

Modify `.gitignore`:

```gitignore
runs/
recipes/*/artifacts/
*.trace.zip
playwright-report/
test-results/
```

But do not ignore recipe source files globally. Recipes may be committed if public-safe.

---

## Phase 1 — Python package scaffold

**Goal:** add Python modules without breaking shell commands.

### Task 1.1: Create package skeleton

Files:

```text
chip_relay/__init__.py
chip_relay/config.py
chip_relay/workspace.py
chip_relay/hygiene.py
chip_relay/cli.py
```

`config.py` should resolve:

```python
base_dir = CHIP_RELAY_BASE_DIR or ~/.local/share/chip-relay
runs_dir = CHIP_RELAY_RUNS_DIR or base_dir/runs
recipes_dir = CHIP_RELAY_RECIPES_DIR or base_dir/recipes
host = CHIP_RELAY_HOST or 127.0.0.1
port = CHIP_RELAY_PORT or 18800
cdp_url = CHIP_RELAY_CDP_URL or http://host:port
```

### Task 1.2: Add tests for config

Files:

- Create: `tests/test_config.py`

Test:

- default base dir uses home;
- env override works;
- CDP URL derived correctly.

Command:

```bash
python3 -m pytest tests/test_config.py -v
```

If pytest is unavailable, add a tiny unittest-compatible test or CI dependency.

### Task 1.3: Keep shell commands stable

Do **not** replace `scripts/chip-relay` wholesale yet.

Add a hidden command first:

```bash
scripts/chip-relay webwright --help
```

or:

```bash
scripts/chip-relay task --help
```

Dispatch to Python only for new commands.

---

## Phase 2 — Workspace lifecycle

**Goal:** `task init/list/show` works and writes manifests atomically.

### Task 2.1: Implement run ID generation

File:

- Modify: `chip_relay/workspace.py`

Contract:

```python
def make_run_id(title: str, now: datetime | None = None) -> str:
    ...
```

Example:

```text
2026-05-28T120000Z-download-may-invoices
```

Slug rules:

- lowercase;
- ASCII transliteration or safe fallback;
- max 60 chars;
- no secrets from task text; if title is too sensitive, allow `--name`.

### Task 2.2: Implement `task init`

Command:

```bash
scripts/chip-relay task init "open example and capture title"
```

Creates:

```text
runs/<run_id>/task.md
runs/<run_id>/manifest.json
runs/<run_id>/scripts/final.py
runs/<run_id>/logs/.gitkeep
runs/<run_id>/screenshots/.gitkeep
runs/<run_id>/results/.gitkeep
runs/<run_id>/verification/.gitkeep
```

Initial `final.py` should be a runnable template that opens example.com or exits with clear TODO depending on mode.

### Task 2.3: Implement `task list` and `task show`

Commands:

```bash
scripts/chip-relay task list
scripts/chip-relay task show <run_id>
scripts/chip-relay --json task show <run_id>
```

JSON output should not include file contents by default.

---

## Phase 3 — Playwright runner

**Goal:** generated final scripts can connect to existing relay CDP and produce artifacts.

### Task 3.1: Add Playwright dependency handling

Do not force global install silently.

`doctor playwright` should report:

- Python version;
- whether `playwright` import works;
- whether browser install is needed for clean mode;
- whether CDP endpoint is reachable.

Command:

```bash
scripts/chip-relay doctor playwright
```

### Task 3.2: Add CDP utility

File:

- Create: `chip_relay/playwright_runner.py`

Functions:

```python
def cdp_version(cdp_url: str) -> dict: ...
def ensure_cdp(cdp_url: str) -> None: ...
def run_final_script(run_dir: Path, env: dict[str, str]) -> RunResult: ...
```

### Task 3.3: Generate better `final.py`

Template should:

- read `CHIP_RELAY_CDP_URL`;
- create logs/screenshots/results dirs;
- write `logs/final.log`;
- screenshot final state;
- write `results/result.json`;
- return non-zero on assertion failure.

### Task 3.4: Add live smoke fixture

Command:

```bash
scripts/chip-relay launch --backend auto
scripts/chip-relay task init "example title smoke" --template example-title
scripts/chip-relay task verify <run_id>
```

Expected:

- `verified` status;
- `results/result.json` contains title/domain;
- screenshot exists;
- hygiene passes.

---

## Phase 4 — Verification gates

**Goal:** `task verify` becomes the definition of done.

### Task 4.1: Implement verifier

File:

- Create: `chip_relay/verifier.py`

Inputs:

```python
verify_run(run_dir: Path, cdp_url: str, level: str = "same-rail") -> VerificationResult
```

Outputs:

```text
verification/verify-result.json
verification/hygiene-report.json
logs/verify.log
```

### Task 4.2: Deterministic gate checks

Implement checks:

- final script exists;
- py_compile passes;
- execution exits 0;
- required logs exist;
- required artifacts exist;
- manifest status update;
- hygiene status ok.

### Task 4.3: Failure reporting

On failure, output should include:

```json
{
  "status": "failed",
  "failed_gate": "final_script_exit",
  "exit_code": 1,
  "log_tail": "last safe 40 lines, redacted"
}
```

Do not dump full logs into Telegram.

---

## Phase 5 — Hygiene scanner

**Goal:** no artifact can be marked verified/packed if it leaks obvious secrets.

### Task 5.1: Port public hygiene scanner to runtime

Current `tests/test_public_hygiene.py` has useful deny patterns. Move shared logic into:

```text
chip_relay/hygiene.py
```

Tests import same scanner.

### Task 5.2: Add artifact scan command

```bash
scripts/chip-relay task scan <run_id>
```

or folded into:

```bash
scripts/chip-relay task verify <run_id>
```

### Task 5.3: Redaction helper

For log tails, implement `redact_text(text)`:

- replace token-like strings;
- replace cookie assignments;
- replace Authorization headers;
- replace OAuth code/state when obvious;
- cap output length.

Hard rule: redaction is for reporting, not a permission to collect forbidden data.

---

## Phase 6 — Recipe extraction

**Goal:** `task pack` creates reusable recipes from verified runs.

### Task 6.1: Implement recipe schema and packer

Files:

```text
chip_relay/recipes.py
templates/recipe.yaml.j2
```

Command:

```bash
scripts/chip-relay task pack <run_id> --name example-title
```

Copies:

```text
runs/<run_id>/scripts/final.py → recipes/example-title/final.py
runs/<run_id>/recipe/recipe.yaml → recipes/example-title/recipe.yaml
```

Do not copy screenshots/logs/results by default.

### Task 6.2: Implement `recipe run`

Command:

```bash
scripts/chip-relay recipe run example-title
```

Creates a fresh run based on recipe and executes final.py there.

### Task 6.3: Parameter support

CLI:

```bash
scripts/chip-relay recipe run stripe-invoices --param month=2026-05 --param account=main
```

Expose params as env:

```text
CHIP_RELAY_PARAM_MONTH=2026-05
CHIP_RELAY_PARAM_ACCOUNT=main
```

And as JSON file:

```text
params.json
```

### Task 6.4: Recipe tests

Each recipe can declare a dry-run/public fixture. V1 can validate schema only.

---

## Phase 7 — Agent loop integration

**Goal:** add true Webwright-style loop where an agent writes/refines scripts inside workspace.

This phase may live outside public `chip-relay` if it depends on Hermes internals.

### 7.1 Minimal agent contract

Agent receives:

- task text;
- run manifest;
- allowed commands;
- CDP URL;
- artifact contract;
- current workspace tree;
- recent log tail.

Agent may write:

- `scripts/explore.py`;
- `scripts/final.py`;
- `results/*`;
- `notes.md`.

Agent may run:

```bash
python3 scripts/explore.py
python3 scripts/final.py
scripts/chip-relay task verify <run_id>
```

Agent must not:

- dump cookies/storage;
- print auth headers;
- exfiltrate artifacts;
- mutate fingerprint/proxy/captcha settings unless explicit policy allows.

### 7.2 Loop states

```text
initialized
↓
exploring
↓
final-draft
↓
verifying
↓
verified | failed-needs-repair | blocked-needs-human
↓
packed optional
```

### 7.3 Human intervention state

Some browser tasks need Chip to pass SMS/2FA/captcha. Represent this explicitly:

```json
{
  "status": "blocked-needs-human",
  "reason": "2fa_required",
  "safe_instruction": "Open relay viewer and complete the SMS prompt. Do not send code to agent."
}
```

After Chip intervenes:

```bash
scripts/chip-relay task resume <run_id>
```

---

## Phase 8 — Production `/relay` adapter

**Goal:** expose the workflow through Chip's `/relay` command without leaking internals.

### 8.1 Command mapping

Telegram/operator commands:

```text
/relay task <natural language>
```

Equivalent to:

```bash
relay task init ...
# agent loop optional
relay task verify ...
```

Additional commands:

```text
/relay runs
/relay run <id>
/relay verify <id>
/relay recipes
/relay recipe <name> key=value
/relay artifacts <id>
```

### 8.2 Response shape

Use compact evidence, never full sensitive logs.

```text
➊ run
┈ id: 2026-05-28T120000Z-example-title
┈ rail: default / cloakbrowser
┈ cdp: local only

➋ verification
┈ final.py: pass
┈ log: logs/verify.log
┈ artifacts: result.json, 1 screenshot
┈ hygiene: ok

➌ recipe
┈ packed: example-title v0.1.0
```

### 8.3 Artifact delivery policy

Default:

- do not send screenshots/log files automatically from authenticated runs;
- send only summary and local paths;
- allow explicit `artifact send` after policy check.

---

## 12. Testing strategy

### 12.1 Unit tests

Add:

```text
tests/test_config.py
tests/test_workspace.py
tests/test_manifest_schema.py
tests/test_hygiene.py
tests/test_recipes.py
tests/test_verifier.py
```

### 12.2 Integration tests

Public clean tests:

```bash
scripts/chip-relay task init "example title smoke" --template example-title
scripts/chip-relay task verify <run_id> --mode clean
```

CDP tests:

```bash
scripts/chip-relay launch --backend auto
scripts/chip-relay task init "example title smoke" --template example-title
scripts/chip-relay task verify <run_id> --mode persistent-cdp
```

### 12.3 Existing tests must stay green

```bash
bash -n scripts/chip-relay scripts/chip-relay.sh scripts/install-cloakbrowser.sh scripts/chip-relay-watchdog.sh
python3 tests/test_public_hygiene.py
python3 tests/test_shell_syntax.py
```

### 12.4 CI additions

`.github/workflows/ci.yml` should run:

```bash
python3 -m py_compile chip_relay/*.py
python3 -m pytest -q
python3 tests/test_public_hygiene.py
python3 tests/test_shell_syntax.py
```

If Playwright is too heavy for CI, mark live tests optional:

```bash
CHIP_RELAY_LIVE_TESTS=1 python3 -m pytest tests/test_live_playwright.py
```

---

## 13. Migration and backward compatibility

### 13.1 No breaking changes in V1

Existing users should be unaffected.

- `scripts/chip-relay launch` behavior unchanged.
- `scripts/chip-relay open` behavior unchanged except bugfixes.
- `CHIP_RELAY_*` env vars preserved.
- state/profile/log paths preserved.

### 13.2 Gradual CLI migration

Step 1:

- shell owns old commands;
- Python owns new `task/recipe/doctor webwright` commands.

Step 2:

- Python reimplements status/doctor/open behind same output contract.

Step 3:

- shell becomes wrapper.

### 13.3 Production sync

After public repo implementation:

- sync relevant scripts/modules into `chip-browser-relay` editable source;
- update production references;
- deploy to HEL1 under chip-owned runtime path;
- run smoke as `chip` user;
- verify `/relay status`, `/relay task init`, `/relay task verify`.

---

## 14. Risks and mitigations

### Risk 1: Leaking authenticated data into artifacts

Mitigation:

- authenticated runs default `private-authenticated`;
- no automatic artifact sending;
- hygiene scan blocks verification/pack;
- forbidden collection classes documented and enforced.

### Risk 2: Breaking persistent auth profile

Mitigation:

- persistent CDP mode never copies/deletes profile;
- profile clone mode delayed to later phase;
- task runner opens new page/context carefully;
- destructive tasks require explicit confirmation/policy.

### Risk 3: “Verified” overclaiming

Mitigation:

- record verification strength;
- same-rail vs fresh-context vs clean-ci explicitly labeled;
- deterministic gates required;
- self-reflection cannot override missing evidence.

### Risk 4: Shell quoting/OAuth URL breakage

Mitigation:

- move URL handling into Python;
- add regression test for nested query strings:

```text
https://example.com/path?a=1&b=2&c=http%3A%2F%2F127.0.0.1%3A1%2Fcb
```

### Risk 5: Tool extraction creates brittle scripts

Mitigation:

- recipe schema includes allowed domains, params, assertions;
- recipe run creates fresh workspace;
- assertions catch silent UI drift;
- recipes can be versioned.

### Risk 6: BrowserOS and CloakBrowser concerns get tangled

Mitigation:

- backend/rail layer stays separate from task runner;
- runner talks to CDP first;
- BrowserOS/MCP becomes optional adapter, not core assumption.

---

## 15. Acceptance criteria for “full integration”

### MVP acceptance

- [ ] `task init` creates a structured run workspace.
- [ ] generated `final.py` connects to existing CDP and writes log/screenshot/result.
- [ ] `task verify` runs `final.py`, captures logs, checks artifacts, runs hygiene scan, updates manifest.
- [ ] `task pack` creates a recipe from verified run.
- [ ] `recipe run` creates a new run and executes recipe.
- [ ] existing commands still work.
- [ ] public hygiene tests pass.
- [ ] docs explain persistent rail vs disposable workspace.

### Production acceptance

- [ ] works under browser-owner runtime home in production.
- [ ] can run against CloakBrowser rail `127.0.0.1:18800`.
- [ ] does not expose raw CDP publicly.
- [ ] authenticated runs are local/private by default.
- [ ] Telegram `/relay` adapter returns compact evidence only.
- [ ] human intervention state is represented safely.
- [ ] risk/fingerprint policies are not bypassed.

### Architect+ acceptance

- [ ] browser task completion is evidence-based, not agent-claim-based.
- [ ] every successful non-trivial task can become a reusable recipe.
- [ ] verification strength is explicit.
- [ ] artifacts are indexed and policy-scanned.
- [ ] persistent auth and disposable execution are cleanly separated.
- [ ] public portable repo remains free of private paths/secrets.

---

## 16. Recommended first PR

Do not start with the agent loop. Start with the substrate.

**PR title:** `feat: add webwright-style task workspaces and verification gate`

Scope:

- Python package scaffold;
- run manifest schema;
- `task init/list/show`;
- example `final.py` template;
- `task verify` deterministic gate;
- hygiene scanner integration;
- docs.

Out of scope for first PR:

- profile clone mode;
- BrowserOS MCP adapter;
- full autonomous agent loop;
- captcha/proxy/fingerprint changes;
- public recipe marketplace.

Why: once `task verify` exists, every future browser agent improvement has a real definition of done.

---

## 17. Concrete first implementation checklist

Run from repo:

```bash
cd chip-relay
```

1. Create docs:

```bash
mkdir -p docs/architecture docs/handoffs
```

2. Add schemas:

```bash
mkdir -p templates
```

3. Add Python package:

```bash
mkdir -p chip_relay
```

4. Add tests:

```bash
mkdir -p tests
```

5. Implement in this order:

```text
config.py
workspace.py
hygiene.py
verifier.py
recipes.py
cli.py
scripts/chip-relay dispatch for task/recipe new commands
```

6. Test after each slice:

```bash
python3 -m py_compile chip_relay/*.py
python3 tests/test_public_hygiene.py
python3 tests/test_shell_syntax.py
```

7. Live smoke:

```bash
scripts/chip-relay launch --backend auto
scripts/chip-relay task init "example title smoke" --template example-title
scripts/chip-relay task verify <run_id>
scripts/chip-relay task pack <run_id> --name example-title
scripts/chip-relay recipe run example-title
```

8. Commit:

```bash
git add .
git commit -m "feat: add webwright-style task verification substrate"
```

---

## 18. Final product definition

The final `/relay` product is not:

```text
a browser the agent can click
```

The final `/relay` product is:

```text
a controlled browser execution system that turns web work into verified, reusable, policy-safe programs
```

Short formula:

```text
persistent identity + disposable workspaces + verified final scripts + recipe extraction
```

That is the full integration target.
