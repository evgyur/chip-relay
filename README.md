# chip-relay

Public-safe browser relay skill for agent automation.

`chip-relay` launches a persistent local CDP browser and lets you switch between:

- **CloakBrowser** — stealth patched Chromium for automation-heavy pages.
- **BrowserOS** — Chromium-compatible browser path for GUI/MCP-style workflows.

It is designed to be copied into a Hermes skill directory or used standalone from a cloned repo.

## What this repo does not contain

- no cookies
- no API keys
- no private IPs or hostnames
- no hardcoded user accounts
- no browser profile data
- no downloaded browser binaries

## Install CloakBrowser path

```bash
scripts/install-cloakbrowser.sh
```

This creates:

```text
~/.local/share/chip-relay/cloakbrowser-venv/
~/.local/bin/cloakbrowser-chrome
```

The wrapper injects CloakBrowser fingerprint flags before normal Chromium/CDP flags.

## Install BrowserOS path

Install BrowserOS using the official project instructions, then ensure `browseros` is on `PATH`.

Linux `.deb` example:

```bash
curl -fsSL "https://cdn.browseros.com/download/BrowserOS.deb" -o /tmp/browseros.deb
sudo dpkg -i /tmp/browseros.deb
sudo apt-get install -f -y
```

## Configuration

Copy the template if you want stable local settings:

```bash
cp templates/chip-relay.env.example .env
```

Then edit `.env`. The script auto-loads `.env` from the repo root when present.

Key variables:

```text
CHIP_RELAY_BACKEND=auto|cloakbrowser|browseros|chromium
CHIP_RELAY_PORT=18800
CHIP_RELAY_HOST=127.0.0.1
CHIP_RELAY_PROFILE_DIR=~/.local/share/chip-relay/profiles/default
CHIP_RELAY_DISPLAY=:1002
CHIP_RELAY_HEADLESS=0|1
CLOAKBROWSER_FINGERPRINT_PLATFORM=windows|macos
```

## Commands

```bash
scripts/chip-relay doctor
scripts/chip-relay status
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay launch --backend browseros
scripts/chip-relay open https://example.com
scripts/chip-relay tabs
scripts/chip-relay health
scripts/chip-relay kill
```

## Webwright-style task factory

`chip-relay` creates durable browser task workspaces and now has the first reproducible loop:

```text
task workspace -> Hermes context -> final.py -> verify feedback loop -> packed recipe
```

New task workspaces include an AI-readable brief in both `task.md` and `manifest.json` under
`task.brief_schema=chip-relay-agent-brief-v2`. The brief gives agents explicit `agent_instructions`,
`success_metrics`, `known_frictions`, and `verification_questions` before they edit `scripts/final.py`.

```bash
scripts/chip-relay task init "example title smoke"
scripts/chip-relay task init "example title smoke" --template example-title
scripts/chip-relay task run <run_id>
scripts/chip-relay task context <run_id>
scripts/chip-relay task context <run_id> --write
scripts/chip-relay task loop <run_id> --agent-command "python3 /path/to/agent.py" --max-attempts 3
scripts/chip-relay task loop <run_id> --agent-command scripts/chip-relay-agent-example --max-attempts 1
scripts/chip-relay task verify <run_id>
scripts/chip-relay task pack <run_id> --name example-title
scripts/chip-relay task list
scripts/chip-relay task show <run_id>
scripts/chip-relay task artifacts <run_id>
scripts/chip-relay task network <run_id> add --json-file request.json
scripts/chip-relay task network <run_id> search --url api --method GET
scripts/chip-relay task network <run_id> export
scripts/chip-relay task init-script <run_id> add webdriver --file init/webdriver.js
scripts/chip-relay task init-script <run_id> list
scripts/chip-relay cleanup
scripts/chip-relay cleanup --execute
scripts/chip-relay stealth doctor --preset cf-sensitive
scripts/chip-relay artifacts <run_id>
scripts/chip-relay relay /relay task init "example title smoke"

scripts/chip-relay recipe list
scripts/chip-relay recipe show example-title
scripts/chip-relay recipe run example-title --param month=2026-05

scripts/chip-relay --json doctor webwright
```

Default runtime paths:

```text
~/.local/share/chip-relay/runs/<run_id>/
├── task.md
├── manifest.json
├── scripts/final.py
├── logs/
├── screenshots/
├── traces/
├── results/
├── agent/
└── verification/
```

`task run` executes `scripts/final.py` once, captures `logs/run.log`, injects `CHIP_RELAY_CDP_URL`, and marks the manifest `ran` or `failed`.

`task context` is the Hermes-native workflow primitive. It returns `chip-relay-hermes-workflow-context-v1`: task, `task_brief`, rail, editable files, verify/show/artifacts commands, current verification state, evidence summary, and metadata-only artifact paths. This is the preferred integration when Hermes itself is the agent: Hermes reads the brief, edits `scripts/final.py`, runs `task verify`, reads structured feedback/evidence, and never sends artifact contents to chat by default. `--write` stores the same context at `agent/hermes-context.json` for repeatable handoff.

`task loop` is the public-safe external-agent bridge. It writes `agent/request-NNN.json`, runs the external `--agent-command` with `CHIP_RELAY_AGENT_CONTEXT`, then calls `task verify`. If verification fails, the next request includes the redacted previous failure under `previous_result`. Loop artifacts stay inside `agent/`: request JSON, feedback JSON, redacted command logs, and `loop-result.json`.

`scripts/chip-relay-agent-example` is a bundled deterministic external-agent example. It reads `CHIP_RELAY_AGENT_CONTEXT`, writes a public-safe `scripts/final.py`, and lets `task loop` complete without any LLM provider. Replace it with a private command such as a Hermes/OpenClaw wrapper when deploying real autonomous generation.

Agent command contract:

```text
input:  CHIP_RELAY_AGENT_CONTEXT=/path/to/agent/request-001.json
output: write or update runs/<id>/scripts/final.py plus any private-local artifacts
rule:   do not dump cookies, auth headers, browser profiles, or raw tokens
```

`task verify` is the completion gate. It compiles and runs `scripts/final.py`, captures a redacted `logs/verify.log`, requires fresh final logs/results or screenshots from the current verify attempt, writes `verification/verify-result.json`, runs a hygiene scan into `verification/hygiene-report.json`, and updates `manifest.json` to `verified` or `failed`. It currently implements `same-rail`; unimplemented strengths fail closed instead of pretending isolation.

Network observations are stored under `network/` inside the run. `task network add/search/export` is metadata-first: URLs have token-like query values redacted, sensitive headers such as `Authorization`, `Cookie`, and `Set-Cookie` are replaced with `[REDACTED]`, and request/response bodies are represented only as presence/byte metadata. The exported JSON is a private-local artifact and is never printed as raw captured content by default.

Init scripts live under `init_scripts/` inside the run. `task init-script add/list` reports only name, size, and SHA-256. The `example-title` Playwright/CDP template loads these scripts with `context.add_init_script(...)` before navigation, which is the right place for webdriver/language/timezone/WebGL consistency patches.

`doctor webwright` also reports browser executable/root/container/sandbox hints, exact local-vs-nonlocal CDP binding, and a redacted proxy diagnostic from `CHIP_RELAY_PROXY`. `cleanup` is dry-run by default and only operates inside `CHIP_RELAY_BASE_DIR`; `--execute` refuses outside-base and symlink targets. Upload helpers use `CHIP_RELAY_UPLOAD_ALLOWED_DIRS` and reject relative, missing, directory, symlink, or outside-root files.

`stealth doctor` is diagnostic-only. Presets `normal`, `strict`, and `cf-sensitive` check fingerprint consistency and classify public challenge samples as `passed`, `captcha/manual`, `blocked`, `needs_proxy`, or `not_run`; the repo intentionally does not claim guaranteed Cloudflare bypass rates.

Hardening rules: run IDs cannot contain path components or escape `runs_dir`; browser cookie/profile dumps (`Cookies`, `Local State`, SQLite DBs, HARs, symlinks) fail hygiene; agent command failures return structured gates such as `agent_command_not_found` or `agent_command_timeout`.

`task show` is the production adapter report: compact operator evidence only (run, rail, local CDP label, verification, artifact count, hygiene, blocker). `artifacts <run_id>` and `task artifacts <run_id>` return metadata-only artifact indexes with paths, sizes, and sensitivity. They do not print file contents and authenticated artifacts stay `private-local/no-auto-send` unless a separate policy-cleared export is added.

`relay [/relay] ...` is the Telegram/operator adapter surface. It accepts slash-command-shaped tokens such as `relay /relay task init "check example"`, strips the optional `/relay` prefix, routes to task/recipe/artifact commands, and returns the same evidence-only JSON or compact text reports. Unknown commands fail closed with `unknown_relay_command`.

`--template example-title` generates a Playwright/CDP smoke script that connects to `http://127.0.0.1:18800`, opens `example.com`, writes `results/result.json`, and saves `screenshots/999-final.png`. The default template stays placeholder-safe for CI and offline development.

`task pack` only packs verified runs. It copies `final.py` and `recipe.json` into `~/.local/share/chip-relay/recipes/<name>/`; it does not copy logs, screenshots, traces, results, or profile data.

## Backend switching

Switching is just relaunching with a different backend:

```bash
scripts/chip-relay kill
scripts/chip-relay launch --backend browseros
scripts/chip-relay status

scripts/chip-relay kill
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay status
```

`auto` tries CloakBrowser first, then BrowserOS, then system Chromium.

## CDP use

Connect Playwright:

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp("http://127.0.0.1:18800")
    page = browser.contexts[0].new_page()
    page.goto("https://example.com")
    print(page.title())
    browser.close()
```

## Systemd watchdog example

```ini
# ~/.config/systemd/user/chip-relay.service
[Unit]
Description=chip-relay browser CDP

[Service]
Type=simple
WorkingDirectory=%h/chip-relay
ExecStart=%h/chip-relay/scripts/chip-relay launch --backend auto --foreground
ExecStop=%h/chip-relay/scripts/chip-relay kill
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now chip-relay.service
```

## Public hygiene checks

```bash
python3 tests/test_public_hygiene.py
python3 tests/test_shell_syntax.py
python3 /path/to/create-skill/scripts/skill_workflow_guard.py .
```
