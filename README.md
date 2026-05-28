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
task workspace -> agent context -> final.py -> verify feedback loop -> packed recipe
```

```bash
scripts/chip-relay task init "example title smoke"
scripts/chip-relay task init "example title smoke" --template example-title
scripts/chip-relay task run <run_id>
scripts/chip-relay task loop <run_id> --agent-command "python3 /path/to/agent.py" --max-attempts 3
scripts/chip-relay task verify <run_id>
scripts/chip-relay task pack <run_id> --name example-title
scripts/chip-relay task list
scripts/chip-relay task show <run_id>
scripts/chip-relay task artifacts <run_id>
scripts/chip-relay artifacts <run_id>

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

`task loop` is the public-safe agent bridge. It writes `agent/request-NNN.json`, runs the external `--agent-command` with `CHIP_RELAY_AGENT_CONTEXT`, then calls `task verify`. If verification fails, the next request includes the redacted previous failure under `previous_result`. Loop artifacts stay inside `agent/`: request JSON, feedback JSON, redacted command logs, and `loop-result.json`.

Agent command contract:

```text
input:  CHIP_RELAY_AGENT_CONTEXT=/path/to/agent/request-001.json
output: write or update runs/<id>/scripts/final.py plus any private-local artifacts
rule:   do not dump cookies, auth headers, browser profiles, or raw tokens
```

`task verify` is the completion gate. It compiles and runs `scripts/final.py`, captures `logs/verify.log`, requires final logs/results or screenshots, writes `verification/verify-result.json`, runs a hygiene scan into `verification/hygiene-report.json`, and updates `manifest.json` to `verified` or `failed`. It reports verification strength as `same-rail` by default.

`task show` is the production adapter report: compact operator evidence only (run, rail, local CDP label, verification, artifact count, hygiene, blocker). `artifacts <run_id>` and `task artifacts <run_id>` return metadata-only artifact indexes with paths, sizes, and sensitivity. They do not print file contents and authenticated artifacts stay `private-local/no-auto-send` unless a separate policy-cleared export is added.

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
