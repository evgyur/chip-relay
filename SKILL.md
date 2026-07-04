---
name: chip-relay
description: Portable browser relay skill for Hermes/agent automation. Use when you need a local CDP browser rail with switchable CloakBrowser and BrowserOS backends, persistent profiles, health checks, tab/open commands, or a public-safe /relay-style setup without private host paths or secrets.
version: 0.1.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [browser, cdp, automation, cloakbrowser, browseros, relay]
---

# chip-relay

Portable `/relay`-style browser rail for agents.

Use this skill when the user asks to:
- install or operate a local browser automation relay;
- switch between CloakBrowser and BrowserOS;
- expose a safe local Chrome DevTools Protocol endpoint for Playwright/Puppeteer/CDP tools;
- keep a persistent browser profile for authenticated automation;
- diagnose bot-detection/browser fingerprint issues without copying private cookies or secrets.

## Core model

`chip-relay` is a small CDP supervisor around two browser paths:

1. **CloakBrowser** — patched Chromium, stealth/fingerprint-oriented automation path.
2. **BrowserOS** — Chromium-compatible browser with optional MCP/agent capabilities.

Backend selection is explicit and reversible:

```bash
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay launch --backend browseros
scripts/chip-relay launch --backend auto
scripts/chip-relay status
scripts/chip-relay health
scripts/chip-relay open https://example.com
scripts/chip-relay kill
```

## Public-safe defaults

No secrets, cookies, private hostnames, IP allowlists, or user-specific paths are stored in this repo.

Runtime state defaults to the current user's home directory:

```text
~/.local/share/chip-relay/
├── profiles/default/
├── logs/
└── state.json
```

Override with environment variables or a local env file copied from `templates/chip-relay.env.example`.

## Quick install

```bash
git clone https://github.com/<owner>/chip-relay.git
cd chip-relay
scripts/install-cloakbrowser.sh
scripts/chip-relay doctor
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay health
```

BrowserOS is optional. Install it separately, then run:

```bash
scripts/chip-relay launch --backend browseros
```

## Operator checklist

1. Run `scripts/chip-relay doctor`.
2. Pick backend: `cloakbrowser`, `browseros`, or `auto`.
3. Launch and verify `http://127.0.0.1:${CHIP_RELAY_PORT:-18800}/json/version`.
4. Use CDP clients only on loopback or through a trusted tunnel.
5. Never commit runtime profiles, cookies, logs, `.env`, or downloaded binaries.
6. For Webwright-style work, use the task layer and report evidence paths instead of pasting artifact contents.

## Webwright task commands

```bash
scripts/chip-relay task init "example title smoke"
scripts/chip-relay task run <run_id>
scripts/chip-relay task context <run_id>
scripts/chip-relay task context <run_id> --write
scripts/chip-relay task loop <run_id> --agent-command "python3 /path/to/agent.py" --max-attempts 3
scripts/chip-relay task loop <run_id> --agent-command scripts/chip-relay-agent-example --max-attempts 1
scripts/chip-relay task verify <run_id>
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
scripts/chip-relay task pack <run_id> --name example-title
```

Production adapter rules:

- `task show` prints compact operator evidence: run, rail, local CDP label, verification, artifact count, hygiene, blocker.
- `relay [/relay] ...` maps Telegram/operator slash-command-shaped input to the safe task/recipe/artifact command surface and fails closed on unknown commands.
- `artifacts` returns metadata only: paths, types, sizes, sensitivity. It must not print log/screenshot/result contents.
- `task network` stores redacted request metadata under `network/`; sensitive headers/query tokens and bodies are not printed by default.
- `task init-script` stores pre-document JavaScript under `init_scripts/` and reports only name/size/SHA-256; `example-title` loads it before navigation.
- `doctor webwright` includes browser environment, exact CDP binding, and redacted `CHIP_RELAY_PROXY` diagnostics.
- `cleanup` is dry-run by default and may only remove relay-managed paths inside `CHIP_RELAY_BASE_DIR`.
- Upload helpers require `CHIP_RELAY_UPLOAD_ALLOWED_DIRS` and reject relative/outside/symlink paths.
- `stealth doctor` is diagnostic-only: presets report fingerprint/challenge state, not guaranteed Cloudflare bypass.
- Authenticated artifacts stay `private-local/no-auto-send` unless a separate policy-cleared export is built.
- `task context` is the Hermes-native workflow primitive: Hermes is the agent, `/relay` is the browser tool/substrate. It returns the editable `scripts/final.py`, verify/show/artifact commands, current verification state, evidence summary, and metadata-only artifact paths.
- new task workspaces include `task.brief_schema=chip-relay-agent-brief-v2` in `manifest.json` and matching sections in `task.md`: `agent_instructions`, `success_metrics`, `known_frictions`, and `verification_questions`.
- Use `task context --write` to persist `agent/hermes-context.json` for repeatable handoff without exposing artifact contents in chat.
- Agent integrations that are not Hermes-in-process stay outside the public repo and connect through `--agent-command` plus `CHIP_RELAY_AGENT_CONTEXT`.
- `scripts/chip-relay-agent-example` is a deterministic public-safe external-agent example for loop smoke tests; it is not a provider integration.
- Run IDs must not contain path components or escape `runs_dir`; verification must require fresh artifacts from the current attempt; browser cookie/profile dumps must fail hygiene.

## Output Contract

When using this skill, return compact operator evidence:

1. selected backend (`cloakbrowser`, `browseros`, `chromium`, or `auto` result);
2. CDP endpoint (`host:port`) and profile directory;
3. commands run;
4. verification result (`status`, `health`, or `/json/version` evidence);
5. any residual risk, especially CDP exposure or missing browser binary.

Never print cookie values, auth headers, browser profile contents, or local `.env` values.

## Quick Test Checklist

```bash
scripts/chip-relay doctor
scripts/chip-relay --json status
bash -n scripts/chip-relay scripts/chip-relay.sh scripts/install-cloakbrowser.sh scripts/chip-relay-watchdog.sh
python3 -m py_compile chip_relay/*.py
python3 tests/test_task_workspace.py
python3 tests/test_task_verify.py
python3 tests/test_task_run_pack.py
python3 tests/test_recipe_commands.py
python3 tests/test_agent_loop.py
python3 tests/test_hermes_workflow_context.py -v
python3 tests/test_bundled_agent_example.py
python3 tests/test_production_adapter.py
python3 tests/test_relay_adapter.py -v
python3 tests/test_review_hardening.py -v
python3 tests/test_stealth_browser_mcp_adoption.py -v
python3 tests/test_public_hygiene.py
python3 tests/test_shell_syntax.py
```

Optional live backend checks:

```bash
scripts/install-cloakbrowser.sh
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay health
scripts/chip-relay kill
```

## Done Criteria

- Backend selection is explicit and reversible.
- CDP binds to loopback by default.
- Runtime state stays outside the repo.
- No secrets, cookies, private IPs, or user-specific absolute paths are committed.
- Shell syntax and public hygiene checks pass.
- `SKILL.md` loads as a Hermes skill and points to the operational docs.

## References

- `README.md` — full setup and command reference.
- `references/security.md` — public repo hygiene and CDP exposure rules.
- `templates/chip-relay.env.example` — configuration template.
