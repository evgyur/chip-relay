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
