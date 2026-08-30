---
name: chip-relay
description: Portable browser relay skill for Hermes/agent automation. Use when you need a local CDP browser rail with switchable CloakBrowser and BrowserOS backends, persistent profiles, health checks, tab/open commands, or a public-safe /relay-style setup without private host paths or secrets.
version: 0.6.0
author: Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [browser, cdp, automation, browser-use, cloakbrowser, browseros, relay, protection-diagnostics]
---

# chip-relay

Portable `/relay`-style browser rail for agents.

Use this skill when the user asks to:
- install or operate a local browser automation relay;
- switch between CloakBrowser and BrowserOS;
- expose a safe local Chrome DevTools Protocol endpoint for Playwright/Puppeteer/CDP tools;
- keep a persistent browser profile for authenticated automation;
- diagnose bot-detection/browser fingerprint issues without copying private cookies or secrets;
- run bounded read-only Browser Use CLI programs through Relay's loopback CDP with private-local evidence;
- detect CAPTCHA gates, wait for browser-native clearance, capture an interactive challenge privately for trusted local vision, apply bounded normalized clicks, and resume without exposing response tokens.

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
scripts/chip-relay task protection <run_id> add --json-file page-signals.json
scripts/chip-relay task protection <run_id> diagnose
scripts/chip-relay task protection <run_id> show
scripts/chip-relay task protection <run_id> observer-enable --preset normal
scripts/chip-relay task captcha <run_id> inspect
scripts/chip-relay task captcha <run_id> wait --timeout 120
scripts/chip-relay task captcha <run_id> capture
scripts/chip-relay task captcha <run_id> act --confidence 0.93 --point 0.25,0.50 --point 0.75,0.50
scripts/chip-relay task captcha <run_id> show
scripts/chip-relay task captcha <run_id> resume --timeout 30
scripts/chip-relay task init-script <run_id> add webdriver --file init/webdriver.js
scripts/chip-relay task init-script <run_id> list
scripts/chip-relay task browser-use <run_id> doctor
scripts/chip-relay task browser-use <run_id> plan --script ~/.local/share/chip-relay/runs/<run_id>/scripts/browser-use.py
scripts/chip-relay task browser-use <run_id> execute --script ~/.local/share/chip-relay/runs/<run_id>/scripts/browser-use.py --timeout 120
scripts/chip-relay task browser-use <run_id> show
scripts/chip-relay cleanup
scripts/chip-relay cleanup --execute
scripts/chip-relay stealth doctor --preset cf-sensitive
scripts/chip-relay --json stealth benchmark --backend active --suite local --repeat 3
scripts/chip-relay --json stealth benchmark --backend chromium --backend cloakbrowser --backend browseros --suite local
scripts/chip-relay --json stealth compare --baseline baseline.json --candidate candidate.json
scripts/chip-relay --json stealth gate --baseline baseline.json --candidate candidate.json
scripts/chip-relay artifacts <run_id>
scripts/chip-relay relay /relay task init "example title smoke"
scripts/chip-relay task pack <run_id> --name example-title
```

Production adapter rules:

- `task show` prints compact operator evidence: run, rail, local CDP label, verification, artifact count, hygiene, blocker.
- `relay [/relay] ...` maps Telegram/operator slash-command-shaped input to the safe task/recipe/artifact command surface and fails closed on unknown commands.
- `artifacts` returns metadata only: paths, types, sizes, sensitivity. It must not print log/screenshot/result contents.
- `task network` stores redacted request metadata under `network/`; all header values, query data, and opaque path segments are removed or hashed, and bodies are never retained. Pinned-descriptor I/O rejects symlinks, FIFOs, malformed rows, and oversized artifacts; base v1 rows are migrated in memory. JSON input files are capped at 64 KiB.
- `task run` and `task verify` hold a run-scoped execution lock. Generation allocation and completion reread the authoritative manifest under a separate pinned-descriptor lock; stale attempt completion and child writes with a mismatched `CHIP_RELAY_ATTEMPT_ID` fail closed.
- `task protection` emits `chip-relay-protection-diagnostic-v1` from normalized metadata for the manifest's current execution generation only. It will not diagnose a still-running generation, and specific blocker guidance requires status plus provider/profile evidence on the same sanitized observation. Passive mode is the default; it retains normalized names/counts internally and irreversible evidence keys, not cookie values, auth, bodies, raw DOM, storage, screenshots, or profile data.
- Supported clean-room classes are Cloudflare, Akamai, DataDome, HUMAN/PerimeterX, Imperva, Kasada, AWS WAF, F5/Shape, reCAPTCHA, hCaptcha, and Turnstile. Each rule has an independent public source entry.
- `task protection ... observer-enable` is explicit `instrumented` mode. It installs a bounded document-start API observer, can affect detectability, and is disabled by default. The current `normal`, `strict`, and `cf-sensitive` preset names are labels only; they do not alter observer behavior.
- Protection output is diagnostic guidance only: no stealth, proxy rotation, or guaranteed bypass/success claim. The CAPTCHA gate may wait for browser-native managed clearance, then use a trusted local visual-assist loop or a person; it never dispatches a third-party solver or injects response tokens.
- `task captcha ... inspect|wait|capture|act|show|resume` supports reCAPTCHA, hCaptcha, Turnstile, and Cloudflare challenge classification. Only after `human_required`, run `capture`, load the returned private-local image with Hermes' local vision tool, and run `act` only at confidence `>=0.85` with normalized challenge-relative points. `act` revalidates the hashed CDP document/loader identity, exact contained region, and live screenshot hash immediately before clicking, moves authorization to `applying` before any click and then to `consumed`/`uncertain`, and serializes capture/action calls under the run lock. Recapture after any stale or still-interactive result; stop after three visual cycles or any low-confidence challenge and use the trusted visible browser plus `resume`. Probe/state parsing is fail-closed; Cloudflare+Turnstile receives a browser-native wait window before visual/human handoff. State and challenge artifacts are mode `0600`, execution-attempt-bound, target- and document-pinned, integrity-checked, and never projected through `/relay`; Hermes context receives exact commands.
- `task init-script` stores pre-document JavaScript under `init_scripts/` and reports only name/size/SHA-256; `example-title` loads it before navigation.
- `task browser-use` sends a statically bounded read-only helper program to a trusted, separately pinned Browser Use CLI. Default executions get unique owner-only Browser Harness runtime/tmp/config paths, are bound to Relay's loopback `BU_CDP_URL`, attest `browser_kind=cdp` plus `Browser.getVersion`, and must close both daemon endpoint and process before success. Same-group descendants are killed after every direct CLI exit. Screenshot import requires an explicit `capture_screenshot()` AST call and a structurally valid PNG created in that execution's fresh temp root. Configured custom commands are labeled unattested. This is not a Python sandbox, redirect firewall, DNS-rebinding defense, or protection from a malicious same-UID CLI.
- `doctor webwright` includes browser environment, exact CDP binding, and redacted `CHIP_RELAY_PROXY` diagnostics.
- `cleanup` is dry-run by default and may only remove relay-managed paths inside `CHIP_RELAY_BASE_DIR`.
- Upload helpers require `CHIP_RELAY_UPLOAD_ALLOWED_DIRS` and reject relative/outside/symlink paths.
- `stealth doctor` is diagnostic-only: presets report fingerprint/challenge state, not guaranteed Cloudflare bypass.
- `stealth benchmark` stores owner-only, private-local normalized evidence. `active` only attaches to exact loopback CDP; backend matrices run sequentially on unique non-default ports and ephemeral profiles with exact PID/start-time/process-group teardown. `public-detectors` is opt-in, fixed-allowlist, and informational only.
- `stealth compare` requires an identical suite ID/version. `stealth gate` fails closed on lost coverage, new fingerprint-check failures, a prior `passed` outcome becoming blocked/manual, or local-fixture median latency above both `baseline + 500 ms` and `3 × baseline`; public-detector latency is informational. There is no aggregate stealth score, arbitrary target URL, or `rebrowser-playwright` dependency.
- `/relay stealth benchmark|compare|gate` returns metadata and private-local artifact paths only; never auto-send benchmark contents.
- Authenticated artifacts stay `private-local/no-auto-send` unless a separate policy-cleared export is built.
- `task context` is the Hermes-native workflow primitive: Hermes is the agent, `/relay` is the browser tool/substrate. It returns editable `scripts/final.py` and `scripts/browser-use.py`, Browser Use plan/execute/show commands, verify/show/artifact commands, current verification state, evidence summary, and metadata-only artifact paths.
- new task workspaces include `task.brief_schema=chip-relay-agent-brief-v2` in `manifest.json` and matching sections in `task.md`: `agent_instructions`, `success_metrics`, `known_frictions`, and `verification_questions`.
- Use `task context --write` to persist `agent/hermes-context.json` for repeatable handoff without exposing artifact contents in chat.
- Agent integrations that are not Hermes-in-process stay outside the public repo and connect through `--agent-command` plus `CHIP_RELAY_AGENT_CONTEXT`.
- `scripts/chip-relay-agent-example` is a deterministic public-safe external-agent example for loop smoke tests; it is not a provider integration.
- Run IDs must not contain path components or escape `runs_dir`; every task run/verify increments a durable attempt ID, verification must require fresh artifacts from that attempt, and browser cookie/profile dumps must fail hygiene. Linux execution/manifest serialization also uses a non-replaceable abstract Unix-socket authority; malformed execution records fail closed, and only a missing record receives legacy generation-zero migration.

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
python3 -m unittest discover -s tests -p 'test_*.py' -v
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
- `references/captcha-workflow.md` — detect → managed wait / human handoff → clearance → resume contract and privacy boundary.
- `docs/protection-diagnostics-sources.md` — clean-room provenance, source, privacy, and no-bypass contract.
- `templates/chip-relay.env.example` — configuration template.
