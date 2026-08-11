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
CHIP_RELAY_PROXY=http://proxy.example:8080
CHIP_RELAY_PROXY_SECRET_FILE=/absolute/private/path/proxy-auth.json
CHIP_RELAY_BROWSER_USE_COMMAND=browser-use
CLOAKBROWSER_FINGERPRINT_PLATFORM=windows|macos
```

Authenticated proxy credentials are never accepted inside `CHIP_RELAY_PROXY`, `.env`, argv, or raw username/password environment variables. Put only the credential-free proxy endpoint and the path to an owner-only `0600` JSON file in configuration:

```json
{"username":"proxy-user","password":"[REDACTED]"}
```

The task runner opens that file with no-follow and owner/mode/type checks, supplies credentials only to an exact matching CDP proxy-auth challenge, removes the secret-file reference from the child environment, and tears the handler down after the task. Remove `CHIP_RELAY_PROXY_SECRET_FILE` to roll back to the existing unauthenticated proxy path.

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
scripts/chip-relay task browser-use <run_id> execute --script ~/.local/share/chip-relay/runs/<run_id>/scripts/browser-use.py
scripts/chip-relay task browser-use <run_id> show
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
├── scripts/browser-use.py
├── browser-use/workspace/
├── logs/
├── screenshots/
├── traces/
├── results/
├── protection/
├── agent/
└── verification/
```

`task run` executes `scripts/final.py` once, captures `logs/run.log`, injects `CHIP_RELAY_CDP_URL`, and marks the manifest `ran` or `failed`. Run and verify executions are serialized by a run-scoped lock. On Linux, a non-replaceable abstract Unix-socket authority backs the pinned-descriptor lock files, so unlink/recreation cannot bypass serialization. Execution IDs are monotonic; malformed execution state fails closed, while only a manifest with no `execution` record is treated as legacy generation zero.

`task context` is the Hermes-native workflow primitive. It returns `chip-relay-hermes-workflow-context-v1`: task, `task_brief`, rail, editable files, verify/show/artifacts commands, current verification state, evidence summary, and metadata-only artifact paths. This is the preferred integration when Hermes itself is the agent: Hermes reads the brief, edits `scripts/final.py`, runs `task verify`, reads structured feedback/evidence, and never sends artifact contents to chat by default. `--write` stores the same context at `agent/hermes-context.json` for repeatable handoff.

### Browser Use CLI bridge

The optional Browser Use lane follows the same stdin-program protocol as upstream Hermes `browser_exec`, while keeping the browser itself on Relay's existing loopback CDP rail:

```text
Hermes / operator -> scripts/browser-use.py -> Browser Use CLI stdin
                  -> BU_CDP_URL=Relay loopback CDP -> private-local evidence
```

Relay does not copy Browser Use or register a second Hermes tool schema. `doctor` selects an explicitly configured trusted command, an installed `browser-use`, or `uvx browser-use`. `plan` validates the exact script and reports its SHA-256. `execute` sends that already-read script to stdin with a minimal child environment, a run-private `BH_AGENT_WORKSPACE`, a bounded timeout, disabled recording, and 1 MiB stdout/stderr caps. A fresh PNG path emitted by `capture_screenshot()` is opened without following symlinks, structurally validated, copied into run-private `screenshots/`, and indexed by hash; the temporary source is removed only when its inode still matches. Reports contain hashes, sizes, status, runner class, and duration; raw output remains under private-local `logs/`.

This lane is deliberately **read-only first**. The accepted AST subset has no imports, dynamic attributes, `js`, raw `cdp`, arbitrary builtins, click, type, upload, form submit, purchase, publish, or delete. It permits only direct calls to the current Browser Use CLI helpers `new_tab`, `goto_url`, `wait_for_load`, `page_info`, `capture_screenshot`, and `ensure_real_tab`, plus assignments and `print` of bounded simple values. Navigation preflight requires public HTTPS and rejects non-global DNS answers.

The boundary is stated narrowly: this is a cooperative policy for the supplied script, **not a Python sandbox, network namespace, redirect firewall, or protection against a malicious same-UID Browser Use binary**. DNS can change after preflight and a public site can redirect. Attached persistent profiles can expose authenticated page data even without mutations, so Browser Use output stays private-local and this lane must not be used for untrusted programs or irreversible actions. The upstream token-reduction claim is not treated as a Relay benchmark until an exact local A/B corpus is run.

`task loop` is the public-safe external-agent bridge. It writes `agent/request-NNN.json`, runs the external `--agent-command` with `CHIP_RELAY_AGENT_CONTEXT`, then calls `task verify`. If verification fails, the next request includes the redacted previous failure under `previous_result`. Loop artifacts stay inside `agent/`: request JSON, feedback JSON, redacted command logs, and `loop-result.json`.

`scripts/chip-relay-agent-example` is a bundled deterministic external-agent example. It reads `CHIP_RELAY_AGENT_CONTEXT`, writes a public-safe `scripts/final.py`, and lets `task loop` complete without any LLM provider. Replace it with a private command such as a Hermes/OpenClaw wrapper when deploying real autonomous generation.

Agent command contract:

```text
input:  CHIP_RELAY_AGENT_CONTEXT=/path/to/agent/request-001.json
output: write or update runs/<id>/scripts/final.py plus any private-local artifacts
rule:   do not dump cookies, auth headers, browser profiles, or raw tokens
```

`task verify` is the completion gate. Under the run-scoped execution lock, it atomically allocates the next manifest generation from the authoritative manifest before running `scripts/final.py`, captures a redacted `logs/verify.log`, requires fresh final logs/results or screenshots from that attempt, writes `verification/verify-result.json`, runs a hygiene scan into `verification/hygiene-report.json`, and updates `manifest.json` to `verified` or `failed`. Completion is accepted only for that attempt ID, and child signal writes must match `CHIP_RELAY_ATTEMPT_ID`. Protection diagnosis uses only observations tagged with the current attempt ID, so concurrent or same-second reruns cannot inherit or mix an older blocker. It currently implements `same-rail`; unimplemented strengths fail closed instead of pretending isolation.

Network observations are stored under `network/` inside the run. `task network add/search/export` is metadata-first: URL query/fragment/userinfo data is removed, non-allowlisted path segments are one-way hashed, every header value is replaced with `[REDACTED]`, and request/response bodies are represented only as presence/byte metadata. Reads and writes use pinned descriptors, reject symlinks/non-regular files, enforce byte caps, and fail closed on malformed records. Base v1 observations are migrated to the closed schema in memory. The exported JSON is a private-local artifact and is never printed as raw captured content by default.

### Protection diagnostics

The native protection layer classifies normalized network and page metadata with schema `chip-relay-protection-diagnostic-v1`. It is diagnostic-only: there is **no bypass**, stealth, CAPTCHA-solving, proxy-rotation, or success guarantee.

```bash
# page-signals.json may contain only normalized URL/status/class/marker/name fields
scripts/chip-relay task protection <run_id> add --json-file page-signals.json
scripts/chip-relay task protection <run_id> diagnose
scripts/chip-relay task protection <run_id> show

# intrusive and disabled by default
scripts/chip-relay task protection <run_id> observer-enable --preset normal
```

Passive mode is the default. Modes are `passive` (default) and `instrumented` (explicit opt-in). JSON inputs are capped at 64 KiB. It combines origin plus allowlisted/hashed URL-path metadata and statuses with header names, cookie names, normalized page markers, and known window keys; query data and all header values are removed. Specific blocker guidance requires status and provider/profile evidence on the same sanitized observation, and diagnosis refuses an execution generation while it is still running. It never persists cookie values, authorization material, request or response bodies, raw DOM text, screenshots, storage contents, or profile data. Diagnosis artifacts stay private-local under `protection/`; evidence keys are irreversible SHA-256 prefixes, while `task show`, verifier evidence, and Hermes context expose only compact provider, confidence, blocker hypothesis, next test, count, and path metadata.

The optional `observer-enable` command installs a document-start init script through the existing run rail. This `instrumented` mode wraps selected browser APIs for ten seconds, restores wrappers transactionally, and retains only API names plus bounded call counts. It captures no call payload data or browser contents. Instrumentation is intrusive, can affect detectability, and cannot prove stealth or bypass. Its `normal`, `strict`, and `cf-sensitive` preset names are currently labels only and do not change observer behavior.

The clean-room baseline covers Cloudflare, Akamai Bot Manager, DataDome, HUMAN/PerimeterX, Imperva, Kasada, AWS WAF, F5/Shape, reCAPTCHA, hCaptcha, and Turnstile. Every rule carries an independent public source URL in `chip_relay/rules/protections-v1.json`. The external Scrapfly project informed only the product category and threat-model review; no NPOSL code, JSON signatures, UI, extension, or runtime dependency is included. See `docs/protection-diagnostics-sources.md`.

Blocker guidance is explicitly hypothetical and distinguishes manual CAPTCHA, rate limiting, likely IP reputation, likely persistent profile state, fingerprint inconsistency, and unknown. Ordered next tests change one variable at a time; automatic bypass and egress rotation remain out of scope.

### CAPTCHA gate and resume

`task captcha` turns CAPTCHA from an opaque task failure into a bounded state machine. It inspects the selected live CDP page using boolean/count-only metadata, recognizes reCAPTCHA, hCaptcha, Turnstile, and Cloudflare managed challenges, and returns `clear`, `managed_wait`, or `human_required`.

For browser-native managed challenges, `wait` observes the existing browser until clearance and returns `cleared`; it does not click or inject anything. The gate rejects malformed/contradictory probes, treats a pending hidden response field as `managed_wait`, and pins the original Chromium target across `inspect`/`resume`, so a new tab cannot cause false clearance. Cloudflare pages that also expose Turnstile receive a managed-wait window first, then become a human handoff if a visible widget remains at timeout.

For an interactive challenge, `capture` is enabled only after `human_required` and takes a private-local screenshot of only the fully visible detected challenge region. A trusted local vision agent or operator can inspect that image and pass normalized challenge-relative points to `act`. Immediately before clicking, relay revalidates the Chromium document/loader identity, exact contained region, and live screenshot hash; it marks the authorization `applying` before any click, ends it as `consumed` only after a fully observed result or `uncertain` after an exception, clicks only the pinned page/document/region, re-inspects the gate, and returns `cleared` only when page metadata confirms clearance. Capture/action calls are serialized under the run lock. Region dimensions and pixel area are capped before screenshot allocation. The screenshot and its integrity-bound state are owner-only `0600`, attempt-bound, target- and document-pinned, and never exposed by the `/relay` response.

This is deliberately not a universal CAPTCHA solver. There is no third-party solver dispatch, response-token injection, unattended answer-extraction service, or guaranteed bypass claim. The trusted local visual-assist loop is bounded to 12 points per capture and fails closed if the page, region, attempt, or screenshot changes. See `references/captcha-workflow.md`.

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

### Bounded browser-native fetch

Inside `scripts/final.py`, use the run-bound helper after the top-level page is already on the intended origin:

```python
from chip_relay.playwright_runner import browser_fetch_for_current_run

metadata = browser_fetch_for_current_run(page, "/api/items?limit=10")
print(metadata.as_public_dict())  # metadata + opaque body handle only
```

This lane accepts only relative GET/HEAD paths, binds them to the page's exact scheme/host/port, sends the existing browser cookies with `credentials: "include"`, disables redirect following, and caps time, bytes, content type, and concurrency. Redirects, origin changes, unsupported methods/types, timeout, oversize, and ambiguous network outcomes fail closed without retries.

GET bodies are written under the current run as owner-only `0600` private artifacts. Manifests and generic artifact indexes contain only bounded metadata and an opaque `body-…` handle. `read_private_body_artifact(run_dir, handle)` is an explicit local-only read; do not print or send its bytes to chat. HEAD returns metadata without creating a body artifact. This is not a generic URL fetcher, CAPTCHA tool, protected-site bypass, cache, batch system, or alternate browser backend.

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
