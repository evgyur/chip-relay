# Browser regression probes (suite version 2)

These are diagnostics, not a promise of Cloudflare clearance or invisibility.
The existing browser owner, profile routing and attachment gates remain in force.
No CAPTCHA interaction, cookie export, input fallback, or browser replacement is added.

## Local suite

`stealth benchmark --backend active --suite local --repeat 2` now covers:

- `clean`: HTTP accessibility and the existing browser-fingerprint checks.
- `captcha` and `blocked`: synthetic negative fixtures; their expected outcomes are
  `captcha/manual` and `blocked`, not successful challenge resolution.
- `input-events`: CDP click and keyboard events, trusted-event flags, pointer and
  key event ordering, exactly one button click, exact synthetic text, and no DOM
  node insertion. No JavaScript click or text-insertion fallback is allowed.
- `init-script`: the probe must run before the page's first script, exactly once
  per document, and again before page code on the next navigation.

The input probe tests CDP/Playwright input only. It does **not** certify physical
keyboard, clipboard, desktop focus, accessibility input, or NoMachine.

Each case separates `page_status`, `fingerprint_status`, and `behavior_status`
from its overall `status`. An accessible page cannot hide failed fingerprint
checks: it becomes `needs_attention`. Missing checks become `not_run`. A URL or
page containing the word "success" is not clearance evidence. Results retain
normalized booleans and fingerprint hashes, not raw page/input/fingerprint data.
`passed` means only that the implemented local checks passed, not that a site
cannot detect automation.

## Compare and gate

```bash
scripts/chip-relay --json stealth compare --baseline baseline.json --candidate candidate.json
scripts/chip-relay --json stealth gate --baseline baseline.json --candidate candidate.json
```

Comparison includes changed behavior checks, separate outcome dimensions,
browser/version, preset, headless/proxy configuration, and protocol evidence.
The gate catches lost checks, new behavior/fingerprint failures, degraded
outcomes, and the existing bounded local latency regressions. Its `passed`
means **no detected regression relative to this baseline**, not absolute stealth.
An unchanged degraded baseline does not become a healthy browser certification.

Suite version 1 and 2 are intentionally incompatible; record and inspect a fresh
v2 baseline. Do not relabel old results to make them comparable. Keep known
negative fixtures in the baseline with their expected negative statuses.

## Explicit external diagnostics

`--suite public-detectors` retains the fixed public detector route. Loading its
page is recorded as accessibility, not an authenticated detector verdict; without
an implemented verdict parser the overall result is `not_run`.

`--suite tls-fingerprint` is a separate explicit opt-in request to
`https://tls.peet.ws/api/all` **inside the same browser context being measured**.
It keeps only validated TLS version, JA3/JA4, and HTTP version fields. It discards
provider IP, headers and other response fields. This measures protocol metadata,
not challenge clearance. Third-party diagnostics can drift or throttle; their
release gate returns `not_run` / `external_diagnostic_only`, never a green gate.
No external diagnostic runs as part of the local suite or smoke command.

If an installed external binding permits only local isolated benchmarks, that
restriction is preserved. These suite options do not grant permission to use an
authenticated/shared browser or to change its binding, proxy or owner.

## Disposable local smoke

Use the component's declared managed Python and an explicitly selected installed
browser executable. This command starts and cleans up **only its own disposable
browser**, without attaching to or restarting an operator's browser:

```bash
python scripts/smoke-browser-regressions.py \
  --executable /absolute/path/to/chrome \
  --output-dir /private/path/to/receipts
```

It performs two real local-suite runs, each with two repetitions, checks the
baseline/candidate gate, and tests negative controls: a JavaScript click must be
untrusted, absent document-start initialization must fail, and an actual page
reporting `navigator.webdriver=true` must not produce `passed`.
The process/profile are temporary. Receipts are private-local; no contents are
auto-delivered. This does not certify attachment to an existing browser.

The local fixture implementation is original. Test categories were informed by
[Stealth Browser MCP](https://github.com/vibheksoni/stealth-browser-mcp), MIT,
reviewed at `ba95cca933c8e90bfeaa515c1d05dad2927794e6`; its lifecycle code and
JavaScript-click fallback were not imported.

## CDP binding compatibility (explicit observation)

Add `--probe-binding` to the disposable smoke command to measure
`Runtime.addBinding` before navigation, after a new document, and after reload.
Every stage checks both function availability and actual `Runtime.bindingCalled`
event delivery. The probe is restricted to the same exact loopback fixture and
never re-registers the binding or injects an init-script workaround.

Its `cdp_binding_probe.status` is separate from the existing local regression
gate: `needs_attention` is a real compatibility finding, not a passed test or
clearance claim. The top-level smoke verifies its own checks and completed
observation, not that the engine passed this optional compatibility probe.
See upstream [issue #632](https://github.com/CloakHQ/CloakBrowser/issues/632).

Production relay source does not directly call this raw binding mechanism or
`expose_binding`/`expose_function`. This is not a proof about every third-party
library internals or future workflow. Do not install a workaround or change the
browser engine merely because the standalone probe finds it broken. First
identify an actual consumer and an affected workflow.
The disposable harness accepts an already-closed context only after every
semantic assertion completed and its owned browser process is still alive;
it never suppresses a failed test, protocol operation, or unexpected exit.
