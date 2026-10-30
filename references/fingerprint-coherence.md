# Offline fingerprint coherence

Use this diagnostic to check a minimized observation against an explicitly chosen
**desktop** profile. It does not connect to a browser, collect headers, launch or
restart anything, change fingerprints, inject JavaScript, or contact a detector.
It uses only the Python standard library. Existing account, browser-owner and
network-selection gates remain unchanged.

## Run

From the repository root, using the environment's declared Python:

```bash
python -m chip_relay.fingerprint_coherence tests/fixtures/fingerprint-desktop-v1.json
python -m unittest discover -s tests -p test_fingerprint_coherence.py -v
```

The included file is entirely synthetic, not an observed session. Its success is
an offline fixture result, **not a live browser certification**. For an authorized
real task, supply a private, minimized JSON file in the same schema. Browser reads
still require the existing identity and attachment checks; this tool grants no
new read or write authority. Do not feed it profiles, cookies, storage exports,
request dumps or response bodies. Inputs are read only; no result file is created.

## Contract v1

The fixture is the complete input example. All six `expected` fields are required:
`platform` (`windows`, `macos`, `linux`), `locale`, `screen` (width, height and
`device_scale_factor`), `device_memory_gb`, `hardware_concurrency`, and `touch`.
Screen and viewport dimensions are CSS pixels; the scale is the observed
`devicePixelRatio`. Viewport dimensions describe the layout viewport at normal
zoom, not an emulated or zoomed visual viewport. Expected values must represent
the intended profile, not values copied blindly from the observation.

`observed` permits these sections and fields only:

* `headers`: lowercase `user-agent`, `accept-language`, `sec-ch-ua-platform`.
* `navigator`: `userAgent`, `platform`, `language`, `deviceMemory`,
  `hardwareConcurrency`, `maxTouchPoints`.
* `screen`: `width`, `height`, `device_scale_factor`.
* `viewport`: `width`, `height`.

Headers and JS values must describe the same authorized browser/page observation.
Unknown fields, including cookie headers, are rejected. Missing sections/fields
and explicit null measurements yield `not_run` for affected checks, not success.
Invalid supplied measurements fail affected checks. Invalid expected profiles
or malformed contracts block the diagnostic.

## Checks and verdicts

There are eleven checks: UA platform, navigator platform, Client Hint platform,
HTTP/JS UA equality, HTTP/JS language agreement, intended locale, intended screen
and pixel ratio, viewport fitting the observed screen, intended device memory,
CPU concurrency and touch capability. Accept-Language respects quality weights
and case-insensitive language tags. Unknown/mobile OS signatures are not accepted
as desktop platforms. Numeric booleans, nonfinite values and negative sizes are
not valid measurements.

The result contains fixed check names and verdicts only, not input values:

* `passed` / exit 0: all eleven checks ran and passed.
* `needs_attention` / exit 1: at least one failed, even if other checks are missing.
* `not_run` / exit 1: incomplete coverage with no detected contradiction.
* `blocked` / exit 2: invalid input or unreadable file; errors do not echo its path
  or contents.

`browser_verified` is always false and `scope` is `offline_consistency_only`.
This is a separate absolute coherence diagnostic, not a new stealth score or a
replacement for the existing baseline/candidate regression gate.

## Deliberate limits and provenance

[Apify fingerprint-suite](https://github.com/apify/fingerprint-suite) motivated
checking multiple surfaces together. This implementation and its fixture are
original; no Apify code, datasets or packages are bundled. A generator is not
needed for this bounded first version. If generator-produced fixtures are added
later, pin the generator/dataset version, review licensing and normalize them
into this contract offline; do not add a production dependency incidentally.

Do not layer `fingerprint-injector` or per-launch randomization over an existing
CloakBrowser/authenticated profile. This tool cannot verify fonts, Canvas,
WebGL, TLS/JA3/JA4, timezone/egress alignment, browser-version authenticity,
Client Hint version/architecture, or actual engine behavior. UA platform parsing
is a desktop signature heuristic, not proof of operating system identity.
A coherent supplied JSON document can be fabricated. Real-site accessibility,
CAPTCHA clearance, authenticated identity and nondetectability are not certified.
