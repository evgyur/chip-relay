# Protection diagnostics: sources and clean-room policy

chip-relay implements a native diagnostic layer. The external Scrapfly Anti-bot Detector repository was reviewed only to understand useful categories of evidence. Its NPOSL-3.0 implementation is not an implementation source for this MIT repository.

## Clean-room boundary

- **No copied source code.** Production code is authored against chip-relay's own task, network, report, and verifier contracts.
- **No copied detector JSON.** Native rules use a different schema and must be supported by an independent public source.
- **No copied descriptions or confidence values.** Names, wording, weights, fixtures, and scoring are authored independently.
- **No bundled Chrome extension.** chip-relay does not install, wrap, fork, or redistribute the upstream extension, assets, UI, manifest, or runtime.
- No copied screenshots, icons, test corpus, generated bundles, or documentation text.

## Rule admission contract

Every shipped rule must include:

1. An independently written rule ID, provider, category, and signal list.
2. At least one **independent public source** URL, preferably first-party vendor/browser documentation. The rule pack, rule, source, and signal objects use exact schemas; source URLs must be credential-free public HTTPS URLs without custom ports, query strings, or fragments.
3. Deterministic positive and negative fixtures written for chip-relay.
4. A review that generic weak signals cannot create a high-confidence provider verdict.
5. Metadata-only evidence. Cookie/header names may be used; their values, bodies, raw DOM, browser storage, profiles, screenshots, and HAR files may not.

## Review provenance

- Pattern inspiration only: <https://github.com/scrapfly/Antibot-Detector>
- License reviewed: NPOSL-3.0 at upstream commit `e5341e9ff4e3fdd5302a93980d74b9923686e987`.
- Native implementation baseline: chip-relay `6217d734e13f078fffad6cbfded067e2707c17e0`.

## Shipped source register

`chip_relay/rules/protections-v1.json` is the machine-readable source register. The clean-room v1 pack contains 11 independently authored rules:

- `cloudflare.challenge` -> Cloudflare challenge-response documentation.
- `akamai.bot-manager` -> Akamai Bot Manager documentation.
- `datadome.bot-protection` -> DataDome cookie/session documentation.
- `human.perimeterx` -> HUMAN application cookie reference.
- `imperva.bot-management` -> Imperva bot-management documentation.
- `kasada.client` -> an independent Kasada protocol analysis.
- `aws-waf.challenge` -> AWS WAF token-domain documentation.
- `f5-shape.bot-defense` -> F5 Distributed Cloud Bot Defense documentation.
- `google.recaptcha` -> Google reCAPTCHA loading documentation.
- `hcaptcha.widget` -> hCaptcha loading documentation.
- `cloudflare.turnstile` -> Cloudflare Turnstile client-side rendering documentation.

Each JSON rule carries its exact HTTPS source URL. `scripts/audit-protection-clean-room.py` deterministically reproduces the audit against the pinned upstream SHA and compares every changed feature file since the pinned clean-room base, including runtime integrations, CLI, tests, workflow, and documentation. The generated receipt itself is the sole content-hash exclusion because hashing a document that embeds its own hash is self-referential; CI still compares that receipt structurally with `--check`. The current receipt reports zero exact meaningful-line matches across 235 tracked upstream source/document files, no upstream runtime dependency, and no upstream name/license terms in production artifacts.
