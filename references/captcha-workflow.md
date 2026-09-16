# CAPTCHA gate workflow

Use this workflow when a relay browser task reaches reCAPTCHA, hCaptcha, Turnstile, or a Cloudflare managed challenge.

## Honest capability boundary

`chip-relay` cannot guarantee that every CAPTCHA will pass. No browser or solver can make that promise across provider changes, site policy, account risk, IP reputation, and challenges that deliberately require a person.

The relay instead prevents CAPTCHA from becoming a blind failure:

1. inspects the current CDP page using boolean/count-only metadata;
2. classifies the page as `clear`, `managed_wait`, or `agent_action`; `human_required` is terminal escalation only;
3. waits for browser-native managed clearance without injecting tokens;
4. attempts one uniquely identified provider-owned checkbox activation per task attempt;
5. captures only the detected challenge region into a private-local screenshot when agent interaction is required;
6. requires the trusted local Hermes vision loop to supply high-confidence normalized click points;
7. verifies the original page, challenge region, screenshot hash, and task attempt before clicking;
8. detects clearance and returns `cleared`, so the task can be rerun or resumed;
9. falls back to a person only after three uncleared visual cycles or a genuine safe-visual blocker;
10. exposes only compact metadata in relay responses and Hermes context.

Out of scope:

- third-party solver dispatch or unattended answer-extraction services;
- response-token injection;
- claims of guaranteed bypass or guaranteed success.

## Commands

```bash
scripts/chip-relay task captcha <run_id> inspect
scripts/chip-relay task captcha <run_id> auto --timeout 30
scripts/chip-relay task captcha <run_id> native
scripts/chip-relay task captcha <run_id> wait --timeout 120
scripts/chip-relay task captcha <run_id> capture
scripts/chip-relay task captcha <run_id> act --confidence 0.93 --point 0.25,0.50 --point 0.75,0.50
scripts/chip-relay task captcha <run_id> show
scripts/chip-relay task captcha <run_id> resume --timeout 30
```

Optional page selection for multi-tab sessions:

```bash
scripts/chip-relay task captcha <run_id> inspect --page-index 0
scripts/chip-relay task captcha <run_id> wait --page-index 0 --timeout 300
```

The same surface is available through the relay adapter:

```bash
scripts/chip-relay relay /relay task captcha <run_id> inspect
scripts/chip-relay relay /relay task captcha <run_id> wait --timeout 120
scripts/chip-relay relay /relay task captcha <run_id> capture
scripts/chip-relay relay /relay task captcha <run_id> act --confidence 0.93 --point 0.50,0.50
scripts/chip-relay relay /relay task captcha <run_id> resume
```

## Operator flow

1. Run the browser task normally.
2. If it stalls on a challenge, run `task captcha <run_id> auto` first.
3. `auto` observes managed clearance and may attempt one uniquely identified provider-owned checkbox. An ambiguous or missing target is not clicked.
4. For `agent_action`, run `capture`. Hermes must load the returned private-local image with its trusted local vision tool; do not send it to chat or an external solver.
5. Click only when confidence is at least `0.85`: convert each target center to `(x / screenshot_width, y / screenshot_height)` and run `act --confidence <score> --point <x,y> ...`. Up to 12 points are accepted for one capture. Immediately before the first click, relay re-captures the live region and requires an exact screenshot-hash match.
6. Every `act` authorization is single-use, even if the click fails. It transitions `ready -> applying` before the first click, then to `consumed` after a fully observed result or `uncertain` after an exception. If the challenge redraws or remains interactive, recapture and continue the agent loop. The third uncleared visual cycle creates a redacted waiting handoff. A low-confidence challenge is a genuine safe-visual blocker and may be handed to a trusted person; then run `resume`.
7. Continue or rerun the task only after `status=cleared`. Concurrent capture/action calls are serialized; a popup, same-target navigation/document change, changed task attempt, changed screenshot, consumed authorization, or moved/partially offscreen/replaced challenge fails closed.
8. If the gate remains blocked, inspect protection diagnostics before changing one variable at a time: profile state, egress reputation, fingerprint consistency, or rate limit.

## State and privacy

The gate writes `protection/captcha-state.json` with mode, provider label, bounded counts, status, timestamps, next action, a hashed Chromium target key, and the current execution-attempt marker. Visual assist also writes `protection/captcha-visual.png` and `protection/captcha-visual.json`; both are owner-only `0600`, private-local, bound to the same target, hashed CDP document/loader identity, exact contained region, and execution attempt, and integrity-checked before clicks. Raw URL/document identity is never persisted. The relay adapter never returns the local screenshot path or image contents.

It does not persist:

- CAPTCHA response tokens;
- raw DOM, page text, or HTML;
- screenshots outside the detected challenge region;
- cookies, storage, browser profile data, authorization headers, or request/response bodies.

## Verification checklist

- A normal page returns `clear`.
- A completed invisible response on a normal page returns `clear` without exposing the token.
- A non-interactive Cloudflare challenge returns `managed_wait`, then `cleared` after browser-native clearance.
- A visible reCAPTCHA/hCaptcha/Turnstile returns `agent_action`; native activation is attempted no more than once per task attempt.
- Visual capture contains the challenge region only, is `0600`, and is not projected through `/relay`.
- `act` rejects confidence below `0.85`, more than 12 points, managed-wait gates, stale attempts, same-target navigation, moved/partially offscreen/oversized targets or regions, modified or redrawn screenshots, consumed authorization, concurrent retry-budget races, and a fourth visual cycle.
- A successful challenge-relative click is re-inspected and returns `cleared` only on verified page clearance; an uncleared third cycle alone creates the CAPTCHA handoff.
- Timeout and polling bounds fail closed.
- State is `0600` and reports remain metadata-only.
