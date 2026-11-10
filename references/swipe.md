# Native inertial swipe on the selected Relay page

Use `HumanInput.swipe` for a requested swipe, not JavaScript `scrollTo`, CSS smooth
scrolling, a sequence of wheel events, or automatic fallback to another backend.

```python
from chip_relay.humanize import humanize_page

with humanize_page(
    selected_page,
    expected_origin=selected_origin,
    expected_account=expected_account,
    identity_check=read_and_verify_live_account,
    mode="off",  # swipe uses native touch independently of click/fill SDK mode
) as human:
    result = human.swipe(
        direction="up",  # finger up => content scrolls downward
        distance=240,    # CSS pixels, 80..600; entire path must fit viewport
        speed=1200,      # intended CSS px/s, 200..3000; 80ms..1.5s gesture
        inertia=True,   # release immediately, letting Chromium supply momentum
        timeout=5000,   # one absolute preflight/dispatch/settling/readback budget
    )
```

Keep the existing bound-task/account-selection rules. For a public synthetic
fixture, verify its actual fixture identity; this never proves a provider login.
`up/down/left/right` describe finger movement. Optional `x/y` choose the start;
both start and end must remain at least 16 CSS pixels inside the viewport. The
adapter rejects iframe/control/secret-editing start targets; it never types.

## What actually runs

- A single page-specific CDP session sends `Input.dispatchTouchEvent` with one
  `touchStart`, a bounded path of `touchMove`, and one `touchEnd`.
- Momentum after release is Chromium's own scrolling, not a JavaScript animation.
  No input is emitted while waiting for settling. `inertia=False` adds a short
  stationary hold before release to suppress velocity.
- The experimental `Input.synthesizeScrollGesture(preventFling=False)` was not
  sufficient on the qualified Chromium build: touch events were accepted without
  page scrolling. It is not silently used or retried as a fallback.
- No `Emulation` command, mobile/device toggle, viewport/UA/fingerprint change,
  launch replacement, OS mouse/trackpad claim or profile mutation is performed.
- Owner binding, selected origin, optional live account and selection context are
  checked. Main-frame navigation aborts further input. One deadline covers the
  action; a small reserve is used only for best-effort touch cancellation and
  CDP detach. A timed-out/failed gesture is uncertain: inspect before retrying.
- Starting on a control or iframe is denied. This is a cooperative scoped input
  adapter, not a sandbox or permission to trigger unrelated site effects.

## Readback and limits

The return value includes backend, requested/observed inertia, document-scroller
positions before/release/settling, post-release delta and `settled`. A false
`inertia_observed` is not replaced with a fabricated success: boundaries, CSS,
OS/build differences and nested scrolling can yield no document-level delta.
Nested scrollers may move without moving the document; inspect the actual target
when judging task success. Speed is requested trajectory timing, not a guarantee
that per-event CDP latency matches a physical device.

This feature is CDP input, not an anti-ban or undetectability guarantee. It does
not authorize platform-account automation, messaging, scraping or evasion.

## Verification

Set `CHIP_RELAY_PYTHON` to the existing qualified Python environment with
Playwright installed; do not infer dependency absence from ambient Python.
Offline checks:

```bash
PYTHONPATH="$PWD" "$CHIP_RELAY_PYTHON" -m unittest discover -s tests -p test_swipe.py -v
```

Explicit disposable live fixture (existing executable, no browser download):

```bash
PYTHONPATH="$PWD" "$CHIP_RELAY_PYTHON" scripts/smoke-swipe-fixture.py \
  --fixture-only --executable "$APPROVED_FIXTURE_CHROMIUM" \
  --output "$TASK_PRIVATE_RECEIPT"
```

The harness starts and closes only its own temporary browser/profile/listener,
creates a real exact-PID binding, exercises the normal bound task child, measures
RAF scroll position **after the trusted touchEnd**, checks eventual stopping,
compares stationary-release control, checks reverse direction, denial/other-page
isolation and unchanged device settings. Never run the fixture against a shared
account profile or make its result a LinkedIn/provider-login claim.
