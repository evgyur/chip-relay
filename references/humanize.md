# Humanized input on the selected relay page

Default: off. The dependency doctor verifies package **and source commit**,
not browser health or account login. From the repository root:

```bash
python3 -c 'import json; from chip_relay.humanize import doctor; print(json.dumps(doctor()))'
```

## Public adapter configuration

This additive adapter does not replace the existing public supervisor or CLI.
For input it requires an operator-supplied exact external binding, not a guessed
CDP URL. The task config accepts `RELAY_BOUND_ENTRY` (a private JSON entry) and
`CHIP_RELAY_CDP_URL`; their endpoints must agree. Binding fields are `lifecycle`
(`external`), `endpoint`, `uid`, `pid`, `start_time`, `executable`, `profile_path`,
`profile_inode`, `profile_device`, `profile_directory` and `capabilities`. Obtain
values from the intended live owner, process generation and existing profile;
never fabricate them or copy another user's registry. Keep this metadata in
private task configuration, not shell history, published examples or reports.
The binding guard checks ownership, executable, listener and profile identity.

The normal `run_final_script` runner revalidates a supplied binding and passes it
to the task child. Unbound legacy tasks remain unchanged, but `humanize_page`
refuses to dispatch input without a verified binding. This release does not add
the private operator's selection CLI or publish its account/network registry.
When an external selection context is supplied, its existing read-only, origin,
account and network guards remain in force.

## Optional click/fill dependency

The SDK is pinned to source
`b1a00eda61efe71da2a1a38831fa6fe861f5d91d`; a PyPI package with the same version
number is not interchangeable. Requirements are in `requirements-humanize.txt`.
Only the MIT Python behavior layer is used. No engine, launch, license-login,
update, download or global BrowserOS/Playwright replacement is invoked.

Inside the verified task's `scripts/final.py`:

```python
from chip_relay.humanize import humanize_page

with humanize_page(
    selected_page,
    expected_origin=selected_origin,
    expected_account=expected_account,
    identity_check=lambda: read_destination_account() == expected_account,
    mode="default",  # or "careful"; omitted => off
) as human:
    human.fill(selected_page.get_by_label("Search"), ordinary_text)
    human.click(selected_page.get_by_role("button", name="Search", exact=True))
```

Resolve account/origin from the task's selection; do not substitute a convenient
profile or make `identity_check` a constant True. It must inspect the live
provider identity for authenticated work. A synthetic fixture does not prove a
real provider login. Read back the business result after clicking; a completed
input action is not completed business work.

## Native touch swipe

The same scoped facade also provides `human.swipe(direction="up", distance=240, speed=1200, inertia=True, timeout=5000)`. It uses native CDP touch input in all modes, independently of the click/fill SDK, and returns observed document scrolling after release. It does not change mobile/touch emulation, UA or viewport. Read [swipe contract and live fixture](swipe.md) before use; directions describe finger motion, so `up` scrolls content down. Inertia is measured, not guaranteed on every page/build.

## Guards and limitations

- Only one explicitly selected page; no Page/Locator class monkeypatches or
  other-page markers. The task page is explicitly brought to front for opted-in
  input to avoid background render throttling. This is not OS/client focus proof.
- Existing owner/endpoint checks remain in force. A supplied selection context
  must match the binding, account and origin. Identity-check pins are read-only.
- Exactly one unique visible enabled locator. Check both its root frame and the
  resolved node's document origin; FrameLocator chains can hide cross-origin
  frames behind an outer-frame locator. Opaque/non-HTTP origins are unsupported.
- Plain text/textarea fields only; password, OTP, token, mnemonic and secret-field
  hints are rejected before entry. Use the existing secret-reference executor
  for credentials, never this adapter. No payment/signing/CAPTCHA authority.
- Typos and idle simulation are disabled. ASCII, shifted symbols, Cyrillic and
  emoji were qualified on a synthetic page. No JavaScript click or value-setting
  fallback; typed content is not logged.
- One action budget spans preflight, SDK/native dispatch and readback, not one
  timeout per mouse step. Expired preflight cannot start input; readback never
  receives a fresh budget. Synchronous owner checks and caller identity callbacks
  can delay error delivery, but cannot refresh the budget or authorize late input.
  Keep identity callbacks bounded. Timeout can leave the business effect uncertain:
  inspect before retrying. No automatic retry or fallback to another input backend.
- `off` uses native input with the same guards and budget. `default` and `careful` use the pinned
  instance-local engine. This is CDP input, not physical NoMachine keyboard or
  clipboard acceptance, not guaranteed invisibility, and not a Python sandbox.

## Qualify adapter changes in order

1. Test one absolute deadline across the entire action. Expire the clock during owner checks and target evaluation and assert zero backend dispatches; also test cancellation of pending async metadata and readback consuming only the remaining budget. Replace the facade's clock object for deterministic tests, not process-global `time.monotonic`, which also drives asyncio's timers.
2. Keep hand-written mocks aligned with both the sync facade and the async locator implementation it actually calls. Then exercise the pinned SDK and Playwright against a real synthetic page; mocked dispatch alone does not qualify their interface.
3. Cover both opted-in modes, exact Unicode/shifted text, trusted events, single-click effects, other-page isolation and same-/cross-origin FrameLocator targets. After an occluded-target timeout, assert no click occurred and no alternate backend or retry ran.
4. Exercise selection through the real task child, not only a resolver unit test. Check preservation of canonical profile, task session and origin; reject conflicting profile, session and destination before browser action. Treat that as intent/transport evidence, never provider-login proof.
5. Recheck the production owner separately before reporting health. If it stopped during qualification, do not rebind or silently choose another account. Use a clearly labelled, task-owned disposable fixture for adapter tests when needed, never as a replacement route for the actual task; close its listeners and terminate only its owned browser process.

The task owns and closes its fixture/page context; the adapter never closes or
restarts a shared browser. The driver disconnects when the task child exits.
