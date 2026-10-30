# Optional attach-only routing library

`chip_relay.attach` is additive. It does not replace the existing portable launcher,
start a browser, switch a profile, alter proxies, install a service, or grant sudo.
It exports portable routing, binding validation and default-off humanized input.
Personal account/profile assignments, network exits, private recipes, installations
and runtime history are intentionally not part of this repository.

## CLI

Choose the Python environment containing your explicitly installed dependencies.
The selector and registry inspection use the standard library; browser probes and
humanized input need the optional reviewed versions:

```bash
python -m pip install -r requirements-attach-humanize.txt
python -m chip_relay.attach doctor
python -m chip_relay.attach --binding "$PRIVATE_BINDING" routes
python -m chip_relay.attach --binding "$PRIVATE_BINDING" --session "$TASK_SESSION" \
  select --site "$TARGET_URL" --account "$EXPECTED_ACCOUNT" --write "$NEW_PRIVATE_PIN"
python -m chip_relay.attach --binding "$PRIVATE_BINDING" --session "$TASK_SESSION" \
  --selection "$NEW_PRIVATE_PIN" status
```

All routing flags precede the subcommand. `select` also accepts `--workflow` and
`--network`; these refer to operator-maintained rules, never invented defaults.
The CLI deliberately has no target-action, password, payment, CAPTCHA, launch,
kill or migration command. Existing `scripts/chip-relay` behavior is unchanged.

## Private registry contract

The caller supplies an absolute existing owner-only binding file (mode 0600).
There is no machine-specific default path. `relay-external-binding-v1` records:

`profiles`: explicit loopback CDP endpoint, UID/PID/process start time, executable,
profile directory, filesystem device/inode, optional pre-existing owner reader,
and capabilities. These values must come from the real supervised process;
an example PID or a folder label is not evidence. Linux ownership checks compare
process generation, profile identity and exact listener socket ownership before
and after inspection. An inaccessible owner is a failure, not absence.

The optional `allowed_sites` capability is a nonempty lowercase domain allowlist.
Private named `task_policy` adapters are not distributed: their presence blocks
until an operator integrates the appropriate adapter, rather than ignoring it.
These restrictions are checked before selected target use.

`aliases`, `account_routes` and `site_routes`: compatibility metadata. A service
alias is not an account identity. Site hints are not authentication proof.

Optional `routing` with schema `relay-routing-v1` contains `rules`, `networks`,
`profile_networks`, `inventory` and `conflicts`. Every profile needs an inventory
entry and a network requirement. Each rule contains `id`, `domains`, `workflow`,
`account`, `profile`, `network`, and `evidence`. A missing account is unresolved,
not a guessed email. More specific domains and site/workflow-qualified assignments
precede broad account defaults. Conflicts and ambiguity fail closed.

Network rows contain exactly `kind`, `expected_ips`, `evidence`, and `scope`.
`unspecified` means no verified dedicated requirement was recorded, NOT direct
or healthy networking. `exact-ipv4` requires canonical literal global IPv4
addresses from operator evidence. `operator-required` represents a distinct
method that this generic IPv4 observer cannot attest; it remains blocked rather
than being silently replaced with another network. No proxy credentials belong
in a route rule. No example live registry is distributed.

## Guard an integration's action

```python
from chip_relay.attach.runner import run_checked
from chip_relay.attach.humanize import humanize_page

def perform(entry, selection):
    # Consumer-owned connection/page; attach to entry['endpoint'], never launch.
    # Verify the destination's actual identity before reading private data.
    with humanize_page(
        selected_page,
        expected_origin=selection['origin'],
        expected_account=selection['expected_account'],
        identity_check=read_and_compare_live_provider_identity,
        mode='careful',
    ) as human:
        human.fill(selected_page.get_by_label('Search'), ordinary_text)
        human.click(selected_page.get_by_role('button', name='Search', exact=True))
    return read_actual_business_result()

result = run_checked(
    private_binding_path, private_pin_path, perform,
    session=task_session, target_url=target_url,
)
```

The consumer supplies the page, identity reader and business-result check.
`run_checked` validates the receipt, task session, exact target origin, required
network proof and actual browser owner, then provides context-local binding and
selection state. It rereads/revalidates files afterward, rejects a valid-but-
different pin or changed owner, restores context on failure and never retries
an uncertain effect. Required network proof is checked before the callback and
at completion; long-running consumers must recheck it before later actions.
Humanized actions also check it individually. There is no success/login flag
inferred from cookies, folder names, CLI credentials or a reachable CDP endpoint.

`humanize_page` is `off` by default. `default` and `careful` use the pinned MIT
Python behavior layer only, not its browser-launch/download/license APIs.
There are no global Page/Locator patches, typos, JavaScript click/value fallback,
secret-field input or automatic retries. Cross-origin frame input is rejected.
One budget spans target checks, backend dispatch and readback; slow synchronous
owner/identity callbacks may delay timeout delivery but cannot refresh that
budget or authorize late input. Input completion is not business completion.

## Network observation

For an operator-established `exact-ipv4` requirement:

```bash
python -m chip_relay.attach --binding "$PRIVATE_BINDING" --session "$TASK_SESSION" \
  --selection "$NEW_PRIVATE_PIN" network-check --write "$NEW_CHECKED_PIN"
```

The observer attaches to the selected existing browser, creates and closes only
its own public diagnostic page in the default persistent context, and reads the
actual HTTPS IPify response. It compares the literal address with the recorded
expectation, rechecks ownership, and creates a new private receipt. That scoped
observation expires after 60 seconds. It is not IPv6, country, an intermediate
proxy chain, selective destination routing, account login or continuous-network
attestation. A changed network needs a new observation. HTTP/probe failures stay
blocked; repeating an idempotent diagnostic is not retrying a business action.

## Security model and tests

This is a cooperative boundary for trusted local same-UID integrations, not a
Python sandbox or a signature against a malicious process that can rewrite the
registry. Arbitrary Python can bypass any library; consumers must use the guard.
Existing privilege and lifecycle owners stay authoritative. The optional fixed
owner reader uses an already-authorized noninteractive sudo route and a bounded
stdlib-only program; it does not create grants or execute candidate code as the
browser owner. CLI failures return bounded gate names, not raw private errors.

```bash
python -m unittest discover -s tests -p 'test_attach_*.py' -v
python tests/test_public_hygiene.py
```

The port keeps the routing/humanize regressions and adds public runner/CLI tests.
Private dispatcher, auth recipes, service wiring, machine paths, actual account
assignments and installation receipts are deliberately excluded. Local fixture
success must never be presented as access to a real provider account.
