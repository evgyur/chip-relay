# Opt-in desktop companion (Linux)

This additive Relay executor uses Vercel Labs `agent-desktop` v1.2.0
(source `2b0a7334fc111730454b726e6800aa41cdafc093`, Apache-2.0).
The adapter itself remains under this repository's MIT license; no upstream
source is vendored. Download the native Linux archive from the official release
and verify the publisher's SHA-256 before executing it.

## Authority and limits

This is NOT a replacement browser engine or a global desktop MCP. Existing
browser selection, account routing, profiles, egress and lifecycle stay external
and unchanged. The companion exposes only bind, snapshot and semantic click.
It has no launch, keyboard, typing, clipboard, screenshot, coordinates, global
surface or headed fallback. It cannot establish account identity on its own.
Do not bind a signed-in browser, wallet, credential form, private messaging app,
payment surface or any app containing secrets under this initial qualification.
The accepted test target is a disposable non-secret GTK application.

A binding is a cooperative same-UID grant, not OS isolation: the native utility
and the Unix user can access more than this wrapper exposes. Bind only an
explicitly approved non-secret app/window. Snapshots and native refmaps may
contain UI text (including GTK4 visually hidden passwords); they are stored
under the target directory and must never enter public logs or uploads.

## Setup and use

Run the companion with Relay's declared managed interpreter, not an ambient
Python or another browser installation. The installed entrypoint is
`scripts/relay-desktop.sh`.

First create a private parent directory (`0700`) outside every real browser
profile. Obtain the target's PID and exact window id/app name/title in its own
approved desktop session. Binding requires the process to belong to the caller,
a readable process generation and desktop environment, and an exact live window
match. No alternate session is guessed.

```sh
scripts/relay-desktop.sh --target /private/targets/synthetic bind \
  --binary /approved/path/to/agent-desktop --pid 1234 \
  --app exact-app-name --window-id exact-native-window-id \
  --title 'Exact approved non-secret title' --allow-nonsecret-ui
scripts/relay-desktop.sh --target /private/targets/synthetic snapshot
scripts/relay-desktop.sh --target /private/targets/synthetic click '@snapshot:e1' \
  --expect-name 'Synthetic action' --expect-role button
scripts/relay-desktop.sh --target /private/targets/synthetic snapshot
```

The binding pins binary bytes, process start/executable, session environment,
native process instance and window. A changed generation/session/window blocks;
a restart needs a new explicitly scoped binding, not a browser restart/rebind.
Snapshots must match the bound window and their native refmaps must pin the same
PID, native process instance, app, window id and title. Only the latest complete
snapshot is actionable, for at most 120 seconds. Expected name/role must be
unique in that observation and advertise Click.

Native v1.2.0 also checks live identity/uniqueness and the recorded process/window
at ref resolution and before delivery: see Linux `tree/resolve/resolve_identity.rs`,
`tree/resolve/resolve_refusal_tests.rs` and `actions/process_check.rs` at the pinned
revision. The adapter's preliminary window enumeration is NOT an atomic security
boundary. Native semantic checks are a dependency, not a claim that all desktop
TOCTOU or malicious same-user changes are prevented.

The adapter exclusively claims a snapshot before dispatch and fsyncs both the
claim and its parent directory. One attempted click consumes that snapshot,
including failures, crashes and uncertain delivery. Do not delete claims to
repeat a possibly executed action: observe the application and take a fresh
snapshot. Native errors retain their delivery/retry disposition; adapter errors
conservatively report unknown/unsafe. A native success is not proof of an
application's durable business effect: take a fresh snapshot or task-specific
readback. No automatic retry is performed.

## Verification

```sh
python -m unittest discover -s tests -p test_desktop.py -v
```

Unit probes cover ambiguity, missing/bare refs, expected name/role, incomplete
observations, capability absence, process/session drift, private-file and
symlink rejection, binary-scoped native metadata, receipt freshness, exclusive
claims and directory fsync. Live acceptance must exercise the installed companion
against a disposable Xvfb + D-Bus + GTK fixture, including visible click effect,
stale native ref rejection, superseded observation and replay blocking.
No tests on this fixture qualify signed-in application access.
