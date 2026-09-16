# Browser operation lifecycle

Use this contract for every browser action that may change browser or business state.

## Effect states

- `succeeded`: completion was positively observed.
- `failed`: dispatch provably did not happen. This is the only automatically retryable terminal state.
- `cancelled`: the operation was cancelled before dispatch.
- `unknown`: dispatch may have happened, but completion cannot be proved.
- `interrupted`: an `operation_started` record has no terminal record, usually after process loss.

A dispatched action must never be rewritten as `failed`. Reconcile the live page and the external business state before retrying `unknown` or `interrupted`.

Current audited operations:

- `task.final_script` (`external`);
- `browser_use.execute` (`browser-state`);
- `captcha.native_activation` (`browser-state`);
- `captcha.visual_action` (`browser-state`).

## Audit

```bash
scripts/chip-relay task audit <run_id> show
scripts/chip-relay relay /relay task audit <run_id> show
```

Events are appended to `audit/operations.jsonl` with owner-only directory/file modes `0700`/`0600`. The file is capped at 16 MiB. Writes are descriptor-pinned, reject symlinks and non-regular files, and are serialized with an advisory lock. Fully terminal files are truncated after 30 days; pending operations and currently waiting handoffs block expiry.

Only allowlisted metadata is accepted: operation/effect class, attempt marker, bounded page/provider labels, counts, visual cycle, and URL origin. Full URL paths and query strings are reduced to `scheme://host[:port]`.

The audit never stores:

- DOM, page text, selectors, scripts, or screenshots;
- input values, passwords, OTPs, tokens, cookies, or authorization data;
- local file paths or raw exception/error messages.

## Human handoff

```bash
scripts/chip-relay task handoff <run_id> request \
  --kind login \
  --reason-code login_required \
  --timeout 600
scripts/chip-relay task handoff <run_id> show
scripts/chip-relay task handoff <run_id> resolve <handoff_id>
scripts/chip-relay task handoff <run_id> cancel <handoff_id>
```

Kinds are `login`, `two_factor`, `consent`, `confirmation`, `captcha`, and `other`. Reasons are closed, machine-readable codes. State is `waiting`, `resolved`, `cancelled`, or `timed_out` and is bound to the current execution attempt. Starting a new execution attempt makes an older waiting handoff stale. State commits carry a one-transition durable audit outbox; every API entry reconciles it under the execution lock, and audit publication is idempotent by handoff ID plus status. Expiration is terminalized before reuse, resolution, cancellation, or replacement.

A handoff record contains no user answer. A password, OTP, consent text, or other protected response belongs only in the trusted browser/UI, never in the CLI argument or handoff file.

CAPTCHA is stricter: a visible interactive challenge starts as `agent_action`. Relay durably consumes the native allowance before dispatch and merges that bit monotonically at every same-page state commit, so stale wait/inspect observations cannot restore it. It observes managed clearance, attempts at most one unambiguous provider-owned checkbox activation per task attempt, then requires Hermes to use the private pinned visual capture/action loop. A CAPTCHA handoff is created automatically only after the third uncleared visual cycle. `captcha_visual_unavailable` is accepted only with same-attempt state proving one consumed native attempt plus an allowlisted real capture failure; a caller-selected reason alone is not evidence.
