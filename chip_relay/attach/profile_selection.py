"""Read-only intent resolution and task-local route pins; never discover/login/attach.

The canonical binding remains the only registry. Account assignments are expected
identities, not authentication evidence. Same-UID task Python is not sandboxed.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import stat
from urllib.parse import urlsplit
from .binding import BindingError, select_binding

SCHEMA = "relay-profile-selection-v1"
PURPOSES = {"authenticated", "identity-check", "public"}
FIELDS = {
    "schema",
    "profile",
    "expected_account",
    "origin",
    "purpose",
    "session",
    "entry_sha256",
    "route_sha256",
    "reason",
    "live_identity_verified",
}


def normalize_origin(url: str) -> str:
    u = urlsplit(url)
    if (
        u.scheme not in {"https", "http"}
        or not u.hostname
        or u.username is not None
        or u.password is not None
    ):
        raise BindingError("selection_http_origin_required")
    port = u.port if u.port is not None else (443 if u.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise BindingError("selection_port_invalid")
    host = "[" + u.hostname + "]" if ":" in u.hostname else u.hostname
    return f"{u.scheme}://{host}:{port}"


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def check_site(entry: dict, url: str) -> None:
    capabilities = entry.get("capabilities", {})
    if capabilities.get("task_policy"):
        raise BindingError("selection_legacy_site_policy_adapter_required")
    if "allowed_sites" not in capabilities:
        return
    allowed = capabilities["allowed_sites"]
    if (
        not isinstance(allowed, list)
        or not allowed
        or any(
            not isinstance(d, str)
            or not d
            or d != d.lower()
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in d)
            or d.startswith(".")
            or d.endswith(".")
            or ".." in d
            for d in allowed
        )
    ):
        raise BindingError("selection_site_policy_invalid")
    host = urlsplit(normalize_origin(url)).hostname

    if not any(host == d or host.endswith("." + d) for d in allowed):
        raise BindingError("selection_site_policy_mismatch")


def _route(bindings: dict, account: str | None) -> dict | None:
    routes = bindings.get("account_routes", {})
    if not isinstance(routes, dict):
        raise BindingError("account_routes_invalid")
    row = routes.get(account) if account is not None else None
    if row is not None and (
        not isinstance(row, dict)
        or set(row) != {"profile", "evidence"}
        or not isinstance(row.get("profile"), str)
        or not isinstance(row.get("evidence"), str)
        or not row["evidence"]
    ):
        raise BindingError("account_route_invalid")
    return row


def resolve(
    bindings: dict,
    *,
    site: str,
    account: str | None = None,
    profile: str | None = None,
    purpose: str = "authenticated",
    session: str = "default",
    workflow: str | None = None,
    network: str | None = None,
) -> dict:
    target = normalize_origin(site)
    if not isinstance(session, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", session
    ):
        raise BindingError("selection_session_invalid")
    if purpose not in PURPOSES:
        raise BindingError("selection_purpose_invalid")
    from .routing_contract import intent, contract

    account, profile, route_intent = intent(
        bindings, target, account, profile, workflow, network
    )
    if account is not None and (
        not isinstance(account, str)
        or not 1 <= len(account) <= 256
        or any(c.isspace() or ord(c) < 32 for c in account)
    ):
        raise BindingError("selection_exact_account_id_required")
    if purpose == "authenticated" and not account:
        raise BindingError("account_intent_required")
    if purpose == "identity-check" and not profile:
        raise BindingError("identity_check_explicit_candidate_required")
    row = _route(bindings, account)
    mapped = select_binding(bindings, row["profile"])[0] if row else None
    if route_intent and route_intent.get("assigned_account"):
        # Site-qualified assignments outrank the legacy account-wide default.
        mapped = select_binding(bindings, profile)[0]
    explicit = select_binding(bindings, profile)[0] if profile else None
    if mapped and explicit and mapped != explicit:
        raise BindingError("profile_account_conflict")
    if mapped:
        selected, reason = mapped, "documented_account_assignment"
    elif explicit:
        selected, reason = explicit, "explicit_profile_pending_live_identity"
    elif account:
        raise BindingError("account_profile_unmapped")
    else:
        host = urlsplit(target).hostname
        routes = bindings.get("site_routes", {})
        if not isinstance(routes, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in routes.items()
        ):
            raise BindingError("selection_site_routes_invalid")
        matches = [
            (d, p) for d, p in routes.items() if host == d or host.endswith("." + d)
        ]
        if not matches:
            raise BindingError("profile_intent_required")
        alias = max(matches, key=lambda x: len(x[0]))[1]
        selected = select_binding(bindings, alias)[0]
        reason = "public_site_hint_not_account_proof"
    entry = bindings["profiles"][selected]
    check_site(entry, target)
    value = {
        "schema": SCHEMA,
        "profile": selected,
        "expected_account": account,
        "origin": target,
        "purpose": purpose,
        "session": session,
        "entry_sha256": digest(entry),
        "route_sha256": digest(row),
        "reason": reason,
        "live_identity_verified": False,
    }
    route_contract = contract(bindings, selected, route_intent)
    if route_contract is not None:
        value["routing"] = route_contract
    return value


def write_selection(path: str, value: dict) -> None:
    p = Path(path)
    if not p.is_absolute() or p != p.resolve() or not p.parent.is_dir():
        raise BindingError("selection_private_absolute_path_required")
    info = p.parent.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise BindingError("selection_parent_owner_or_permissions")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def read_selection(
    path: str,
    bindings: dict,
    explicit_profile: str | None = None,
    expected_session: str | None = None,
) -> dict:
    p = Path(path)
    if not p.is_absolute() or p != p.resolve(strict=True):
        raise BindingError("selection_path_rejected")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise BindingError("selection_owner_or_permissions")
        value = json.load(handle)
    if (
        not isinstance(value, dict)
        or set(value) not in (FIELDS, FIELDS | {"routing"})
        or value["schema"] != SCHEMA
        or value["live_identity_verified"] is not False
    ):
        raise BindingError("selection_schema_invalid")
    if (
        explicit_profile
        and select_binding(bindings, explicit_profile)[0] != value["profile"]
    ):
        raise BindingError("selection_profile_conflict")
    if expected_session is not None and value["session"] != expected_session:
        raise BindingError("selection_task_session_mismatch")
    if "routing" in value and not isinstance(value["routing"], dict):
        raise BindingError("selection_routing_schema_invalid")
    current = resolve(
        bindings,
        site=value["origin"],
        account=value["expected_account"],
        profile=value["profile"],
        purpose=value["purpose"],
        session=value["session"],
        workflow=value.get("routing", {}).get("workflow"),
        network=value.get("routing", {}).get("network"),
    )
    if value["origin"] != current["origin"]:
        raise BindingError("selection_noncanonical_origin")
    if (
        current["entry_sha256"] != value["entry_sha256"]
        or current["route_sha256"] != value["route_sha256"]
    ):
        raise BindingError("selection_stale_reselect_required")
    expected = current.get("routing")
    supplied = value.get("routing")
    if expected is not None:
        if not isinstance(supplied, dict) or set(supplied) != set(expected):
            raise BindingError("selection_routing_reselect_required")
        if {k: v for k, v in supplied.items() if k != "proof"} != {
            k: v for k, v in expected.items() if k != "proof"
        }:
            raise BindingError("selection_routing_stale")
        if supplied["proof"] is not None:
            from .routing_contract import require_network

            require_network(value)
    elif supplied is not None:
        raise BindingError("selection_routing_unexpected")
    return value


def command(
    args: list[str], bindings: dict, profile: str | None, session: str = "default"
) -> dict:
    if session == "default":
        raise BindingError("selection_explicit_task_session_required")
    parser = argparse.ArgumentParser(prog="relay select")
    parser.add_argument("--site", required=True)
    parser.add_argument("--account")
    parser.add_argument("--profile")
    parser.add_argument("--purpose", choices=sorted(PURPOSES), default="authenticated")
    parser.add_argument("--write")
    parser.add_argument("--workflow")
    parser.add_argument("--network")
    opts = parser.parse_args(args)
    if (
        profile
        and opts.profile
        and select_binding(bindings, profile)[0]
        != select_binding(bindings, opts.profile)[0]
    ):
        raise BindingError("conflicting_profile_selection")
    value = resolve(
        bindings,
        site=opts.site,
        account=opts.account,
        profile=profile or opts.profile,
        purpose=opts.purpose,
        session=session,
        workflow=opts.workflow,
        network=opts.network,
    )
    if opts.write:
        write_selection(opts.write, value)
    return {
        "status": "selected",
        "selection": value,
        "selection_path": opts.write,
        "browser_connected": False,
        "next": "Use --selection PATH; verify live destination account before private reads or writes.",
    }
