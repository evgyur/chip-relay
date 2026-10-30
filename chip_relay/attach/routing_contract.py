"""One registry's site/account/network contracts. No owner or network mutation."""

from __future__ import annotations
import ipaddress
import time
from urllib.parse import urlsplit
from .binding import BindingError, select_binding

NETWORK_FIELDS = {"kind", "expected_ips", "evidence", "scope"}
KINDS = {"unspecified", "exact-ipv4", "operator-required"}


def validate(bindings):
    catalog = bindings.get("routing")
    if catalog is None:
        return None
    if (
        not isinstance(catalog, dict)
        or set(catalog)
        != {"schema", "rules", "networks", "profile_networks", "inventory", "conflicts"}
        or catalog["schema"] != "relay-routing-v1"
    ):
        raise BindingError("routing_schema_invalid")
    networks = catalog["networks"]
    if not isinstance(networks, dict) or not networks:
        raise BindingError("routing_networks_invalid")
    for key, row in networks.items():
        if (
            not isinstance(key, str)
            or not isinstance(row, dict)
            or set(row) != NETWORK_FIELDS
            or row["kind"] not in KINDS
            or not isinstance(row["evidence"], str)
            or not row["evidence"]
            or not isinstance(row["scope"], str)
        ):
            raise BindingError("routing_network_invalid")
        if not isinstance(row["expected_ips"], list):
            raise BindingError("routing_ips_invalid")
        for address in row["expected_ips"]:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                raise BindingError("routing_ip_literal_required") from None
            if str(parsed) != address or parsed.version != 4 or not parsed.is_global:
                raise BindingError("routing_public_ipv4_required")
        if row["kind"] == "exact-ipv4" and not row["expected_ips"]:
            raise BindingError("routing_expected_ip_required")
        if row["kind"] != "exact-ipv4" and row["expected_ips"]:
            raise BindingError("routing_unexpected_ip_constraint")
    defaults = catalog["profile_networks"]
    if (
        not isinstance(defaults, dict)
        or set(defaults) != set(bindings["profiles"])
        or any(n not in networks for n in defaults.values())
    ):
        raise BindingError("routing_profile_coverage_invalid")
    if not isinstance(catalog["rules"], list):
        raise BindingError("routing_rules_invalid")
    seen = set()
    for row in catalog["rules"]:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "id",
                "domains",
                "workflow",
                "account",
                "profile",
                "network",
                "evidence",
            }
            or not isinstance(row["id"], str)
            or row["id"] in seen
        ):
            raise BindingError("routing_rule_invalid")
        seen.add(row["id"])
        select_binding(bindings, row["profile"])
        if (
            row["network"] not in networks
            or not isinstance(row["domains"], list)
            or not row["domains"]
        ):
            raise BindingError("routing_rule_invalid")
        for domain in row["domains"]:
            if (
                not isinstance(domain, str)
                or domain != domain.lower()
                or not domain
                or any(
                    c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in domain
                )
                or domain.startswith(".")
                or domain.endswith(".")
                or ".." in domain
            ):
                raise BindingError("routing_domain_invalid")
        if row["workflow"] is not None and (
            not isinstance(row["workflow"], str) or not row["workflow"]
        ):
            raise BindingError("routing_workflow_invalid")
        if row["account"] is not None and (
            not isinstance(row["account"], str)
            or not row["account"]
            or any(c.isspace() for c in row["account"])
        ):
            raise BindingError("routing_account_invalid")
        if not isinstance(row["evidence"], str) or not row["evidence"]:
            raise BindingError("routing_evidence_required")

    if not isinstance(catalog["inventory"], dict) or set(catalog["inventory"]) != set(
        bindings["profiles"]
    ):
        raise BindingError("routing_inventory_coverage_invalid")
    if not isinstance(catalog["conflicts"], list):
        raise BindingError("routing_conflicts_invalid")
    return catalog


def intent(bindings, site, account, profile, workflow, network):
    catalog = validate(bindings)
    if catalog is None:
        if workflow or network:
            raise BindingError("routing_catalog_required")
        return account, profile, None
    host = urlsplit(site).hostname
    matches = [
        r
        for r in catalog["rules"]
        if any(host == d or host.endswith("." + d) for d in r["domains"])
        and (r["workflow"] == workflow if workflow else r["workflow"] is None)
    ]
    if workflow and not matches:
        raise BindingError("routing_workflow_site_unmapped")
    if matches:
        # Narrow host contracts dominate broader suffixes before account resolution.
        specificity = max(
            max(len(d) for d in r["domains"] if host == d or host.endswith("." + d))
            for r in matches
        )
        matches = [
            r
            for r in matches
            if any(
                len(d) == specificity and (host == d or host.endswith("." + d))
                for d in r["domains"]
            )
        ]
        if account:
            exact = [r for r in matches if r["account"] == account]
            if exact:
                matches = exact
            elif any(r["account"] is not None for r in matches):
                raise BindingError("routing_site_account_conflict")
        elif profile:
            matches = [
                r
                for r in matches
                if select_binding(bindings, r["profile"])[0]
                == select_binding(bindings, profile)[0]
            ]
            if not matches:
                raise BindingError("routing_profile_conflict")
        choices = {
            (r["account"], select_binding(bindings, r["profile"])[0], r["network"])
            for r in matches
        }
        if len(choices) != 1:
            raise BindingError("routing_account_ambiguous")
        rule = matches[0]
        if account is None:
            account = rule["account"]
        canonical = select_binding(bindings, rule["profile"])[0]
        if profile and select_binding(bindings, profile)[0] != canonical:
            raise BindingError("routing_profile_conflict")
        profile = canonical
        if network and network not in catalog["networks"]:
            raise BindingError("routing_network_unknown")
        if (
            network
            and network != rule["network"]
            and catalog["networks"][rule["network"]]["kind"] != "unspecified"
        ):
            raise BindingError("routing_network_conflict")
        return (
            account,
            profile,
            {
                "rule": rule["id"],
                "workflow": workflow,
                "network": network or rule["network"],
                "assigned_account": rule["account"] is not None,
            },
        )
    if workflow:
        raise BindingError("routing_workflow_site_unmapped")
    if network is not None and network not in catalog["networks"]:
        raise BindingError("routing_network_unknown")
    return account, profile, {"rule": None, "workflow": None, "network": network}


def contract(bindings, profile, intent):
    catalog = validate(bindings)
    if catalog is None:
        return None
    requested = intent.get("network") if intent else None
    default = catalog["profile_networks"][profile]
    if (
        requested
        and default != requested
        and catalog["networks"][default]["kind"] != "unspecified"
    ):
        raise BindingError("routing_profile_network_conflict")
    network = requested or default
    from .profile_selection import digest

    return {
        "rule": intent.get("rule") if intent else None,
        "workflow": intent.get("workflow") if intent else None,
        "network": network,
        "policy": catalog["networks"][network],
        "catalog_sha256": digest(catalog),
        "proof": None,
    }


def require_network(selection):
    route = selection.get("routing") if selection else None
    if not route or route["policy"]["kind"] == "unspecified":
        return
    if route["policy"]["kind"] == "operator-required":
        raise BindingError("routing_network_operator_verification_required")
    proof = route.get("proof")
    if not isinstance(proof, dict) or set(proof) != {
        "source",
        "ip",
        "observed_at",
        "entry_sha256",
        "scope_sha256",
    }:
        raise BindingError("routing_network_verification_required")
    from .profile_selection import digest

    scope = {k: v for k, v in selection.items() if k != "routing"}
    if (
        proof["source"] != "same-browser-default-context-ipify-ipv4"
        or proof["ip"] not in route["policy"]["expected_ips"]
        or proof["entry_sha256"] != selection["entry_sha256"]
        or proof["scope_sha256"] != digest(scope)
    ):
        raise BindingError("routing_network_proof_mismatch")
    if (
        type(proof["observed_at"]) not in (int, float)
        or not 0 <= time.time() - proof["observed_at"] <= 60
    ):
        raise BindingError("routing_network_proof_stale")


def probe(bindings, entry, selection):
    from playwright.sync_api import Error

    try:
        return _probe(bindings, entry, selection)
    except Error:
        raise BindingError("routing_network_probe_failed") from None


def _probe(bindings, entry, selection):
    """Observe only a new public diagnostic page in the selected default context."""
    route = selection.get("routing")
    if not route or route["policy"]["kind"] != "exact-ipv4":
        raise BindingError("routing_network_probe_not_supported")
    from .binding import verify_binding
    from .profile_selection import digest
    from playwright.sync_api import sync_playwright

    verify_binding(entry)
    with sync_playwright() as driver:
        browser = driver.chromium.connect_over_cdp(entry["endpoint"], timeout=5000)
        if not browser.contexts:
            raise BindingError("routing_default_context_missing")
        page = browser.contexts[0].new_page()
        try:
            response = page.goto(
                "https://api.ipify.org/?format=json",
                timeout=10000,
                wait_until="domcontentloaded",
            )
            if (
                not response
                or response.status != 200
                or page.url != "https://api.ipify.org/?format=json"
            ):
                raise BindingError("routing_network_probe_response_invalid")
            body = response.text()
            if len(body) > 1024:
                raise BindingError("routing_network_probe_response_invalid")
            import json

            value = json.loads(body)
            if not isinstance(value, dict) or set(value) != {"ip"}:
                raise BindingError("routing_network_probe_response_invalid")
            if not isinstance(value["ip"], str):
                raise BindingError("routing_network_probe_ip_literal_required")
            try:
                observed = str(ipaddress.IPv4Address(value["ip"]))
            except ValueError:
                raise BindingError(
                    "routing_network_probe_ip_literal_required"
                ) from None
            if observed != value["ip"]:
                raise BindingError("routing_network_probe_ip_literal_required")
        finally:
            page.close()
    verify_binding(entry)
    if observed not in route["policy"]["expected_ips"]:
        raise BindingError("routing_network_exit_mismatch")
    import copy

    checked = copy.deepcopy(selection)
    checked["routing"]["proof"] = {
        "source": "same-browser-default-context-ipify-ipv4",
        "ip": observed,
        "observed_at": time.time(),
        "entry_sha256": selection["entry_sha256"],
        "scope_sha256": digest({k: v for k, v in selection.items() if k != "routing"}),
    }
    require_network(checked)
    return checked
