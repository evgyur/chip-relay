import copy, tempfile, time, unittest, json
from ipaddress import IPv4Address

PUBLIC_V4 = str(IPv4Address(134744072))
OTHER_V4 = str(IPv4Address(16843009))
from pathlib import Path
from unittest.mock import patch, MagicMock
from test_attach_profile_selection import registry
from chip_relay.attach.binding import BindingError
from chip_relay.attach.profile_selection import (
    resolve,
    write_selection,
    read_selection,
    digest,
)
from chip_relay.attach.routing_contract import validate, require_network, probe


def catalog():
    d = registry()
    networks = {
        "inherit": {
            "kind": "unspecified",
            "expected_ips": [],
            "evidence": "no recorded requirement",
            "scope": "egress unknown",
        },
        "fixed": {
            "kind": "exact-ipv4",
            "expected_ips": [PUBLIC_V4],
            "evidence": "synthetic test constraint, not actual egress",
            "scope": "IPv4 only",
        },
        "mac": {
            "kind": "operator-required",
            "expected_ips": [],
            "evidence": "owner method required",
            "scope": "RU destination IPv4, not IPv6",
        },
    }
    rule = (
        lambda ident, account, profile, domains=["accounts.example.test"], workflow=None: (
            dict(
                id=ident,
                domains=domains,
                workflow=workflow,
                account=account,
                profile=profile,
                network="inherit",
                evidence="test owner assignment",
            )
        )
    )
    d["routing"] = {
        "schema": "relay-routing-v1",
        "rules": [
            rule("first", "first@example.test", "a"),
            rule("second", "second@example.test", "b"),
            rule("project", "first@example.test", "b", ["project.test"]),
            rule(
                "registration", "first@example.test", "b", ["project.test"], "register"
            ),
        ],
        "networks": networks,
        "profile_networks": {p: "inherit" for p in d["profiles"]},
        "inventory": {p: {"identity": "unknown"} for p in d["profiles"]},
        "conflicts": [],
    }
    return d


def pin(d=None, **kwargs):
    return resolve(
        d or catalog(),
        site=kwargs.pop("site", "https://accounts.example.test"),
        account=kwargs.pop("account", "second@example.test"),
        session="task-one",
        **kwargs,
    )


class RoutingTests(unittest.TestCase):
    def test_account_specific_route_and_no_live_login_claim(self):
        value = pin()
        self.assertEqual(value["profile"], "account-b")
        self.assertFalse(value["live_identity_verified"])
        self.assertIsNone(value["routing"]["proof"])

    def test_ambiguous_site_never_defaults(self):
        with self.assertRaisesRegex(BindingError, "ambiguous"):
            pin(account=None)

    def test_site_specific_profile_overrides_legacy_account_default(self):
        self.assertEqual(
            pin(site="https://project.test", account="first@example.test")["profile"],
            "account-b",
        )

    def test_explicit_profile_conflict(self):
        with self.assertRaisesRegex(BindingError, "profile_conflict"):
            pin(profile="main")

    def test_workflow_is_site_bound(self):
        self.assertEqual(
            pin(site="https://project.test", account=None, workflow="register")[
                "expected_account"
            ],
            "first@example.test",
        )
        with self.assertRaisesRegex(BindingError, "workflow_site"):
            pin(workflow="register")

    def test_cannot_replace_known_site_account(self):
        with self.assertRaisesRegex(BindingError, "site_account_conflict"):
            pin(account="unknown@example.test")

    def test_unknown_network_and_stricter_requested_network(self):
        with self.assertRaisesRegex(BindingError, "network_unknown"):
            pin(network="imaginary")
        self.assertEqual(pin(network="mac")["routing"]["network"], "mac")

    def test_unknown_operator_network_stays_blocked(self):
        with self.assertRaisesRegex(BindingError, "operator_verification"):
            require_network(pin(network="mac"))

    def test_missing_and_wrong_network_proof(self):
        value = pin(network="fixed")
        with self.assertRaisesRegex(BindingError, "verification_required"):
            require_network(value)
        value["routing"]["proof"] = {
            "source": "curl",
            "ip": PUBLIC_V4,
            "observed_at": time.time(),
            "entry_sha256": value["entry_sha256"],
            "scope_sha256": digest({k: v for k, v in value.items() if k != "routing"}),
        }
        with self.assertRaisesRegex(BindingError, "proof_mismatch"):
            require_network(value)

    def test_fresh_scope_bound_observation_and_expiry(self):
        value = pin(network="fixed")
        value["routing"]["proof"] = {
            "source": "same-browser-default-context-ipify-ipv4",
            "ip": PUBLIC_V4,
            "observed_at": time.time(),
            "entry_sha256": value["entry_sha256"],
            "scope_sha256": digest({k: v for k, v in value.items() if k != "routing"}),
        }
        require_network(value)
        changed = copy.deepcopy(value)
        changed["session"] = "other"
        with self.assertRaisesRegex(BindingError, "mismatch"):
            require_network(changed)
        value["routing"]["proof"]["observed_at"] -= 61
        with self.assertRaisesRegex(BindingError, "stale"):
            require_network(value)

    def test_changed_catalog_and_legacy_pins_require_reselection(self):
        d = catalog()
        value = pin(d)
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "pin"
            write_selection(str(p), value)
            self.assertEqual(read_selection(str(p), d), value)
            modified = copy.deepcopy(d)
            modified["routing"]["networks"]["inherit"]["evidence"] = "changed"
            with self.assertRaisesRegex(BindingError, "routing_stale"):
                read_selection(str(p), modified)
            legacy = copy.deepcopy(value)
            del legacy["routing"]
            q = Path(tmp) / "legacy"
            write_selection(str(q), legacy)
            with self.assertRaisesRegex(BindingError, "routing_reselect"):
                read_selection(str(q), d)

    def test_all_profiles_must_be_covered(self):
        d = catalog()
        del d["routing"]["profile_networks"]["meeting"]
        with self.assertRaisesRegex(BindingError, "coverage"):
            validate(d)

    def test_ip_literals_and_no_unknown_network_fields(self):
        for field, value in [
            ("expected_ips", ["localhost"]),
            ("expected_ips", ["127.0.0.1"]),
            ("password", "forbidden"),
        ]:
            d = catalog()
            d["routing"]["networks"]["fixed"][field] = value
            with self.assertRaises(BindingError):
                validate(d)

    def test_narrow_domain_dominates_broad_suffix(self):
        d = catalog()
        r = copy.deepcopy(d["routing"]["rules"][0])
        r.update(
            id="broad",
            domains=["example.test"],
            account="first@example.test",
            profile="a",
        )
        d["routing"]["rules"].append(r)
        self.assertEqual(pin(d)["profile"], "account-b")

    def test_probe_uses_same_context_and_closes_only_own_page(self):
        value = pin(network="fixed")
        driver = MagicMock()
        browser = driver.chromium.connect_over_cdp.return_value
        context = MagicMock()
        browser.contexts = [context]
        page = context.new_page.return_value
        page.url = "https://api.ipify.org/?format=json"
        page.goto.return_value.status = 200
        page.goto.return_value.text.return_value = json.dumps({"ip": PUBLIC_V4})
        manager = MagicMock()
        manager.__enter__.return_value = driver
        with (
            patch("playwright.sync_api.sync_playwright", return_value=manager),
            patch(
                "chip_relay.attach.binding.verify_binding",
                return_value={"verified": True},
            ),
        ):
            checked = probe(catalog(), {"endpoint": "http://127.0.0.1:1234"}, value)
        require_network(checked)
        page.close.assert_called_once()
        browser.close.assert_not_called()
        context.close.assert_not_called()

    def test_nonliteral_public_ip_response_cannot_be_coerced_into_proof(self):
        import json

        for bad in [134744072, True, "00" + PUBLIC_V4, " " + PUBLIC_V4]:
            driver = MagicMock()
            browser = driver.chromium.connect_over_cdp.return_value
            context = MagicMock()
            browser.contexts = [context]
            page = context.new_page.return_value
            page.url = "https://api.ipify.org/?format=json"
            page.goto.return_value.status = 200
            page.goto.return_value.text.return_value = json.dumps({"ip": bad})
            manager = MagicMock()
            manager.__enter__.return_value = driver
            with (
                patch("playwright.sync_api.sync_playwright", return_value=manager),
                patch(
                    "chip_relay.attach.binding.verify_binding",
                    return_value={"verified": True},
                ),
            ):
                with self.assertRaisesRegex(BindingError, "ip_literal_required"):
                    probe(
                        catalog(),
                        {"endpoint": "http://127.0.0.1:1234"},
                        pin(network="fixed"),
                    )
            page.close.assert_called_once()
