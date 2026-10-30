import copy, json, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from chip_relay.attach.binding import BindingError
from chip_relay.attach.profile_selection import resolve, read_selection, write_selection


def registry():
    return {
        "profiles": {
            "account-a": {"pid": 11},
            "account-b": {"pid": 22},
            "meeting": {"pid": 33},
        },
        "aliases": {"main": "meeting", "a": "account-a", "b": "account-b"},
        "site_routes": {"accounts.example.test": "a", "mail.example.test": "a"},
        "account_routes": {
            "first@example.test": {"profile": "a", "evidence": "owner assignment"},
            "second@example.test": {"profile": "b", "evidence": "owner assignment"},
        },
    }


class SelectionTests(unittest.TestCase):
    def test_explicit_account_beats_generic_site_hint(self):
        chosen = resolve(
            registry(),
            site="https://accounts.example.test/login",
            account="second@example.test",
        )
        self.assertEqual(chosen["profile"], "account-b")
        self.assertFalse(chosen["live_identity_verified"])
        self.assertEqual(chosen["origin"], "https://accounts.example.test:443")

    def test_wrong_explicit_profile_never_silently_overrides_account(self):
        with self.assertRaisesRegex(BindingError, "profile_account_conflict"):
            resolve(
                registry(),
                site="https://accounts.example.test",
                account="second@example.test",
                profile="main",
            )

    def test_no_implicit_main_or_authenticated_default_account(self):
        for kwargs in [
            dict(site="https://accounts.example.test"),
            dict(site="https://unknown.test", purpose="public"),
        ]:
            with self.assertRaises(BindingError):
                resolve(registry(), **kwargs)

    def test_unknown_account_does_not_guess_profile(self):
        with self.assertRaisesRegex(BindingError, "account_profile_unmapped"):
            resolve(
                registry(),
                site="https://accounts.example.test",
                account="unknown@example.test",
            )
        explicit = resolve(
            registry(),
            site="https://accounts.example.test",
            account="unknown@example.test",
            profile="b",
        )
        self.assertEqual(explicit["reason"], "explicit_profile_pending_live_identity")
        self.assertFalse(explicit["live_identity_verified"])

    def test_explicit_alias_and_canonical_name_match(self):
        for name in ["a", "account-a"]:
            self.assertEqual(
                resolve(
                    registry(),
                    site="https://mail.example.test",
                    account="first@example.test",
                    profile=name,
                )["profile"],
                "account-a",
            )

    def test_identity_inspection_requires_an_explicit_candidate(self):
        with self.assertRaisesRegex(BindingError, "explicit_candidate"):
            resolve(
                registry(), site="https://mail.example.test", purpose="identity-check"
            )
        self.assertEqual(
            resolve(
                registry(),
                site="https://mail.example.test",
                purpose="identity-check",
                profile="b",
            )["profile"],
            "account-b",
        )

    def test_site_hint_is_public_only_and_domain_boundary_exact(self):
        self.assertEqual(
            resolve(registry(), site="https://sub.mail.example.test", purpose="public")[
                "profile"
            ],
            "account-a",
        )
        for url in [
            "https://notmail.example.test",
            "https://mail.example.test.evil.test",
        ]:
            with self.assertRaises(BindingError):
                resolve(registry(), site=url, purpose="public")

    def test_live_binding_change_expires_pin(self):
        old = registry()
        chosen = resolve(
            old, site="https://mail.example.test", account="first@example.test"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pin.json"
            write_selection(str(path), chosen)
            self.assertEqual(read_selection(str(path), old)["profile"], "account-a")
            new = copy.deepcopy(old)
            new["profiles"]["account-a"]["pid"] = 44
            with self.assertRaisesRegex(BindingError, "stale_reselect"):
                read_selection(str(path), new)

    def test_alias_drift_or_explicit_profile_conflict_cannot_switch_pin(self):
        old = registry()
        chosen = resolve(
            old, site="https://mail.example.test", purpose="public", profile="a"
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pin.json"
            write_selection(str(path), chosen)
            changed = copy.deepcopy(old)
            changed["aliases"]["a"] = "account-b"
            self.assertEqual(read_selection(str(path), changed)["profile"], "account-a")
            with self.assertRaisesRegex(BindingError, "selection_profile_conflict"):
                read_selection(str(path), changed, "a")

    def test_receipt_is_private_new_only_and_cannot_claim_authentication(self):
        chosen = resolve(
            registry(), site="https://mail.example.test", purpose="public", profile="a"
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "pin.json"
            write_selection(str(p), chosen)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_selection(str(p), chosen)
            p.chmod(0o644)
            with self.assertRaisesRegex(BindingError, "owner_or_permissions"):
                read_selection(str(p), registry())
            p.chmod(0o600)
            chosen["live_identity_verified"] = True
            p.write_text(json.dumps(chosen))
            with self.assertRaisesRegex(BindingError, "schema_invalid"):
                read_selection(str(p), registry())

    def test_credentials_and_non_http_urls_are_not_routes(self):
        for url in [
            "https://user:secret@mail.example.test",
            "https://@mail.example.test",
            "file:///etc/passwd",
        ]:
            with self.assertRaises(BindingError):
                resolve(registry(), site=url, purpose="public", profile="a")

    def test_current_site_policy_remains_effective(self):
        d = registry()
        d["profiles"]["account-a"]["capabilities"] = {
            "allowed_sites": ["accounts.example.test"]
        }
        with self.assertRaisesRegex(BindingError, "site_policy_mismatch"):
            resolve(d, site="https://unrelated.test", purpose="public", profile="a")

    def test_portable_site_allowlist_and_unknown_legacy_policy_fail_closed(self):
        d = registry()
        entry = d["profiles"]["account-a"]
        entry["capabilities"] = {"allowed_sites": ["example.test"]}
        self.assertEqual(
            resolve(d, site="https://sub.example.test", purpose="public", profile="a")[
                "profile"
            ],
            "account-a",
        )
        with self.assertRaisesRegex(BindingError, "site_policy_mismatch"):
            resolve(
                d, site="https://example.test.evil.test", purpose="public", profile="a"
            )
        for bad in [[], None, "example.test", [".example.test"], ["EXAMPLE.test"]]:
            entry["capabilities"] = {"allowed_sites": bad}
            with self.assertRaisesRegex(BindingError, "site_policy_invalid"):
                resolve(d, site="https://example.test", purpose="public", profile="a")
        entry["capabilities"] = {"task_policy": "legacy-scoped"}
        with self.assertRaisesRegex(
            BindingError, "legacy_site_policy_adapter_required"
        ):
            resolve(d, site="https://example.test", purpose="public", profile="a")

    def test_task_session_pin_cannot_be_reused_by_another_task(self):
        chosen = resolve(
            registry(),
            site="https://mail.example.test",
            purpose="public",
            profile="a",
            session="topic-task-a",
        )
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "pin.json"
            write_selection(str(p), chosen)
            with self.assertRaisesRegex(BindingError, "task_session_mismatch"):
                read_selection(str(p), registry(), expected_session="topic-task-b")

    def test_native_select_never_attaches_or_uses_default_session(self):
        import io
        from contextlib import redirect_stdout
        from chip_relay.attach.__main__ import main

        args = [
            "--binding",
            "/unused",
            "--session",
            "topic-task-a",
            "select",
            "--site",
            "https://accounts.example.test",
            "--account",
            "second@example.test",
        ]
        with (
            patch("chip_relay.attach.__main__.read_bindings", return_value=registry()),
            patch(
                "chip_relay.attach.__main__.verify_binding",
                side_effect=AssertionError("must not attach"),
            ),
            patch(
                "chip_relay.attach.__main__.probe",
                side_effect=AssertionError("must not connect"),
            ),
        ):
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(args)
            payload = json.loads(out.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(payload["selection"]["profile"], "account-b")
            self.assertFalse(payload["browser_connected"])
            args[3] = "default"
            out = io.StringIO()
            with redirect_stdout(out):
                code = main(args)
            self.assertEqual(code, 78)
            self.assertEqual(
                json.loads(out.getvalue())["failed_gate"],
                "selection_explicit_task_session_required",
            )


if __name__ == "__main__":
    unittest.main()
