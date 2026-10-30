import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from test_attach_routing_contract import catalog, pin
from chip_relay.attach.binding import BindingError
from chip_relay.attach.config import load_config
from chip_relay.attach.profile_selection import write_selection, resolve
from chip_relay.attach.runner import run_checked


class CheckedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "selection.json"
        self.data = catalog()
        self.selected = pin(self.data)
        write_selection(str(self.path), self.selected)
        self.reader = patch(
            "chip_relay.attach.runner.read_bindings",
            side_effect=lambda *a: copy.deepcopy(self.data),
        )
        self.reader.start()
        self.addCleanup(self.reader.stop)
        for name in [
            "chip_relay.attach.runner.verify_binding",
            "chip_relay.attach.config.verify_binding",
        ]:
            p = patch(name, return_value={"verified": True})
            p.start()
            self.addCleanup(p.stop)

    def run_action(self, action, **kw):
        return run_checked(
            "/fixture/binding",
            str(self.path),
            action,
            session="task-one",
            target_url="https://accounts.example.test",
            **kw,
        )

    def test_exact_context_passed_and_restored(self):
        before = load_config()

        def action(entry, selected):
            self.assertEqual(entry, self.data["profiles"]["account-b"])
            self.assertEqual(load_config().selection, selected)
            self.assertEqual(load_config().external_binding, entry)
            return "observed-result"

        self.assertEqual(self.run_action(action), "observed-result")
        self.assertIs(load_config(), before)

    def test_exception_is_not_retried_and_context_restored(self):
        before = load_config()
        calls = []

        def action(*args):
            calls.append(1)
            raise RuntimeError("uncertain effect")

        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            self.run_action(action)
        self.assertEqual(calls, [1])
        self.assertIs(load_config(), before)

    def test_omitted_pin_blocks_before_callback(self):
        calls = []
        with self.assertRaisesRegex(BindingError, "selection_required"):
            run_checked(
                "/fixture/binding",
                None,
                lambda *a: calls.append(1),
                session="task-one",
                target_url="https://accounts.example.test",
            )
        self.assertEqual(calls, [])

    def test_network_proof_missing_blocks_before_callback(self):
        self.path.unlink()
        write_selection(str(self.path), pin(self.data, network="fixed"))
        calls = []
        with self.assertRaisesRegex(BindingError, "verification_required"):
            self.run_action(lambda *a: calls.append(1))
        self.assertEqual(calls, [])

    def test_wrong_profile_blocks_before_callback(self):
        calls = []
        with self.assertRaisesRegex(BindingError, "profile_conflict"):
            self.run_action(lambda *a: calls.append(1), profile="main")
        self.assertEqual(calls, [])

    def test_valid_pin_swap_does_not_validate_original_action(self):
        def action(*args):
            replacement = resolve(
                self.data,
                site="https://accounts.example.test",
                account="first@example.test",
                session="task-one",
            )
            self.path.write_text(json.dumps(replacement))
            return "must not report success"

        with self.assertRaisesRegex(BindingError, "selection_changed_during_action"):
            self.run_action(action)

    def test_registry_drift_blocks_postvalidation(self):
        def action(*args):
            self.data["profiles"]["account-b"]["pid"] += 1
            return "must not report success"

        with self.assertRaisesRegex(BindingError, "stale_reselect"):
            self.run_action(action)
