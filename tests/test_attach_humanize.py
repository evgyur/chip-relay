import unittest
import asyncio
from types import SimpleNamespace as NS
from unittest.mock import patch
from chip_relay.attach.binding import BindingError
from chip_relay.attach.humanize import humanize_page, origin


class Page:
    def __init__(self):
        self.url = "https://example.test/form"
        self._impl_obj = NS()
        self.focused = 0

    def bring_to_front(self):
        self.focused += 1

    @staticmethod
    def _sync(awaitable):
        return asyncio.run(awaitable)


class Locator:
    def __init__(self, page, secret=False, count=1):
        frame = NS(_page=page._impl_obj, url=page.url, parent_frame=None)
        self._impl_obj = NS(_frame=frame)
        self.secret = secret
        self.n = count
        self.calls = []
        self.value = ""

        def method(name):
            async def invoke(*args, **kwargs):
                return getattr(self, name)(*args, **kwargs)

            return invoke

        for name in [
            "count",
            "is_visible",
            "is_enabled",
            "evaluate",
            "click",
            "fill",
            "input_value",
        ]:
            setattr(self._impl_obj, name, method(name))

    def count(self):
        return self.n

    def is_visible(self):
        return True

    def is_enabled(self):
        return True

    def evaluate(self, expression):
        return {
            "secret": self.secret,
            "text": True,
            "origin": getattr(self, "node_origin", origin(self._impl_obj._frame.url)),
        }

    def click(self, **kw):
        self.calls.append("click")

    def fill(self, value, **kw):
        self.calls.append("fill")
        self.value = value

    def input_value(self, **kw):
        return self.value


class HumanizeTests(unittest.TestCase):
    def setUp(self):
        self.entry = {"capabilities": {}}
        self.bound = NS(external_binding=self.entry, selection=None)
        self.config = patch(
            "chip_relay.attach.humanize.load_config",
            return_value=self.bound,
        )
        self.config.start()
        self.addCleanup(self.config.stop)
        self.verify = patch(
            "chip_relay.attach.humanize.verify_binding", return_value={"verified": True}
        )
        self.verify.start()
        self.addCleanup(self.verify.stop)

    def test_default_off_does_not_patch_upstream_and_restores_closed_scope(self):
        page = Page()
        target = Locator(page)
        with patch("cloakbrowser.human.patch_page") as backend:
            with humanize_page(page, expected_origin=page.url) as h:
                h.click(target)
                h.fill(target, "ordinary text")
                self.assertEqual(h.report()["mode"], "off")
            backend.assert_not_called()
        self.assertEqual(target.calls, ["click", "fill"])
        with self.assertRaisesRegex(BindingError, "humanize_scope_closed"):
            h.click(target)

    def test_explicit_mode_disables_typos_and_marks_only_selected_page(self):
        page, other = Page(), Page()
        configs = []

        def backend(selected, cfg, cursor):
            configs.append(cfg)
            return object()

        with (
            patch("cloakbrowser.human.Human", side_effect=backend),
            patch("chip_relay.attach.humanize.HumanInput._dispatch"),
        ):
            with humanize_page(page, expected_origin=page.url, mode="default") as h:
                self.assertIsNotNone(h._engine)
                self.assertFalse(hasattr(other._impl_obj, "_cloak_human"))
                h.click(Locator(page))
            self.assertIsNone(h._engine)
        self.assertEqual(page.focused, 1)
        self.assertEqual(other.focused, 0)
        self.assertEqual(configs[0].mistype_chance, 0)

    def test_secret_ambiguous_and_wrong_page_targets_never_dispatch(self):
        page = Page()
        with humanize_page(page, expected_origin=page.url) as h:
            for target in [
                Locator(page, secret=True),
                Locator(page, count=2),
                Locator(Page()),
            ]:
                with self.assertRaises(BindingError):
                    h.click(target)
                self.assertEqual(target.calls, [])

    def test_account_identity_and_origin_fail_closed(self):
        page = Page()
        with self.assertRaisesRegex(BindingError, "live_account_identity"):
            with humanize_page(
                page, expected_origin=page.url, expected_account="fixture"
            ):
                pass
        with humanize_page(page, expected_origin=page.url) as h:
            page.url = "https://another.test/"
            with self.assertRaisesRegex(BindingError, "page_origin_mismatch"):
                h.click(Locator(page))

    def test_cross_origin_frame_and_unbounded_timeout_rejected(self):
        page = Page()
        target = Locator(page)
        target._impl_obj._frame.url = "https://another.test/"
        with humanize_page(page, expected_origin=page.url) as h:
            with self.assertRaisesRegex(BindingError, "frame_origin_mismatch"):
                h.click(target)
            with self.assertRaisesRegex(BindingError, "bounded_timeout"):
                h.click(Locator(page), timeout=0)
        self.assertEqual(target.calls, [])

    def test_framelocator_resolved_document_origin_is_checked(self):
        page = Page()
        target = Locator(page)
        target.node_origin = "https://another.test"
        with humanize_page(page, expected_origin=page.url) as h:
            with self.assertRaisesRegex(BindingError, "frame_origin_mismatch"):
                h.click(target)
        self.assertEqual(target.calls, [])

    def test_dispatch_failure_is_not_retried(self):
        from playwright.sync_api import TimeoutError as BrowserTimeout

        page = Page()
        target = Locator(page)
        with (
            humanize_page(page, expected_origin=page.url) as h,
            patch.object(
                target, "click", side_effect=BrowserTimeout("ambiguous")
            ) as click,
        ):
            with self.assertRaises(BrowserTimeout):
                h.click(target)
            self.assertEqual(click.call_count, 1)
            self.assertEqual(h.report()["completed_actions"], 0)

    def test_binding_is_required_and_unrecognized_modes_rejected(self):
        with patch(
            "chip_relay.attach.humanize.load_config",
            return_value=NS(external_binding=None, selection=None),
        ):
            with self.assertRaisesRegex(
                BindingError, "verified_external_binding_required"
            ):
                with humanize_page(Page(), expected_origin="https://example.test"):
                    pass
        with self.assertRaisesRegex(BindingError, "mode_unknown"):
            with humanize_page(
                Page(), expected_origin="https://example.test", mode="auto"
            ):
                pass

    def test_expired_preflight_cannot_start_click_or_fill(self):
        from playwright.sync_api import TimeoutError as BrowserTimeout

        for action in ["click", "fill"]:
            clock = [1000.0]
            page = Page()
            target = Locator(page)
            original = target.evaluate

            def slow_facts(expression):
                clock[0] += 0.060
                return original(expression)

            with (
                patch(
                    "chip_relay.attach.humanize.time", NS(monotonic=lambda: clock[0])
                ),
                patch.object(target, "evaluate", side_effect=slow_facts),
                humanize_page(page, expected_origin=page.url) as h,
            ):
                with self.assertRaises(BrowserTimeout):
                    if action == "click":
                        h.click(target, timeout=10)
                    else:
                        h.fill(target, "ordinary", timeout=10)
                self.assertEqual(target.calls, [])
                self.assertEqual(h.actions, 0)

    def test_async_preflight_rpc_is_cancelled_on_the_same_deadline(self):
        from playwright.sync_api import TimeoutError as BrowserTimeout

        page = Page()
        target = Locator(page)
        completed = []

        async def slow_facts(expression):
            await asyncio.sleep(0.1)
            completed.append(True)
            return target.evaluate(expression)

        target._impl_obj.evaluate = slow_facts
        with humanize_page(page, expected_origin=page.url) as h:
            with self.assertRaises(BrowserTimeout):
                h.click(target, timeout=10)
            self.assertEqual(target.calls, [])
            self.assertEqual(completed, [])

    def test_readback_uses_remaining_budget_not_a_new_timeout(self):
        from playwright.sync_api import TimeoutError as BrowserTimeout

        clock = [1000.0]
        page = Page()
        target = Locator(page)

        def late_readback(**kwargs):
            clock[0] += 0.060
            return target.value

        with (
            patch("chip_relay.attach.humanize.time", NS(monotonic=lambda: clock[0])),
            patch.object(target, "input_value", side_effect=late_readback),
            humanize_page(page, expected_origin=page.url) as h,
        ):
            with self.assertRaises(BrowserTimeout):
                h.fill(target, "ordinary", timeout=10)
            self.assertEqual(target.calls, ["fill"])
            self.assertEqual(h.actions, 0)

    def test_expired_owner_check_cannot_refresh_the_action_budget(self):
        from playwright.sync_api import TimeoutError as BrowserTimeout

        clock = [1000.0]
        page = Page()
        target = Locator(page)
        with (
            patch("chip_relay.attach.humanize.time", NS(monotonic=lambda: clock[0])),
            humanize_page(page, expected_origin=page.url) as h,
        ):

            def slow_guard():
                clock[0] += 0.060

            with patch.object(h, "_page_guard", side_effect=slow_guard):
                with self.assertRaises(BrowserTimeout):
                    h.click(target, timeout=10)
            self.assertEqual(target.calls, [])
            self.assertEqual(h.actions, 0)

    def test_origin_never_accepts_credentials_or_non_http(self):
        for url in [
            "file:///etc/passwd",
            "https://user:secret@example.test",
            "data:text/html,test",
        ]:
            with self.assertRaises(BindingError):
                origin(url)

    def test_selected_account_and_origin_cannot_be_dropped_by_adapter(self):
        from chip_relay.attach.profile_selection import SCHEMA, digest

        page = Page()
        selected = {
            "schema": SCHEMA,
            "entry_sha256": digest(self.entry),
            "origin": origin(page.url),
            "purpose": "authenticated",
            "expected_account": "first@example.test",
        }
        with patch.object(self.bound, "selection", selected):
            with self.assertRaisesRegex(BindingError, "selection_intent_mismatch"):
                with humanize_page(page, expected_origin=page.url):
                    pass
            with humanize_page(
                page,
                expected_origin=page.url,
                expected_account="first@example.test",
                identity_check=lambda: True,
            ) as h:
                h.click(Locator(page))
            selected["purpose"] = "identity-check"
        with patch.object(self.bound, "selection", selected):
            with self.assertRaisesRegex(BindingError, "selection_readonly"):
                with humanize_page(
                    page,
                    expected_origin=page.url,
                    expected_account="first@example.test",
                    identity_check=lambda: True,
                ):
                    pass


if __name__ == "__main__":
    unittest.main()
