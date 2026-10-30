"""Default-off, page-scoped human input for an already verified relay task.

Cooperative action guards, not a sandbox for arbitrary task Python. Never use
this facade for credentials, CAPTCHA, wallet signing or payment authorization.
"""

from __future__ import annotations

from contextlib import contextmanager
import asyncio
from importlib.metadata import version, distribution
import json
import time
from urllib.parse import urlsplit

from typing import Any, Callable

from .binding import BindingError, verify_binding
from .config import load_config

SDK_VERSION = "0.6.4"
SDK_SOURCE = "b1a00eda61efe71da2a1a38831fa6fe861f5d91d"
MODES = frozenset({"off", "default", "careful"})


def origin(url: str) -> str:
    u = urlsplit(url)
    if (
        u.scheme not in {"http", "https"}
        or not u.hostname
        or u.username is not None
        or u.password is not None
    ):
        raise BindingError("humanize_exact_http_origin_required")
    port = u.port or (443 if u.scheme == "https" else 80)
    host = "[" + u.hostname + "]" if ":" in u.hostname else u.hostname
    return f"{u.scheme}://{host}:{port}"


def doctor() -> dict:
    try:
        sdk, playwright = version("cloakbrowser"), version("playwright")
        direct = json.loads(
            distribution("cloakbrowser").read_text("direct_url.json") or "{}"
        )
        source = direct.get("vcs_info", {}).get("commit_id")
    except Exception:
        return {
            "status": "blocked",
            "failed_gate": "humanize_dependency_missing",
            "default_mode": "off",
        }
    qualified = sdk == SDK_VERSION and source == SDK_SOURCE
    return {
        "status": "available" if qualified else "blocked",
        "failed_gate": None if qualified else "humanize_dependency_version_mismatch",
        "source_commit": source,
        "default_mode": "off",
        "sdk": sdk,
        "playwright": playwright,
        "scope": "one explicitly selected page in a bound task child",
        "browser_download": False,
    }


def _frame_origin(frame: Any) -> str:
    for _ in range(16):
        if frame.url not in {"about:blank", "about:srcdoc"}:
            return origin(frame.url)
        frame = frame.parent_frame
        if frame is None:
            break
    raise BindingError("humanize_frame_origin_unproved")


class HumanInput:
    def __init__(
        self,
        page: Any,
        expected_origin: str,
        mode: str,
        expected_account: str | None,
        identity_check: Callable[[], bool] | None,
    ):
        self.page, self.expected_origin, self.mode = page, expected_origin, mode
        self.expected_account, self.identity_check = expected_account, identity_check
        self.config = load_config()
        if self.config.external_binding is None:
            raise BindingError("humanize_verified_external_binding_required")
        self.entry = self.config.external_binding
        self.actions = 0
        self.closed = False
        self._engine = None

    def _page_guard(self) -> None:
        if self.closed:
            raise BindingError("humanize_scope_closed")
        verify_binding(self.entry)
        if origin(self.page.url) != self.expected_origin:
            raise BindingError("humanize_page_origin_mismatch")
        from .profile_selection import check_site, digest, SCHEMA

        check_site(self.entry, self.page.url)
        selected = self.config.selection
        if selected:
            if (
                not isinstance(selected, dict)
                or selected.get("schema") != SCHEMA
                or selected.get("entry_sha256") != digest(self.entry)
            ):
                raise BindingError("humanize_selection_binding_mismatch")
            if selected.get("purpose") == "identity-check":
                raise BindingError("humanize_selection_readonly")
            from .routing_contract import require_network

            require_network(selected)
            if (
                selected.get("origin") != self.expected_origin
                or selected.get("expected_account") != self.expected_account
            ):
                raise BindingError("humanize_selection_intent_mismatch")
        if self.expected_account is not None and (
            self.identity_check is None or self.identity_check() is not True
        ):
            raise BindingError("humanize_live_account_identity_required")

    def _target(
        self, locator: Any, *, fill: bool, deadline: float | None = None
    ) -> None:
        deadline = time.monotonic() + 5 if deadline is None else deadline
        self._remaining(deadline)
        self._page_guard()
        self._remaining(deadline)
        impl = locator._impl_obj
        frame = impl._frame
        if frame._page is not self.page._impl_obj:
            raise BindingError("humanize_wrong_page_target")
        if _frame_origin(frame) != self.expected_origin:
            raise BindingError("humanize_frame_origin_mismatch")
        if (
            self._rpc(locator, "count", deadline) != 1
            or not self._rpc(locator, "is_visible", deadline)
            or not self._rpc(locator, "is_enabled", deadline)
        ):
            raise BindingError("humanize_unique_visible_enabled_target_required")
        facts = self._rpc(
            locator,
            "evaluate",
            deadline,
            r"""el => {
          const type=(el.getAttribute('type')||'text').toLowerCase();
          const hint=[el.getAttribute('name'),el.id,el.getAttribute('autocomplete')].filter(Boolean).join(' ');
          return {origin:el.ownerDocument.location.origin, secret:type==='password'||/password|passwd|passphrase|one-time-code|otp|mnemonic|private.?key|secret|token/i.test(hint),
                  text:el.tagName==='TEXTAREA'||el.tagName==='INPUT'&&['text','search','email','url','tel'].includes(type)};
        }""",
        )
        # FrameLocator chains retain the outer frame in Playwright's Locator
        # object. Verify the resolved node's document too, not just that root.
        if origin(facts.get("origin", "")) != self.expected_origin:
            raise BindingError("humanize_frame_origin_mismatch")
        if facts["secret"]:
            raise BindingError("humanize_secret_field_forbidden")
        if fill and not facts["text"]:
            raise BindingError("humanize_plain_text_field_required")
        self._remaining(deadline)

    @staticmethod
    def _timeout(timeout: int) -> int:
        if type(timeout) is not int or not 1 <= timeout <= 30000:
            raise BindingError("humanize_bounded_timeout_required")
        return timeout

    def click(self, locator: Any, *, timeout: int = 5000) -> None:
        deadline = time.monotonic() + self._timeout(timeout) / 1000
        self._target(locator, fill=False, deadline=deadline)
        # Exactly one backend call. Never retry an ambiguous dispatched action.
        self._dispatch(locator, "click", deadline)
        self._remaining(deadline)
        verify_binding(self.entry)
        self._remaining(deadline)
        self.actions += 1

    def fill(self, locator: Any, text: str, *, timeout: int = 10000) -> None:
        deadline = time.monotonic() + self._timeout(timeout) / 1000
        if (
            not isinstance(text, str)
            or len(text) > 4096
            or any(c in text for c in "\r\n\x00")
        ):
            raise BindingError("humanize_bounded_single_line_text_required")
        self._target(locator, fill=True, deadline=deadline)
        self._dispatch(locator, "fill", deadline, text)
        self._remaining(deadline)
        verify_binding(self.entry)
        if self._rpc(locator, "input_value", deadline) != text:
            raise BindingError("humanize_text_readback_mismatch")
        self._remaining(deadline)
        self.actions += 1

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = (deadline - time.monotonic()) * 1000
        if remaining <= 0:
            from playwright.sync_api import TimeoutError as BrowserTimeout

            raise BrowserTimeout(
                "Humanize action budget expired; inspect effect before retry"
            )
        return remaining

    def _rpc(self, locator: Any, method: str, deadline: float, *args, **kwargs):
        timeout = self._remaining(deadline)

        async def execute():
            return await asyncio.wait_for(
                getattr(locator._impl_obj, method)(*args, **kwargs), timeout / 1000
            )

        try:
            result = self.page._sync(execute())
        except asyncio.TimeoutError:
            from playwright.sync_api import TimeoutError as BrowserTimeout

            raise BrowserTimeout(
                "Humanize action budget expired; inspect effect before retry"
            ) from None
        self._remaining(deadline)
        return result

    def _dispatch(
        self, locator: Any, action: str, deadline: float, text: str = ""
    ) -> None:
        timeout = self._remaining(deadline)
        if self.mode == "off":
            if action == "click":
                self._rpc(locator, "click", deadline, timeout=timeout)
            else:
                self._rpc(locator, "fill", deadline, text, timeout=timeout)
            return
        if self._engine is None:
            raise BindingError("humanize_engine_missing")
        from cloakbrowser.human.engine import Target
        from cloakbrowser.human.world import ACTION, Action
        from playwright.sync_api import TimeoutError as BrowserTimeout

        async def execute():
            token = ACTION.set(Action(timeout))
            try:
                impl = locator._impl_obj
                target = Target(impl._frame, impl._selector, strict=True)
                options = {"timeout": timeout}
                operation = (
                    self._engine.click(target, options, api="relay.humanize.click")
                    if action == "click"
                    else self._engine.fill(
                        target, text, options, api="relay.humanize.fill"
                    )
                )
                await asyncio.wait_for(operation, timeout / 1000)
            finally:
                ACTION.reset(token)

        try:
            self.page._sync(execute())
        except asyncio.TimeoutError:
            raise BrowserTimeout(
                "Humanize overall action deadline exceeded; inspect effect before retry"
            ) from None

    def report(self) -> dict:
        return {
            "mode": self.mode,
            "completed_actions": self.actions,
            "typo_simulation": False,
            "fallback": False,
            "physical_client_input_proved": False,
        }


@contextmanager
def humanize_page(
    page: Any,
    *,
    expected_origin: str,
    mode: str = "off",
    expected_account: str | None = None,
    identity_check: Callable[[], bool] | None = None,
):
    """Use only in the relay's bound final.py, on the explicitly selected page.

    Account check must inspect the destination's current account, not a profile
    alias or cookie presence. The engine is instance-scoped: no Page/Locator
    classes or other pages are patched. Non-selected pages remain native.
    """
    if mode not in MODES:
        raise BindingError("humanize_mode_unknown")
    human = HumanInput(
        page, origin(expected_origin), mode, expected_account, identity_check
    )
    human._page_guard()
    if hasattr(page._impl_obj, "_cloak_human"):
        raise BindingError("humanize_page_already_patched")
    enabled = mode != "off"
    try:
        if enabled:
            if doctor()["status"] != "available":
                raise BindingError("humanize_dependency_unavailable")
            from cloakbrowser.human import Human, CursorState, resolve_config
            from cloakbrowser.human.patch import _check_playwright

            _check_playwright()
            cfg = resolve_config(
                mode, {"mistype_chance": 0.0, "idle_between_actions": False}
            )
            # Repeated pointer events are render-throttled on background tabs.
            # Focus only the explicitly selected task page, never a last tab.
            page.bring_to_front()
            human._engine = Human(page._impl_obj, cfg, CursorState())
        yield human
    finally:
        human.closed = True
        human._engine = None
