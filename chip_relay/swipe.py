"""Bound native touch swipe. Browser supplies momentum; no JS/wheel fallback.

Used only through HumanInput.swipe on the already-selected task page. Does not
change touch emulation, UA, viewport, profile, browser lifecycle or account.
"""
from __future__ import annotations

import asyncio
import math
import time
from typing import Any

from .binding import BindingError


def _number(value: Any, low: float, high: float, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise BindingError("swipe_invalid_" + label)
    return float(value)


def geometry(width: float, height: float, direction: str, distance: float,
             x: float | None, y: float | None) -> tuple[float, float, float, float]:
    """Direction names describe finger movement: up scrolls content downward."""
    if direction not in {"up", "down", "left", "right"}:
        raise BindingError("swipe_invalid_direction")
    distance = _number(distance, 80, 600, "distance")
    width, height = _number(width, 100, 20000, "viewport"), _number(height, 100, 20000, "viewport")
    sx = (width * (.8 if direction == "left" else .2 if direction == "right" else .5)) if x is None else _number(x, 0, width, "x")
    sy = (height * (.8 if direction == "up" else .2 if direction == "down" else .5)) if y is None else _number(y, 0, height, "y")
    ex = sx + (distance if direction == "right" else -distance if direction == "left" else 0)
    ey = sy + (distance if direction == "down" else -distance if direction == "up" else 0)
    if not all(16 <= v <= limit - 16 for v, limit in [(sx, width), (ex, width), (sy, height), (ey, height)]):
        raise BindingError("swipe_path_out_of_viewport")
    return sx, sy, ex, ey


def swipe(human: Any, *, direction: str = "up", distance: float = 240,
          speed: float = 1200, inertia: bool = True, x: float | None = None,
          y: float | None = None, timeout: int = 5000) -> dict:
    """One native touchStart/move/end sequence; no retry after uncertain input.

    A short stationary hold suppresses release velocity for inertia=False.
    Return document-scroller measurements; nested scrollers may move independently.
    A False inertia_observed is honest (boundary, CSS, device or browser behavior).
    """
    deadline = time.monotonic() + human._timeout(timeout) / 1000
    distance = _number(distance, 80, 600, "distance")
    speed = _number(speed, 200, 3000, "speed")
    if type(inertia) is not bool:
        raise BindingError("swipe_invalid_inertia")
    if direction not in {"up", "down", "left", "right"}:
        raise BindingError("swipe_invalid_direction")
    duration = distance / speed
    if not .08 <= duration <= 1.5:
        raise BindingError("swipe_duration_out_of_bounds")
    human._remaining(deadline)
    human._page_guard()
    human._remaining(deadline)
    navigation = [False]

    def navigated(frame):
        if frame == human.page.main_frame:
            navigation[0] = True

    human.page.on("framenavigated", navigated)

    def remaining():
        return human._remaining(deadline) / 1000

    def guard():
        remaining()
        if navigation[0] or human.page.is_closed():
            raise BindingError("swipe_page_changed_during_action")

    async def execute():
        session = None
        pressed = False
        impl = human.page._impl_obj

        async def observe():
            guard()
            return await impl.evaluate("({x:scrollX,y:scrollY,t:performance.now()})")

        async def core():
            nonlocal session, pressed
            guard()
            await impl.bring_to_front()
            facts = await impl.evaluate("({width:innerWidth,height:innerHeight,origin:location.origin})")
            if facts["origin"] != human.expected_origin:
                raise BindingError("swipe_origin_mismatch")
            sx, sy, ex, ey = geometry(facts["width"], facts["height"], direction, distance, x, y)
            safe = await impl.evaluate("""({x,y})=>{
                const e=document.elementFromPoint(x,y);
                if(!e)return false;
                return !e.closest('iframe,frame,input,textarea,select,button,a,[contenteditable],video,audio');
            }""", {"x": sx, "y": sy})
            if safe is not True:
                raise BindingError("swipe_unsafe_start_target")
            before = await observe()
            session = await human.page.context._impl_obj.new_cdp_session(impl)
            guard()
            # A path is not a click, wheel animation, or OS touchpad emulation.
            pressed = True  # A timed-out start can have reached the browser.
            await session.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": sx, "y": sy}]})
            steps = max(6, min(90, math.ceil(duration * 60)))
            started = time.monotonic()
            for index in range(1, steps + 1):
                target_time = started + index * duration / steps
                await asyncio.sleep(max(0, target_time - time.monotonic()))
                guard()
                fraction = index / steps
                await session.send("Input.dispatchTouchEvent", {"type": "touchMove", "touchPoints": [{"x": sx+(ex-sx)*fraction, "y": sy+(ey-sy)*fraction}]})
            if not inertia:
                await asyncio.sleep(.16)
            guard()
            await session.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})
            pressed = False
            released = await observe()
            last, stable = released, 0
            # Read-only settling: no input is emitted after touchEnd.
            while stable < 4:
                await asyncio.sleep(.05)
                current = await observe()
                stable = stable + 1 if abs(current["x"]-last["x"]) <= .5 and abs(current["y"]-last["y"]) <= .5 else 0
                last = current
            dx, dy = last["x"]-released["x"], last["y"]-released["y"]
            return {"backend": "cdp-native-touch", "direction": direction,
                    "distance_css_px": distance, "inertia_requested": inertia,
                    "inertia_observed": abs(dx) > 1 or abs(dy) > 1,
                    "document_scroll_before": {k: before[k] for k in ["x", "y"]},
                    "document_scroll_at_release": {k: released[k] for k in ["x", "y"]},
                    "document_scroll_after": {k: last[k] for k in ["x", "y"]},
                    "post_release_delta": {"x": dx, "y": dy}, "settled": True}

        try:
            # Reserve a small portion of the SAME absolute budget for cancellation.
            return await asyncio.wait_for(core(), max(.001, remaining() - .1))
        finally:
            # Cleanup is cancellation only, never another swipe/backend or retry.
            if session is not None:
                if pressed and not navigation[0] and not human.page.is_closed():
                    try:
                        budget = remaining()
                        if budget > .01:
                            await asyncio.wait_for(session.send("Input.dispatchTouchEvent", {"type": "touchCancel", "touchPoints": []}), min(.07, budget))
                    except Exception:
                        pass  # Result stays uncertain; caller must inspect, not retry.
                try:
                    budget = remaining()
                    if budget > .005:
                        await asyncio.wait_for(session.detach(), min(.03, budget))
                except Exception:
                    pass

    try:
        result = human.page._sync(execute())
        human._remaining(deadline)
        human._page_guard()
        human._remaining(deadline)
        human.actions += 1
        return result
    except asyncio.TimeoutError:
        from playwright.sync_api import TimeoutError as BrowserTimeout
        raise BrowserTimeout("Swipe budget expired; inspect state before retry") from None
    finally:
        human.page.remove_listener("framenavigated", navigated)
