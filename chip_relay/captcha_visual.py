from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from .captcha import (
    CaptchaGateError,
    _page_target_key,
    _write_captcha_state_locked,
    inspect_captcha_gate,
    load_captcha_state,
)
from .config import RelayConfig
from .network import utc_now_text
from .protection import _open_protection_dir_fd, _read_bounded_fd, _write_all
from .workspace import execution_marker, execution_run_lock, load_manifest, update_manifest

VISUAL_SCHEMA = "chip-relay-captcha-visual-v1"
VISUAL_STATE_FILE = "captcha-visual.json"
VISUAL_SCREENSHOT_FILE = "captcha-visual.png"
MAX_VISUAL_STATE_BYTES = 32 * 1024
MAX_SCREENSHOT_BYTES = 10 * 1024 * 1024
MAX_POINTS = 12
MAX_VISUAL_CYCLES = 3
MIN_VISUAL_CONFIDENCE = 0.85
MAX_REGION_PIXELS = 4_194_304
REGION_TOLERANCE = 0.5
_PAGE_KEY = re.compile(r"^[0-9a-f]{16}$")
_DOCUMENT_KEY = re.compile(r"^[0-9a-f]{16}$")


class CaptchaVisualError(ValueError):
    pass


def _attempt_marker(run_dir: Path) -> dict[str, Any]:
    try:
        return execution_marker(load_manifest(run_dir))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CaptchaVisualError("captcha_visual_attempt_unavailable") from exc


def _allocate_visual_cycle(run_dir: Path, marker: dict[str, Any]) -> int:
    allocated: list[int] = []

    def updater(manifest: dict[str, Any]) -> None:
        if execution_marker(manifest) != marker:
            raise CaptchaVisualError("captcha_visual_attempt_changed")
        execution = manifest.get("execution")
        if not isinstance(execution, dict):
            raise CaptchaVisualError("captcha_visual_budget_unavailable")
        current = execution.get("captcha_visual_cycle", 0)
        if isinstance(current, bool) or not isinstance(current, int) or not 0 <= current <= MAX_VISUAL_CYCLES:
            raise CaptchaVisualError("captcha_visual_budget_unavailable")
        if current >= MAX_VISUAL_CYCLES:
            raise CaptchaVisualError("captcha_visual_retry_limit")
        allocated.append(current + 1)
        execution["captcha_visual_cycle"] = allocated[0]

    try:
        update_manifest(run_dir, updater)
    except CaptchaVisualError:
        raise
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CaptchaVisualError("captcha_visual_budget_unavailable") from exc
    if len(allocated) != 1:
        raise CaptchaVisualError("captcha_visual_budget_unavailable")
    return allocated[0]


def _safe_bounds(raw: Any) -> dict[str, float]:
    if not isinstance(raw, dict) or set(raw) != {"x", "y", "width", "height"}:
        raise CaptchaVisualError("captcha_visual_region_invalid")
    result: dict[str, float] = {}
    for key in ("x", "y", "width", "height"):
        value = raw.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise CaptchaVisualError("captcha_visual_region_invalid")
        result[key] = float(value)
    if result["x"] < 0 or result["y"] < 0:
        raise CaptchaVisualError("captcha_visual_region_invalid")
    if result["width"] < 20 or result["height"] < 20:
        raise CaptchaVisualError("captcha_visual_region_too_small")
    if result["width"] > 4096 or result["height"] > 4096:
        raise CaptchaVisualError("captcha_visual_region_too_large")
    if result["width"] * result["height"] > MAX_REGION_PIXELS:
        raise CaptchaVisualError("captcha_visual_region_too_large")
    return result


def parse_visual_points(values: Iterable[str]) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    for value in values:
        if not isinstance(value, str) or value.count(",") != 1:
            raise CaptchaVisualError("invalid_captcha_visual_point")
        left, right = value.split(",", 1)
        try:
            x, y = float(left), float(right)
        except ValueError as exc:
            raise CaptchaVisualError("invalid_captcha_visual_point") from exc
        if not math.isfinite(x) or not math.isfinite(y) or not (0 <= x <= 1) or not (0 <= y <= 1):
            raise CaptchaVisualError("invalid_captcha_visual_point")
        points.append((x, y))
    if not points or len(points) > MAX_POINTS:
        raise CaptchaVisualError("invalid_captcha_visual_point_count")
    return points


def _write_private_bytes(run_dir: Path, name: str, data: bytes, *, max_bytes: int) -> None:
    if not data or len(data) > max_bytes:
        raise CaptchaVisualError("captcha_visual_artifact_size_invalid")
    try:
        root_fd = _open_protection_dir_fd(run_dir, create=True)
    except (OSError, ValueError) as exc:
        raise CaptchaVisualError("unsafe_captcha_visual_path") from exc
    if root_fd is None:
        raise CaptchaVisualError("unsafe_captcha_visual_path")
    temporary = f".{name}-{os.getpid()}-{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass
        raise CaptchaVisualError("unsafe_captcha_visual_path") from exc
    finally:
        os.close(root_fd)


def _read_private_bytes(run_dir: Path, name: str, *, max_bytes: int) -> bytes:
    try:
        root_fd = _open_protection_dir_fd(run_dir, create=False)
    except (OSError, ValueError) as exc:
        raise CaptchaVisualError("unsafe_captcha_visual_path") from exc
    if root_fd is None:
        raise CaptchaVisualError("captcha_visual_not_captured")
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY
        for flag_name in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            flags |= getattr(os, flag_name, 0)
        try:
            descriptor = os.open(name, flags, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise CaptchaVisualError("captcha_visual_not_captured") from exc
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CaptchaVisualError("unsafe_captcha_visual_path")
        return _read_bounded_fd(
            descriptor,
            max_bytes=max_bytes,
            too_large_gate="captcha_visual_artifact_too_large",
        )
    except CaptchaVisualError:
        raise
    except (OSError, ValueError) as exc:
        raise CaptchaVisualError("unsafe_captcha_visual_path") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(root_fd)


def _write_visual_authorization_status(run_dir: Path, visual: dict[str, Any], status_value: str) -> None:
    if status_value not in {"ready", "applying", "consumed", "uncertain"}:
        raise CaptchaVisualError("malformed_captcha_visual_state")
    updated = dict(visual)
    updated["authorization_status"] = status_value
    updated["consumed"] = status_value != "ready"
    encoded = (json.dumps(updated, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_private_bytes(run_dir, VISUAL_STATE_FILE, encoded, max_bytes=MAX_VISUAL_STATE_BYTES)


def _consume_visual_authorization(run_dir: Path, visual: dict[str, Any]) -> None:
    _write_visual_authorization_status(run_dir, visual, "applying")
    try:
        root_fd = _open_protection_dir_fd(run_dir, create=False)
    except (OSError, ValueError) as exc:
        raise CaptchaVisualError("unsafe_captcha_visual_path") from exc
    if root_fd is None:
        raise CaptchaVisualError("captcha_visual_not_captured")
    try:
        os.unlink(VISUAL_SCREENSHOT_FILE, dir_fd=root_fd)
        os.fsync(root_fd)
    except FileNotFoundError as exc:
        raise CaptchaVisualError("captcha_visual_not_captured") from exc
    except OSError as exc:
        raise CaptchaVisualError("unsafe_captcha_visual_path") from exc
    finally:
        os.close(root_fd)


def _read_private_json(run_dir: Path, name: str) -> dict[str, Any]:
    data = _read_private_bytes(run_dir, name, max_bytes=MAX_VISUAL_STATE_BYTES)
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptchaVisualError("malformed_captcha_visual_state") from exc
    if not isinstance(payload, dict):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    return payload


def _challenge_bounds_script() -> str:
    return r"""
() => {
  const selectors = [
    'iframe[title*="challenge" i]',
    'iframe[title*="captcha" i]',
    'iframe[src*="recaptcha"]',
    'iframe[src*="hcaptcha.com"]',
    'iframe[src*="challenges.cloudflare.com"]',
    '.g-recaptcha',
    '.h-captcha',
    '.cf-turnstile',
    '#challenge-stage'
  ];
  const candidates = [];
  for (const selector of selectors) {
    for (const element of document.querySelectorAll(selector)) {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      if (style.display === 'none' || style.visibility === 'hidden' || rect.width < 20 || rect.height < 20) continue;
      const title = (element.getAttribute('title') || '').toLowerCase();
      const priority = title.includes('challenge') || title.includes('captcha') ? 10000000 : 0;
      candidates.push({element, score: priority + rect.width * rect.height});
    }
  }
  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score);
  const element = candidates[0].element;
  element.scrollIntoView({block: 'center', inline: 'center'});
  const rect = element.getBoundingClientRect();
  return {
    x: rect.left,
    y: rect.top,
    width: rect.width,
    height: rect.height,
    clip_x: rect.left + window.scrollX,
    clip_y: rect.top + window.scrollY,
    viewport_width: window.innerWidth,
    viewport_height: window.innerHeight
  };
}
"""


def _select_page(browser: Any, page_key: str) -> Any:
    pages = [page for context in browser.contexts for page in context.pages]
    for page in pages:
        if secrets.compare_digest(_page_target_key(page.context, page), page_key):
            return page
    raise CaptchaVisualError("captcha_page_target_changed")


def _page_document_key(page: Any) -> str:
    session = page.context.new_cdp_session(page)
    try:
        tree = session.send("Page.getFrameTree")
    finally:
        session.detach()
    try:
        frame = tree["frameTree"]["frame"]
        identity = {
            "frame_id": frame["id"],
            "loader_id": frame["loaderId"],
            "url": frame["url"],
        }
    except (KeyError, TypeError) as exc:
        raise CaptchaVisualError("captcha_document_identity_unavailable") from exc
    if any(not isinstance(value, str) or not value or len(value) > 16384 for value in identity.values()):
        raise CaptchaVisualError("captcha_document_identity_unavailable")
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _live_region(raw: Any) -> tuple[dict[str, float], dict[str, float]]:
    if not isinstance(raw, dict):
        raise CaptchaVisualError("captcha_visual_region_unavailable")
    bounds = _safe_bounds({key: raw.get(key) for key in ("x", "y", "width", "height")})
    viewport_width = raw.get("viewport_width")
    viewport_height = raw.get("viewport_height")
    clip_x = raw.get("clip_x")
    clip_y = raw.get("clip_y")
    values = (viewport_width, viewport_height, clip_x, clip_y)
    if any(isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) for value in values):
        raise CaptchaVisualError("captcha_visual_region_unavailable")
    viewport_width = float(viewport_width)
    viewport_height = float(viewport_height)
    clip_x = float(clip_x)
    clip_y = float(clip_y)
    if viewport_width <= 0 or viewport_height <= 0 or clip_x < 0 or clip_y < 0:
        raise CaptchaVisualError("captcha_visual_region_unavailable")
    if bounds["x"] + bounds["width"] > viewport_width + REGION_TOLERANCE:
        raise CaptchaVisualError("captcha_visual_region_not_contained")
    if bounds["y"] + bounds["height"] > viewport_height + REGION_TOLERANCE:
        raise CaptchaVisualError("captcha_visual_region_not_contained")
    return bounds, {"x": clip_x, "y": clip_y, "width": bounds["width"], "height": bounds["height"]}


def _capture_with_playwright(config: RelayConfig, page_key: str) -> tuple[bytes, dict[str, float], str]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise CaptchaVisualError("playwright_unavailable") from exc
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(config.cdp_url)
            page = _select_page(browser, page_key)
            page.bring_to_front()
            document_key = _page_document_key(page)
            raw = page.evaluate(_challenge_bounds_script())
            bounds, clip = _live_region(raw)
            image = page.screenshot(type="png", clip=clip, animations="disabled")
            if not secrets.compare_digest(_page_document_key(page), document_key):
                raise CaptchaVisualError("captcha_visual_document_changed")
    except CaptchaVisualError:
        raise
    except Exception as exc:
        raise CaptchaVisualError(f"captcha_visual_capture_failed: {type(exc).__name__}") from exc
    if not isinstance(image, bytes):
        image = bytes(image)
    return image, bounds, document_key


def _apply_with_playwright(
    config: RelayConfig,
    page_key: str,
    expected_bounds: dict[str, float],
    expected_digest: str,
    expected_document_key: str,
    points: list[tuple[float, float]],
) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise CaptchaVisualError("playwright_unavailable") from exc
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(config.cdp_url)
            page = _select_page(browser, page_key)
            page.bring_to_front()
            if not secrets.compare_digest(_page_document_key(page), expected_document_key):
                raise CaptchaVisualError("captcha_visual_document_changed")
            raw = page.evaluate(_challenge_bounds_script())
            current, clip = _live_region(raw)
            if any(abs(current[key] - expected_bounds[key]) > REGION_TOLERANCE for key in ("x", "y", "width", "height")):
                raise CaptchaVisualError("captcha_visual_stale")
            current_image = page.screenshot(type="png", clip=clip, animations="disabled")
            if not isinstance(current_image, bytes):
                current_image = bytes(current_image)
            if not current_image.startswith(b"\x89PNG\r\n\x1a\n") or not secrets.compare_digest(
                hashlib.sha256(current_image).hexdigest(), expected_digest
            ):
                raise CaptchaVisualError("captcha_visual_content_changed")
            if not secrets.compare_digest(_page_document_key(page), expected_document_key):
                raise CaptchaVisualError("captcha_visual_document_changed")
            for x, y in points:
                page.mouse.click(current["x"] + current["width"] * x, current["y"] + current["height"] * y)
                page.wait_for_timeout(150)
            page.wait_for_timeout(500)
    except CaptchaVisualError:
        raise
    except Exception as exc:
        raise CaptchaVisualError(f"captcha_visual_action_failed: {type(exc).__name__}") from exc


def _validate_visual_state(payload: dict[str, Any]) -> dict[str, Any]:
    expected = {"schema", "attempt_marker", "page_key", "document_key", "bounds", "screenshot_sha256", "captured_at", "artifact_policy", "cycle", "consumed", "authorization_status"}
    if set(payload) != expected or payload.get("schema") != VISUAL_SCHEMA:
        raise CaptchaVisualError("malformed_captcha_visual_state")
    page_key = payload.get("page_key")
    document_key = payload.get("document_key")
    digest = payload.get("screenshot_sha256")
    if not isinstance(page_key, str) or not _PAGE_KEY.fullmatch(page_key):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if not isinstance(document_key, str) or not _DOCUMENT_KEY.fullmatch(document_key):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if payload.get("artifact_policy") != "private-local/no-auto-send":
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if not isinstance(payload.get("cycle"), int) or isinstance(payload.get("cycle"), bool) or not 1 <= payload["cycle"] <= MAX_VISUAL_CYCLES:
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if not isinstance(payload.get("consumed"), bool):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    authorization_status = payload.get("authorization_status")
    if authorization_status not in {"ready", "applying", "consumed", "uncertain"}:
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if payload["consumed"] != (authorization_status != "ready"):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    if not isinstance(payload.get("captured_at"), str):
        raise CaptchaVisualError("malformed_captcha_visual_state")
    payload["bounds"] = _safe_bounds(payload.get("bounds"))
    return payload


def capture_captcha_visual(
    config: RelayConfig,
    run_dir: Path,
    *,
    capturer: Callable[[RelayConfig, str], tuple[bytes, dict[str, float], str]] | None = None,
) -> dict[str, Any]:
    with execution_run_lock(run_dir):
        return _capture_captcha_visual_locked(config, run_dir, capturer=capturer)


def _capture_captcha_visual_locked(
    config: RelayConfig,
    run_dir: Path,
    *,
    capturer: Callable[[RelayConfig, str], tuple[bytes, dict[str, float], str]] | None = None,
) -> dict[str, Any]:
    marker = _attempt_marker(run_dir)
    try:
        state = load_captcha_state(run_dir)
    except CaptchaGateError as exc:
        raise CaptchaVisualError("captcha_visual_gate_unavailable") from exc
    if state is None or state.get("status") != "human_required":
        raise CaptchaVisualError("captcha_visual_gate_not_interactive")
    page_key = state.get("page_key")
    if not isinstance(page_key, str) or not _PAGE_KEY.fullmatch(page_key):
        raise CaptchaVisualError("captcha_visual_target_unavailable")
    cycle = _allocate_visual_cycle(run_dir, marker)
    try:
        previous = _read_private_json(run_dir, VISUAL_STATE_FILE)
    except CaptchaVisualError as exc:
        if str(exc) != "captcha_visual_not_captured":
            raise
    else:
        _validate_visual_state(previous)
    budget_state = dict(state)
    budget_state["visual_cycle"] = cycle
    try:
        _write_captcha_state_locked(run_dir, budget_state, expected_attempt_marker=marker)
    except CaptchaGateError as exc:
        raise CaptchaVisualError("captcha_visual_budget_unavailable") from exc
    image, raw_bounds, document_key = (capturer or _capture_with_playwright)(config, page_key)
    bounds = _safe_bounds(raw_bounds)
    if not isinstance(document_key, str) or not _DOCUMENT_KEY.fullmatch(document_key):
        raise CaptchaVisualError("captcha_document_identity_unavailable")
    if not isinstance(image, bytes) or not image.startswith(b"\x89PNG\r\n\x1a\n"):
        raise CaptchaVisualError("captcha_visual_artifact_invalid")
    digest = hashlib.sha256(image).hexdigest()
    if _attempt_marker(run_dir) != marker:
        raise CaptchaVisualError("captcha_visual_stale")
    _write_private_bytes(run_dir, VISUAL_SCREENSHOT_FILE, image, max_bytes=MAX_SCREENSHOT_BYTES)
    visual_state = {
        "schema": VISUAL_SCHEMA,
        "attempt_marker": marker,
        "page_key": page_key,
        "document_key": document_key,
        "bounds": bounds,
        "screenshot_sha256": digest,
        "captured_at": utc_now_text(),
        "artifact_policy": "private-local/no-auto-send",
        "cycle": cycle,
        "consumed": False,
        "authorization_status": "ready",
    }
    encoded = (json.dumps(visual_state, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _write_private_bytes(run_dir, VISUAL_STATE_FILE, encoded, max_bytes=MAX_VISUAL_STATE_BYTES)
    if _attempt_marker(run_dir) != marker:
        raise CaptchaVisualError("captcha_visual_stale")
    path = run_dir / "protection" / VISUAL_SCREENSHOT_FILE
    return {
        "status": "captured",
        "artifact_path": str(path),
        "sha256": digest,
        "width": round(bounds["width"]),
        "height": round(bounds["height"]),
        "point_space": "normalized-challenge-region",
        "artifact_policy": "private-local/no-auto-send",
        "cycle": cycle,
    }


def apply_captcha_visual_actions(
    config: RelayConfig,
    run_dir: Path,
    points: list[tuple[float, float]],
    *,
    confidence: float,
    actioner: Callable[[RelayConfig, str, dict[str, float], str, str, list[tuple[float, float]]], None] | None = None,
    inspector: Callable[..., dict[str, Any]] = inspect_captcha_gate,
) -> dict[str, Any]:
    with execution_run_lock(run_dir):
        return _apply_captcha_visual_actions_locked(
            config,
            run_dir,
            points,
            confidence=confidence,
            actioner=actioner,
            inspector=inspector,
        )


def _apply_captcha_visual_actions_locked(
    config: RelayConfig,
    run_dir: Path,
    points: list[tuple[float, float]],
    *,
    confidence: float,
    actioner: Callable[[RelayConfig, str, dict[str, float], str, str, list[tuple[float, float]]], None] | None = None,
    inspector: Callable[..., dict[str, Any]] = inspect_captcha_gate,
) -> dict[str, Any]:
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence):
        raise CaptchaVisualError("captcha_visual_confidence_invalid")
    if not MIN_VISUAL_CONFIDENCE <= float(confidence) <= 1:
        raise CaptchaVisualError("captcha_visual_confidence_too_low")
    normalized = parse_visual_points([f"{x},{y}" for x, y in points])
    visual = _read_private_json(run_dir, VISUAL_STATE_FILE)
    _validate_visual_state(visual)
    if visual["consumed"]:
        raise CaptchaVisualError("captcha_visual_not_captured")
    screenshot = _read_private_bytes(run_dir, VISUAL_SCREENSHOT_FILE, max_bytes=MAX_SCREENSHOT_BYTES)
    if not screenshot.startswith(b"\x89PNG\r\n\x1a\n") or not secrets.compare_digest(
        hashlib.sha256(screenshot).hexdigest(), visual["screenshot_sha256"]
    ):
        raise CaptchaVisualError("captcha_visual_artifact_changed")
    marker = _attempt_marker(run_dir)
    if visual.get("attempt_marker") != marker:
        raise CaptchaVisualError("captcha_visual_stale")
    try:
        state = load_captcha_state(run_dir)
    except CaptchaGateError as exc:
        raise CaptchaVisualError("captcha_visual_gate_unavailable") from exc
    page_key = visual["page_key"]
    if state is None or state.get("page_key") != page_key or state.get("status") != "human_required":
        raise CaptchaVisualError("captcha_visual_stale")
    _consume_visual_authorization(run_dir, visual)
    try:
        (actioner or _apply_with_playwright)(
            config,
            page_key,
            visual["bounds"],
            visual["screenshot_sha256"],
            visual["document_key"],
            normalized,
        )
        if _attempt_marker(run_dir) != marker:
            raise CaptchaVisualError("captcha_visual_stale")
        inspected = inspector(config, run_dir, page_index=-1, page_key=page_key, persist=False)
        if _attempt_marker(run_dir) != marker:
            raise CaptchaVisualError("captcha_visual_stale")
        result = dict(inspected)
        if inspected.get("status") == "clear":
            result.update(
                {
                    "status": "cleared",
                    "next_action": "rerun_or_continue_task",
                    "human_handoff": False,
                }
            )
        _write_captcha_state_locked(run_dir, result, expected_attempt_marker=marker)
    except Exception:
        try:
            _write_visual_authorization_status(run_dir, visual, "uncertain")
        except CaptchaVisualError:
            pass
        raise
    _write_visual_authorization_status(run_dir, visual, "consumed")
    result["action_count"] = len(normalized)
    result["visual_cycle"] = visual["cycle"]
    result["confidence"] = round(float(confidence), 4)
    result["artifact_policy"] = "private-local/no-auto-send"
    return result
