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
from typing import Any, Callable

from .config import RelayConfig
from .network import redact_url, utc_now_text
from .protection import _open_protection_dir_fd, _read_bounded_fd, _write_all
from .workspace import execution_marker, execution_run_lock, load_manifest

SCHEMA = "chip-relay-captcha-gate-v1"
STATE_FILE = "captcha-state.json"
MAX_STATE_BYTES = 64 * 1024

_PROVIDER_PRIORITY = ("cloudflare", "recaptcha", "hcaptcha", "turnstile")
_PROVIDER_LABELS = {
    "recaptcha": "reCAPTCHA",
    "hcaptcha": "hCaptcha",
    "turnstile": "Turnstile",
    "cloudflare": "Cloudflare managed challenge",
}
_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_STATE_PAYLOAD_KEYS = {
    "status",
    "provider",
    "title_classification",
    "interactive",
    "visible_widget_count",
    "response_field_count",
    "token_present",
    "next_action",
    "automation",
    "human_handoff",
    "claim_policy",
    "checked_at",
    "checks",
    "elapsed_seconds",
    "page_index",
    "page_count",
    "page_key",
    "visual_cycle",
}
_STATE_RECORD_KEYS = _STATE_PAYLOAD_KEYS | {"schema", "attempt_marker", "artifact_policy"}
_STATE_TRANSITIONS = {
    "clear": ({"continue_task"}, False),
    "managed_wait": ({"wait_for_browser_native_clearance"}, False),
    "human_required": (
        {
            "solve_in_visible_trusted_browser_then_resume",
            "solve_in_visible_trusted_browser_then_run_captcha_resume",
        },
        True,
    ),
    "cleared": ({"rerun_or_continue_task"}, False),
    "timed_out": ({"inspect_protection_and_egress_before_retry"}, False),
}


class CaptchaGateError(ValueError):
    pass


def _current_attempt_marker(run_dir: Path) -> dict[str, Any]:
    try:
        return execution_marker(load_manifest(run_dir))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CaptchaGateError("captcha_attempt_marker_unavailable") from exc


def _current_visual_cycle(run_dir: Path, expected_marker: dict[str, Any]) -> int:
    try:
        manifest = load_manifest(run_dir)
        if execution_marker(manifest) != expected_marker:
            raise CaptchaGateError("captcha_attempt_changed")
        execution = manifest.get("execution")
        value = execution.get("captcha_visual_cycle", 0) if isinstance(execution, dict) else 0
    except CaptchaGateError:
        raise
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise CaptchaGateError("captcha_visual_budget_unavailable") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3:
        raise CaptchaGateError("captcha_visual_budget_unavailable")
    return value


def _bounded_int(value: Any, *, default: int = 0, minimum: int = 0, maximum: int = 1000) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(minimum, min(maximum, value))


def _strict_probe_count(raw: dict[str, Any], name: str) -> int:
    value = raw.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 1000:
        raise CaptchaGateError(f"invalid_captcha_probe: {name}")
    return value


def classify_captcha_probe(raw: Any) -> dict[str, Any]:
    """Convert boolean/count-only page metadata into a safe CAPTCHA gate decision."""
    if not isinstance(raw, dict):
        raise CaptchaGateError("invalid_captcha_probe: expected object")

    providers = raw.get("providers")
    if not isinstance(providers, dict) or set(providers) != set(_PROVIDER_LABELS):
        raise CaptchaGateError("invalid_captcha_probe: providers")
    if any(type(providers.get(name)) is not bool for name in _PROVIDER_LABELS):
        raise CaptchaGateError("invalid_captcha_probe: providers")
    detected = [name for name in _PROVIDER_PRIORITY if providers.get(name) is True]
    provider_key = detected[0] if detected else None
    provider = _PROVIDER_LABELS.get(provider_key) if provider_key else None

    title_classification = raw.get("title_classification")
    if title_classification not in {"normal", "challenge", "captcha"}:
        raise CaptchaGateError("invalid_captcha_probe: title_classification")
    visible_widgets = _strict_probe_count(raw, "visible_widgets")
    response_fields = _strict_probe_count(raw, "response_fields")
    if type(raw.get("token_present")) is not bool or type(raw.get("interactive")) is not bool:
        raise CaptchaGateError("invalid_captcha_probe: boolean fields")
    token_present = raw["token_present"]
    interactive = raw["interactive"]
    if interactive != (visible_widgets > 0 and not token_present):
        raise CaptchaGateError("invalid_captcha_probe: interactive mismatch")
    if (visible_widgets > 0 or response_fields > 0) and provider_key is None:
        raise CaptchaGateError("invalid_captcha_probe: unowned challenge nodes")
    if token_present and response_fields == 0:
        raise CaptchaGateError("invalid_captcha_probe: token without response field")
    pending_hidden = provider_key is not None and response_fields > 0 and not token_present
    active = title_classification in {"challenge", "captcha"} or visible_widgets > 0 or pending_hidden

    if token_present and title_classification == "normal":
        state = "clear"
        next_action = "continue_task"
    elif not active:
        state = "clear"
        next_action = "continue_task"
    elif provider_key == "cloudflare" or not interactive:
        state = "managed_wait"
        next_action = "wait_for_browser_native_clearance"
    else:
        state = "human_required"
        next_action = "solve_in_visible_trusted_browser_then_resume"

    return {
        "schema": SCHEMA,
        "status": state,
        "provider": provider,
        "title_classification": title_classification,
        "interactive": interactive,
        "visible_widget_count": visible_widgets,
        "response_field_count": response_fields,
        "token_present": token_present,
        "next_action": next_action,
        "automation": "browser-native-wait-only",
        "human_handoff": state == "human_required",
        "claim_policy": "best-effort/no-guaranteed-solve",
        "forbidden": ["token injection", "automatic answer extraction", "solver-service dispatch"],
    }


def _probe_script() -> str:
    return r"""
() => {
  const visible = (el) => {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
  };
  const selectors = {
    recaptcha: [
      'iframe[src*="recaptcha"]',
      '.g-recaptcha',
      'textarea[name="g-recaptcha-response"]'
    ],
    hcaptcha: [
      'iframe[src*="hcaptcha.com"]',
      '.h-captcha',
      'textarea[name="h-captcha-response"]'
    ],
    turnstile: [
      'iframe[src*="challenges.cloudflare.com"]',
      '.cf-turnstile',
      'input[name="cf-turnstile-response"]'
    ]
  };
  const matched = {};
  let visibleWidgets = 0;
  let responseFields = 0;
  let tokenPresent = false;
  for (const [provider, list] of Object.entries(selectors)) {
    const nodes = list.flatMap((selector) => Array.from(document.querySelectorAll(selector)));
    matched[provider] = nodes.length > 0;
    visibleWidgets += nodes.filter(visible).length;
    for (const node of nodes) {
      if (node.matches('textarea,input')) {
        responseFields += 1;
        if (typeof node.value === 'string' && node.value.length > 10) tokenPresent = true;
      }
    }
  }
  const title = (document.title || '').toLowerCase();
  const cloudflare = title.includes('just a moment') ||
    document.querySelector('#challenge-running, #challenge-stage, .cf-challenge-running') !== null;
  matched.cloudflare = cloudflare;
  let titleClassification = 'normal';
  if (title.includes('captcha')) titleClassification = 'captcha';
  else if (cloudflare || title.includes('challenge') || title.includes('verify you are human')) titleClassification = 'challenge';
  const interactive = visibleWidgets > 0 && !tokenPresent;
  return {
    providers: matched,
    title_classification: titleClassification,
    visible_widgets: visibleWidgets,
    response_fields: responseFields,
    token_present: tokenPresent,
    interactive,
    final_url: window.location.href
  };
}
"""


def _page_target_key(context: Any, page: Any) -> str:
    session = context.new_cdp_session(page)
    try:
        info = session.send("Target.getTargetInfo")
    except Exception as exc:
        raise CaptchaGateError("captcha_page_identity_unavailable") from exc
    finally:
        try:
            session.detach()
        except Exception:
            pass
    target_info = info.get("targetInfo") if isinstance(info, dict) else None
    target_id = target_info.get("targetId") if isinstance(target_info, dict) else None
    if not isinstance(target_id, str) or not target_id:
        raise CaptchaGateError("captcha_page_identity_unavailable")
    return hashlib.sha256(target_id.encode("utf-8", "strict")).hexdigest()[:16]


def inspect_captcha_gate(
    config: RelayConfig,
    run_dir: Path,
    *,
    page_index: int = -1,
    page_key: str | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    attempt_marker = _current_attempt_marker(run_dir)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise CaptchaGateError("playwright_unavailable") from exc

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(config.cdp_url)
            contexts = browser.contexts
            pages = [page for context in contexts for page in context.pages]
            if not pages:
                raise CaptchaGateError("captcha_page_unavailable")
            selected: int | None = None
            selected_key: str | None = None
            if page_key is not None:
                for candidate_index, candidate_page in enumerate(pages):
                    candidate_key = _page_target_key(candidate_page.context, candidate_page)
                    if secrets.compare_digest(candidate_key, page_key):
                        selected = candidate_index
                        selected_key = candidate_key
                        break
                if selected is None:
                    raise CaptchaGateError("captcha_page_target_changed")
            else:
                selected = page_index if page_index >= 0 else len(pages) - 1
                if selected < 0 or selected >= len(pages):
                    raise CaptchaGateError("captcha_page_index_out_of_range")
                selected_key = _page_target_key(pages[selected].context, pages[selected])
            raw = pages[selected].evaluate(_probe_script())
    except CaptchaGateError:
        raise
    except Exception as exc:
        raise CaptchaGateError(f"captcha_inspection_failed: {type(exc).__name__}") from exc

    decision = classify_captcha_probe(raw)
    decision.update(
        {
            "run_id": run_dir.name,
            "page_index": selected,
            "page_count": len(pages),
            "page_key": selected_key,
            "url": redact_url(str(raw.get("final_url", "")))[:1000] if isinstance(raw, dict) else "",
            "checked_at": utc_now_text(),
            "artifact_policy": "metadata-only/private-local",
        }
    )
    if persist:
        write_captcha_state(run_dir, decision, expected_attempt_marker=attempt_marker)
    return decision


def _write_private_state(run_dir: Path, payload: dict[str, Any]) -> None:
    try:
        root_fd = _open_protection_dir_fd(run_dir, create=True)
    except (OSError, ValueError) as exc:
        raise CaptchaGateError("unsafe_captcha_state_path") from exc
    if root_fd is None:
        raise CaptchaGateError("unsafe_captcha_state_path")
    temporary = f".captcha-{os.getpid()}-{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MAX_STATE_BYTES:
        os.close(root_fd)
        raise CaptchaGateError("captcha_state_too_large")
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, STATE_FILE, src_dir_fd=root_fd, dst_dir_fd=root_fd)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass
        raise CaptchaGateError("unsafe_captcha_state_path") from exc
    finally:
        os.close(root_fd)


def _validate_state_payload(payload: dict[str, Any]) -> None:
    status = payload.get("status")
    if not isinstance(status, str):
        raise CaptchaGateError("malformed_captcha_state")
    transition = _STATE_TRANSITIONS.get(status)
    if transition is None:
        raise CaptchaGateError("malformed_captcha_state")
    allowed_actions, expected_handoff = transition
    if payload.get("next_action") not in allowed_actions:
        raise CaptchaGateError("malformed_captcha_state")
    if type(payload.get("human_handoff")) is not bool or payload["human_handoff"] is not expected_handoff:
        raise CaptchaGateError("malformed_captcha_state")
    if payload.get("provider") not in {None, *_PROVIDER_LABELS.values()}:
        raise CaptchaGateError("malformed_captcha_state")
    title_classification = payload.get("title_classification")
    if title_classification is not None and title_classification not in {"normal", "challenge", "captcha"}:
        raise CaptchaGateError("malformed_captcha_state")
    for name in ("interactive", "token_present"):
        if name in payload and type(payload[name]) is not bool:
            raise CaptchaGateError("malformed_captcha_state")
    for name in ("visible_widget_count", "response_field_count", "checks"):
        if name in payload:
            value = payload[name]
            minimum = 1 if name == "checks" else 0
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 1000:
                raise CaptchaGateError("malformed_captcha_state")
    for name in ("page_index", "page_count"):
        if name in payload:
            value = payload[name]
            minimum = 1 if name == "page_count" else 0
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > 1000:
                raise CaptchaGateError("malformed_captcha_state")
    page_key = payload.get("page_key")
    if page_key is not None and (not isinstance(page_key, str) or not re.fullmatch(r"[0-9a-f]{16}", page_key)):
        raise CaptchaGateError("malformed_captcha_state")
    page_fields = {name for name in ("page_index", "page_count", "page_key") if name in payload}
    if page_fields and page_fields != {"page_index", "page_count", "page_key"}:
        raise CaptchaGateError("malformed_captcha_state")
    if page_fields and payload["page_index"] >= payload["page_count"]:
        raise CaptchaGateError("malformed_captcha_state")
    visual_cycle = payload.get("visual_cycle")
    if isinstance(visual_cycle, bool) or not isinstance(visual_cycle, int) or not 0 <= visual_cycle <= 3:
        raise CaptchaGateError("malformed_captcha_state")
    if "elapsed_seconds" in payload:
        elapsed = payload["elapsed_seconds"]
        if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
            raise CaptchaGateError("malformed_captcha_state")
    checked_at = payload.get("checked_at")
    if checked_at is not None and (not isinstance(checked_at, str) or not _ISO_UTC.fullmatch(checked_at)):
        raise CaptchaGateError("malformed_captcha_state")
    if "automation" in payload and payload["automation"] != "browser-native-wait-only":
        raise CaptchaGateError("malformed_captcha_state")
    if "claim_policy" in payload and payload["claim_policy"] != "best-effort/no-guaranteed-solve":
        raise CaptchaGateError("malformed_captcha_state")


def _write_captcha_state_locked(
    run_dir: Path,
    payload: dict[str, Any],
    *,
    expected_attempt_marker: dict[str, Any] | None = None,
) -> None:
    safe = {name: payload[name] for name in _STATE_PAYLOAD_KEYS if name in payload}
    current_marker = _current_attempt_marker(run_dir)
    if expected_attempt_marker is not None and current_marker != expected_attempt_marker:
        raise CaptchaGateError("captcha_attempt_changed")
    manifest_cycle = _current_visual_cycle(run_dir, current_marker)
    if "visual_cycle" in safe and safe["visual_cycle"] != manifest_cycle:
        raise CaptchaGateError("captcha_visual_budget_mismatch")
    safe["visual_cycle"] = manifest_cycle
    _validate_state_payload(safe)
    safe["schema"] = SCHEMA
    safe["attempt_marker"] = current_marker
    safe["artifact_policy"] = "metadata-only/private-local"
    _write_private_state(run_dir, safe)
    if (
        expected_attempt_marker is not None
        and _current_attempt_marker(run_dir) != expected_attempt_marker
    ):
        raise CaptchaGateError("captcha_attempt_changed")


def write_captcha_state(
    run_dir: Path,
    payload: dict[str, Any],
    *,
    expected_attempt_marker: dict[str, Any] | None = None,
) -> None:
    with execution_run_lock(run_dir):
        _write_captcha_state_locked(
            run_dir,
            payload,
            expected_attempt_marker=expected_attempt_marker,
        )


def load_captcha_state(run_dir: Path) -> dict[str, Any] | None:
    try:
        root_fd = _open_protection_dir_fd(run_dir, create=False)
    except (OSError, ValueError) as exc:
        raise CaptchaGateError("unsafe_captcha_state_path") from exc
    if root_fd is None:
        return None
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        try:
            descriptor = os.open(STATE_FILE, flags, dir_fd=root_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CaptchaGateError("unsafe_captcha_state_path") from exc
        try:
            metadata = os.fstat(descriptor)
            unsafe_mode = stat.S_IMODE(metadata.st_mode) & 0o077
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or unsafe_mode:
                raise CaptchaGateError("unsafe_captcha_state_path: expected owner-only regular file")
            try:
                data = _read_bounded_fd(
                    descriptor,
                    max_bytes=MAX_STATE_BYTES,
                    too_large_gate="captcha_state_too_large",
                )
            except ValueError as exc:
                raise CaptchaGateError("unsafe_captcha_state_path") from exc
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptchaGateError("malformed_captcha_state") from exc
    if not isinstance(payload, dict) or payload.get("schema") != SCHEMA:
        raise CaptchaGateError("malformed_captcha_state")
    if set(payload) - _STATE_RECORD_KEYS:
        raise CaptchaGateError("malformed_captcha_state")
    if payload.get("artifact_policy") != "metadata-only/private-local":
        raise CaptchaGateError("malformed_captcha_state")
    _validate_state_payload(payload)
    marker = payload.get("attempt_marker")
    current_marker = _current_attempt_marker(run_dir)
    if marker != current_marker:
        raise CaptchaGateError("stale_captcha_state")
    if payload["visual_cycle"] != _current_visual_cycle(run_dir, current_marker):
        raise CaptchaGateError("malformed_captcha_state")
    return payload


def captcha_summary(run_dir: Path) -> dict[str, Any]:
    try:
        state = load_captcha_state(run_dir)
    except CaptchaGateError:
        return {
            "status": "stale",
            "provider": None,
            "next_action": "run_captcha_inspect",
            "human_handoff": False,
        }
    if state is None:
        return {
            "status": "not_checked",
            "provider": None,
            "next_action": "run_captcha_inspect_if_challenged",
            "human_handoff": False,
        }
    return {
        "status": state.get("status", "unknown"),
        "provider": state.get("provider"),
        "next_action": state.get("next_action"),
        "human_handoff": state.get("human_handoff") is True,
        "checked_at": state.get("checked_at"),
        "artifact": "protection/captcha-state.json",
    }


def wait_for_captcha_clearance(
    config: RelayConfig,
    run_dir: Path,
    *,
    timeout: float = 120,
    poll_interval: float = 2,
    page_index: int = -1,
    inspector: Callable[..., dict[str, Any]] = inspect_captcha_gate,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    if not math.isfinite(timeout) or timeout < 0 or timeout > 3600:
        raise CaptchaGateError("invalid_captcha_timeout")
    if not math.isfinite(poll_interval) or poll_interval <= 0 or poll_interval > 60:
        raise CaptchaGateError("invalid_captcha_poll_interval")

    attempt_marker = _current_attempt_marker(run_dir)
    started = monotonic()
    checks = 0
    latest: dict[str, Any] | None = None
    sticky_page_index = page_index
    sticky_page_key: str | None = None
    if page_index < 0:
        try:
            previous = load_captcha_state(run_dir)
        except CaptchaGateError:
            previous = None
        if previous is not None and previous.get("status") in {"managed_wait", "human_required", "timed_out"}:
            prior_key = previous.get("page_key")
            prior_index = previous.get("page_index")
            if isinstance(prior_key, str):
                sticky_page_key = prior_key
            if isinstance(prior_index, int) and not isinstance(prior_index, bool):
                sticky_page_index = prior_index
    while True:
        if _current_attempt_marker(run_dir) != attempt_marker:
            raise CaptchaGateError("captcha_attempt_changed")
        latest = inspector(
            config,
            run_dir,
            page_index=sticky_page_index,
            page_key=sticky_page_key,
            persist=False,
        )
        if _current_attempt_marker(run_dir) != attempt_marker:
            raise CaptchaGateError("captcha_attempt_changed")
        checks += 1
        if sticky_page_key is None and isinstance(latest.get("page_key"), str):
            sticky_page_key = latest["page_key"]
        if sticky_page_index < 0:
            sticky_page_index = _bounded_int(latest.get("page_index"), default=-1, minimum=-1)
        if latest.get("status") == "clear":
            result = dict(latest)
            result.update(
                {
                    "status": "cleared",
                    "checks": checks,
                    "elapsed_seconds": round(max(0.0, monotonic() - started), 3),
                    "next_action": "rerun_or_continue_task",
                }
            )
            write_captcha_state(run_dir, result, expected_attempt_marker=attempt_marker)
            return result
        elapsed = monotonic() - started
        if elapsed >= timeout:
            needs_human = latest.get("human_handoff") is True or (
                latest.get("provider") == "Cloudflare managed challenge"
                and _bounded_int(latest.get("visible_widget_count")) > 0
            )
            result = dict(latest)
            result.update(
                {
                    "status": "human_required" if needs_human else "timed_out",
                    "checks": checks,
                    "elapsed_seconds": round(max(0.0, elapsed), 3),
                    "next_action": (
                        "solve_in_visible_trusted_browser_then_run_captcha_resume"
                        if needs_human
                        else "inspect_protection_and_egress_before_retry"
                    ),
                    "human_handoff": needs_human,
                }
            )
            write_captcha_state(run_dir, result, expected_attempt_marker=attempt_marker)
            return result
        sleep(min(poll_interval, max(0.0, timeout - elapsed)))
