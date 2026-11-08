from __future__ import annotations

import json
import math
import os
import re
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .operation_audit import record_handoff_event
from .workspace import execution_marker, execution_run_lock, load_manifest

SCHEMA = "chip-relay-human-handoff-v1"
HANDOFF_DIR = "handoff"
STATE_FILE = "state.json"
MAX_STATE_BYTES = 64 * 1024
KINDS = {"captcha", "login", "two_factor", "consent", "confirmation", "other"}
REASON_CODES = {
    "captcha_automation_exhausted",
    "captcha_visual_unavailable",
    "credential_entry_required",
    "second_factor_required",
    "user_consent_required",
    "irreversible_confirmation_required",
    "operator_judgment_required",
}
STATUSES = {"waiting", "resolved", "cancelled", "timed_out"}
_ID = re.compile(r"^[0-9a-f]{32}$")
_PAGE_KEY = re.compile(r"^[0-9a-f]{16}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_VISUAL_UNAVAILABLE_REASONS = {
    "playwright_unavailable",
    "captcha_visual_region_unavailable",
    "captcha_visual_target_unavailable",
}


class HumanHandoffError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _time_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _open_handoff_dir(run_dir: Path, *, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(run_dir, flags)
    except OSError as exc:
        raise HumanHandoffError("unsafe_handoff_path") from exc
    try:
        root = os.fstat(root_fd)
        if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid():
            raise HumanHandoffError("unsafe_handoff_path")
        if create:
            try:
                os.mkdir(HANDOFF_DIR, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
        try:
            handoff_fd = os.open(HANDOFF_DIR, flags, dir_fd=root_fd)
        except FileNotFoundError:
            if not create:
                return -1
            raise
        metadata = os.fstat(handoff_fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            os.close(handoff_fd)
            raise HumanHandoffError("unsafe_handoff_path")
        if create:
            os.fchmod(handoff_fd, 0o700)
        elif stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(handoff_fd)
            raise HumanHandoffError("unsafe_handoff_path")
        return handoff_fd
    finally:
        os.close(root_fd)


def _validate(payload: Any) -> dict[str, Any]:
    expected = {
        "schema",
        "handoff_id",
        "kind",
        "reason_code",
        "status",
        "created_at",
        "updated_at",
        "expires_at",
        "attempt_marker",
        "page_key",
        "provider",
        "audit_pending",
        "artifact_policy",
    }
    if not isinstance(payload, dict) or set(payload) != expected or payload.get("schema") != SCHEMA:
        raise HumanHandoffError("malformed_handoff_state")
    if not isinstance(payload.get("handoff_id"), str) or not _ID.fullmatch(payload["handoff_id"]):
        raise HumanHandoffError("malformed_handoff_state")
    if payload.get("kind") not in KINDS or payload.get("reason_code") not in REASON_CODES or payload.get("status") not in STATUSES:
        raise HumanHandoffError("malformed_handoff_state")
    pending = payload.get("audit_pending")
    if pending is not None and (pending not in STATUSES or pending != payload["status"]):
        raise HumanHandoffError("malformed_handoff_state")
    for name in ("created_at", "updated_at", "expires_at"):
        if not isinstance(payload.get(name), str) or not _TIMESTAMP.fullmatch(payload[name]):
            raise HumanHandoffError("malformed_handoff_state")
    try:
        created = _parse_time(payload["created_at"])
        updated = _parse_time(payload["updated_at"])
        expires = _parse_time(payload["expires_at"])
    except ValueError as exc:
        raise HumanHandoffError("malformed_handoff_state") from exc
    if created > updated or created > expires:
        raise HumanHandoffError("malformed_handoff_state")
    if payload["status"] == "waiting" and updated > expires:
        raise HumanHandoffError("malformed_handoff_state")
    page_key = payload.get("page_key")
    if page_key is not None and (not isinstance(page_key, str) or not _PAGE_KEY.fullmatch(page_key)):
        raise HumanHandoffError("malformed_handoff_state")
    provider = payload.get("provider")
    if provider is not None and (not isinstance(provider, str) or not 1 <= len(provider) <= 64 or any(char in provider for char in "\r\n\x00")):
        raise HumanHandoffError("malformed_handoff_state")
    marker = payload.get("attempt_marker")
    if not isinstance(marker, dict) or set(marker) != {"generation", "attempt_id"}:
        raise HumanHandoffError("malformed_handoff_state")
    if payload.get("artifact_policy") != "redacted-metadata-only/private-local":
        raise HumanHandoffError("malformed_handoff_state")
    return payload


def _write(run_dir: Path, payload: dict[str, Any]) -> None:
    _validate(payload)
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > MAX_STATE_BYTES:
        raise HumanHandoffError("handoff_state_too_large")
    directory_fd = _open_handoff_dir(run_dir, create=True)
    temporary = f".handoff-{os.getpid()}-{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_fd: int | None = None
    try:
        file_fd = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(file_fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short handoff write")
            view = view[written:]
        os.fsync(file_fd)
        os.close(file_fd)
        file_fd = None
        os.rename(temporary, STATE_FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise HumanHandoffError("handoff_write_failed") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)


def _read(run_dir: Path) -> dict[str, Any] | None:
    directory_fd = _open_handoff_dir(run_dir, create=False)
    if directory_fd < 0:
        return None
    file_fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            file_fd = os.open(STATE_FILE, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > MAX_STATE_BYTES:
            raise HumanHandoffError("unsafe_handoff_path")
        data = bytearray()
        while len(data) <= MAX_STATE_BYTES:
            chunk = os.read(file_fd, min(65_536, MAX_STATE_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_STATE_BYTES:
            raise HumanHandoffError("handoff_state_too_large")
    except OSError as exc:
        raise HumanHandoffError("handoff_read_failed") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
    try:
        return _validate(json.loads(bytes(data).decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HumanHandoffError("malformed_handoff_state") from exc


def _context(payload: dict[str, Any]) -> dict[str, Any]:
    context: dict[str, Any] = {"reason_code": payload["reason_code"]}
    for name in ("page_key", "provider"):
        if payload.get(name) is not None:
            context[name] = payload[name]
    return context


def _reconcile_audit_locked(run_dir: Path, payload: dict[str, Any]) -> dict[str, Any]:
    pending = payload.get("audit_pending")
    if pending is None:
        return payload
    record_handoff_event(
        run_dir,
        operation_id=payload["handoff_id"],
        operation=f"handoff.{payload['kind']}",
        status=pending,
        context=_context(payload),
        attempt_marker=payload["attempt_marker"],
    )
    payload["audit_pending"] = None
    _write(run_dir, payload)
    return payload


def _publish_transition_locked(
    run_dir: Path,
    payload: dict[str, Any],
    status: str,
    *,
    when: datetime | None = None,
) -> dict[str, Any]:
    if status not in STATUSES:
        raise HumanHandoffError("invalid_handoff_transition")
    payload["status"] = status
    payload["updated_at"] = _time_text(when or _now())
    payload["audit_pending"] = status
    _write(run_dir, payload)
    return _reconcile_audit_locked(run_dir, payload)


def _terminalize_expired_locked(run_dir: Path, payload: dict[str, Any], now: datetime) -> dict[str, Any]:
    if payload["status"] == "waiting" and now >= _parse_time(payload["expires_at"]):
        return _publish_transition_locked(run_dir, payload, "timed_out", when=now)
    return payload


def _validate_captcha_escalation_locked(run_dir: Path, reason_code: str) -> None:
    from .captcha import CaptchaGateError, load_captcha_state

    try:
        captcha_state = load_captcha_state(run_dir)
    except CaptchaGateError as exc:
        raise HumanHandoffError("captcha_handoff_state_unavailable") from exc
    if captcha_state is None:
        raise HumanHandoffError("captcha_handoff_state_unavailable")
    exhausted = (
        reason_code == "captcha_automation_exhausted"
        and captcha_state.get("status") == "human_required"
        and captcha_state.get("visual_cycle") == 3
        and captcha_state.get("native_attempts") == 1
    )
    visual_unavailable = (
        reason_code == "captcha_visual_unavailable"
        and captcha_state.get("status") == "agent_action"
        and captcha_state.get("native_attempts") == 1
        and captcha_state.get("visual_unavailable_reason") in _VISUAL_UNAVAILABLE_REASONS
    )
    if not exhausted and not visual_unavailable:
        raise HumanHandoffError("captcha_self_service_not_exhausted")


def request_handoff(
    run_dir: Path,
    *,
    kind: str,
    reason_code: str,
    timeout_seconds: float = 600,
    page_key: str | None = None,
    provider: str | None = None,
) -> dict[str, Any]:
    if kind not in KINDS or reason_code not in REASON_CODES:
        raise HumanHandoffError("invalid_handoff_request")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 30 <= timeout_seconds <= 86_400:
        raise HumanHandoffError("invalid_handoff_timeout")
    with execution_run_lock(run_dir):
        now = _now()
        marker = execution_marker(load_manifest(run_dir))
        existing = _read(run_dir)
        if existing is not None:
            existing = _reconcile_audit_locked(run_dir, existing)
            existing = _terminalize_expired_locked(run_dir, existing, now)
            if existing["status"] == "waiting":
                if marker == existing["attempt_marker"]:
                    return _public(existing)
                existing = _publish_transition_locked(run_dir, existing, "cancelled", when=now)
        if kind == "captcha":
            _validate_captcha_escalation_locked(run_dir, reason_code)
        payload = {
            "schema": SCHEMA,
            "handoff_id": secrets.token_hex(16),
            "kind": kind,
            "reason_code": reason_code,
            "status": "waiting",
            "created_at": _time_text(now),
            "updated_at": _time_text(now),
            "expires_at": _time_text(now + timedelta(seconds=float(timeout_seconds))),
            "attempt_marker": marker,
            "page_key": page_key,
            "provider": provider,
            "audit_pending": "waiting",
            "artifact_policy": "redacted-metadata-only/private-local",
        }
        _write(run_dir, payload)
        payload = _reconcile_audit_locked(run_dir, payload)
        return _public(payload)


def _transition(run_dir: Path, handoff_id: str, status: str) -> dict[str, Any]:
    if not _ID.fullmatch(handoff_id) or status not in {"resolved", "cancelled"}:
        raise HumanHandoffError("invalid_handoff_transition")
    with execution_run_lock(run_dir):
        payload = _read(run_dir)
        if payload is None or payload["handoff_id"] != handoff_id:
            raise HumanHandoffError("handoff_not_found")
        payload = _reconcile_audit_locked(run_dir, payload)
        now = _now()
        payload = _terminalize_expired_locked(run_dir, payload, now)
        if payload["status"] == "timed_out":
            return _public(payload)
        if payload["status"] != "waiting":
            if payload["status"] == status:
                return _public(payload)
            raise HumanHandoffError("handoff_not_waiting")
        if execution_marker(load_manifest(run_dir)) != payload["attempt_marker"]:
            raise HumanHandoffError("stale_handoff")
        payload = _publish_transition_locked(run_dir, payload, status, when=now)
        return _public(payload)


def resolve_handoff(run_dir: Path, handoff_id: str) -> dict[str, Any]:
    return _transition(run_dir, handoff_id, "resolved")


def cancel_handoff(run_dir: Path, handoff_id: str) -> dict[str, Any]:
    return _transition(run_dir, handoff_id, "cancelled")


def handoff_summary(run_dir: Path) -> dict[str, Any]:
    with execution_run_lock(run_dir):
        payload = _read(run_dir)
        if payload is None:
            return {"status": "none", "human_required": False, "artifact": None}
        payload = _reconcile_audit_locked(run_dir, payload)
        now = _now()
        payload = _terminalize_expired_locked(run_dir, payload, now)
        if execution_marker(load_manifest(run_dir)) != payload["attempt_marker"]:
            public = _public(payload)
            public.update({"status": "stale", "human_required": False})
            return public
        return _public(payload)


def _public(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "handoff_id": payload["handoff_id"],
        "kind": payload["kind"],
        "reason_code": payload["reason_code"],
        "status": payload["status"],
        "human_required": payload["status"] == "waiting",
        "expires_at": payload["expires_at"],
        "provider": payload.get("provider"),
        "artifact": f"{HANDOFF_DIR}/{STATE_FILE}",
        "artifact_policy": "redacted-metadata-only/private-local",
    }
