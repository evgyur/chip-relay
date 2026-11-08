from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .network import utc_now_text
from .workspace import execution_marker, load_manifest

SCHEMA = "chip-relay-operation-audit-v1"
AUDIT_DIR = "audit"
AUDIT_FILE = "operations.jsonl"
MAX_AUDIT_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 16 * 1024
RETENTION_DAYS = 30
MAX_EVENTS = 100_000
_OPERATION = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_OPERATION_ID = re.compile(r"^[0-9a-f]{32}$")
_EFFECT_CLASSES = {"read-only", "browser-state", "external"}
_TERMINAL = {"succeeded", "failed", "cancelled", "unknown", "interrupted"}
_EVENT_TYPES = {"operation_started", "operation_finished", "human_handoff"}
_CONTEXT_KEYS = {"origin", "page_key", "provider", "reason_code", "action_count", "visual_cycle"}


class OperationAuditError(ValueError):
    pass


def _open_audit_dir(run_dir: Path, *, create: bool) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(run_dir, flags)
    except OSError as exc:
        raise OperationAuditError("unsafe_operation_audit_path") from exc
    try:
        root = os.fstat(root_fd)
        if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid():
            raise OperationAuditError("unsafe_operation_audit_path")
        if create:
            try:
                os.mkdir(AUDIT_DIR, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
        try:
            audit_fd = os.open(AUDIT_DIR, flags, dir_fd=root_fd)
        except FileNotFoundError:
            if not create:
                return -1
            raise
        metadata = os.fstat(audit_fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            os.close(audit_fd)
            raise OperationAuditError("unsafe_operation_audit_path")
        if create:
            os.fchmod(audit_fd, 0o700)
        elif stat.S_IMODE(metadata.st_mode) != 0o700:
            os.close(audit_fd)
            raise OperationAuditError("unsafe_operation_audit_path")
        return audit_fd
    except Exception:
        raise
    finally:
        os.close(root_fd)


def _safe_origin(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 2048 or any(char in value for char in "\r\n\x00"):
        raise OperationAuditError("invalid_operation_audit_context")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OperationAuditError("invalid_operation_audit_context") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise OperationAuditError("invalid_operation_audit_context")
    host = parsed.hostname.lower().rstrip(".")
    default = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default else "")


def _sanitize_context(raw: dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict) or set(raw) - _CONTEXT_KEYS:
        raise OperationAuditError("invalid_operation_audit_context")
    result: dict[str, Any] = {}
    for key, value in raw.items():
        if key == "origin":
            normalized = _safe_origin(value)
            if normalized is not None:
                result[key] = normalized
        elif key in {"action_count", "visual_cycle"}:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000:
                raise OperationAuditError("invalid_operation_audit_context")
            result[key] = value
        else:
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(char in value for char in "\r\n\x00"):
                raise OperationAuditError("invalid_operation_audit_context")
            result[key] = value
    return result


def _append_event(
    run_dir: Path,
    event: dict[str, Any],
    *,
    dedupe: tuple[str, str, str] | None = None,
) -> None:
    encoded = (json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_EVENT_BYTES:
        raise OperationAuditError("operation_audit_event_too_large")
    directory_fd = _open_audit_dir(run_dir, create=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    file_fd: int | None = None
    try:
        file_fd = os.open(AUDIT_FILE, flags, 0o600, dir_fd=directory_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise OperationAuditError("unsafe_operation_audit_path")
        os.fchmod(file_fd, 0o600)
        fcntl.flock(file_fd, fcntl.LOCK_EX)
        if dedupe is not None:
            os.lseek(file_fd, 0, os.SEEK_SET)
            current = bytearray()
            while len(current) <= MAX_AUDIT_BYTES:
                chunk = os.read(file_fd, min(64 * 1024, MAX_AUDIT_BYTES + 1 - len(current)))
                if not chunk:
                    break
                current.extend(chunk)
            if len(current) > MAX_AUDIT_BYTES:
                raise OperationAuditError("operation_audit_too_large")
            for line in bytes(current).splitlines():
                try:
                    existing = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise OperationAuditError("malformed_operation_audit") from exc
                if (
                    isinstance(existing, dict)
                    and existing.get("event") == dedupe[0]
                    and existing.get("operation_id") == dedupe[1]
                    and existing.get("status") == dedupe[2]
                ):
                    return
            os.lseek(file_fd, 0, os.SEEK_END)
        if os.fstat(file_fd).st_size + len(encoded) > MAX_AUDIT_BYTES:
            raise OperationAuditError("operation_audit_full")
        view = memoryview(encoded)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short operation audit write")
            view = view[written:]
        os.fsync(file_fd)
        os.fsync(directory_fd)
    except OperationAuditError:
        raise
    except OSError as exc:
        raise OperationAuditError("operation_audit_write_failed") from exc
    finally:
        if file_fd is not None:
            try:
                fcntl.flock(file_fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(file_fd)
        os.close(directory_fd)


def _base_event(
    run_dir: Path,
    *,
    event_type: str,
    operation_id: str,
    operation: str,
    effect_class: str,
    attempt_marker: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if event_type not in _EVENT_TYPES or not _OPERATION_ID.fullmatch(operation_id):
        raise OperationAuditError("invalid_operation_audit_event")
    if not _OPERATION.fullmatch(operation) or effect_class not in _EFFECT_CLASSES:
        raise OperationAuditError("invalid_operation_audit_event")
    if attempt_marker is None:
        try:
            marker = execution_marker(load_manifest(run_dir))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise OperationAuditError("operation_audit_attempt_unavailable") from exc
    else:
        marker = dict(attempt_marker)
        if (
            set(marker) != {"generation", "attempt_id"}
            or isinstance(marker.get("generation"), bool)
            or not isinstance(marker.get("generation"), int)
            or marker["generation"] < 0
            or not isinstance(marker.get("attempt_id"), str)
            or not marker["attempt_id"]
        ):
            raise OperationAuditError("operation_audit_attempt_unavailable")
    return {
        "schema": SCHEMA,
        "event": event_type,
        "operation_id": operation_id,
        "operation": operation,
        "effect_class": effect_class,
        "attempt_marker": marker,
        "at": utc_now_text(),
    }


@dataclass
class OperationHandle:
    run_dir: Path
    operation_id: str
    operation: str
    effect_class: str
    dispatched: bool = False
    finished: bool = False

    def mark_dispatched(self) -> None:
        if self.finished:
            raise OperationAuditError("operation_already_finished")
        self.dispatched = True

    def finish(self, status: str, *, error_class: str | None = None, context: dict[str, Any] | None = None) -> dict[str, Any]:
        if self.finished:
            raise OperationAuditError("operation_already_finished")
        if status not in _TERMINAL:
            raise OperationAuditError("invalid_operation_status")
        if status == "failed" and self.dispatched and self.effect_class != "read-only":
            raise OperationAuditError("dispatched_effect_must_not_be_failed")
        if error_class is not None and (not isinstance(error_class, str) or not _OPERATION.fullmatch(error_class)):
            raise OperationAuditError("invalid_operation_error_class")
        event = _base_event(
            self.run_dir,
            event_type="operation_finished",
            operation_id=self.operation_id,
            operation=self.operation,
            effect_class=self.effect_class,
        )
        event.update(
            {
                "status": status,
                "dispatched": self.dispatched,
                "retry_safe": status in {"failed", "cancelled"} and not self.dispatched,
                "context": _sanitize_context(context),
            }
        )
        if error_class:
            event["error_class"] = error_class
        _append_event(self.run_dir, event)
        self.finished = True
        return event

    def fail_from_exception(self, error_class: str) -> dict[str, Any]:
        status = "unknown" if self.dispatched and self.effect_class != "read-only" else "failed"
        return self.finish(status, error_class=error_class)


def begin_operation(
    run_dir: Path,
    operation: str,
    *,
    effect_class: str,
    context: dict[str, Any] | None = None,
) -> "OperationHandle":
    _prune_expired(run_dir)
    operation_id = secrets.token_hex(16)
    event = _base_event(
        run_dir,
        event_type="operation_started",
        operation_id=operation_id,
        operation=operation,
        effect_class=effect_class,
    )
    event["context"] = _sanitize_context(context)
    _append_event(run_dir, event)
    return OperationHandle(run_dir, operation_id, operation, effect_class)


def record_handoff_event(
    run_dir: Path,
    *,
    operation_id: str,
    operation: str,
    status: str,
    context: dict[str, Any] | None = None,
    attempt_marker: dict[str, Any] | None = None,
) -> None:
    if status not in {"waiting", "resolved", "cancelled", "timed_out"}:
        raise OperationAuditError("invalid_handoff_status")
    event = _base_event(
        run_dir,
        event_type="human_handoff",
        operation_id=operation_id,
        operation=operation,
        effect_class="browser-state",
        attempt_marker=attempt_marker,
    )
    event.update({"status": status, "context": _sanitize_context(context)})
    _append_event(
        run_dir,
        event,
        dedupe=("human_handoff", operation_id, status),
    )


def _validate_loaded_event(item: Any) -> dict[str, Any]:
    allowed = {
        "schema",
        "event",
        "operation_id",
        "operation",
        "effect_class",
        "attempt_marker",
        "at",
        "context",
        "status",
        "dispatched",
        "retry_safe",
        "error_class",
    }
    if (
        not isinstance(item, dict)
        or set(item) - allowed
        or item.get("schema") != SCHEMA
        or item.get("event") not in _EVENT_TYPES
        or not isinstance(item.get("operation_id"), str)
        or _OPERATION_ID.fullmatch(item["operation_id"]) is None
        or not isinstance(item.get("operation"), str)
        or _OPERATION.fullmatch(item["operation"]) is None
        or item.get("effect_class") not in _EFFECT_CLASSES
        or not isinstance(item.get("at"), str)
    ):
        raise OperationAuditError("malformed_operation_audit")
    try:
        datetime.fromisoformat(item["at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperationAuditError("malformed_operation_audit") from exc
    marker = item.get("attempt_marker")
    if not isinstance(marker, dict) or set(marker) != {"generation", "attempt_id"}:
        raise OperationAuditError("malformed_operation_audit")
    if _sanitize_context(item.get("context")) != item.get("context", {}):
        raise OperationAuditError("malformed_operation_audit")
    event_type = item["event"]
    if event_type == "operation_started" and set(item) & {"status", "dispatched", "retry_safe", "error_class"}:
        raise OperationAuditError("malformed_operation_audit")
    if event_type == "operation_finished":
        if item.get("status") not in _TERMINAL or type(item.get("dispatched")) is not bool or type(item.get("retry_safe")) is not bool:
            raise OperationAuditError("malformed_operation_audit")
    if event_type == "human_handoff" and item.get("status") not in {"waiting", "resolved", "cancelled", "timed_out"}:
        raise OperationAuditError("malformed_operation_audit")
    error_class = item.get("error_class")
    if error_class is not None and (not isinstance(error_class, str) or _OPERATION.fullmatch(error_class) is None):
        raise OperationAuditError("malformed_operation_audit")
    return item


def _read_events(run_dir: Path) -> list[dict[str, Any]]:
    directory_fd = _open_audit_dir(run_dir, create=False)
    if directory_fd < 0:
        return []
    file_fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            file_fd = os.open(AUDIT_FILE, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return []
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_size > MAX_AUDIT_BYTES:
            raise OperationAuditError("unsafe_operation_audit_path")
        data = bytearray()
        while len(data) <= MAX_AUDIT_BYTES:
            chunk = os.read(file_fd, min(65_536, MAX_AUDIT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_AUDIT_BYTES:
            raise OperationAuditError("operation_audit_full")
    except OSError as exc:
        raise OperationAuditError("operation_audit_read_failed") from exc
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(directory_fd)
    events: list[dict[str, Any]] = []
    for line in bytes(data).splitlines():
        if len(events) >= MAX_EVENTS:
            raise OperationAuditError("operation_audit_event_limit")
        try:
            item = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OperationAuditError("malformed_operation_audit") from exc
        events.append(_validate_loaded_event(item))
    return events


def _prune_expired(run_dir: Path) -> None:
    directory_fd = _open_audit_dir(run_dir, create=False)
    if directory_fd < 0:
        return
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        try:
            descriptor = os.open(AUDIT_FILE, flags, dir_fd=directory_fd)
        except FileNotFoundError:
            return
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OperationAuditError("unsafe_operation_audit_path")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            os.lseek(descriptor, 0, os.SEEK_SET)
            data = bytearray()
            while len(data) <= MAX_AUDIT_BYTES:
                chunk = os.read(descriptor, min(64 * 1024, MAX_AUDIT_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_AUDIT_BYTES:
                raise OperationAuditError("operation_audit_too_large")
            events: list[dict[str, Any]] = []
            for raw_line in bytes(data).splitlines():
                if not raw_line:
                    continue
                try:
                    event = json.loads(raw_line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise OperationAuditError("malformed_operation_audit") from exc
                events.append(_validate_loaded_event(event))
            if not events:
                return
            started = {event["operation_id"] for event in events if event["event"] == "operation_started"}
            finished = {event["operation_id"] for event in events if event["event"] == "operation_finished"}
            handoff_latest: dict[str, str] = {}
            for event in events:
                if event["event"] == "human_handoff":
                    handoff_latest[event["operation_id"]] = event["status"]
            waiting_handoff = any(status == "waiting" for status in handoff_latest.values())
            latest = max(
                datetime.fromisoformat(event["at"].replace("Z", "+00:00"))
                for event in events
            )
            if not (started - finished) and not waiting_handoff and latest < datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS):
                os.ftruncate(descriptor, 0)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory_fd)


def audit_summary(run_dir: Path) -> dict[str, Any]:
    _prune_expired(run_dir)
    events = _read_events(run_dir)
    started: dict[str, dict[str, Any]] = {}
    terminal: dict[str, dict[str, Any]] = {}
    counts = {status: 0 for status in sorted(_TERMINAL)}
    handoffs = {status: 0 for status in ("waiting", "resolved", "cancelled", "timed_out")}
    for event in events:
        operation_id = event.get("operation_id")
        if not isinstance(operation_id, str) or not _OPERATION_ID.fullmatch(operation_id):
            raise OperationAuditError("malformed_operation_audit")
        if event["event"] == "operation_started":
            if operation_id in started:
                raise OperationAuditError("malformed_operation_audit")
            started[operation_id] = event
        elif event["event"] == "operation_finished":
            status = event.get("status")
            if operation_id not in started or operation_id in terminal or status not in _TERMINAL:
                raise OperationAuditError("malformed_operation_audit")
            terminal[operation_id] = event
            counts[status] += 1
        else:
            status = event.get("status")
            if status not in handoffs:
                raise OperationAuditError("malformed_operation_audit")
            handoffs[status] += 1
    pending = [operation_id for operation_id in started if operation_id not in terminal]
    counts["interrupted"] += len(pending)
    return {
        "schema": "chip-relay-operation-audit-summary-v1",
        "status": "ok",
        "event_count": len(events),
        "operation_count": len(started),
        "terminal_counts": counts,
        "pending_count": len(pending),
        "pending_effect_state": "interrupted" if pending else None,
        "handoff_counts": handoffs,
        "artifact": f"{AUDIT_DIR}/{AUDIT_FILE}" if events else None,
        "artifact_policy": "redacted-metadata-only/private-local",
    }
