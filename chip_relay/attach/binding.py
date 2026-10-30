"""Explicit external-browser identity binding. No browser lifecycle operations.

Linux proc inspection is read-only and must run with sufficient visibility.
Permission errors are a gate, never evidence that an endpoint is unowned.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shlex
import stat
from urllib.parse import urlsplit


class BindingError(ValueError):
    pass


def canonical_path(value: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise BindingError("absolute_path_required")
    path = Path(value)
    if ".." in path.parts or path != path.resolve(strict=True):
        raise BindingError("path_symlink_or_traversal")
    return path


def read_bindings(path: Path) -> dict:
    path = canonical_path(str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o077
        ):
            raise BindingError("binding_owner_or_permissions")
        if info.st_size > 65536:
            raise BindingError("binding_too_large")
        with os.fdopen(fd, "r", closefd=False) as stream:
            data = json.load(stream)
    finally:
        os.close(fd)
    if not isinstance(data, dict) or data.get("schema") != "relay-external-binding-v1":
        raise BindingError("binding_schema")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise BindingError("binding_profiles_required")
    for name, entry in profiles.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            raise BindingError("binding_alias_invalid")
        validate_entry(entry)
    aliases = data.get("aliases", {})
    if not isinstance(aliases, dict):
        raise BindingError("binding_alias_invalid")
    for name, target in aliases.items():
        if (
            name in profiles
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name)
            or target not in profiles
        ):
            raise BindingError("binding_alias_invalid")
    return data


def validate_entry(entry: dict) -> None:
    if not isinstance(entry, dict) or entry.get("lifecycle") != "external":
        raise BindingError("external_lifecycle_required")
    url = urlsplit(entry.get("endpoint", ""))
    if (
        url.scheme != "http"
        or url.hostname != "127.0.0.1"
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
        or not url.port
    ):
        raise BindingError("loopback_endpoint_required")
    for key in ("uid", "pid", "start_time", "profile_inode", "profile_device"):
        if type(entry.get(key)) is not int or entry[key] < (
            1 if key in ("pid", "start_time", "profile_inode") else 0
        ):
            raise BindingError("identity_receipt_missing:" + key)
    for key in ("executable", "profile_path"):
        if not isinstance(entry.get(key), str) or not entry[key].startswith("/"):
            raise BindingError("identity_receipt_missing:" + key)
    if entry.get("identity_reader") not in (None, "sudo-owner-python3-v1"):
        raise BindingError("identity_reader_not_supported")
    capabilities = entry.get("capabilities", {})
    if not isinstance(capabilities, dict):
        raise BindingError("capabilities_schema")
    allowed = {
        "rail",
        "visible",
        "meeting_media",
        "display",
        "xauthority",
        "xdg_runtime",
        "pulse",
        "authenticated",
        "publicProbeAllowed",
        "expectedUaFamily",
        "expectedPlatform",
        "task_policy",
        "isolated_benchmark",
        "allowed_sites",
    }
    if set(capabilities) - allowed:
        raise BindingError("capabilities_unknown_field")
    for key, value in capabilities.items():
        if key == "allowed_sites":
            if (
                not isinstance(value, list)
                or not 1 <= len(value) <= 64
                or any(
                    not isinstance(d, str)
                    or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", d)
                    or ".." in d
                    for d in value
                )
            ):
                raise BindingError("capabilities_site_allowlist_invalid")
            continue
        if key in {
            "visible",
            "meeting_media",
            "display",
            "xauthority",
            "xdg_runtime",
            "pulse",
            "authenticated",
            "publicProbeAllowed",
            "isolated_benchmark",
        }:
            if type(value) is not bool:
                raise BindingError("capabilities_boolean_required")
        elif not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,64}", value
        ):
            raise BindingError("capabilities_metadata_required")
    if entry.get("identity_reader") and entry["uid"] == 0:
        raise BindingError("identity_reader_root_forbidden")
    directory = entry.get("profile_directory")
    if (
        not isinstance(directory, str)
        or not directory
        or "/" in directory
        or directory in {".", ".."}
    ):
        raise BindingError("profile_directory_required")


def select_binding(data: dict, alias: str | None) -> tuple[str, dict]:
    if not alias:
        raise BindingError("explicit_profile_required")
    name = data.get("aliases", {}).get(alias, alias)
    if name not in data["profiles"]:
        raise BindingError("unknown_profile_alias")
    return name, data["profiles"][name]


def process_identity(pid: int, proc: Path = Path("/proc")) -> dict:
    root = proc / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    raw = (root / "cmdline").read_bytes().rstrip(b"\0")
    args = [s.decode() for s in raw.split(b"\0")]
    # Chromium may flatten its process title into one NUL-terminated string.
    if len(args) == 1:
        args = shlex.split(args[0])
    return {
        "uid": root.stat().st_uid,
        "start_time": int(fields[19]),
        "executable": os.readlink(root / "exe"),
        "args": args,
    }


def flag(args: list[str], name: str) -> str | None:
    values = []
    for i, item in enumerate(args):
        if item.startswith(name + "="):
            values.append(item.split("=", 1)[1])
        elif item == name and i + 1 < len(args):
            values.append(args[i + 1])
    if len(values) > 1:
        raise BindingError("duplicate_identity_flag")
    return values[0] if values else None


def listener_inodes(port: int, proc: Path = Path("/proc")) -> set[str]:
    result = set()
    for filename in ("tcp", "tcp6"):
        for line in (proc / "net" / filename).read_text().splitlines()[1:]:
            fields = line.split()
            address, raw_port = fields[1].split(":")
            if fields[3] != "0A" or int(raw_port, 16) != port:
                continue
            if filename != "tcp" or address != "0100007F":
                raise BindingError("listener_not_exact_loopback")
            result.add(fields[9])
    if len(result) != 1:
        raise BindingError("listener_missing_or_ambiguous")
    return result


def verify_binding(entry: dict, proc: Path = Path("/proc")) -> dict:
    validate_entry(entry)
    executable = canonical_path(entry["executable"])
    profile = Path(entry["profile_path"])
    reader = entry.get("identity_reader") == "sudo-owner-python3-v1"
    receipt = {}
    if reader:
        from .identity_reader import read_identity

        receipt = read_identity(entry["pid"], entry["uid"])
        before = receipt["identity"]
    else:
        before = process_identity(entry["pid"], proc)
    try:
        profile = canonical_path(entry["profile_path"])
        info = profile.stat()
        observed = (info.st_uid, info.st_ino, info.st_dev)
        directory = profile.is_dir()
    except PermissionError:
        metadata = receipt.get("profiles", {}).get(str(profile), {})
        if metadata.get("canonical") != str(profile) or ".." in profile.parts:
            raise BindingError("profile_canonical_receipt_required")
        observed = (metadata.get("uid"), metadata.get("inode"), metadata.get("device"))
        directory = metadata.get("directory") is True
    if not executable.is_file() or not directory:
        raise BindingError("identity_path_type")
    if observed != (entry["uid"], entry["profile_inode"], entry["profile_device"]):
        raise BindingError("profile_identity_mismatch")
    for key in ("uid", "start_time", "executable"):
        if before[key] != entry[key]:
            raise BindingError("process_identity_mismatch:" + key)
    args = before["args"]
    port = urlsplit(entry["endpoint"]).port
    native = entry.get("profile_evidence") == "browseros-open-lock-v1"
    if entry.get("profile_evidence") not in (None, "browseros-open-lock-v1"):
        raise BindingError("profile_evidence_not_supported")
    if native:
        if not reader or executable.name != "browseros":
            raise BindingError("browseros_owner_reader_required")
        if str(profile / ".browseros/server.lock") not in receipt.get(
            "profile_locks", []
        ):
            raise BindingError("browseros_profile_lock_mismatch")
        # BrowserOS enables CDP internally rather than via command-line flags.
        # Exact listener ownership below still binds the selected port.
        if flag(args, "--user-data-dir") not in (None, str(profile)):
            raise BindingError("process_profile_mismatch")
        if entry["profile_directory"] != "Default":
            raise BindingError("browseros_default_profile_required")
    else:
        if flag(args, "--remote-debugging-port") != str(port):
            raise BindingError("process_port_mismatch")
        if flag(args, "--user-data-dir") != str(profile):
            raise BindingError("process_profile_mismatch")
    # Chromium's omitted profile-directory denotes Default, not another persona.
    if (flag(args, "--profile-directory") or "Default") != entry["profile_directory"]:
        raise BindingError("process_profile_directory_mismatch")
    sockets = listener_inodes(port, proc)
    owned = set(receipt["sockets"]) if reader else set()
    if not reader:
        for fd in (proc / str(entry["pid"]) / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue
            if target.startswith("socket:["):
                owned.add(target[8:-1])
    if not sockets <= owned:
        raise BindingError("listener_owner_mismatch")
    after = (
        read_identity(entry["pid"], entry["uid"])["identity"]
        if reader
        else process_identity(entry["pid"], proc)
    )
    if after != before:
        raise BindingError("process_changed_during_validation")
    return {
        "verified": True,
        "lifecycle": "external",
        "profile_directory": entry["profile_directory"],
    }
