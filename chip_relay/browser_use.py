from __future__ import annotations

import ast
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .config import RelayConfig
from .hygiene import redact_text
from .workspace import execution_run_lock

SCHEMA = "chip-relay-browser-use-result-v1"
SUMMARY_SCHEMA = "chip-relay-browser-use-summary-v1"
MODE = "cooperative-read-only"
MAX_SCRIPT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_METADATA_BYTES = 128 * 1024
MAX_SCREENSHOT_BYTES = 16 * 1024 * 1024
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
READ_HELPERS = {
    "capture_screenshot",
    "ensure_real_tab",
    "goto_url",
    "new_tab",
    "page_info",
    "wait_for_load",
}
Resolver = Callable[..., Sequence[tuple[Any, ...]]]


class BrowserUseUnavailable(RuntimeError):
    pass


def _utc_now_text() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_cdp_url(cdp_url: str) -> str:
    if not isinstance(cdp_url, str) or len(cdp_url) > 2048 or any(char in cdp_url for char in "\r\n\x00"):
        raise ValueError("browser_use_loopback_cdp_required")
    try:
        parsed = urlsplit(cdp_url)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("browser_use_loopback_cdp_required") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("browser_use_loopback_cdp_required")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost":
        return cdp_url
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("browser_use_loopback_cdp_required") from exc
    if not address.is_loopback:
        raise ValueError("browser_use_loopback_cdp_required")
    return cdp_url


def _validate_public_https_url(url: str, resolver: Resolver) -> None:
    if not isinstance(url, str) or len(url) > 8192 or any(char in url for char in "\r\n\x00"):
        raise ValueError("browser_use_public_https_url_required")
    try:
        parsed = urlsplit(url)
        port = parsed.port or 443
    except ValueError as exc:
        raise ValueError("browser_use_public_https_url_required") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("browser_use_public_https_url_required")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("browser_use_public_https_url_required")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not literal.is_global:
            raise ValueError("browser_use_public_https_url_required")
        return
    try:
        answers = resolver(host, port, type=socket.SOCK_STREAM)
    except (OSError, socket.gaierror) as exc:
        raise ValueError("browser_use_public_https_url_required") from exc
    addresses: set[str] = set()
    for answer in answers:
        if not isinstance(answer, tuple) or len(answer) < 5:
            raise ValueError("browser_use_public_https_url_required")
        sockaddr = answer[4]
        if not isinstance(sockaddr, tuple) or not sockaddr or not isinstance(sockaddr[0], str):
            raise ValueError("browser_use_public_https_url_required")
        addresses.add(sockaddr[0])
    if not addresses or len(addresses) > 32:
        raise ValueError("browser_use_public_https_url_required")
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("browser_use_public_https_url_required") from exc
        if not address.is_global:
            raise ValueError("browser_use_public_https_url_required")


def _validate_constant(node: ast.AST) -> None:
    if not isinstance(node, ast.Constant) or type(node.value) not in {str, int, float, bool, type(None)}:
        raise ValueError("browser_use_script_policy")
    if isinstance(node.value, str) and len(node.value) > 8192:
        raise ValueError("browser_use_script_policy")


def _validate_helper_call(call: ast.Call, resolver: Resolver) -> int:
    if not isinstance(call.func, ast.Name) or call.func.id not in READ_HELPERS:
        raise ValueError("browser_use_script_policy")
    if any(keyword.arg is None for keyword in call.keywords):
        raise ValueError("browser_use_script_policy")
    for arg in call.args:
        _validate_constant(arg)
    for keyword in call.keywords:
        _validate_constant(keyword.value)
    helper = call.func.id
    if helper in {"new_tab", "goto_url"}:
        if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
            raise ValueError("browser_use_script_policy")
        _validate_public_https_url(call.args[0].value, resolver)
        return 1
    if call.args or call.keywords:
        raise ValueError("browser_use_script_policy")
    return 0


def validate_read_only_script(source: str, *, resolver: Resolver = socket.getaddrinfo) -> dict[str, Any]:
    if not isinstance(source, str):
        raise ValueError("browser_use_script")
    encoded = source.encode("utf-8")
    if not encoded or len(encoded) > MAX_SCRIPT_BYTES or "\x00" in source:
        raise ValueError("browser_use_script")
    try:
        tree = ast.parse(source, mode="exec")
    except SyntaxError as exc:
        raise ValueError("browser_use_script_syntax") from exc
    assigned: set[str] = set()
    navigations = 0

    def safe_expression(node: ast.AST) -> int:
        if isinstance(node, ast.Constant):
            _validate_constant(node)
            return 0
        if isinstance(node, ast.Name):
            if node.id not in assigned:
                raise ValueError("browser_use_script_policy")
            return 0
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in READ_HELPERS:
            return _validate_helper_call(node, resolver)
        if isinstance(node, (ast.List, ast.Tuple)):
            return sum(safe_expression(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            count = 0
            for key, value in zip(node.keys, node.values, strict=True):
                if key is None:
                    raise ValueError("browser_use_script_policy")
                count += safe_expression(key) + safe_expression(value)
            return count
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            if node.keywords:
                raise ValueError("browser_use_script_policy")
            return sum(safe_expression(arg) for arg in node.args)
        raise ValueError("browser_use_script_policy")

    for statement in tree.body:
        if isinstance(statement, ast.Expr):
            navigations += safe_expression(statement.value)
            continue
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                raise ValueError("browser_use_script_policy")
            target = statement.targets[0].id
            if target in {"print", *READ_HELPERS} or target.startswith("_") or not target.isidentifier():
                raise ValueError("browser_use_script_policy")
            navigations += safe_expression(statement.value)
            assigned.add(target)
            continue
        raise ValueError("browser_use_script_policy")
    if not tree.body:
        raise ValueError("browser_use_script")
    return {
        "schema": "chip-relay-browser-use-policy-v1",
        "mode": MODE,
        "helpers": sorted(READ_HELPERS),
        "navigations": navigations,
        "script_sha256": _sha256(encoded),
        "network_boundary": "preflight-only/no-redirect-enforcement",
        "trust_boundary": "cooperative-policy/not-a-sandbox",
    }


def _read_script(run_dir: Path, script_path: Path) -> tuple[str, str]:
    scripts_dir = run_dir / "scripts"
    try:
        supplied = Path(script_path)
        if supplied.parent.resolve(strict=True) != scripts_dir.resolve(strict=True):
            raise ValueError("browser_use_script_path")
        if supplied.name in {"", ".", ".."} or supplied.suffix != ".py":
            raise ValueError("browser_use_script_path")
        dir_fd = os.open(
            scripts_dir,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("browser_use_script_path") from exc
    fd: int | None = None
    try:
        fd = os.open(
            supplied.name,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=dir_fd,
        )
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_size <= 0
            or metadata.st_size > MAX_SCRIPT_BYTES
        ):
            raise ValueError("browser_use_script_path")
        data = bytearray()
        while len(data) <= MAX_SCRIPT_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_SCRIPT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_SCRIPT_BYTES:
            raise ValueError("browser_use_script")
    except OSError as exc:
        raise ValueError("browser_use_script_path") from exc
    finally:
        if fd is not None:
            os.close(fd)
        os.close(dir_fd)
    try:
        source = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("browser_use_script") from exc
    return source, _sha256(bytes(data))


def _command(config: RelayConfig) -> tuple[list[str], str]:
    if config.browser_use_command:
        try:
            parts = shlex.split(config.browser_use_command)
        except ValueError as exc:
            raise ValueError("browser_use_command") from exc
        if not parts:
            raise ValueError("browser_use_command")
        executable = shutil.which(parts[0]) if os.sep not in parts[0] else parts[0]
        if not executable or not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            raise BrowserUseUnavailable("browser_use_cli_missing")
        parts[0] = executable
        return parts, "configured"
    direct = shutil.which("browser-use")
    if direct:
        return [direct], "browser-use"
    uvx = shutil.which("uvx")
    if uvx:
        return [uvx, "browser-use"], "uvx"
    raise BrowserUseUnavailable("browser_use_cli_missing")


def browser_use_doctor(config: RelayConfig) -> dict[str, Any]:
    errors: list[str] = []
    runner = "unavailable"
    try:
        _validate_cdp_url(config.cdp_url)
    except ValueError as exc:
        errors.append(str(exc))
    try:
        _parts, runner = _command(config)
    except (ValueError, BrowserUseUnavailable) as exc:
        errors.append(str(exc))
    return {
        "schema": "chip-relay-browser-use-doctor-v1",
        "status": "ready" if not errors else "blocked",
        "mode": MODE,
        "runner": runner,
        "cdp": "loopback-relay" if not any("cdp" in error for error in errors) else "blocked",
        "errors": errors,
        "allowed_helpers": sorted(READ_HELPERS),
        "trust_boundary": "cooperative-policy/not-a-sandbox",
        "network_boundary": "public-https-preflight/no-redirect-enforcement",
        "artifact_policy": "private-local/metadata-only-report",
    }


def browser_use_plan(
    config: RelayConfig,
    run_dir: Path,
    script_path: Path,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> dict[str, Any]:
    _validate_cdp_url(config.cdp_url)
    source, script_sha256 = _read_script(run_dir, script_path)
    policy = validate_read_only_script(source, resolver=resolver)
    doctor = browser_use_doctor(config)
    return {
        "schema": "chip-relay-browser-use-plan-v1",
        "status": "ready" if doctor["status"] == "ready" else "blocked",
        "mode": MODE,
        "cdp": "loopback-relay",
        "script_sha256": script_sha256,
        "policy": policy,
        "runner": doctor["runner"],
        "errors": doctor["errors"],
        "artifact_policy": "private-local/metadata-only-report",
    }


def _private_directory(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise ValueError("browser_use_workspace")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise ValueError("browser_use_workspace")
    path.chmod(0o700)
    return path


def _atomic_write(path: Path, data: bytes) -> None:
    parent = _private_directory(path.parent)
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError("browser_use_artifact")
    tmp = parent / f".{path.name}-{os.getpid()}-{time.monotonic_ns()}.tmp"
    fd = os.open(
        tmp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short browser-use write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dir_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_CLOEXEC)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _minimal_env(config: RelayConfig, run_dir: Path) -> dict[str, str]:
    workspace = _private_directory(run_dir / "browser-use" / "workspace")
    env: dict[str, str] = {}
    for key in ("HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    env.update(
        {
            "BU_CDP_URL": config.cdp_url,
            "BH_AGENT_WORKSPACE": str(workspace),
            "BH_RECORD": "0",
            "NO_COLOR": "1",
        }
    )
    return env


def _terminate_process(proc: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)


def _run_cli(
    command: list[str],
    source: str,
    *,
    env: dict[str, str],
    cwd: Path,
    timeout: float,
) -> tuple[int, bytes, bytes, str | None]:
    with tempfile.TemporaryFile(mode="w+b") as stdin_file, tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
        stdin_file.write(source.encode("utf-8"))
        stdin_file.seek(0)
        try:
            proc = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdin=stdin_file,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except OSError as exc:
            raise BrowserUseUnavailable("browser_use_cli_start_failed") from exc
        deadline = time.monotonic() + timeout
        failure: str | None = None
        while proc.poll() is None:
            if time.monotonic() >= deadline:
                failure = "timeout"
                _terminate_process(proc)
                break
            if os.fstat(stdout_file.fileno()).st_size > MAX_OUTPUT_BYTES or os.fstat(stderr_file.fileno()).st_size > MAX_OUTPUT_BYTES:
                failure = "output_too_large"
                _terminate_process(proc)
                break
            time.sleep(0.05)
        return_code = int(proc.returncode if proc.returncode is not None else -1)
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(MAX_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(MAX_OUTPUT_BYTES + 1)
        if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
            failure = "output_too_large"
            stdout = stdout[:MAX_OUTPUT_BYTES]
            stderr = stderr[:MAX_OUTPUT_BYTES]
        return return_code, stdout, stderr, failure


def _valid_png(data: bytes) -> bool:
    if len(data) < 57 or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    offset = 8
    saw_header = False
    saw_data = False
    compressed = bytearray()
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            return False
        chunk = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        if zlib.crc32(kind + chunk) != expected_crc:
            return False
        if not saw_header:
            if kind != b"IHDR" or length != 13:
                return False
            width, height = struct.unpack(">II", chunk[:8])
            if not 1 <= width <= 8192 or not 1 <= height <= 8192 or width * height > 16_000_000:
                return False
            if chunk[10:13] != b"\x00\x00\x00":
                return False
            saw_header = True
        elif kind == b"IDAT":
            saw_data = True
            compressed.extend(chunk)
            if len(compressed) > MAX_SCREENSHOT_BYTES:
                return False
        elif kind == b"IEND":
            if length != 0 or end != len(data) or not saw_data:
                return False
            try:
                inflater = zlib.decompressobj()
                decoded = inflater.decompress(bytes(compressed), 64 * 1024 * 1024 + 1)
                if len(decoded) > 64 * 1024 * 1024 or not inflater.eof:
                    return False
            except zlib.error:
                return False
            return saw_header
        offset = end
    return False


def _capture_screenshot_artifact(run_dir: Path, stdout: bytes, *, started_wall: float) -> dict[str, Any] | None:
    candidates: list[Path] = []
    for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
        text = raw_line.strip()
        if 1 <= len(text) <= 4096:
            candidate = Path(text)
            if candidate.is_absolute() and candidate.suffix.lower() == ".png":
                candidates.append(candidate)
    for candidate in reversed(candidates):
        try:
            fd = os.open(
                candidate,
                os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
        except OSError:
            continue
        source_metadata: os.stat_result | None = None
        try:
            source_metadata = os.fstat(fd)
            if (
                not stat.S_ISREG(source_metadata.st_mode)
                or source_metadata.st_uid != os.geteuid()
                or not 8 <= source_metadata.st_size <= MAX_SCREENSHOT_BYTES
                or source_metadata.st_mtime < started_wall - 5
            ):
                continue
            data = bytearray()
            while len(data) <= MAX_SCREENSHOT_BYTES:
                chunk = os.read(fd, min(64 * 1024, MAX_SCREENSHOT_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            final_metadata = os.fstat(fd)
            if (
                len(data) > MAX_SCREENSHOT_BYTES
                or final_metadata.st_dev != source_metadata.st_dev
                or final_metadata.st_ino != source_metadata.st_ino
                or final_metadata.st_size != source_metadata.st_size
                or final_metadata.st_mtime_ns != source_metadata.st_mtime_ns
            ):
                continue
        finally:
            os.close(fd)
        if not _valid_png(bytes(data)):
            continue
        digest = _sha256(bytes(data))
        relative = Path("screenshots") / f"browser-use-{digest[:16]}.png"
        _atomic_write(run_dir / relative, bytes(data))
        try:
            current = candidate.lstat()
            if (
                source_metadata is not None
                and stat.S_ISREG(current.st_mode)
                and current.st_dev == source_metadata.st_dev
                and current.st_ino == source_metadata.st_ino
            ):
                candidate.unlink()
        except OSError:
            pass
        return {
            "path": str(relative),
            "size_bytes": len(data),
            "sha256": digest,
            "media_type": "image/png",
        }
    return None


def execute_browser_use(
    config: RelayConfig,
    run_dir: Path,
    script_path: Path,
    *,
    timeout: float = 120,
    resolver: Resolver = socket.getaddrinfo,
) -> dict[str, Any]:
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= 600:
        raise ValueError("browser_use_timeout")
    _validate_cdp_url(config.cdp_url)
    source, script_sha256 = _read_script(run_dir, script_path)
    policy = validate_read_only_script(source, resolver=resolver)
    command, runner = _command(config)
    started = time.monotonic()
    started_wall = time.time()
    with execution_run_lock(run_dir):
        return_code, stdout, stderr, failure = _run_cli(
            command,
            source,
            env=_minimal_env(config, run_dir),
            cwd=run_dir,
            timeout=float(timeout),
        )
        stdout_text = redact_text(stdout.decode("utf-8", errors="replace"))
        stderr_text = redact_text(stderr.decode("utf-8", errors="replace"))
        _atomic_write(run_dir / "logs" / "browser-use.log", stdout_text.encode("utf-8"))
        _atomic_write(run_dir / "logs" / "browser-use.stderr.log", stderr_text.encode("utf-8"))
        screenshot = _capture_screenshot_artifact(run_dir, stdout, started_wall=started_wall)
        status = "succeeded" if return_code == 0 and failure is None else "failed"
        result = {
            "schema": SCHEMA,
            "status": status,
            "mode": MODE,
            "cdp": "loopback-relay",
            "runner": runner,
            "script_sha256": script_sha256,
            "policy_sha256": _sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")),
            "exit_code": return_code,
            "failure": failure or (None if return_code == 0 else "browser_use_cli_exit"),
            "stdout": {"size_bytes": len(stdout), "sha256": _sha256(stdout)},
            "stderr": {"size_bytes": len(stderr), "sha256": _sha256(stderr)},
            "screenshot": screenshot,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "finished_at": _utc_now_text(),
            "artifact_policy": "private-local/metadata-only-report",
            "trust_boundary": "cooperative-policy/not-a-sandbox",
            "network_boundary": "public-https-preflight/no-redirect-enforcement",
        }
        encoded = (json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _atomic_write(run_dir / "results" / "browser-use" / "last.json", encoded)
        return result


def _validate_stored_screenshot(run_dir: Path, payload: Any) -> None:
    if payload is None:
        return
    if (
        not isinstance(payload, dict)
        or set(payload) != {"path", "size_bytes", "sha256", "media_type"}
        or not isinstance(payload.get("path"), str)
        or re.fullmatch(r"screenshots/browser-use-[0-9a-f]{16}\.png", payload["path"]) is None
        or not isinstance(payload.get("size_bytes"), int)
        or not 8 <= payload["size_bytes"] <= MAX_SCREENSHOT_BYTES
        or not isinstance(payload.get("sha256"), str)
        or SHA256_PATTERN.fullmatch(payload["sha256"]) is None
        or payload.get("media_type") != "image/png"
    ):
        raise ValueError("browser_use_screenshot_metadata")
    path = run_dir / payload["path"]
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise ValueError("browser_use_screenshot_metadata") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size != payload["size_bytes"]
        ):
            raise ValueError("browser_use_screenshot_metadata")
        data = bytearray()
        while len(data) <= MAX_SCREENSHOT_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_SCREENSHOT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(fd)
    if len(data) != payload["size_bytes"] or _sha256(bytes(data)) != payload["sha256"] or not _valid_png(bytes(data)):
        raise ValueError("browser_use_screenshot_metadata")


def _load_result(path: Path, *, run_dir: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("browser_use_metadata") from exc
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size > MAX_METADATA_BYTES
        ):
            raise ValueError("browser_use_metadata")
        data = bytearray()
        while len(data) <= MAX_METADATA_BYTES:
            chunk = os.read(fd, min(64 * 1024, MAX_METADATA_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > MAX_METADATA_BYTES:
            raise ValueError("browser_use_metadata")
    finally:
        os.close(fd)
    try:
        payload = json.loads(bytes(data).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("browser_use_metadata") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != SCHEMA
        or payload.get("status") not in {"succeeded", "failed"}
        or payload.get("mode") != MODE
        or not isinstance(payload.get("script_sha256"), str)
        or SHA256_PATTERN.fullmatch(payload["script_sha256"]) is None
    ):
        raise ValueError("browser_use_metadata")
    _validate_stored_screenshot(run_dir, payload.get("screenshot"))
    return payload


def browser_use_summary(run_dir: Path) -> dict[str, Any]:
    try:
        payload = _load_result(run_dir / "results" / "browser-use" / "last.json", run_dir=run_dir)
    except ValueError as exc:
        return {
            "schema": SUMMARY_SCHEMA,
            "status": "invalid",
            "mode": MODE,
            "failure": str(exc),
            "artifact_policy": "private-local/metadata-only-report",
        }
    if payload is None:
        return {
            "schema": SUMMARY_SCHEMA,
            "status": "not-run",
            "mode": MODE,
            "artifact_policy": "private-local/metadata-only-report",
        }
    return {
        "schema": SUMMARY_SCHEMA,
        "status": payload["status"],
        "mode": MODE,
        "cdp": payload.get("cdp"),
        "runner": payload.get("runner"),
        "script_sha256": payload["script_sha256"],
        "exit_code": payload.get("exit_code"),
        "failure": payload.get("failure"),
        "duration_ms": payload.get("duration_ms"),
        "screenshot": payload.get("screenshot"),
        "trust_boundary": "cooperative-policy/not-a-sandbox",
        "network_boundary": "public-https-preflight/no-redirect-enforcement",
        "artifact_policy": "private-local/metadata-only-report",
    }
