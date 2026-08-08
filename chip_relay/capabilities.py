"""Security contracts for the two bounded relay capability additions.

Design provenance: two implementation patterns were studied in Botasaurus at
revision 6c9260d (authenticated proxy handling and browser-context requests).
No Botasaurus code or dependency is imported; chip-relay remains the product
and runtime boundary. Batch/cache orchestration and cursor automation are out
of scope.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit


class CapabilityContractError(ValueError):
    """A fail-closed capability boundary violation."""


_RAW_PROXY_SECRET_KEYS = (
    "CHIP_RELAY_PROXY_USERNAME",
    "CHIP_RELAY_PROXY_PASSWORD",
    "CHIP_RELAY_PROXY_AUTH",
)
_BODY_HANDLE = re.compile(r"^body-[0-9a-f]{16,64}$")


def _contract_error(code: str) -> CapabilityContractError:
    return CapabilityContractError(code)


def _explicit_port(parsed, *, code: str) -> int:
    try:
        port = parsed.port
    except ValueError as exc:
        raise _contract_error(code) from exc
    if port is None:
        raise _contract_error(code)
    return port


def _format_host(hostname: str) -> str:
    return f"[{hostname}]" if ":" in hostname else hostname


def normalize_proxy_server(server: str) -> str:
    if not isinstance(server, str) or not server.strip():
        raise _contract_error("proxy_server_empty")
    try:
        parsed = urlsplit(server.strip())
    except ValueError as exc:
        raise _contract_error("proxy_server_invalid") from exc
    if parsed.scheme not in {"http", "https"}:
        raise _contract_error("proxy_scheme_unsupported")
    if parsed.username is not None or parsed.password is not None:
        raise _contract_error("proxy_credentials_in_server")
    if not parsed.hostname:
        raise _contract_error("proxy_server_missing_hostname")
    port = _explicit_port(parsed, code="proxy_server_missing_port")
    if parsed.path or parsed.query or parsed.fragment:
        raise _contract_error("proxy_server_components")
    return urlunsplit((parsed.scheme, f"{_format_host(parsed.hostname)}:{port}", "", "", ""))


def validate_secret_reference(path_value: os.PathLike[str] | str) -> Path:
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        raise _contract_error("secret_ref_absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise _contract_error("secret_ref_missing") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise _contract_error("secret_ref_symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise _contract_error("secret_ref_regular")
    if metadata.st_uid != os.geteuid():
        raise _contract_error("secret_ref_owner")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077 or not mode & stat.S_IRUSR:
        raise _contract_error("secret_ref_mode")

    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise _contract_error("secret_ref_parent_symlink")
        except CapabilityContractError:
            raise
        except OSError as exc:
            raise _contract_error("secret_ref_parent") from exc
    return path.resolve(strict=True)


@dataclass(frozen=True)
class ProxyAuthDescriptor:
    server: str
    secret_ref: Path | None = None

    @classmethod
    def create(
        cls,
        server: str,
        secret_ref: os.PathLike[str] | str | None = None,
    ) -> "ProxyAuthDescriptor":
        normalized = normalize_proxy_server(server)
        reference = validate_secret_reference(secret_ref) if secret_ref is not None else None
        return cls(server=normalized, secret_ref=reference)

    @property
    def authenticated(self) -> bool:
        return self.secret_ref is not None

    def as_public_dict(self) -> dict[str, object]:
        return {
            "server": self.server,
            "authenticated": self.authenticated,
            "secret_ref_configured": self.secret_ref is not None,
        }


def reject_credential_environment(env: Mapping[str, str]) -> None:
    for key in _RAW_PROXY_SECRET_KEYS:
        if env.get(key):
            raise _contract_error("proxy_credentials_in_environment")
    proxy = env.get("CHIP_RELAY_PROXY", "")
    if proxy:
        try:
            parsed = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        except ValueError as exc:
            raise _contract_error("proxy_server_invalid") from exc
        if parsed.username is not None or parsed.password is not None:
            raise _contract_error("proxy_credentials_in_environment")


def load_proxy_auth_descriptor(env: Mapping[str, str]) -> ProxyAuthDescriptor | None:
    reject_credential_environment(env)
    server = env.get("CHIP_RELAY_PROXY", "").strip()
    secret_ref = env.get("CHIP_RELAY_PROXY_SECRET_FILE", "").strip()
    if not server:
        if secret_ref:
            raise _contract_error("secret_without_proxy")
        return None
    return ProxyAuthDescriptor.create(server, secret_ref or None)


@dataclass(frozen=True)
class BrowserFetchPolicy:
    methods: tuple[str, ...] = ("GET", "HEAD")
    max_bytes: int = 1_048_576
    timeout_ms: int = 15_000
    content_types: tuple[str, ...] = (
        "application/json",
        "text/plain",
        "text/html",
        "application/xml",
        "text/xml",
    )
    max_inflight: int = 1

    def __post_init__(self) -> None:
        if self.methods != ("GET", "HEAD"):
            raise _contract_error("fetch_methods_policy")
        if self.max_inflight != 1:
            raise _contract_error("fetch_concurrency_policy")
        if not 1 <= self.max_bytes <= 16 * 1_048_576:
            raise _contract_error("fetch_size_policy")
        if not 1 <= self.timeout_ms <= 60_000:
            raise _contract_error("fetch_timeout_policy")
        if not self.content_types or any(not item or "\n" in item or "\r" in item for item in self.content_types):
            raise _contract_error("fetch_content_type_policy")


@dataclass(frozen=True)
class BrowserFetchRequest:
    path: str
    method: str
    purpose: str = field(repr=False)

    @classmethod
    def create(cls, path: str, *, method: str = "GET", purpose: str = "task") -> "BrowserFetchRequest":
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise _contract_error("fetch_path_relative")
        if "\\" in path or "\x00" in path:
            raise _contract_error("fetch_path_invalid")
        try:
            parsed = urlsplit(path)
        except ValueError as exc:
            raise _contract_error("fetch_path_invalid") from exc
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise _contract_error("fetch_path_relative")
        decoded_path = unquote(parsed.path)
        if any(part in {".", ".."} for part in decoded_path.split("/")):
            raise _contract_error("fetch_path_traversal")
        normalized_method = method.upper()
        if normalized_method not in {"GET", "HEAD"}:
            raise _contract_error("fetch_method")
        if purpose != "task":
            raise _contract_error("fetch_purpose")
        return cls(path=urlunsplit(("", "", parsed.path, parsed.query, "")), method=normalized_method, purpose=purpose)


_DEFAULT_PORTS = {"http": 80, "https": 443}


def exact_origin(url: str) -> str:
    if not isinstance(url, str) or not url:
        raise _contract_error("origin_invalid")
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise _contract_error("origin_invalid") from exc
    if parsed.scheme not in _DEFAULT_PORTS or not parsed.hostname:
        raise _contract_error("origin_invalid")
    if parsed.username is not None or parsed.password is not None:
        raise _contract_error("origin_userinfo")
    try:
        port = parsed.port
    except ValueError as exc:
        raise _contract_error("origin_port") from exc
    host = _format_host(parsed.hostname.lower())
    netloc = host if port is None or port == _DEFAULT_PORTS[parsed.scheme] else f"{host}:{port}"
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def normalize_relative_fetch_url(page_url: str, path: str) -> str:
    request = BrowserFetchRequest.create(path)
    origin = exact_origin(page_url)
    target = urljoin(origin + "/", request.path)
    if exact_origin(target) != origin:
        raise _contract_error("fetch_origin")
    return target


def validate_response_origin(bound_origin: str, response_url: str, *, redirected: bool) -> None:
    normalized_bound = exact_origin(bound_origin)
    if exact_origin(response_url) != normalized_bound:
        raise _contract_error("response_origin")
    if redirected:
        raise _contract_error("redirect_denied")


@dataclass(frozen=True)
class BrowserFetchMetadata:
    status: int
    method: str
    url: str
    content_type: str
    content_length: int
    body_handle: str | None

    def __post_init__(self) -> None:
        if not 100 <= self.status <= 599:
            raise _contract_error("response_status")
        if self.method not in {"GET", "HEAD"}:
            raise _contract_error("response_method")
        exact_origin(self.url)
        if "\n" in self.content_type or "\r" in self.content_type:
            raise _contract_error("response_content_type")
        if self.content_length < 0:
            raise _contract_error("response_length")
        if self.method == "HEAD" and self.body_handle is not None:
            raise _contract_error("head_body_handle")
        if self.body_handle is not None and not _BODY_HANDLE.fullmatch(self.body_handle):
            raise _contract_error("body_handle")

    def as_public_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "method": self.method,
            "url": self.url,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "body_handle": self.body_handle,
        }
