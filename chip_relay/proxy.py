from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from .capabilities import CapabilityContractError


class ProxyConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ProxyConfig:
    server: str
    username: Optional[str] = None
    password: Optional[str] = None


def _format_host(hostname: str) -> str:
    if ":" in hostname and not hostname.startswith("["):
        return f"[{hostname}]"
    return hostname


def parse_proxy_config(proxy_url: str) -> ProxyConfig:
    if not isinstance(proxy_url, str) or not proxy_url.strip():
        raise ProxyConfigError("proxy_url_empty")
    raw = proxy_url.strip()
    value = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlsplit(value)
    except Exception as exc:
        raise ProxyConfigError("proxy_url_invalid") from exc
    if not parsed.hostname:
        raise ProxyConfigError("proxy_url_missing_hostname")
    if parsed.port is None:
        raise ProxyConfigError("proxy_url_missing_port")
    if parsed.username is not None or parsed.password is not None:
        raise CapabilityContractError("proxy_credentials_in_environment")
    if parsed.scheme not in {"http", "https"} or parsed.path or parsed.query or parsed.fragment:
        raise ProxyConfigError("proxy_url_invalid_components")
    host = _format_host(parsed.hostname)
    server = urlunsplit((parsed.scheme or "http", f"{host}:{parsed.port}", "", "", ""))
    return ProxyConfig(server=server, username=parsed.username, password=parsed.password)


def merge_proxy_server_arg(args: list[str], proxy_server: str | None) -> list[str]:
    if not proxy_server:
        return list(args)
    prefix = "--proxy-server="
    filtered = [arg for arg in args if not arg.startswith(prefix)]
    filtered.append(f"{prefix}{proxy_server}")
    return filtered


def redact_launch_arg(arg: str) -> str:
    if not isinstance(arg, str):
        return str(arg)
    prefix = "--proxy-server="
    if arg.startswith(prefix):
        return prefix + redact_proxy_url(arg[len(prefix):])
    if "://" in arg and "@" in arg:
        return redact_proxy_url(arg)
    return arg


def redact_proxy_url(value: str | None) -> str:
    if not value:
        return ""
    raw = value.strip()
    parse_value = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlsplit(parse_value)
    except Exception:
        return "[REDACTED]"
    host = parsed.hostname or ""
    netloc = _format_host(host)
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    redacted = urlunsplit((parsed.scheme or "http", netloc, parsed.path, parsed.query, parsed.fragment))
    if "://" not in raw and redacted.startswith("http://"):
        return redacted[len("http://"):]
    return redacted
