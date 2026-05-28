from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DENY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_or_stripe_key", re.compile(r"(?:sk-|sk_live_|sk_test_)[A-Za-z0-9_\-\.]{6,}")),
    ("github_token", re.compile(r"gh[opsu]_[A-Za-z0-9]{20,}")),
    ("groq_key", re.compile(r"gsk_[A-Za-z0-9]{20,}")),
    ("perplexity_key", re.compile(r"pplx-[A-Za-z0-9]{20,}")),
    ("authorization_header", re.compile(r"Authorization\s*:\s*Bearer\s+\S+", re.IGNORECASE)),
    ("cookie_assignment", re.compile(r"\b(?:SID|HSID|SSID|auth_token|ct0|sessionid)\s*=\s*[^\s;]+", re.IGNORECASE)),
    ("oauth_code", re.compile(r"[?&](?:code|access_token|refresh_token)=([^\s&#]+)", re.IGNORECASE)),
]

TEXT_SUFFIXES = {".txt", ".log", ".json", ".md", ".py", ".yaml", ".yml", ""}


@dataclass(frozen=True)
class HygieneFinding:
    path: str
    pattern: str
    severity: str = "high"

    def as_dict(self) -> dict[str, str]:
        return {"path": self.path, "pattern": self.pattern, "severity": self.severity, "action": "block"}


def iter_scannable_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        if path.suffix in TEXT_SUFFIXES:
            yield path


def scan_text(text: str, rel_path: str) -> list[HygieneFinding]:
    findings: list[HygieneFinding] = []
    for name, pattern in DENY_PATTERNS:
        if pattern.search(text):
            findings.append(HygieneFinding(path=rel_path, pattern=name))
    return findings


def scan_path(root: Path) -> dict[str, object]:
    findings: list[HygieneFinding] = []
    scanned = 0
    for path in iter_scannable_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        rel = str(path.relative_to(root))
        findings.extend(scan_text(text, rel))
    return {
        "status": "failed" if findings else "ok",
        "scanned_files": scanned,
        "findings": [finding.as_dict() for finding in findings],
    }


def redact_text(text: str, limit: int = 4000) -> str:
    redacted = text
    for _name, pattern in DENY_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    if len(redacted) > limit:
        redacted = redacted[-limit:]
    return redacted
