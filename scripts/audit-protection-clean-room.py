#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

UPSTREAM_SHA = "e5341e9ff4e3fdd5302a93980d74b9923686e987"
BASE_SHA = "6217d734e13f078fffad6cbfded067e2707c17e0"
UPSTREAM_EXTENSIONS = {".css", ".html", ".js", ".json", ".md"}
RECEIPT_PATH = "docs/protection-diagnostics-clean-room-audit.json"
MIN_MEANINGFUL_LINE_LENGTH = 40


def tracked_files(root: Path) -> list[str]:
    output = subprocess.check_output(["git", "ls-files"], cwd=root, text=True)
    return sorted(line for line in output.splitlines() if line)


def git_head(root: Path) -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def audited_files(root: Path) -> list[str]:
    subprocess.check_call(
        ["git", "cat-file", "-e", f"{BASE_SHA}^{{commit}}"],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    output = subprocess.check_output(
        ["git", "diff", "--name-only", BASE_SHA, "--"],
        cwd=root,
        text=True,
    )
    names = sorted(
        name
        for name in output.splitlines()
        if name and name != RECEIPT_PATH and (root / name).is_file()
    )
    if not names:
        raise SystemExit("no feature files found relative to the clean-room base")
    return names


def meaningful_lines(paths: Iterable[Path]) -> set[str]:
    lines: set[str] = set()
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        for raw_line in text.splitlines():
            normalized = re.sub(r"\s+", " ", raw_line.strip())
            if len(normalized) < MIN_MEANINGFUL_LINE_LENGTH:
                continue
            if normalized in {"{", "}", "[", "]", "(", ")"}:
                continue
            lines.add(normalized)
    return lines


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_audit(repo_root: Path, upstream_root: Path) -> dict[str, object]:
    actual_sha = git_head(upstream_root)
    if actual_sha != UPSTREAM_SHA:
        raise SystemExit(f"upstream SHA mismatch: expected {UPSTREAM_SHA}, got {actual_sha}")
    upstream_names = [
        name for name in tracked_files(upstream_root)
        if Path(name).suffix.lower() in UPSTREAM_EXTENSIONS
    ]
    upstream_paths = [upstream_root / name for name in upstream_names]
    scope = audited_files(repo_root)
    audited_paths = [repo_root / name for name in scope]
    missing = [str(path) for path in audited_paths if not path.is_file()]
    if missing:
        raise SystemExit(f"missing production files: {missing}")

    upstream_lines = meaningful_lines(upstream_paths)
    audited_lines = meaningful_lines(audited_paths)
    exact_matches = sorted(upstream_lines & audited_lines)
    upstream_manifest = "\n".join(
        f"{name}\0{sha256_file(upstream_root / name)}" for name in upstream_names
    ).encode("utf-8")
    runtime_paths = [repo_root / name for name in scope if name.startswith("chip_relay/")]
    runtime_text = "\n".join(path.read_text(encoding="utf-8", errors="ignore") for path in runtime_paths).lower()
    forbidden_terms = sum(runtime_text.count(term) for term in ("scrapfly", "antibot-detector", "nposl"))
    runtime_dependency = any(
        marker in runtime_text
        for marker in (
            "import antibot_detector",
            "from antibot_detector",
            "require('antibot-detector')",
            'require("antibot-detector")',
        )
    )
    rules = json.loads((repo_root / "chip_relay/rules/protections-v1.json").read_text(encoding="utf-8"))
    sources_ok = all(
        isinstance(rule.get("source"), dict)
        and str(rule["source"].get("url", "")).startswith("https://")
        for rule in rules.get("rules", [])
    )
    return {
        "schema": "chip-relay-clean-room-provenance-audit-v1",
        "upstream_review": {
            "repository": "scrapfly/Antibot-Detector",
            "review_sha": actual_sha,
            "license": "NPOSL-3.0",
            "files_compared": len(upstream_names),
        },
        "audited_files": scope,
        "receipt_exclusion": {
            "path": RECEIPT_PATH,
            "reason": "self-referential content hash is impossible; the receipt is compared structurally by --check",
        },
        "content_receipt": {
            "upstream_file_manifest_sha256": hashlib.sha256(upstream_manifest).hexdigest(),
            "audited_sha256": {name: sha256_file(repo_root / name) for name in scope},
        },
        "algorithm": {
            "tracked_extensions": sorted(UPSTREAM_EXTENSIONS),
            "minimum_normalized_line_length": MIN_MEANINGFUL_LINE_LENGTH,
            "whitespace": "collapsed",
            "comparison": "exact normalized lines",
        },
        "checks": {
            "exact_meaningful_line_matches": len(exact_matches),
            "rule_count": len(rules.get("rules", [])),
            "all_rules_have_independent_https_source": sources_ok,
            "upstream_name_or_license_terms_in_production": forbidden_terms,
            "copied_extension_or_ui": bool(exact_matches),
            "runtime_dependency_on_upstream": runtime_dependency,
        },
        "boundary": "External material informed category and threat-model review only. Implementation, rules, observer, CLI, reports, tests, and documentation were authored clean-room for this MIT repository.",
        "verdict": "pass" if not exact_matches and not forbidden_terms and not runtime_dependency and sources_ok else "fail",
    }


def comparable(payload: dict[str, object]) -> dict[str, object]:
    result = dict(payload)
    result.pop("audited_at", None)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--upstream-root", required=True)
    parser.add_argument("--check")
    parser.add_argument("--write")
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    upstream_root = Path(args.upstream_root).resolve()
    payload = build_audit(repo_root, upstream_root)
    payload["audited_at"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if args.check:
        expected = json.loads(Path(args.check).read_text(encoding="utf-8"))
        if comparable(expected) != comparable(payload):
            print(json.dumps({"status": "failed", "reason": "audit_receipt_drift"}, sort_keys=True))
            return 1
    if args.write:
        Path(args.write).write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "verdict": payload["verdict"], "checks": payload["checks"]}, sort_keys=True))
    return 0 if payload["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
