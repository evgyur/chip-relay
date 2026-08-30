from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BENCHMARK_SCHEMA = "chip-relay-stealth-benchmark-v1"
COMPARE_SCHEMA = "chip-relay-stealth-comparison-v1"
MAX_RESULT_BYTES = 1_048_576
LOCAL_LATENCY_ABSOLUTE_TOLERANCE_MS = 500
LOCAL_LATENCY_MULTIPLIER = 3
ALLOWED_CASE_STATUSES = {
    "passed",
    "captcha/manual",
    "blocked",
    "needs_proxy",
    "not_run",
    "error",
    "unavailable",
}
_REGRESSION_STATUSES = {"blocked", "captcha/manual", "error", "not_run", "unavailable"}


class BenchmarkContractError(ValueError):
    pass


@dataclass(frozen=True)
class GateResult:
    status: str
    failed_gate: str | None
    regressions: tuple[dict[str, Any], ...]
    comparison: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "chip-relay-stealth-gate-v1",
            "status": self.status,
            "failed_gate": self.failed_gate,
            "regressions": list(self.regressions),
            "comparison": self.comparison,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def snapshot_sha256(sample: object) -> str:
    return hashlib.sha256(canonical_json_bytes(sample)).hexdigest()


def _require_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise BenchmarkContractError(f"benchmark_{key}_invalid")
    return value


def validate_result(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise BenchmarkContractError("benchmark_result_object_required")
    if payload.get("schema") != BENCHMARK_SCHEMA:
        raise BenchmarkContractError("benchmark_schema_incompatible")
    _require_string(payload, "run_id")
    _require_string(payload, "suite_id")
    _require_string(payload, "suite_version")
    _require_string(payload, "started_at")
    _require_string(payload, "completed_at")
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise BenchmarkContractError("benchmark_results_required")
    seen: set[str] = set()
    for backend in results:
        if not isinstance(backend, dict):
            raise BenchmarkContractError("benchmark_backend_invalid")
        identity = _require_string(backend, "identity")
        if identity in seen:
            raise BenchmarkContractError("benchmark_backend_duplicate")
        seen.add(identity)
        requested = _require_string(backend, "requested")
        _require_string(backend, "resolved")
        cases = backend.get("cases")
        if not isinstance(cases, list) or (not cases and backend.get("status") != "unavailable"):
            raise BenchmarkContractError("benchmark_cases_required")
        case_names: set[str] = set()
        for case in cases:
            if not isinstance(case, dict):
                raise BenchmarkContractError("benchmark_case_invalid")
            name = _require_string(case, "name")
            if name in case_names:
                raise BenchmarkContractError("benchmark_case_duplicate")
            case_names.add(name)
            status_value = case.get("status")
            if status_value not in ALLOWED_CASE_STATUSES:
                raise BenchmarkContractError("benchmark_case_status_invalid")
            elapsed = case.get("elapsed_ms")
            if not isinstance(elapsed, int) or elapsed < 0:
                raise BenchmarkContractError("benchmark_elapsed_invalid")
            checks = case.get("fingerprint_checks")
            if not isinstance(checks, list):
                raise BenchmarkContractError("benchmark_checks_invalid")
            for check in checks:
                if not isinstance(check, dict) or not isinstance(check.get("name"), str) or not isinstance(check.get("ok"), bool):
                    raise BenchmarkContractError("benchmark_check_invalid")
        if requested == "active" and backend.get("ephemeral_profile") is True:
            raise BenchmarkContractError("benchmark_active_profile_claim_invalid")
    if len(canonical_json_bytes(payload)) > MAX_RESULT_BYTES:
        raise BenchmarkContractError("benchmark_result_too_large")
    return payload


def read_result(path_value: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(path_value).expanduser()
    try:
        meta = path.lstat()
    except OSError as exc:
        raise BenchmarkContractError("benchmark_result_missing") from exc
    if stat.S_ISLNK(meta.st_mode):
        raise BenchmarkContractError("benchmark_result_symlink")
    if not stat.S_ISREG(meta.st_mode):
        raise BenchmarkContractError("benchmark_result_regular_file_required")
    if meta.st_size > MAX_RESULT_BYTES:
        raise BenchmarkContractError("benchmark_result_too_large")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BenchmarkContractError("benchmark_result_invalid_json") from exc
    return validate_result(payload)


def atomic_write_result(path_value: str | os.PathLike[str], payload: dict[str, Any]) -> Path:
    validate_result(payload)
    path = Path(path_value).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent_meta = path.parent.lstat()
    if stat.S_ISLNK(parent_meta.st_mode) or not stat.S_ISDIR(parent_meta.st_mode):
        raise BenchmarkContractError("benchmark_output_parent_unsafe")
    data = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if len(data.encode("utf-8")) > MAX_RESULT_BYTES:
        raise BenchmarkContractError("benchmark_result_too_large")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        path.chmod(0o600)
    finally:
        if tmp.exists():
            tmp.unlink()
    return path


def _backend_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["identity"]): item for item in payload["results"]}


def _case_map(backend: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {str(item["name"]): item for item in backend.get("cases", [])}


def compare_results(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    validate_result(baseline)
    validate_result(candidate)
    if baseline["suite_id"] != candidate["suite_id"] or baseline["suite_version"] != candidate["suite_version"]:
        raise BenchmarkContractError("benchmark_suite_incompatible")
    baseline_backends = _backend_map(baseline)
    candidate_backends = _backend_map(candidate)
    backend_diffs: list[dict[str, Any]] = []
    for identity in sorted(set(baseline_backends) | set(candidate_backends)):
        before = baseline_backends.get(identity)
        after = candidate_backends.get(identity)
        if before is None or after is None:
            backend_diffs.append({
                "identity": identity,
                "status": "added" if before is None else "missing",
                "case_diffs": [],
            })
            continue
        before_cases = _case_map(before)
        after_cases = _case_map(after)
        case_diffs: list[dict[str, Any]] = []
        for name in sorted(set(before_cases) | set(after_cases)):
            old = before_cases.get(name)
            new = after_cases.get(name)
            if old is None or new is None:
                case_diffs.append({"name": name, "status": "added" if old is None else "missing"})
                continue
            old_checks = {item["name"]: item["ok"] for item in old["fingerprint_checks"]}
            new_checks = {item["name"]: item["ok"] for item in new["fingerprint_checks"]}
            check_diffs = [
                {"name": check, "before": old_checks.get(check), "after": new_checks.get(check)}
                for check in sorted(set(old_checks) | set(new_checks))
                if old_checks.get(check) != new_checks.get(check)
            ]
            case_diffs.append({
                "name": name,
                "status": "compared",
                "before_status": old["status"],
                "after_status": new["status"],
                "before_elapsed_ms": old["elapsed_ms"],
                "after_elapsed_ms": new["elapsed_ms"],
                "elapsed_delta_ms": new["elapsed_ms"] - old["elapsed_ms"],
                "fingerprint_check_diffs": check_diffs,
            })
        backend_diffs.append({"identity": identity, "status": "compared", "case_diffs": case_diffs})
    return {
        "schema": COMPARE_SCHEMA,
        "suite_id": baseline["suite_id"],
        "suite_version": baseline["suite_version"],
        "baseline_run_id": baseline["run_id"],
        "candidate_run_id": candidate["run_id"],
        "coverage": {
            "baseline_backends": len(baseline_backends),
            "candidate_backends": len(candidate_backends),
        },
        "backend_diffs": backend_diffs,
    }


def gate_results(baseline: dict[str, Any], candidate: dict[str, Any]) -> GateResult:
    comparison = compare_results(baseline, candidate)
    if comparison["suite_id"] == "chip-relay-public-detectors":
        return GateResult(
            status="passed",
            failed_gate=None,
            regressions=(),
            comparison=comparison,
        )
    regressions: list[dict[str, Any]] = []
    if comparison["coverage"]["candidate_backends"] < comparison["coverage"]["baseline_backends"]:
        regressions.append({"type": "coverage_regression", "scope": "backends"})
    for backend in comparison["backend_diffs"]:
        if backend["status"] == "missing":
            regressions.append({"type": "coverage_regression", "backend": backend["identity"]})
            continue
        if backend["status"] != "compared":
            continue
        for case in backend["case_diffs"]:
            if case["status"] == "missing":
                regressions.append({"type": "coverage_regression", "backend": backend["identity"], "case": case["name"]})
                continue
            if case["status"] != "compared":
                continue
            if case["before_status"] == "passed" and case["after_status"] in _REGRESSION_STATUSES:
                regressions.append({
                    "type": "outcome_regression",
                    "backend": backend["identity"],
                    "case": case["name"],
                    "before": case["before_status"],
                    "after": case["after_status"],
                })
            if comparison["suite_id"] == "chip-relay-local":
                latency_limit = max(
                    case["before_elapsed_ms"] + LOCAL_LATENCY_ABSOLUTE_TOLERANCE_MS,
                    case["before_elapsed_ms"] * LOCAL_LATENCY_MULTIPLIER,
                )
                if case["after_elapsed_ms"] > latency_limit:
                    regressions.append({
                        "type": "latency_regression",
                        "backend": backend["identity"],
                        "case": case["name"],
                        "before_ms": case["before_elapsed_ms"],
                        "after_ms": case["after_elapsed_ms"],
                        "limit_ms": latency_limit,
                    })
            for check in case["fingerprint_check_diffs"]:
                if check["before"] is not None and check["after"] is None:
                    regressions.append({
                        "type": "coverage_regression",
                        "backend": backend["identity"],
                        "case": case["name"],
                        "check": check["name"],
                    })
    baseline_backends = _backend_map(baseline)
    for identity, candidate_backend in _backend_map(candidate).items():
        baseline_backend = baseline_backends.get(identity)
        baseline_cases = _case_map(baseline_backend) if baseline_backend is not None else {}
        for candidate_case in candidate_backend["cases"]:
            baseline_case = baseline_cases.get(candidate_case["name"])
            baseline_checks = (
                {item["name"]: item["ok"] for item in baseline_case["fingerprint_checks"]}
                if baseline_case is not None
                else {}
            )
            for check in candidate_case["fingerprint_checks"]:
                if check["ok"] is False and baseline_checks.get(check["name"]) is not False:
                    regressions.append({
                        "type": "fingerprint_regression",
                        "backend": identity,
                        "case": candidate_case["name"],
                        "check": check["name"],
                    })
    failed_gate = None
    if regressions:
        failed_gate = "fingerprint_regression" if any(item["type"] == "fingerprint_regression" for item in regressions) else str(regressions[0]["type"])
    return GateResult(
        status="passed" if not regressions else "failed",
        failed_gate=failed_gate,
        regressions=tuple(regressions),
        comparison=comparison,
    )
