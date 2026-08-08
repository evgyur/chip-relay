from __future__ import annotations

import base64
import binascii
import threading
from pathlib import Path
from typing import Any

from .artifacts import record_browser_fetch_artifact
from .capabilities import (
    BrowserFetchMetadata,
    BrowserFetchPolicy,
    BrowserFetchRequest,
    CapabilityContractError,
    exact_origin,
    normalize_relative_fetch_url,
    validate_response_origin,
)
from .workspace import remove_private_body_artifact, write_private_body_artifact


class BrowserFetchError(RuntimeError):
    pass


_FETCH_LOCK = threading.Lock()

_BROWSER_FETCH_SCRIPT = r"""
async ({ url, method, expectedOrigin, maxBytes, timeoutMs, contentTypes }) => {
  if (window.location.origin !== expectedOrigin) return { kind: "origin_changed" };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const rejectResponse = async (kind, response = null, reader = null) => {
    try {
      if (reader) await reader.cancel();
      else if (response && response.body) await response.body.cancel();
    } catch (_cancelError) {
      // The abort below remains the authoritative fail-closed teardown.
    } finally {
      controller.abort();
    }
    return { kind };
  };
  try {
    const response = await fetch(url, {
      method,
      credentials: "include",
      redirect: "manual",
      cache: "no-store",
      referrerPolicy: "same-origin",
      signal: controller.signal,
    });
    if (response.type === "opaqueredirect" || response.status === 0 || response.redirected) {
      return await rejectResponse("redirect", response);
    }
    const finalUrl = new URL(response.url);
    if (finalUrl.origin !== expectedOrigin || window.location.origin !== expectedOrigin) {
      return await rejectResponse("origin_changed", response);
    }
    const contentType = (response.headers.get("content-type") || "")
      .split(";", 1)[0].trim().toLowerCase();
    if (!contentTypes.includes(contentType)) {
      return await rejectResponse("unsupported_type", response);
    }
    const declaredLength = response.headers.get("content-length") || "";
    if (/^[0-9]+$/.test(declaredLength) && Number(declaredLength) > maxBytes) {
      return await rejectResponse("oversize", response);
    }
    const chunks = [];
    let size = 0;
    if (method !== "HEAD" && response.body) {
      const reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) {
          return await rejectResponse("oversize", response, reader);
        }
        chunks.push(value);
      }
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    let binary = "";
    for (let index = 0; index < bytes.length; index += 32768) {
      binary += String.fromCharCode(...bytes.subarray(index, index + 32768));
    }
    return {
      kind: "ok",
      status: response.status,
      url: response.url,
      contentType,
      declaredLength,
      size,
      bodyB64: btoa(binary),
    };
  } catch (_error) {
    return { kind: controller.signal.aborted ? "timeout" : "uncertain" };
  } finally {
    clearTimeout(timer);
  }
}
"""


def _error(code: str) -> BrowserFetchError:
    return BrowserFetchError(code)


def _validated_payload(payload: Any, *, target_url: str, expected_origin: str, request: BrowserFetchRequest, policy: BrowserFetchPolicy) -> tuple[int, str, int, bytes]:
    if not isinstance(payload, dict):
        raise _error("fetch_result_invalid")
    kind = payload.get("kind")
    failures = {
        "redirect": "fetch_redirect",
        "unsupported_type": "fetch_content_type",
        "timeout": "fetch_timeout",
        "oversize": "fetch_oversize",
        "origin_changed": "fetch_origin_changed",
        "uncertain": "fetch_uncertain",
    }
    if kind in failures:
        raise _error(failures[kind])
    if kind != "ok":
        raise _error("fetch_result_invalid")

    status = payload.get("status")
    response_url = payload.get("url")
    content_type = payload.get("contentType")
    size = payload.get("size")
    encoded = payload.get("bodyB64")
    if type(status) is not int or not isinstance(response_url, str) or not isinstance(content_type, str):
        raise _error("fetch_result_invalid")
    if type(size) is not int or not 0 <= size <= policy.max_bytes or not isinstance(encoded, str):
        raise _error("fetch_result_invalid")
    try:
        validate_response_origin(expected_origin, response_url, redirected=False)
    except CapabilityContractError as exc:
        raise _error("fetch_origin_changed") from exc
    if response_url != target_url:
        raise _error("fetch_redirect")
    if content_type not in policy.content_types:
        raise _error("fetch_content_type")
    try:
        body = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _error("fetch_body_encoding") from exc
    if len(body) != size or (request.method == "HEAD" and body):
        raise _error("fetch_body_size")
    if not 100 <= status <= 599:
        raise _error("fetch_status")
    return status, content_type, size, body


def browser_native_fetch(
    page: Any,
    run_dir: Path,
    path: str,
    *,
    method: str = "GET",
    purpose: str = "task",
    policy: BrowserFetchPolicy | None = None,
) -> BrowserFetchMetadata:
    active_policy = policy or BrowserFetchPolicy()
    try:
        request = BrowserFetchRequest.create(path, method=method, purpose=purpose)
        page_url = page.url
        expected_origin = exact_origin(page_url)
        target_url = normalize_relative_fetch_url(page_url, request.path)
    except (CapabilityContractError, AttributeError, TypeError) as exc:
        raise _error(str(exc) or "fetch_request") from exc

    if not _FETCH_LOCK.acquire(blocking=False):
        raise _error("fetch_concurrency")
    try:
        try:
            payload = page.evaluate(
                _BROWSER_FETCH_SCRIPT,
                {
                    "url": target_url,
                    "method": request.method,
                    "expectedOrigin": expected_origin,
                    "maxBytes": active_policy.max_bytes,
                    "timeoutMs": active_policy.timeout_ms,
                    "contentTypes": list(active_policy.content_types),
                },
            )
        except Exception as exc:
            raise _error("fetch_uncertain") from exc
        status, content_type, size, body = _validated_payload(
            payload,
            target_url=target_url,
            expected_origin=expected_origin,
            request=request,
            policy=active_policy,
        )

        handle: str | None = None
        try:
            if request.method == "GET":
                handle = write_private_body_artifact(run_dir, body)
            metadata = BrowserFetchMetadata(
                status=status,
                method=request.method,
                url=expected_origin,
                content_type=content_type,
                content_length=size,
                body_handle=handle,
            )
            record_browser_fetch_artifact(run_dir, metadata.as_public_dict())
            return metadata
        except Exception as exc:
            if handle is not None:
                try:
                    remove_private_body_artifact(run_dir, handle)
                except Exception as cleanup_exc:
                    raise _error("fetch_artifact_cleanup_failed") from cleanup_exc
            if isinstance(exc, BrowserFetchError):
                raise
            raise _error("fetch_artifact") from exc
    finally:
        _FETCH_LOCK.release()
