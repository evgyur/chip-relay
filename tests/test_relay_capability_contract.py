from __future__ import annotations

import dataclasses
import os
import pathlib
import tempfile
import unittest

from chip_relay.capabilities import (
    BrowserFetchMetadata,
    BrowserFetchPolicy,
    BrowserFetchRequest,
    CapabilityContractError,
    ProxyAuthDescriptor,
    exact_origin,
    load_proxy_auth_descriptor,
    normalize_relative_fetch_url,
    reject_credential_environment,
    validate_response_origin,
)


class RelayCapabilityContractTests(unittest.TestCase):
    def test_proxy_descriptor_accepts_only_http_https_and_nonsecret_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = pathlib.Path(tmp) / "proxy-secret.json"
            secret.write_text('{"username":"u","password":"p"}', encoding="utf-8")
            secret.chmod(0o600)
            descriptor = ProxyAuthDescriptor.create("https://127.0.0.1:8443", secret)
            self.assertEqual(descriptor.server, "https://127.0.0.1:8443")
            self.assertEqual(descriptor.secret_ref, secret.resolve())

            for unsafe in (
                "socks5://127.0.0.1:1080",
                "http://user:pass@127.0.0.1:8080",
                "http://127.0.0.1",
                "http://127.0.0.1:8080/path",
            ):
                with self.subTest(unsafe=unsafe), self.assertRaises(CapabilityContractError):
                    ProxyAuthDescriptor.create(unsafe, secret)

    def test_proxy_secret_reference_is_absolute_regular_owner_only_and_no_follow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            secret = root / "secret.json"
            secret.write_text("{}", encoding="utf-8")
            secret.chmod(0o600)
            ProxyAuthDescriptor.create("http://127.0.0.1:8080", secret)

            secret.chmod(0o640)
            with self.assertRaisesRegex(CapabilityContractError, "secret_ref_mode"):
                ProxyAuthDescriptor.create("http://127.0.0.1:8080", secret)
            secret.chmod(0o600)

            link = root / "link.json"
            link.symlink_to(secret)
            with self.assertRaisesRegex(CapabilityContractError, "secret_ref_symlink"):
                ProxyAuthDescriptor.create("http://127.0.0.1:8080", link)

            directory = root / "directory"
            directory.mkdir(mode=0o700)
            with self.assertRaisesRegex(CapabilityContractError, "secret_ref_regular"):
                ProxyAuthDescriptor.create("http://127.0.0.1:8080", directory)

    def test_credential_bearing_environment_is_rejected(self) -> None:
        forbidden = (
            {"CHIP_RELAY_PROXY": "http://user:pass@example.com:8080"},
            {"CHIP_RELAY_PROXY_USERNAME": "user"},
            {"CHIP_RELAY_PROXY_PASSWORD": "pass"},
            {"CHIP_RELAY_PROXY_AUTH": "basic abc"},
        )
        for env in forbidden:
            with self.subTest(env=list(env)), self.assertRaises(CapabilityContractError):
                reject_credential_environment(env)

    def test_environment_loader_accepts_only_nonsecret_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = pathlib.Path(tmp) / "secret.json"
            secret.write_text("{}", encoding="utf-8")
            secret.chmod(0o600)
            env = {
                "CHIP_RELAY_PROXY": "http://127.0.0.1:8080",
                "CHIP_RELAY_PROXY_SECRET_FILE": str(secret),
            }
            descriptor = load_proxy_auth_descriptor(env)
            self.assertIsNotNone(descriptor)
            self.assertEqual(descriptor.secret_ref, secret.resolve())
            self.assertIsNone(load_proxy_auth_descriptor({}))

            with self.assertRaisesRegex(CapabilityContractError, "secret_without_proxy"):
                load_proxy_auth_descriptor({"CHIP_RELAY_PROXY_SECRET_FILE": str(secret)})

    def test_browser_fetch_policy_is_strict_and_single_flight(self) -> None:
        policy = BrowserFetchPolicy()
        self.assertEqual(policy.methods, ("GET", "HEAD"))
        self.assertEqual(policy.max_inflight, 1)
        self.assertGreater(policy.max_bytes, 0)
        self.assertGreater(policy.timeout_ms, 0)
        self.assertTrue(policy.content_types)

    def test_browser_fetch_accepts_relative_exact_origin_get_head_only(self) -> None:
        page_url = "https://example.com:443/app/index"
        self.assertEqual(exact_origin(page_url), "https://example.com")
        self.assertEqual(
            normalize_relative_fetch_url(page_url, "/api/items?q=1"),
            "https://example.com/api/items?q=1",
        )
        for method in ("GET", "HEAD"):
            request = BrowserFetchRequest.create("/api/items", method=method)
            self.assertEqual(request.method, method)

        unsafe_paths = (
            "https://example.com/api",
            "//example.com/api",
            "http://user:pass@example.com/api",
            "api/relative-without-root",
            "/../private",
            "/api#fragment",
        )
        for path in unsafe_paths:
            with self.subTest(path=path), self.assertRaises(CapabilityContractError):
                BrowserFetchRequest.create(path)
        with self.assertRaisesRegex(CapabilityContractError, "fetch_method"):
            BrowserFetchRequest.create("/api", method="POST")

    def test_redirect_origin_change_and_protected_purposes_fail_closed(self) -> None:
        origin = exact_origin("https://example.com/app")
        validate_response_origin(origin, "https://example.com/next", redirected=False)
        with self.assertRaisesRegex(CapabilityContractError, "redirect_denied"):
            validate_response_origin(origin, "https://example.com/next", redirected=True)
        with self.assertRaisesRegex(CapabilityContractError, "response_origin"):
            validate_response_origin(origin, "https://other.example/next", redirected=False)

        for purpose in ("captcha", "protected-site", "challenge", "bypass"):
            with self.subTest(purpose=purpose), self.assertRaisesRegex(CapabilityContractError, "fetch_purpose"):
                BrowserFetchRequest.create("/api", purpose=purpose)

    def test_public_fetch_metadata_has_no_raw_body_cookie_or_headers(self) -> None:
        fields = {field.name for field in dataclasses.fields(BrowserFetchMetadata)}
        self.assertFalse(fields & {"body", "body_bytes", "cookies", "headers"})
        metadata = BrowserFetchMetadata(
            status=200,
            method="GET",
            url="https://example.com/api",
            content_type="application/json",
            content_length=7,
            body_handle="body-0123456789abcdef",
        )
        payload = metadata.as_public_dict()
        self.assertEqual(payload["body_handle"], "body-0123456789abcdef")
        self.assertFalse(set(payload) & {"body", "body_bytes", "cookies", "headers"})

    def test_no_botasaurus_dependency_or_forbidden_capability_fields(self) -> None:
        import chip_relay.capabilities as capabilities

        source = pathlib.Path(capabilities.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import botasaurus", source.lower())
        self.assertNotIn("from botasaurus", source.lower())
        field_names = {field.name for field in dataclasses.fields(BrowserFetchPolicy)}
        self.assertFalse(field_names & {"batch", "cache", "cursor", "retries"})


if __name__ == "__main__":
    unittest.main()
