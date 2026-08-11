from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from chip_relay.cli import build_parser
from chip_relay.config import RelayConfig
from chip_relay.hermes_context import hermes_task_context
from chip_relay.reports import evidence_report
from chip_relay.workspace import init_run


class BrowserUseBridgeTests(unittest.TestCase):
    def make_config(self, root: pathlib.Path, command: str | None = None) -> RelayConfig:
        return RelayConfig(
            base_dir=root,
            runs_dir=root / "runs",
            recipes_dir=root / "recipes",
            host="127.0.0.1",
            port=18800,
            cdp_url="http://127.0.0.1:18800",
            profile="default",
            profile_dir=root / "profiles" / "default",
            proxy=None,
            upload_allowed_dirs=None,
            browser_use_command=command,
        )

    def make_run(self, config: RelayConfig) -> pathlib.Path:
        return init_run(config, "Browser Use bridge", run_id="browser-use-test").run_dir

    def test_doctor_does_not_auto_download_unpinned_cli(self) -> None:
        from chip_relay.browser_use import browser_use_doctor

        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(pathlib.Path(tmp), command=None)

            def only_uvx(name: str) -> str | None:
                return "/usr/bin/uvx" if name == "uvx" else None

            with mock.patch("chip_relay.browser_use.shutil.which", side_effect=only_uvx):
                payload = browser_use_doctor(config)
            self.assertEqual(payload["status"], "blocked")
            self.assertIn("browser_use_cli_missing", payload["errors"])

    def test_new_run_contains_safe_browser_use_script_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            run_dir = self.make_run(self.make_config(root, command=sys.executable))
            script = run_dir / "scripts" / "browser-use.py"
            self.assertTrue(script.is_file())
            source = script.read_text(encoding="utf-8")
            self.assertIn("page_info", source)
            self.assertNotIn("click_at_xy", source)

    def test_accidental_effect_and_kitesurf_surfaces_are_not_public_cli_commands(self) -> None:
        parser = build_parser()
        for tokens in (
            ["task", "effect", "run", "show"],
            ["task", "kitesurf", "run", "doctor"],
        ):
            with self.subTest(tokens=tokens), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                parser.parse_args(tokens)

    def test_read_only_policy_rejects_mutation_dynamic_python_and_private_targets(self) -> None:
        from chip_relay.browser_use import validate_read_only_script

        allowed = """new_tab('https://example.com/docs')
info = page_info()
print(info)
capture_screenshot()
"""
        payload = validate_read_only_script(
            allowed,
            resolver=lambda *_args, **_kwargs: [
                (2, 1, 6, "", (".".join(("93", "184", "216", "34")), 443))  # noqa: FLY002
            ],
        )
        self.assertEqual(payload["mode"], "cooperative-read-only")
        self.assertEqual(payload["navigations"], 1)

        rejected = (
            "click_at_xy(10, 10)",
            "fill_input('#email', 'private')",
            "js('document.title = 1')",
            "cdp('Runtime.evaluate', expression='fetch(\"https://example.com\")')",
            "import os\nprint(os.environ)",
            "getattr(globals(), 'open')('/etc/passwd')",
            "new_tab('http://127.1/admin')",
        )
        for source in rejected:
            with self.subTest(source=source), self.assertRaises(ValueError):
                validate_read_only_script(source)

        private_address = ".".join(("10", "0", "0", "9"))  # noqa: FLY002
        with self.assertRaisesRegex(ValueError, "browser_use_public_https_url_required"):
            validate_read_only_script(
                "new_tab('https://internal.example')",
                resolver=lambda *_args, **_kwargs: [(2, 1, 6, "", (private_address, 443))],
            )
        with self.assertRaisesRegex(ValueError, "browser_use_public_https_url_required"):
            validate_read_only_script(
                "new_tab('https://empty.example')",
                resolver=lambda *_args, **_kwargs: [],
            )

    def test_execute_pipes_validated_script_to_cli_with_relay_cdp_and_metadata_only_result(self) -> None:
        from chip_relay.browser_use import browser_use_summary, execute_browser_use

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cli = root / "fake_browser_use.py"
            fake_cli.write_text(
                """import json, os, struct, sys, zlib
source = sys.stdin.read()
shot = os.path.join(os.environ['BH_AGENT_WORKSPACE'], '..', 'source-shot.png')
def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
png = bytes.fromhex('89504e470d0a1a0a')
png += chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
png += chunk(b'IDAT', zlib.compress(b'\\x00\\x00\\x00\\x00\\x00'))
png += chunk(b'IEND', b'')
with open(shot, 'wb') as handle:
    handle.write(png)
print(json.dumps({
    'cdp': os.environ.get('BU_CDP_URL'),
    'workspace': os.environ.get('BH_AGENT_WORKSPACE'),
    'secret_present': 'RELAY_TEST_SECRET' in os.environ,
    'umask': oct(os.umask(0)),
    'source_sha': __import__('hashlib').sha256(source.encode()).hexdigest(),
}))
print(shot)
""",
                encoding="utf-8",
            )
            command = f"{sys.executable} {fake_cli}"
            config = self.make_config(root, command=command)
            run_dir = self.make_run(config)
            script = run_dir / "scripts" / "browser-use.py"
            script.write_text(
                "new_tab('https://example.com')\n"
                "info = page_info()\n"
                "print(info)\n",
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"RELAY_TEST_SECRET": "private"}, clear=False):
                result = execute_browser_use(
                    config,
                    run_dir,
                    script,
                    timeout=10,
                    resolver=lambda *_args, **_kwargs: [
                        (2, 1, 6, "", (".".join(("93", "184", "216", "34")), 443))  # noqa: FLY002
                    ],
                )

            self.assertEqual(result["status"], "succeeded")
            self.assertEqual(result["mode"], "cooperative-read-only")
            self.assertEqual(result["cdp"], "loopback-relay")
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(len(result["script_sha256"]), 64)
            serialized = json.dumps(result, sort_keys=True)
            self.assertNotIn(str(fake_cli), serialized)
            self.assertNotIn(str(run_dir), serialized)
            self.assertNotIn("new_tab", serialized)

            log_payload = json.loads((run_dir / "logs" / "browser-use.log").read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(log_payload["cdp"], config.cdp_url)
            self.assertTrue(pathlib.Path(log_payload["workspace"]).is_relative_to(run_dir))
            self.assertFalse(log_payload["secret_present"])
            self.assertEqual(log_payload["umask"], "0o77")
            self.assertTrue(result["screenshot"]["path"].startswith("screenshots/"))
            self.assertTrue((run_dir / result["screenshot"]["path"]).is_file())
            self.assertNotIn("source-shot", json.dumps(result))
            summary = browser_use_summary(run_dir)
            self.assertEqual(summary["status"], "succeeded")
            self.assertEqual(summary["script_sha256"], result["script_sha256"])

            evidence = evidence_report(config, run_dir)
            self.assertEqual(evidence["browser_use"]["status"], "succeeded")
            context = hermes_task_context(config, run_dir)
            self.assertIn("scripts/browser-use.py", context["editable_files"])
            self.assertIn("browser_use_execute", context["commands"])

    def test_output_cap_fails_closed_without_putting_output_in_summary(self) -> None:
        from chip_relay.browser_use import MAX_OUTPUT_BYTES, execute_browser_use

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cli = root / "noisy.py"
            fake_cli.write_text(
                f"import sys\nsys.stdin.read()\nsys.stdout.write('x' * {MAX_OUTPUT_BYTES + 1})\n",
                encoding="utf-8",
            )
            config = self.make_config(root, command=f"{sys.executable} {fake_cli}")
            run_dir = self.make_run(config)
            script = run_dir / "scripts" / "browser-use.py"
            result = execute_browser_use(config, run_dir, script, timeout=10)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure"], "output_too_large")
            self.assertLessEqual(result["stdout"]["size_bytes"], MAX_OUTPUT_BYTES)
            self.assertNotIn("x" * 100, json.dumps(result))

    def test_timeout_kills_browser_use_process_group(self) -> None:
        from chip_relay.browser_use import execute_browser_use

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            marker = root / "late-child-write"
            fake_cli = root / "hang.py"
            child = f"import pathlib,time;time.sleep(1.5);pathlib.Path({str(marker)!r}).write_text('late')"
            fake_cli.write_text(
                "import subprocess,sys,time\n"
                "sys.stdin.read()\n"
                f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
                "time.sleep(10)\n",
                encoding="utf-8",
            )
            config = self.make_config(root, command=f"{sys.executable} {fake_cli}")
            run_dir = self.make_run(config)
            result = execute_browser_use(config, run_dir, run_dir / "scripts" / "browser-use.py", timeout=1.0)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["failure"], "timeout")
            time.sleep(0.8)
            self.assertFalse(marker.exists())

    def test_malformed_screenshot_is_not_imported(self) -> None:
        from chip_relay.browser_use import execute_browser_use

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cli = root / "bad_image.py"
            fake_cli.write_text(
                """import os, sys
sys.stdin.read()
shot = os.path.join(os.environ['BH_AGENT_WORKSPACE'], '..', 'bad.png')
with open(shot, 'wb') as handle:
    handle.write(bytes.fromhex('89504e470d0a1a0a') + b'not-a-png')
print(shot)
""",
                encoding="utf-8",
            )
            config = self.make_config(root, command=f"{sys.executable} {fake_cli}")
            run_dir = self.make_run(config)
            result = execute_browser_use(config, run_dir, run_dir / "scripts" / "browser-use.py", timeout=10)
            self.assertEqual(result["status"], "succeeded")
            self.assertIsNone(result["screenshot"])

    def test_screenshot_outside_cli_temp_roots_is_ignored(self) -> None:
        from chip_relay.browser_use import execute_browser_use

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            outside = root / "outside.png"
            fake_cli = root / "outside_image.py"
            fake_cli.write_text(
                f"""import struct, sys, zlib
sys.stdin.read()
def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
png = bytes.fromhex('89504e470d0a1a0a')
png += chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
png += chunk(b'IDAT', zlib.compress(b'\\x00\\x00\\x00\\x00\\x00'))
png += chunk(b'IEND', b'')
with open({str(outside)!r}, 'wb') as handle:
    handle.write(png)
print({str(outside)!r})
""",
                encoding="utf-8",
            )
            config = self.make_config(root, command=f"{sys.executable} {fake_cli}")
            run_dir = self.make_run(config)
            result = execute_browser_use(config, run_dir, run_dir / "scripts" / "browser-use.py", timeout=10)
            self.assertEqual(result["status"], "succeeded")
            self.assertIsNone(result["screenshot"])
            self.assertTrue(outside.is_file())

    def test_summary_rejects_symlink_metadata(self) -> None:
        from chip_relay.browser_use import browser_use_summary

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.make_config(root, command=sys.executable)
            run_dir = self.make_run(config)
            external = root / "external.json"
            external.write_text(json.dumps({"schema": "chip-relay-browser-use-result-v1", "status": "succeeded"}))
            metadata = run_dir / "results" / "browser-use" / "last.json"
            metadata.parent.mkdir(parents=True)
            metadata.symlink_to(external)
            self.assertEqual(browser_use_summary(run_dir)["status"], "invalid")

    def test_summary_rejects_forged_screenshot_reference(self) -> None:
        from chip_relay.browser_use import browser_use_summary

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.make_config(root, command=sys.executable)
            run_dir = self.make_run(config)
            metadata = run_dir / "results" / "browser-use" / "last.json"
            metadata.parent.mkdir(parents=True)
            metadata.write_text(
                json.dumps(
                    {
                        "schema": "chip-relay-browser-use-result-v1",
                        "status": "succeeded",
                        "mode": "cooperative-read-only",
                        "script_sha256": "0" * 64,
                        "screenshot": {
                            "path": "/etc/passwd",
                            "size_bytes": 1,
                            "sha256": "0" * 64,
                            "media_type": "image/png",
                        },
                    }
                ),
                encoding="utf-8",
            )
            metadata.chmod(0o600)
            self.assertEqual(browser_use_summary(run_dir)["status"], "invalid")

    def test_non_loopback_cdp_and_unsafe_script_path_fail_closed(self) -> None:
        from chip_relay.browser_use import browser_use_plan

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config = self.make_config(root, command=sys.executable)
            run_dir = self.make_run(config)
            script = run_dir / "scripts" / "browser-use.py"
            script.write_text("print(page_info())\n", encoding="utf-8")

            non_loopback = ".".join(("192", "0", "2", "10"))  # noqa: FLY002
            unsafe_config = RelayConfig(**{**config.__dict__, "cdp_url": f"http://{non_loopback}:9222"})
            with self.assertRaisesRegex(ValueError, "browser_use_loopback_cdp_required"):
                browser_use_plan(unsafe_config, run_dir, script)

            external = root / "external.py"
            external.write_text("print(page_info())\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "browser_use_script_path"):
                browser_use_plan(config, run_dir, external)

    def test_cli_doctor_plan_execute_and_show(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            fake_cli = root / "fake_browser_use.py"
            fake_cli.write_text("import sys\nsys.stdin.read()\nprint('browser-use-ok')\n", encoding="utf-8")
            config = self.make_config(root, command=f"{sys.executable} {fake_cli}")
            run_dir = self.make_run(config)
            script = run_dir / "scripts" / "browser-use.py"
            script.write_text("print(page_info())\n", encoding="utf-8")
            env = os.environ.copy()
            env["CHIP_RELAY_BASE_DIR"] = str(root)
            env["CHIP_RELAY_BROWSER_USE_COMMAND"] = str(config.browser_use_command)
            env["PYTHONPATH"] = str(pathlib.Path(__file__).resolve().parents[1])
            cli = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "chip-relay"

            commands = (
                (["doctor"], "ready"),
                (["plan", "--script", str(script)], "ready"),
                (["execute", "--script", str(script), "--timeout", "10"], "succeeded"),
                (["show"], "succeeded"),
            )
            for suffix, expected in commands:
                proc = subprocess.run(
                    [str(cli), "--json", "task", "browser-use", run_dir.name, *suffix],
                    cwd=cli.parents[1],
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout)["status"], expected)


if __name__ == "__main__":
    unittest.main()
