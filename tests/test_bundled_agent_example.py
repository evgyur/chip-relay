#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"
AGENT = "scripts/chip-relay-agent-example"


class BundledAgentExampleTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def test_bundled_agent_example_satisfies_task_loop_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_relay("task", "init", "Bundled Agent Smoke", base_dir=base, json_mode=True)
            self.assertEqual(created.returncode, 0, created.stderr)
            run_id = json.loads(created.stdout)["run_id"]
            run_dir = pathlib.Path(json.loads(created.stdout)["run_dir"])

            looped = self.run_relay(
                "task", "loop", run_id,
                "--agent-command", str(AGENT),
                "--max-attempts", "1",
                base_dir=base,
                json_mode=True,
            )
            self.assertEqual(looped.returncode, 0, looped.stderr)
            payload = json.loads(looped.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["attempts"], 1)

            result = json.loads((run_dir / "results" / "result.json").read_text())
            self.assertEqual(result["status"], "generated-by-chip-relay-agent-example")
            self.assertEqual(result["task"], "Bundled Agent Smoke")
            self.assertTrue((run_dir / "agent" / "request-001.json").is_file())
            self.assertTrue((run_dir / "agent" / "feedback-001.json").is_file())
            self.assertTrue((run_dir / "agent" / "loop-result.json").is_file())
            final_source = (run_dir / "scripts" / "final.py").read_text()
            self.assertNotIn("Authorization", final_source)
            self.assertNotIn("cookie", final_source.lower())

    def test_bundled_agent_example_fails_closed_without_context_env(self) -> None:
        result = subprocess.run([str(ROOT / AGENT)], cwd=ROOT, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CHIP_RELAY_AGENT_CONTEXT", result.stderr)


if __name__ == "__main__":
    unittest.main()
