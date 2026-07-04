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


class HermesWorkflowContextTests(unittest.TestCase):
    def run_cli(self, *args: str, base_dir: pathlib.Path, json_mode: bool = True) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def test_task_context_gives_hermes_a_tool_contract_not_backend_framing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_cli("task", "init", "Hermes writes final script", base_dir=base)
            self.assertEqual(created.returncode, 0, created.stderr)
            run_id = json.loads(created.stdout)["run_id"]

            context = self.run_cli("task", "context", run_id, base_dir=base)
            self.assertEqual(context.returncode, 0, context.stderr)
            payload = json.loads(context.stdout)

            self.assertEqual(payload["schema"], "chip-relay-hermes-workflow-context-v1")
            self.assertEqual(payload["model"], "hermes-agent-uses-relay-tool")
            self.assertEqual(payload["run_id"], run_id)
            self.assertEqual(payload["next_action"], "edit_final_script_then_run_verify")
            self.assertEqual(payload["task"]["brief_schema"], "chip-relay-agent-brief-v2")
            self.assertEqual(payload["task_brief"], payload["task"]["brief"])
            self.assertIn("agent_instructions", payload["task_brief"])
            self.assertIn("success_metrics", payload["task_brief"])
            self.assertIn("known_frictions", payload["task_brief"])
            self.assertIn("verification_questions", payload["task_brief"])
            self.assertEqual(payload["editable_files"], ["scripts/final.py"])
            self.assertEqual(payload["artifact_policy"], "private-local/no-auto-send")
            self.assertEqual(payload["commands"]["verify"], f"scripts/chip-relay task verify {run_id}")
            self.assertEqual(payload["commands"]["show"], f"scripts/chip-relay task show {run_id}")
            self.assertNotIn("agent_command", json.dumps(payload))
            self.assertNotIn("Cookies", json.dumps(payload))
            self.assertNotIn("Local State", json.dumps(payload))

    def test_task_context_can_be_written_and_updates_after_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_cli("task", "init", "Hermes verified context", base_dir=base)
            self.assertEqual(created.returncode, 0, created.stderr)
            run_id = json.loads(created.stdout)["run_id"]

            verified = self.run_cli("task", "verify", run_id, base_dir=base)
            self.assertEqual(verified.returncode, 0, verified.stderr)

            context = self.run_cli("task", "context", run_id, "--write", base_dir=base)
            self.assertEqual(context.returncode, 0, context.stderr)
            payload = json.loads(context.stdout)
            context_path = pathlib.Path(payload["context_path"])
            self.assertTrue(context_path.exists())
            written = json.loads(context_path.read_text(encoding="utf-8"))
            self.assertEqual(written["next_action"], "done_or_pack_recipe")
            self.assertEqual(written["verification"]["status"], "verified")

    def test_relay_task_context_is_available_for_operator_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            created = self.run_cli("relay", "/relay", "task", "init", "Hermes relay context", base_dir=base)
            self.assertEqual(created.returncode, 0, created.stderr)
            run_id = json.loads(created.stdout)["run_id"]

            context = self.run_cli("relay", "/relay", "task", "context", run_id, base_dir=base)
            self.assertEqual(context.returncode, 0, context.stderr)
            payload = json.loads(context.stdout)
            self.assertEqual(payload["command"], "task.context")
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["context"]["model"], "hermes-agent-uses-relay-tool")
            self.assertEqual(payload["context"]["next_action"], "edit_final_script_then_run_verify")


if __name__ == "__main__":
    unittest.main()
