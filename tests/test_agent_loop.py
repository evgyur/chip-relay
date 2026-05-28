#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "chip-relay"


class AgentLoopTests(unittest.TestCase):
    def run_relay(self, *args: str, base_dir: pathlib.Path, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(SCRIPT)]
        if json_mode:
            cmd.append("--json")
        cmd.extend(args)
        env = os.environ.copy()
        env["CHIP_RELAY_BASE_DIR"] = str(base_dir)
        env["PYTHONPATH"] = str(ROOT)
        return subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)

    def create_run(self, base: pathlib.Path, title: str = "Agent Loop Smoke") -> tuple[str, pathlib.Path]:
        created = self.run_relay("task", "init", title, base_dir=base, json_mode=True)
        self.assertEqual(created.returncode, 0, created.stderr)
        payload = json.loads(created.stdout)
        return payload["run_id"], pathlib.Path(payload["run_dir"])

    def write_agent(self, tmp: pathlib.Path) -> pathlib.Path:
        agent = tmp / "fixture_agent.py"
        agent.write_text(textwrap.dedent(r'''
            #!/usr/bin/env python3
            from __future__ import annotations
            import json
            import os
            import pathlib
            import textwrap

            context = json.loads(pathlib.Path(os.environ["CHIP_RELAY_AGENT_CONTEXT"]).read_text())
            run_dir = pathlib.Path(context["run_dir"])
            final = run_dir / "scripts" / "final.py"
            if context["attempt"] == 1:
                final.write_text("raise SystemExit(7)\\n", encoding="utf-8")
            else:
                final_code = (
                    "#!/usr/bin/env python3\n"
                    "from __future__ import annotations\n"
                    "import json\n"
                    "import pathlib\n"
                    "root = pathlib.Path(__file__).resolve().parents[1]\n"
                    "(root / 'logs').mkdir(exist_ok=True)\n"
                    "(root / 'results').mkdir(exist_ok=True)\n"
                    "(root / 'logs' / 'final.log').write_text('agent loop final ok\\n', encoding='utf-8')\n"
                    "(root / 'results' / 'result.json').write_text(json.dumps({'status': 'ok', 'attempt': 2}), encoding='utf-8')\n"
                )
                final.write_text(final_code, encoding="utf-8")
        '''), encoding="utf-8")
        agent.chmod(0o755)
        return agent

    def test_task_loop_retries_agent_until_verify_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp) / "base"
            agent = self.write_agent(pathlib.Path(tmp))
            run_id, run_dir = self.create_run(base)

            looped = self.run_relay(
                "task", "loop", run_id,
                "--agent-command", f"python3 {agent}",
                "--max-attempts", "2",
                base_dir=base,
                json_mode=True,
            )
            self.assertEqual(looped.returncode, 0, looped.stderr)
            payload = json.loads(looped.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["attempts"], 2)
            self.assertEqual(payload["run_id"], run_id)
            self.assertTrue((run_dir / "agent" / "request-001.json").is_file())
            self.assertTrue((run_dir / "agent" / "feedback-001.json").is_file())
            self.assertTrue((run_dir / "agent" / "attempt-001.log").is_file())
            manifest = json.loads((run_dir / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "verified")
            self.assertEqual(manifest["agent_loop"]["attempts"], 2)

    def test_task_loop_fails_closed_when_agent_command_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            run_id, _ = self.create_run(base, "Missing Agent")
            looped = self.run_relay("task", "loop", run_id, base_dir=base, json_mode=True)
            self.assertNotEqual(looped.returncode, 0)
            payload = json.loads(looped.stdout)
            self.assertEqual(payload["status"], "failed")
            self.assertEqual(payload["failed_gate"], "agent_command_missing")


if __name__ == "__main__":
    unittest.main()
