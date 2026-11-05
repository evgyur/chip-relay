import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from chip_relay import desktop as d


class DesktopGuardTests(unittest.TestCase):
    def observation(self):
        return {'ok': True, 'data': {'complete': True, 'tree': {'children': [
            {'ref_id': '@s1:e1', 'name': 'Synthetic action', 'role': 'button',
             'available_actions': ['Click']}]}}}

    def test_qualified_unique_ref(self):
        d.check_click(self.observation(), '@s1:e1', 'Synthetic action', 'button')

    def test_bare_ref_blocked(self):
        with self.assertRaises(d.Blocked):
            d.check_click(self.observation(), '@e1', 'Synthetic action', 'button')

    def test_wrong_label_blocked(self):
        with self.assertRaises(d.Blocked):
            d.check_click(self.observation(), '@s1:e1', 'Pay', 'button')

    def test_wrong_role_blocked(self):
        with self.assertRaises(d.Blocked):
            d.check_click(self.observation(), '@s1:e1', 'Synthetic action', 'entry')

    def test_missing_ref_blocked(self):
        with self.assertRaises(d.Blocked):
            d.check_click(self.observation(), '@s1:e99', 'Synthetic action', 'button')

    def test_ambiguous_label_blocked(self):
        r = self.observation()
        twin = copy.deepcopy(r['data']['tree']['children'][0]); twin['ref_id'] = '@s1:e2'
        r['data']['tree']['children'].append(twin)
        with self.assertRaises(d.Blocked):
            d.check_click(r, '@s1:e1', 'Synthetic action', 'button')

    def test_incomplete_observation_blocked(self):
        r = self.observation(); r['data']['complete'] = False
        with self.assertRaises(d.Blocked):
            d.check_click(r, '@s1:e1', 'Synthetic action', 'button')

    def test_no_click_capability_blocked(self):
        r = self.observation(); r['data']['tree']['children'][0]['available_actions'] = []
        with self.assertRaises(d.Blocked):
            d.check_click(r, '@s1:e1', 'Synthetic action', 'button')

    def test_wrong_generation_no_dispatch(self):
        b = {'process': {'pid': 1}}
        with patch.object(d, 'identity', return_value={'pid': 2}), patch.object(d.subprocess, 'run') as run:
            with self.assertRaises(d.Blocked): d.invoke(b, ['click', '@s1:e1'])
            run.assert_not_called()

    def test_changed_environment_no_dispatch(self):
        b = {'process': {'pid': 1}, 'session_env': {}}
        with patch.object(d, 'identity', return_value=b['process']), patch.object(d, 'session_env', return_value={'DISPLAY': ':99'}), patch.object(d.subprocess, 'run') as run:
            with self.assertRaises(d.Blocked): d.invoke(b, ['snapshot'])
            run.assert_not_called()

    def test_private_file_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/'binding'; p.write_text('{}'); p.chmod(0o644)
            with self.assertRaises(d.Blocked): d.private(p)
            p.chmod(0o600); d.private(p)
            link = Path(t)/'link'; link.symlink_to(p)
            with self.assertRaises(d.Blocked): d.private(link)

    def test_claim_never_overwritten(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/'s1.claimed'; d.save(p, {'first': True})
            with self.assertRaises(FileExistsError): d.save(p, {'first': False})
            self.assertEqual(json.loads(p.read_text()), {'first': True})

    def test_expired_or_superseded_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); old = root/'s1.json'; new = root/'s2.json'
            d.save(old, {}); d.fresh_receipt(root, old)
            d.save(new, {})
            os.utime(old, (1, 1))
            with self.assertRaises(d.Blocked): d.fresh_receipt(root, old)
            with patch.object(d.time, 'time', return_value=new.stat().st_mtime+121):
                with self.assertRaises(d.Blocked): d.fresh_receipt(root, new)

    def test_save_syncs_file_and_directory(self):
        with tempfile.TemporaryDirectory() as t, patch.object(d.os, 'fsync') as sync:
            d.save(Path(t)/'claim', {})
            self.assertEqual(sync.call_count, 2)

    def test_refmap_wrong_pid_blocked(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); sub = root/'snapshots'/'s1'; sub.mkdir(parents=True)
            d.save(sub/'refmap.json', {'inner': {'@e1': {'pid': 2}}})
            b = {'native_state': t, 'process': {'pid': 1}, 'native_process_instance': 'old',
                 'app': 'fixture', 'window_id': 'one', 'title': 'synthetic'}
            with self.assertRaises(d.Blocked): d.verify_refmap(b, 's1')

    def test_no_global_commands(self):
        for command in ('launch', 'press', 'clipboard-get', 'screenshot', 'type', 'mcp'):
            with self.assertRaises(SystemExit): d.main(['--target', '/unused', command])


if __name__ == '__main__':
    unittest.main()
