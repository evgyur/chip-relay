"""Opt-in Linux desktop executor. No browser lifecycle, global input or secrets.

Same-user cooperative guards, NOT a sandbox. Bind only approved non-secret apps.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SESSION_KEYS = ('DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS',
                'XDG_RUNTIME_DIR', 'AT_SPI_BUS_ADDRESS', 'WAYLAND_DISPLAY')


class Blocked(ValueError):
    pass


def private(path: Path, directory=False):
    s = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise Blocked('private_owner_required')


def save(path, value):
    # Never follow an existing file or replace another writer's receipt.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    parent = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def identity(pid):
    p = Path('/proc') / str(pid)
    if p.stat().st_uid != os.getuid():
        raise Blocked('process_owner_mismatch')
    fields = (p / 'stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] == 'Z':
        raise Blocked('process_dead')
    return {'pid': pid, 'start': fields[19], 'exe': str((p/'exe').resolve(strict=True))}


def session_env(pid):
    pairs = (Path('/proc')/str(pid)/'environ').read_bytes().split(b'\0')
    e = {}
    for item in pairs:
        k, sep, v = item.partition(b'=')
        if sep and k.decode(errors='replace') in SESSION_KEYS:
            e[k.decode()] = v.decode()
    if not e.get('DISPLAY') or not e.get('DBUS_SESSION_BUS_ADDRESS'):
        raise Blocked('desktop_session_required')
    # Do not inherit model keys, browser cookies, proxy or ambient bus addresses.
    return {'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()), 'LANG': 'C.UTF-8', **e}


def digest(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def invoke(binding, command):
    if identity(binding['process']['pid']) != binding['process']:
        raise Blocked('process_generation_changed')
    env = session_env(binding['process']['pid'])
    if {k: env.get(k) for k in SESSION_KEYS} != binding['session_env']:
        raise Blocked('desktop_session_changed')
    if digest(binding['binary']) != binding['binary_sha256']:
        raise Blocked('binary_changed')
    env['AGENT_DESKTOP_HOME'] = binding['native_state']
    try:
        # Timeout after dispatch is uncertain, never automatically retried.
        p = subprocess.run([binding['binary'], *command], env=env, capture_output=True,
                           timeout=20, check=False)
    except subprocess.TimeoutExpired:
        raise Blocked('native_timeout_delivery_unknown') from None
    if len(p.stdout) > 2_000_000:
        raise Blocked('native_output_too_large')
    result = json.loads(p.stdout)
    if not isinstance(result, dict) or not isinstance(result.get('ok'), bool):
        raise Blocked('invalid_native_envelope')
    if identity(binding['process']['pid']) != binding['process']:
        raise Blocked('process_changed_during_call')
    return result


def verify_window(binding):
    result = invoke(binding, ['list-windows', '--app', binding['app']])
    if not result['ok']:
        raise Blocked('window_identity_unavailable')
    matches = [w for w in result['data'] if w['id'] == binding['window_id']]
    if len(matches) != 1:
        raise Blocked('window_missing_or_ambiguous')
    w = matches[0]
    if w.get('pid') != binding['process']['pid'] or w.get('title') != binding['title']:
        raise Blocked('window_identity_changed')
    if binding.get('native_process_instance') not in (None, w.get('process_instance')):
        raise Blocked('window_process_generation_changed')
    return w


def verify_refmap(binding, sid):
    # v1.2.0 stores these fields and checks them again in native resolution
    # and immediately before delivery (Linux actions/process_check.rs).
    p = Path(binding['native_state'])/'snapshots'/sid/'refmap.json'
    private(p)
    m = json.loads(p.read_text())['inner']
    for entry in m.values():
        expected = {'pid': binding['process']['pid'],
                    'process_instance': binding['native_process_instance'],
                    'source_app': binding['app'],
                    'source_window_id': binding['window_id'],
                    'source_window_title': binding['title']}
        if any(entry.get(k) != v for k, v in expected.items()):
            raise Blocked('native_ref_scope_mismatch')
    return m


def fresh_receipt(root, receipt):
    age = time.time() - receipt.stat().st_mtime
    snapshots = [p for p in root.glob('s*.json')
                 if re.fullmatch(r'[A-Za-z0-9_-]{1,80}\.json', p.name)]
    if not 0 <= age <= 120 or max(snapshots, key=lambda p: p.stat().st_mtime_ns) != receipt:
        raise Blocked('snapshot_expired_or_superseded')


def elements(node):
    if isinstance(node, dict):
        if 'ref_id' in node:
            yield node
        for child in node.get('children', []):
            yield from elements(child)


def check_click(observation, ref, name, role):
    if not re.fullmatch(r'@[A-Za-z0-9_-]+:e[0-9]+', ref):
        raise Blocked('qualified_ref_required')
    if not observation.get('ok') or observation.get('data', {}).get('complete') is not True:
        raise Blocked('complete_observation_required')
    nodes = list(elements(observation['data'].get('tree', {})))
    selected = [n for n in nodes if n['ref_id'] == ref]
    twins = [n for n in nodes if n.get('name') == name and n.get('role') == role]
    if len(selected) != 1 or len(twins) != 1 or selected[0] != twins[0]:
        raise Blocked('target_missing_or_ambiguous')
    if 'Click' not in selected[0].get('available_actions', []):
        raise Blocked('click_capability_required')


def bind(args):
    root = Path(args.target).absolute()
    private(root.parent, directory=True)
    # Binding creates a new private target, never overwrites an existing grant.
    root.mkdir(mode=0o700)
    binary = Path(args.binary).resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise Blocked('native_executable_required')
    proc = identity(args.pid)
    env = session_env(args.pid)
    b = {'schema': 'relay-desktop-v1', 'process': proc, 'app': args.app,
         'window_id': args.window_id, 'title': args.title,
         'session_env': {k: env.get(k) for k in SESSION_KEYS},
         'binary': str(binary), 'binary_sha256': digest(binary),
         'native_state': str(root/'native-state')}
    (root/'native-state').mkdir(mode=0o700)
    window = verify_window(b)
    b['native_process_instance'] = window['process_instance']
    save(root/'binding.json', b)
    return {'ok': True, 'command': 'bind', 'scope': 'one_nonsecret_app_window',
            'lifecycle': 'external', 'sandbox': False}


def run(args):
    root = Path(args.target).absolute()
    private(root, directory=True)
    private(root/'binding.json')
    b = json.loads((root/'binding.json').read_text())
    if b.get('schema') != 'relay-desktop-v1' or b['native_state'] != str(root/'native-state'):
        raise Blocked('binding_invalid')
    private(root/'native-state', directory=True)
    fd = os.open(root/'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        private(root/'lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        verify_window(b)
        if args.command == 'snapshot':
            r = invoke(b, ['snapshot', '--app', b['app'], '--window-id', b['window_id'],
                           '--timeout-ms', '10000'])
            # Receipts are immutable; snapshots may contain private UI content.
            if r['ok']:
                sid = r.get('data', {}).get('snapshot_id', '')
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', sid):
                    raise Blocked('snapshot_id_invalid')
                window = r['data'].get('window', {})
                if window.get('id') != b['window_id'] or window.get('title') != b['title']:
                    raise Blocked('snapshot_window_mismatch')
                verify_window(b)
                verify_refmap(b, sid)
                save(root/(sid+'.json'), r)
            return r
        sid = args.ref[1:].split(':', 1)[0]
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', sid):
            raise Blocked('qualified_ref_required')
        receipt = root/(sid+'.json')
        private(receipt)
        fresh_receipt(root, receipt)
        verify_refmap(b, sid)
        check_click(json.loads(receipt.read_text()), args.ref, args.expect_name, args.expect_role)
        # Claim BEFORE invoking. Any crash/timeout/uncertainty prevents replay.
        save(root/(sid+'.claimed'), {'command': 'click', 'ref': args.ref})
        return invoke(b, ['click', args.ref, '--timeout-ms', '5000'])


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', required=True, help='private, explicit per-window binding directory')
    sub = p.add_subparsers(dest='command', required=True)
    b = sub.add_parser('bind')
    for name in ('binary', 'app', 'window-id', 'title'):
        b.add_argument('--'+name, required=True)
    b.add_argument('--pid', type=int, required=True)
    b.add_argument('--allow-nonsecret-ui', required=True, action='store_true')
    sub.add_parser('snapshot')
    c = sub.add_parser('click')
    c.add_argument('ref')
    c.add_argument('--expect-name', required=True)
    c.add_argument('--expect-role', required=True)
    args = p.parse_args(argv)
    try:
        result = bind(args) if args.command == 'bind' else run(args)
        code = 0 if result['ok'] else 1
    except (Blocked, OSError, ValueError, KeyError, TypeError) as e:
        # Never print native stderr, UI text, environment or path exceptions.
        reason = str(e) if isinstance(e, Blocked) else type(e).__name__
        result = {'ok': False, 'command': args.command, 'error': {'code': 'RELAY_DESKTOP_BLOCKED',
                  'reason': reason, 'disposition': {'delivery': 'unknown', 'retry': 'unsafe'}}}
        code = 78
    print(json.dumps(result))
    return code


if __name__ == '__main__':
    sys.exit(main())
