"""Opt-in existing sudo route. No candidate modules execute as the browser owner."""

from __future__ import annotations
import json
import subprocess

# Fixed stdlib-only program. Only numeric PID/UID are arguments; no binding-
# supplied program executes as the browser owner. Failures contain no raw paths,
# argv, stderr, profile contents or credentials.
PROBE = r"""
import json, os, pathlib, shlex, sys
pid, uid = map(int, sys.argv[1:])
phase = 'process'
try:
    assert pid > 0 and uid > 0 and os.geteuid() == uid
    root = pathlib.Path('/proc') / str(pid)
    def identity():
        fields = (root/'stat').read_text().rsplit(')', 1)[1].split()
        raw = (root/'cmdline').read_bytes()
        assert len(raw) <= 65536
        args = [x.decode() for x in raw.rstrip(b'\0').split(b'\0')]
        if len(args) == 1: args = shlex.split(args[0])
        flags = []
        for i, arg in enumerate(args):
            for key in ('--remote-debugging-port', '--user-data-dir', '--profile-directory'):
                if arg.startswith(key+'='): flags.append(arg)
                elif arg == key and i+1 < len(args): flags.extend([key,args[i+1]])
        return dict(uid=root.stat().st_uid, start_time=int(fields[19]), executable=os.readlink(root/'exe'), args=flags)
    before = identity()
    sockets = []
    profile_locks = []
    for fd in (root/'fd').iterdir():
        try: target = os.readlink(fd)
        except FileNotFoundError: continue
        if target.startswith('socket:['): sockets.append(target[8:-1])
        elif target.endswith('/.browseros/server.lock'): profile_locks.append(target)
    if identity() != before:
        raise RuntimeError('process_changed')
    assert before['uid'] == uid
    phase = 'profile'
    profiles = {}
    paths = [x.split('=',1)[1] for x in before['args'] if x.startswith('--user-data-dir=')]
    # Preserve the same metadata for both accepted Chromium flag spellings.
    paths += [before['args'][i+1] for i,a in enumerate(before['args'][:-1]) if a == '--user-data-dir']
    paths += [x[:-len('/.browseros/server.lock')] for x in profile_locks]
    for value in set(paths):
        p = pathlib.Path(value)
        st = p.stat()
        profiles[value] = dict(canonical=str(p.resolve(strict=True)), uid=st.st_uid, inode=st.st_ino, device=st.st_dev, directory=p.is_dir())
    phase = 'process'
    if identity() != before:
        raise RuntimeError('process_changed')
    out = json.dumps(dict(schema='relay-identity-reader-v1', pid=pid, identity=before, sockets=sockets, profile_locks=profile_locks, profiles=profiles))
    assert len(out) <= 65536
    print(out)
except (OSError, ValueError, IndexError, AssertionError, RuntimeError) as exc:
    gate = 'identity_reader_invalid_metadata'
    if isinstance(exc, PermissionError): gate = 'identity_reader_permission_denied'
    elif isinstance(exc, FileNotFoundError): gate = 'profile_not_found' if phase == 'profile' else 'process_not_running'
    elif isinstance(exc, RuntimeError) and str(exc) == 'process_changed': gate = 'process_changed_during_validation'
    print(json.dumps(dict(schema='relay-identity-reader-error-v1', pid=pid, failed_gate=gate)))
    sys.exit(78)
"""

ERROR_GATES = frozenset(
    {
        "process_not_running",
        "profile_not_found",
        "identity_reader_permission_denied",
        "identity_reader_invalid_metadata",
        "process_changed_during_validation",
    }
)


def read_identity(pid: int, uid: int) -> dict:
    from .binding import BindingError

    if (
        type(pid) is not int
        or type(uid) is not int
        or not 0 < pid < 2**31
        or not 0 < uid < 2**31
    ):
        raise BindingError("identity_reader_numeric_identity_required")
    try:
        result = subprocess.run(
            [
                "/usr/bin/sudo",
                "-n",
                "-u",
                "#" + str(uid),
                "--",
                "/usr/bin/python3",
                "-I",
                "-c",
                PROBE,
                str(pid),
                str(uid),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BindingError("identity_reader_timeout") from exc
    except OSError as exc:
        raise BindingError("identity_reader_unavailable") from exc
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise BindingError("identity_reader_response_too_large")
    if result.returncode:
        gate = "identity_reader_failed"
        try:
            error = json.loads(result.stdout)
            if (
                isinstance(error, dict)
                and error.get("schema") == "relay-identity-reader-error-v1"
                and type(error.get("pid")) is int
                and error["pid"] == pid
                and error.get("failed_gate") in ERROR_GATES
            ):
                gate = error["failed_gate"]
        except (ValueError, TypeError):
            pass
        raise BindingError(gate)
    try:
        data = json.loads(result.stdout)
        identity = data["identity"]
        if (
            data["schema"] != "relay-identity-reader-v1"
            or data["pid"] != pid
            or identity["uid"] != uid
            or type(identity["start_time"]) is not int
            or not isinstance(identity["executable"], str)
            or not isinstance(identity["args"], list)
            or not all(isinstance(x, str) for x in identity["args"])
            or not isinstance(data["sockets"], list)
            or not all(isinstance(x, str) and x.isdecimal() for x in data["sockets"])
        ):
            raise ValueError("schema")
    except (ValueError, KeyError, TypeError) as exc:
        raise BindingError("identity_reader_invalid_receipt") from exc
    return data
