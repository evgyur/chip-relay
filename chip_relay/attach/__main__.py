"""Opt-in attach-only CLI; it has no login, lifecycle or target-action command."""

import argparse
import json
import re
from pathlib import Path
from .binding import BindingError, read_bindings, select_binding, verify_binding
from .profile_selection import command, read_selection, write_selection
from .routing_contract import validate, probe


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binding")
    parser.add_argument("--profile")
    parser.add_argument("--session", default="default")
    parser.add_argument("--selection")
    parser.add_argument(
        "command", choices=["select", "routes", "status", "network-check", "doctor"]
    )
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            if args.arguments:
                raise BindingError("doctor_takes_no_arguments")
            from .humanize import doctor

            result = doctor()
            code = 0 if result["status"] == "available" else 78
        else:
            if not args.binding:
                raise BindingError("external_binding_required")
            bindings = read_bindings(Path(args.binding).expanduser())
            if args.command == "select":
                if args.selection:
                    raise BindingError("select_requires_new_receipt")
                result = command(args.arguments, bindings, args.profile, args.session)
            elif args.command == "routes":
                if args.arguments:
                    raise BindingError("routes_takes_no_arguments")
                result = {
                    "status": "configured_intent_not_live_proof",
                    "routing": validate(bindings),
                    "browser_connected": False,
                }
            else:
                selected = (
                    read_selection(args.selection, bindings, args.profile, args.session)
                    if args.selection
                    else None
                )
                name, entry = select_binding(
                    bindings, selected["profile"] if selected else args.profile
                )
                identity = verify_binding(entry)
                if args.command == "status":
                    if args.arguments:
                        raise BindingError("status_takes_no_arguments")
                    result = {
                        "status": "attached_identity_verified",
                        "profile": name,
                        **identity,
                        "live_identity_verified": False,
                        "network_verified": False,
                    }
                else:
                    if (
                        selected is None
                        or len(args.arguments) != 2
                        or args.arguments[0] != "--write"
                    ):
                        raise BindingError(
                            "usage: --selection PIN network-check --write NEW_PIN"
                        )
                    checked = probe(bindings, entry, selected)
                    write_selection(args.arguments[1], checked)
                    result = {
                        "status": "ipv4_exit_verified",
                        "selection_path": args.arguments[1],
                        "scope": "selected default context IPv4 only; not login, IPv6 or proxy-chain proof",
                        "fallback": False,
                    }
            code = 0
        print(json.dumps(result))
        return code
    except ImportError:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "fallback": False,
                    "failed_gate": "attach_dependency_unavailable",
                }
            )
        )
        return 78
    except (BindingError, OSError, ValueError, KeyError, TypeError) as exc:
        # A local file/error can contain credentials or private page values.
        gate = str(exc).split(":", 1)[0] if isinstance(exc, BindingError) else ""
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,100}", gate):
            gate = "attach_precondition_failed"
        print(json.dumps({"status": "blocked", "fallback": False, "failed_gate": gate}))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
