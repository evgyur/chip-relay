#!/usr/bin/env bash
# Opt-in desktop companion. Does not attach to or start a browser.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${CHIP_RELAY_PYTHON:-${CHIP_RELAY_CLOAK_VENV:-${HOME}/.local/share/chip-relay/cloakbrowser-venv}/bin/python}"
if [[ ! -x "$PY" ]]; then
  printf '%s\n' '{"ok":false,"error":{"code":"declared_managed_python_missing"}}' >&2
  exit 78
fi
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -P -m chip_relay.desktop "$@"
