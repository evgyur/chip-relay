#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if ! "$SCRIPT_DIR/chip-relay" --json status | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("cdp",{}).get("state")=="up" else 1)'; then
  "$SCRIPT_DIR/chip-relay" launch --backend "${CHIP_RELAY_BACKEND:-auto}"
fi
