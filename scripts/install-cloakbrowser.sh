#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${CHIP_RELAY_BASE_DIR:-$HOME/.local/share/chip-relay}"
VENV_DIR="${CHIP_RELAY_CLOAK_VENV:-$BASE_DIR/cloakbrowser-venv}"
CACHE_DIR="${CLOAKBROWSER_CACHE_DIR:-$BASE_DIR/cloakbrowser-cache}"
BIN_DIR="${CHIP_RELAY_BIN_DIR:-$HOME/.local/bin}"
WRAPPER="$BIN_DIR/cloakbrowser-chrome"
PYTHON="${PYTHON:-python3}"
CLOAK_VERSION="${CLOAKBROWSER_VERSION:-cloakbrowser}"

mkdir -p "$BASE_DIR" "$CACHE_DIR" "$BIN_DIR"

if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$PYTHON" -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install --upgrade "$CLOAK_VERSION" 'playwright>=1.40'

cat > "$WRAPPER" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
BASE_DIR="${CHIP_RELAY_BASE_DIR:-$HOME/.local/share/chip-relay}"
VENV_DIR="${CHIP_RELAY_CLOAK_VENV:-$BASE_DIR/cloakbrowser-venv}"
CACHE_DIR="${CLOAKBROWSER_CACHE_DIR:-$BASE_DIR/cloakbrowser-cache}"
PY="$VENV_DIR/bin/python"
if [ ! -x "$PY" ]; then
  echo "cloakbrowser venv missing: $PY" >&2
  exit 127
fi
BIN="$(CLOAKBROWSER_CACHE_DIR="$CACHE_DIR" "$PY" - <<'PY'
from cloakbrowser.download import ensure_binary
print(ensure_binary())
PY
)"
SEED="${CLOAKBROWSER_FINGERPRINT_SEED:-$((10000 + RANDOM % 90000))}"
PLATFORM="${CLOAKBROWSER_FINGERPRINT_PLATFORM:-windows}"
exec "$BIN" \
  --no-sandbox \
  --fingerprint="$SEED" \
  --fingerprint-platform="$PLATFORM" \
  --ignore-gpu-blocklist \
  "$@"
SH
chmod 0755 "$WRAPPER"

CLOAKBROWSER_CACHE_DIR="$CACHE_DIR" "$VENV_DIR/bin/python" -m cloakbrowser install >/dev/null
"$WRAPPER" --version
printf 'installed wrapper: %s\n' "$WRAPPER"
