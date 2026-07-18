#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

CREATE_USER=false
if [[ "${1:-}" == "--create-user" ]]; then
  CREATE_USER=true
elif [[ -n "${1:-}" ]]; then
  echo "Usage: ./setup_kali.sh [--create-user]" >&2
  exit 2
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[ERROR] python3 was not found. Install it with:" >&2
  echo "        sudo apt update && sudo apt install -y python3 python3-venv python3-pip" >&2
  exit 1
fi

"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("[ERROR] ShadowTrace requires Python 3.11 or newer.")
print(f"[OK] Python {sys.version.split()[0]}")
PY

VENV_DIR="$ROOT_DIR/.venv"
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[1/5] Creating project virtual environment at .venv ..."
  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    echo "[ERROR] Could not create the virtual environment." >&2
    echo "        On Kali run: sudo apt install -y python3-venv" >&2
    exit 1
  fi
else
  echo "[1/5] Reusing existing .venv ..."
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "[2/5] Updating pip build tooling ..."
python -m pip install --upgrade pip setuptools wheel

echo "[3/5] Installing ShadowTrace dependencies ..."
python -m pip install -r "$ROOT_DIR/requirements.txt"

echo "[4/5] Preparing .env configuration ..."
if [[ ! -f "$ROOT_DIR/.env" ]]; then
  cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
  python - <<'PY'
from pathlib import Path
import secrets

path = Path('.env')
text = path.read_text(encoding='utf-8')
text = text.replace('replace-with-a-long-random-secret', secrets.token_urlsafe(48), 1)
path.write_text(text, encoding='utf-8')
PY
  chmod 600 "$ROOT_DIR/.env"
  echo "[OK] Created .env with a random application secret."
else
  echo "[OK] Existing .env preserved."
fi

echo "[5/5] Initializing/upgrading the database ..."
python "$ROOT_DIR/scripts/init_db.py"

if [[ "$CREATE_USER" == true ]]; then
  echo
  echo "Create the first administrator account:"
  python "$ROOT_DIR/scripts/create_user.py" --role Admin
fi

cat <<EOF2

[READY] ShadowTrace setup completed successfully.

Start it with:
  cd "$ROOT_DIR"
  source .venv/bin/activate
  python run.py

Then open:
  http://127.0.0.1:5000

If you did not create a user yet, run:
  source .venv/bin/activate
  python scripts/create_user.py --role Admin
EOF2
