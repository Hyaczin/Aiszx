#!/usr/bin/env bash
# Aiszx installer for Parrot OS.
#
# Isolation rules:
#   * System Python is never modified: no sudo, no pip outside the project venv.
#   * Interpreter preference: $AISZX_PYTHON → pyenv-managed 3.11+ → system python3 (3.11+).
#   * Dependencies go into ./.venv via `.venv/bin/python -m pip`.
#   * Nothing is installed with apt and no security tool is installed: missing OS packages and tools
#     are reported with the command to run (`python3 pentest.py tools missing`).
#
# Usage: ./install.sh [--dev] [--system-site-packages] [--recreate] [--dry-run] [--check]
#   --dev                    also install test dependencies (pytest)
#   --system-site-packages   let the venv see APT Python packages (python3-yaml, python3-jinja2) for offline installs
#   --recreate               delete and rebuild .venv
#   --dry-run                print what would be done; change nothing
#   --check                  change nothing; verify the installation and run `pentest.py doctor`
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

DEV=0; SYSTEM_SITE=0; RECREATE=0; DRY=0; CHECK=0
for arg in "$@"; do
  case "$arg" in
    --dev) DEV=1 ;;
    --system-site-packages) SYSTEM_SITE=1 ;;
    --recreate) RECREATE=1 ;;
    --dry-run) DRY=1 ;;
    --check) CHECK=1 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  echo "Do not run install.sh as root. Aiszx installs into a per-project virtual environment." >&2
  exit 1
fi

# Every state-changing step goes through run(), so --dry-run shows exactly what would happen.
run() {
  if [ "$DRY" -eq 1 ]; then echo "    would run: $*"; else "$@"; fi
}

version_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; }

pick_python() {
  if [ -n "${AISZX_PYTHON:-}" ]; then
    version_ok "$AISZX_PYTHON" && { echo "$AISZX_PYTHON"; return; }
    echo "AISZX_PYTHON=$AISZX_PYTHON is not Python 3.11+" >&2; exit 1
  fi
  if command -v pyenv >/dev/null 2>&1; then
    local root candidate
    root="$(pyenv root)"
    # Newest installed pyenv interpreter in the 3.11+ range (pyenv-managed; does not touch system Python).
    for candidate in $(ls -1 "$root/versions" 2>/dev/null | grep -E '^3\.[0-9]+\.[0-9]+$' | sort -t. -k1,1nr -k2,2nr -k3,3nr); do
      if version_ok "$root/versions/$candidate/bin/python"; then echo "$root/versions/$candidate/bin/python"; return; fi
    done
  fi
  if command -v python3 >/dev/null 2>&1 && version_ok python3; then command -v python3; return; fi
  echo "No Python 3.11+ found. Install one with pyenv (pyenv install 3.11) or use Parrot's python3." >&2
  exit 1
}

VPY=.venv/bin/python

if [ "$CHECK" -eq 1 ]; then
  status=0
  if [ -x "$VPY" ]; then
    echo "[ok] .venv: $("$VPY" -c 'import sys; print(sys.version.split()[0])')"
  else
    echo "[!!] .venv missing: run ./install.sh"; exit 1
  fi
  if "$VPY" -c 'import yaml, jinja2' 2>/dev/null; then
    echo "[ok] dependencies importable (PyYAML, Jinja2)"
  else
    echo "[!!] dependencies missing in .venv: run ./install.sh"; status=1
  fi
  "$VPY" pentest.py doctor || status=$?
  exit "$status"
fi

PY="$(pick_python)"
echo "[*] interpreter: $PY ($("$PY" -c 'import sys; print(sys.version.split()[0])'))"
[ "$DRY" -eq 1 ] && echo "[*] dry run: nothing will be changed"

if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
  echo "[!] The venv/ensurepip modules are missing for $PY." >&2
  echo "    For Parrot's system python3 run:  sudo apt install python3-venv" >&2
  echo "    (install.sh does not run apt itself.)" >&2
  exit 1
fi

if [ "$RECREATE" -eq 1 ] && [ -d .venv ]; then
  echo "[*] removing existing .venv"
  run rm -rf .venv
fi

if [ ! -x "$VPY" ] || { [ "$RECREATE" -eq 1 ] && [ "$DRY" -eq 1 ]; }; then
  echo "[*] creating .venv"
  if [ "$SYSTEM_SITE" -eq 1 ]; then run "$PY" -m venv --system-site-packages .venv; else run "$PY" -m venv .venv; fi
else
  echo "[*] reusing .venv ($("$VPY" -c 'import sys; print(sys.version.split()[0])'))"
fi

if [ "$DRY" -eq 0 ] && "$VPY" -c 'import yaml, jinja2' 2>/dev/null && [ "$SYSTEM_SITE" -eq 1 ]; then
  echo "[*] PyYAML and Jinja2 already available (system site packages); skipping pip install"
else
  echo "[*] installing requirements.txt into .venv"
  run "$VPY" -m pip install --disable-pip-version-check -r requirements.txt
fi
if [ "$DEV" -eq 1 ]; then
  echo "[*] installing requirements-dev.txt into .venv"
  run "$VPY" -m pip install --disable-pip-version-check -r requirements-dev.txt
fi

echo "[*] initialising Aiszx (creates the data directory; migrates the database with a backup first)"
run "$VPY" pentest.py init

if [ "$DRY" -eq 1 ]; then
  echo "[*] dry run complete"
  exit 0
fi

echo
echo "[*] health check (read-only; nothing is installed for you)"
"$VPY" pentest.py doctor || echo "[!] doctor reported problems above; each has a suggested fix"

cat <<'EOF'

[+] Done. Run commands with:   python3 pentest.py <command>
    (pentest.py switches into .venv automatically; no need to activate it)
    Missing tools:  python3 pentest.py tools missing   (explains how to install each one; asks before doing anything)
    Next:           python3 pentest.py scope add 10.10.10.0/24
                    python3 pentest.py target add 10.10.10.5
    Checklist:      docs/DEPLOYMENT.md
EOF
