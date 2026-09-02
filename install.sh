#!/usr/bin/env sh
# Airlock installer — one command, Linux & macOS.
#   curl -fsSL https://raw.githubusercontent.com/cyberbobas/airlock/main/install.sh | sh
#
# Installs the `airlock` CLI, then tells you the one command that proves it works.
set -eu

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
dim()  { printf '\033[2m%s\033[0m\n' "$*"; }
err()  { printf '\033[31m%s\033[0m\n' "$*" >&2; }

# --- find a Python >= 3.11 ---------------------------------------------------
PY=""
for c in python3.13 python3.12 python3.11 python3 python; do
  if command -v "$c" >/dev/null 2>&1; then
    if "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3,11) else 1)' 2>/dev/null; then
      PY="$c"; break
    fi
  fi
done
if [ -z "$PY" ]; then
  err "Airlock needs Python 3.11 or newer. Install it, then re-run this."
  err "  Debian/Ubuntu: sudo apt install python3 python3-pip pipx"
  err "  macOS:         brew install python pipx"
  exit 1
fi
say "Using $("$PY" --version 2>&1)"

PKG="${AIRLOCK_PACKAGE:-airlock-agent}"

# --- install: pipx (isolated, preferred) -> pip --user -> pip ----------------
if command -v pipx >/dev/null 2>&1; then
  say "Installing $PKG with pipx…"
  pipx install "$PKG"
elif "$PY" -m pipx --version >/dev/null 2>&1; then
  say "Installing $PKG with pipx…"
  "$PY" -m pipx install "$PKG"
else
  say "pipx not found — installing $PKG with pip (--user)…"
  "$PY" -m pip install --user --upgrade "$PKG" || "$PY" -m pip install --upgrade "$PKG"
fi

# --- verify + point at the demo ---------------------------------------------
if command -v airlock >/dev/null 2>&1; then
  BIN="airlock"
else
  BIN="$PY -m airlock.cli"
  err "airlock is installed but not on PATH yet."
  err "Add your local bin dir to PATH (pipx: run 'pipx ensurepath' and reopen the shell)."
fi

echo
say "Installed. See it stop a key-theft in one command:"
dim  "    $BIN demo"
echo
say "Then wire it into your agents:"
dim  "    $BIN init        # gates your agents, and asks which AI tier you want:"
dim  "                     #   lite (no model) · standard (built-in AI) · pro (BYO)"
dim  "                     #   non-interactive: AIRLOCK_TIER=standard $BIN init --tier standard"
dim  "    $BIN ai-status   # shows the AI tier / model / provider"
dim  "    $BIN doctor      # confirms what is actually enforcing"
