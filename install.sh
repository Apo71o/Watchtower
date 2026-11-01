#!/usr/bin/env bash
# Watchtower installer for Debian-family Linux.
# Installs the Python app into an isolated environment and adds a desktop
# launcher. Never runs sudo by itself: anything needing root is printed and
# only run if you answer "y".
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_HOME="${XDG_DATA_HOME:-$HOME/.local/share}/watchtower-app"
BIN_DIR="$HOME/.local/bin"
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
ask() { read -r -p "$1 [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }

# 1. Python >= 3.11 with venv
PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
    echo "Python 3.11+ is required (found: $("$PY" --version 2>&1 || echo none))." >&2
    exit 1
fi

# 2. System libraries Qt needs (PySide6 wheels bundle Qt itself, but not these).
QT_PKGS=(libegl1 libgl1 libxkbcommon0 libxcb-cursor0 libfontconfig1 libdbus-1-3)
if ! "$PY" -c 'import venv, ensurepip' 2>/dev/null; then
    PYV="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
    QT_PKGS+=("python${PYV}-venv")
fi
MISSING=()
for p in "${QT_PKGS[@]}"; do
    dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || MISSING+=("$p")
done
if ((${#MISSING[@]})); then
    say "These system packages are needed for the GUI / Python venv:"
    echo "    sudo apt install ${MISSING[*]}"
    if ask "Run that now (uses sudo)?"; then
        sudo apt install -y "${MISSING[@]}"
    else
        echo "Skipped. The GUI may not start until they are installed."
    fi
fi

# 3. App install: pipx if available, else a private venv.
if command -v pipx >/dev/null 2>&1 && [[ "${WATCHTOWER_NO_PIPX:-}" != "1" ]]; then
    say "Installing with pipx"
    pipx install --force "$SRC"
    LAUNCH="$(command -v watchtower || echo "$BIN_DIR/watchtower")"
else
    say "Creating venv in $APP_HOME/venv"
    "$PY" -m venv "$APP_HOME/venv"
    "$APP_HOME/venv/bin/pip" install --upgrade pip >/dev/null
    "$APP_HOME/venv/bin/pip" install "$SRC"
    mkdir -p "$BIN_DIR"
    ln -sf "$APP_HOME/venv/bin/watchtower" "$BIN_DIR/watchtower"
    LAUNCH="$BIN_DIR/watchtower"
fi

# 4. Desktop launcher
mkdir -p "$DESKTOP_DIR"
sed "s|@EXEC@|$LAUNCH|" "$SRC/packaging/watchtower.desktop.in" > "$DESKTOP_DIR/watchtower.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true

say "Installed. Launch from your app menu, or run: watchtower"
say "Check external tools without the GUI: watchtower --check-deps"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) echo "Note: add $BIN_DIR to your PATH.";; esac
