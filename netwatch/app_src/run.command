#!/bin/bash
# Netwatch launcher: runs inside a Terminal window opened by Netwatch.app.
# Sets up a private Python environment on first run, asks which interface to
# watch, then starts the passive monitor with sudo.

HERE="$(cd "$(dirname "$0")" && pwd)"
DATA="$HOME/Library/Application Support/Netwatch"     # private venv lives here
OUT="$HOME/Documents/Netwatch"                        # alerts.jsonl is saved here
VENV="$DATA/venv"

pause_and_exit() { echo; read -r -p "Press Enter to close this window. " _; exit "${1:-0}"; }

clear
echo "==============================================================="
echo " Netwatch - passive network monitor (read-only, sends nothing)"
echo " Only use on networks you own or are authorized to monitor."
echo "==============================================================="
echo

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
    echo "Python 3 is not installed yet."
    echo "If a window just appeared offering to install developer tools, click"
    echo "Install, wait for it to finish, then open Netwatch again."
    echo "Otherwise install Python from https://www.python.org/downloads/"
    pause_and_exit 1
fi

mkdir -p "$DATA" "$OUT"

# First run (or app updated): build the environment and install scapy + rich.
if [ ! -x "$VENV/bin/python3" ] || ! cmp -s "$HERE/requirements.txt" "$DATA/requirements.txt"; then
    echo "First-time setup (about a minute, needs internet)..."
    python3 -m venv "$VENV" \
        && "$VENV/bin/python3" -m pip install --quiet --upgrade pip \
        && "$VENV/bin/python3" -m pip install --quiet -r "$HERE/requirements.txt" \
        && cp "$HERE/requirements.txt" "$DATA/requirements.txt" \
        || { echo "Setup failed. Check your internet connection and try again."; pause_and_exit 1; }
    echo "Setup done."
    echo
fi

echo "Network interfaces on this Mac:"
echo
"$VENV/bin/python3" "$HERE/netwatch.py" --list-interfaces || pause_and_exit 1
echo
read -r -p "Press Enter to watch the default (*), or type a name (e.g. en0): " IFACE
echo

ARGS=()
[ -n "$IFACE" ] && ARGS+=(-i "$IFACE")
# Optional threshold overrides: drop a config.json into ~/Documents/Netwatch.
[ -f "$OUT/config.json" ] && ARGS+=(-c "$OUT/config.json")

echo "Capturing packets needs administrator rights."
echo "Type your Mac login password and press Enter (nothing shows as you type)."
echo
cd "$OUT" || pause_and_exit 1
sudo "$VENV/bin/python3" "$HERE/netwatch.py" "${ARGS[@]}"
STATUS=$?
echo
echo "Alerts are saved in: $OUT/alerts.jsonl"
pause_and_exit $STATUS
