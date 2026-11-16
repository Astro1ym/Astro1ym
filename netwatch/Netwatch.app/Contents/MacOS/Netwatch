#!/bin/bash
# Netwatch.app launcher. No Terminal window: sets up a private Python
# environment on first run, asks for the administrator password with the
# standard macOS dialog, starts the passive monitor in the background and
# opens its dashboard in your browser. Quit from the dashboard's Quit button.

RES="$(cd "$(dirname "$0")/../Resources" && pwd)"
DATA="$HOME/Library/Application Support/Netwatch"     # venv, token, log
OUT="$HOME/Netwatch"                                  # alerts.jsonl, optional config.json
APPDIR="$DATA/app"                                    # private copy of the program
VENV="$DATA/venv"
PORT=8787
BASE="http://127.0.0.1:$PORT"

dialog() {   # dialog "message"
    osascript - "$1" <<'AS' >/dev/null 2>&1
on run argv
    display dialog (item 1 of argv) with title "Netwatch" buttons {"OK"} default button 1
end run
AS
}
notify() {
    osascript - "$1" <<'AS' >/dev/null 2>&1
on run argv
    display notification (item 1 of argv) with title "Netwatch"
end run
AS
}
is_up() { curl -s --noproxy 127.0.0.1 --max-time 1 -o /dev/null "$BASE/"; }

mkdir -p "$DATA" "$OUT" "$APPDIR"

# Already running? Just bring the dashboard back.
if is_up && [ -s "$DATA/token" ]; then
    open "$BASE/#t=$(cat "$DATA/token")"
    exit 0
fi

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
    dialog "Netwatch needs Python 3.

If macOS just offered to install the command line developer tools, click Install, wait for it to finish, then open Netwatch again.

Otherwise install Python from python.org/downloads."
    exit 1
fi

# First run (or app updated): build the environment and install scapy + rich.
if [ ! -x "$VENV/bin/python3" ] || ! cmp -s "$RES/requirements.txt" "$DATA/requirements.txt"; then
    notify "Setting up for first use. This takes about a minute."
    if ! { python3 -m venv "$VENV" \
            && "$VENV/bin/python3" -m pip install --quiet --upgrade pip \
            && "$VENV/bin/python3" -m pip install --quiet -r "$RES/requirements.txt" \
            && cp "$RES/requirements.txt" "$DATA/requirements.txt"; } >"$DATA/setup.log" 2>&1; then
        dialog "Setup failed. Check your internet connection and open Netwatch again.

Details: $DATA/setup.log"
        exit 1
    fi
fi

# Run from a private copy outside the app bundle. macOS privacy protection
# stops background processes (even as root) from reading Downloads, Documents
# and Desktop, which is where the app usually sits.
if ! cp "$RES/netwatch.py" "$RES/dashboard.html" "$APPDIR/" 2>"$DATA/setup.log"; then
    dialog "Netwatch could not copy its files.

$(cat "$DATA/setup.log")"
    exit 1
fi

# Secret that lets only this browser session talk to the monitor.
(umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$DATA/token")
touch "$OUT/alerts.jsonl"            # created as you, so it stays yours

CONFIG=""
[ -f "$OUT/config.json" ] && CONFIG="$OUT/config.json"

# Start the monitor as root via the standard macOS password prompt.
: > "$DATA/netwatch.log"
if ! osascript - "$OUT" "$VENV/bin/python3" "$APPDIR/netwatch.py" "$PORT" "$DATA/token" "$DATA/netwatch.log" "$CONFIG" <<'AS' >/dev/null 2>"$DATA/start.err"
on run argv
    set cmd to "cd " & quoted form of (item 1 of argv) & " && " & quoted form of (item 2 of argv) & " " & quoted form of (item 3 of argv) & " --web --web-port " & (item 4 of argv) & " --web-token-file " & quoted form of (item 5 of argv)
    if (item 7 of argv) is not "" then set cmd to cmd & " -c " & quoted form of (item 7 of argv)
    set cmd to cmd & " > " & quoted form of (item 6 of argv) & " 2>&1 &"
    do shell script cmd with prompt "Netwatch needs administrator access to watch network traffic. It only listens; it never sends anything." with administrator privileges
end run
AS
then
    # -128 is "user cancelled" (password dialog dismissed): quit quietly.
    grep -q -- "-128" "$DATA/start.err" && exit 0
    dialog "Netwatch could not start.

$(cat "$DATA/start.err")"
    exit 1
fi

for _ in $(seq 1 120); do
    if is_up; then
        open "$BASE/#t=$(cat "$DATA/token")"
        exit 0
    fi
    sleep 0.5
done
REASON="$(tail -n 6 "$DATA/netwatch.log" 2>/dev/null)"
dialog "Netwatch could not start.

${REASON:-The monitor produced no output.}

Full log: $DATA/netwatch.log"
exit 1
