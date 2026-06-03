# One-line description shown in the Plugin Config dialog
import json
import sys

# ── Plugin identity ──────────────────────────────────────────────────────────
# This string appears as the column header in the results table.
COLUMN_TITLE = 'My Plugin'

# ── Protocol ─────────────────────────────────────────────────────────────────
# The scanner calls this script in two ways:
#
#   1. python <plugin>.py --title
#      Must respond with: {"title": "<column header>"}
#      Called once at startup to build the results table.
#
#   2. python <plugin>.py <ip>
#      Must respond with: {"short": "<brief>", "long": "<detailed>"}
#      short : shown in the results table cell  (keep it under ~20 chars)
#      long  : shown in the Details panel on double-click
#      On error: {"short": "ERR", "long": "<reason>"}
#
# Output must be a single JSON line on stdout.
# Timeout is 10 s by default (configurable in plugin_manager.py).
# ─────────────────────────────────────────────────────────────────────────────


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def scan(ip: str) -> None:
    # ── your scanning logic here ─────────────────────────────────────────────
    import socket
    port = 8080
    try:
        with socket.create_connection((ip, port), timeout=4):
            short = 'open'
            long_ = f'[MY_PLUGIN :{port}]\n  Status : open'
    except OSError:
        short = 'N/A'
        long_ = f'[MY_PLUGIN :{port}]\n  Status : closed / filtered'

    print(json.dumps({'short': short, 'long': long_}))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)
    if len(sys.argv) < 2:
        print(json.dumps({'short': 'ERR', 'long': 'Usage: <plugin>.py <ip>'}))
        sys.exit(1)
    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({'short': 'ERR', 'long': str(exc)}))
        sys.exit(1)
