# One-line description shown in the Plugin Config dialog
import json
import sys

# ── Plugin identity ──────────────────────────────────────────────────────────
# This string appears as the column header in the results table.
COLUMN_TITLE = 'My Plugin'

# ── Protocol ─────────────────────────────────────────────────────────────────
# The scanner calls this script in up to three ways:
#
#   1. python <plugin>.py --title
#      Must respond with: {"title": "<column header>"}
#      Called once at startup to build the results table.
#
#   2. python <plugin>.py --options                          [OPTIONAL]
#      Must respond with: {"options": [{...}, ...]}
#      Called once to discover configurable settings, shown to the user
#      in the Plugins dialog (e.g. a dropdown to pick a display mode).
#      Skip this entirely if your plugin has nothing to configure — the
#      scanner treats a missing/invalid response as "no options", so
#      existing plugins never need to add this to keep working.
#
#      Each option dict supports:
#        name     : str   — key used in the --opts JSON sent back to you
#        label    : str   — shown next to the control in the dialog
#        type     : str   — "choice" (dropdown) is currently supported
#        choices  : list  — required for type "choice"
#        default  : any   — preselected value
#
#   3. python <plugin>.py <ip> [--opts <json>]                [--opts OPTIONAL]
#      Must respond with: {"short": "<brief>", "long": "<detailed>"}
#      --opts is appended only when the user configured option values for
#      this plugin; it carries them as a JSON object, e.g. --opts '{"mode": "b"}'.
#      short : shown in the results table cell  (keep it under ~20 chars)
#      long  : shown in the Details panel on double-click
#      On error: {"short": "ERR", "long": "<reason>"}
#
# Output must be a single JSON line on stdout.
# Timeout is adaptive (15-90s, see plugin_manager.py).
# ─────────────────────────────────────────────────────────────────────────────


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def get_options() -> None:
    # Remove this function (and its __main__ hook below) if your plugin
    # has nothing to configure.
    print(json.dumps({'options': [
        {
            'name': 'mode',
            'label': 'Display',
            'type': 'choice',
            'choices': ['option_a', 'option_b'],
            'default': 'option_a',
        },
    ]}))


def scan(ip: str, options: dict | None = None) -> None:
    options = options or {}
    mode = options.get('mode', 'option_a')

    # ── your scanning logic here ─────────────────────────────────────────────
    import socket
    port = 8080
    try:
        with socket.create_connection((ip, port), timeout=4):
            short = 'open' if mode == 'option_a' else f'open ({mode})'
            long_ = f'[MY_PLUGIN :{port}]\n  Status : open\n  Mode   : {mode}'
    except OSError:
        short = 'N/A'
        long_ = f'[MY_PLUGIN :{port}]\n  Status : closed / filtered'

    print(json.dumps({'short': short, 'long': long_}))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == '--options':
        get_options()
        sys.exit(0)
    if len(sys.argv) < 2:
        print(json.dumps({'short': 'ERR', 'long': 'Usage: <plugin>.py <ip> [--opts <json>]'}))
        sys.exit(1)

    opts = {}
    if len(sys.argv) > 3 and sys.argv[2] == '--opts':
        try:
            opts = json.loads(sys.argv[3])
        except json.JSONDecodeError:
            opts = {}

    try:
        scan(sys.argv[1], opts)
    except Exception as exc:
        print(json.dumps({'short': 'ERR', 'long': str(exc)}))
        sys.exit(1)
