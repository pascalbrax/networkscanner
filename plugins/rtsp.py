# RTSP scanner for IP cams
import json
import socket
import sys

# ── Plugin identity ──────────────────────────────────────────────────────────
# This string appears as the column header in the results table.
COLUMN_TITLE = 'RTSP'

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

RTSP_PORT = 554
CONNECT_TIMEOUT = 4
READ_TIMEOUT = 4
MAX_BANNER_BYTES = 4096


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def _safe_preview(data: bytes) -> str:
    """Return a compact printable preview of the RTSP response/banner."""
    if not data:
        return ''
    text = data.decode('utf-8', errors='replace')
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return '\n'.join(lines[:12])


def scan(ip: str) -> None:
    request = (
        f'OPTIONS rtsp://{ip}:{RTSP_PORT}/ RTSP/1.0\r\n'
        'CSeq: 1\r\n'
        'User-Agent: RTSP-Service-Plugin/1.0\r\n'
        '\r\n'
    ).encode('ascii')

    try:
        with socket.create_connection((ip, RTSP_PORT), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(READ_TIMEOUT)
            sock.sendall(request)

            try:
                response = sock.recv(MAX_BANNER_BYTES)
            except socket.timeout:
                response = b''

        preview = _safe_preview(response)

        if response.startswith(b'RTSP/'):
            first_line = preview.splitlines()[0] if preview else 'RTSP response received'
            short = 'RTSP open'
            long_ = (
                f'[RTSP :{RTSP_PORT}]\n'
                f'  Status : open\n'
                f'  Probe  : RTSP OPTIONS\n'
                f'  Result : {first_line}\n'
            )
            if preview:
                long_ += f'\nResponse preview:\n{preview}'
        else:
            short = 'open?'
            long_ = (
                f'[RTSP :{RTSP_PORT}]\n'
                f'  Status : TCP open, RTSP not confirmed\n'
                f'  Probe  : RTSP OPTIONS\n'
            )
            if preview:
                long_ += f'\nResponse preview:\n{preview}'
            else:
                long_ += '  Detail : no response before timeout'

    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        short = ''
        long_ = (
            f'[RTSP :{RTSP_PORT}]\n'
            f'  Status : closed / filtered\n'
            f'  Detail : {exc}'
        )

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
