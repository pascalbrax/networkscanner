# Check for VNC servers
import json
import socket
import sys

# ── Plugin identity ──────────────────────────────────────────────────────────
# This string appears as the column header in the results table.
COLUMN_TITLE = 'VNC'

# ── Protocol ─────────────────────────────────────────────────────────────────
# The scanner calls this script in two ways:
#
#   1. python <plugin>.py --title
#      Must respond with: {"title": "<column header>"}
#
#   2. python <plugin>.py <ip>
#      Must respond with: {"short": "<brief>", "long": "<detailed>"}
#      On error: {"short": "ERR", "long": "<reason>"}
#
# Output must be a single JSON line on stdout.
# Timeout is 10 s by default in the scanner, so this plugin keeps its own
# network timeout short and checks only the standard VNC port by default.
# ─────────────────────────────────────────────────────────────────────────────

VNC_PORT = 5900
TIMEOUT_SECONDS = 2.0

SECURITY_TYPES = {
    0: 'Invalid / failure',
    1: 'None',
    2: 'VNC Authentication',
    5: 'RA2',
    6: 'RA2ne',
    16: 'Tight',
    18: 'TLS',
    19: 'VeNCrypt',
    20: 'GTK-VNC SASL',
    21: 'MD5 hash authentication',
    22: 'xvp',
    30: 'Apple Remote Desktop',
    129: 'Tight Unix Login',
    130: 'Tight External',
    131: 'VeNCrypt Plain',
}


def emit(obj: dict) -> None:
    print(json.dumps(obj, separators=(',', ':')), flush=True)


def get_title() -> None:
    emit({'title': COLUMN_TITLE})


def recv_some(sock: socket.socket, size: int) -> bytes:
    try:
        return sock.recv(size)
    except (socket.timeout, TimeoutError):
        return b''


def decode_security_types(raw: bytes, protocol: str) -> list[str]:
    if not raw:
        return []

    # RFB 3.3 sends one 4-byte big-endian security type.
    if protocol.startswith('003.003') and len(raw) >= 4:
        sec_type = int.from_bytes(raw[:4], 'big')
        return [SECURITY_TYPES.get(sec_type, f'Unknown ({sec_type})')]

    # RFB 3.7/3.8 sends: 1 byte count, then count type bytes.
    count = raw[0]
    if count == 0:
        return ['Server returned failure/no security types']

    types = raw[1:1 + count]
    return [SECURITY_TYPES.get(t, f'Unknown ({t})') for t in types]


def probe_vnc(ip: str, port: int = VNC_PORT) -> dict:
    result = {
        'port': port,
        'open': False,
        'is_vnc': False,
        'protocol': '',
        'security': [],
        'detail': '',
    }

    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT_SECONDS) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            result['open'] = True

            # VNC/RFB servers send a 12-byte banner, e.g. b'RFB 003.008\n'.
            banner = recv_some(sock, 12)
            if not banner.startswith(b'RFB '):
                result['detail'] = f'Port open, but no RFB banner: {banner!r}'
                return result

            result['is_vnc'] = True
            protocol = banner.decode('ascii', errors='replace').strip().replace('RFB ', '')
            result['protocol'] = protocol

            # Reply with the banner to advance the handshake far enough to read
            # security types. This does not authenticate or try credentials.
            sock.sendall(banner)
            raw_security = recv_some(sock, 256)
            result['security'] = decode_security_types(raw_security, protocol)
            return result

    except socket.timeout:
        result['detail'] = 'connection timed out'
    except ConnectionRefusedError:
        result['detail'] = 'connection refused'
    except OSError as exc:
        result['detail'] = str(exc)

    return result


def scan(ip: str) -> None:
    item = probe_vnc(ip, VNC_PORT)

    lines = [f'[VNC :{VNC_PORT}]']
    if item['is_vnc']:
        security = ', '.join(item['security']) if item['security'] else 'not advertised / unreadable'
        short = f"VNC {item['protocol']}"
        lines.extend([
            '  Status   : open',
            '  Service  : VNC/RFB',
            f"  Protocol : RFB {item['protocol']}",
            f'  Security : {security}',
        ])
    elif item['open']:
        short = 'open/non-VNC'
        lines.extend([
            '  Status   : open',
            '  Service  : not confirmed as VNC',
            f"  Detail   : {item['detail']}",
        ])
    else:
        short = ''
        lines.extend([
            '  Status   : closed / filtered',
            f"  Detail   : {item['detail'] or 'no response'}",
        ])

    emit({'short': short[:20], 'long': '\n'.join(lines)})


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)
    if len(sys.argv) < 2:
        emit({'short': 'ERR', 'long': 'Usage: <plugin>.py <ip>'})
        sys.exit(1)
    try:
        scan(sys.argv[1])
    except Exception as exc:
        emit({'short': 'ERR', 'long': str(exc)})
        sys.exit(1)
