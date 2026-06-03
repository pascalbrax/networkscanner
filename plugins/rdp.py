# Check RDP availability (port 3389)
import json
import socket
import sys

COLUMN_TITLE = 'RDP'
PORT = 3389
TIMEOUT = 4


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def scan(ip: str) -> None:
    try:
        with socket.create_connection((ip, PORT), timeout=TIMEOUT) as sock:
            # Minimal RDP Connection Request PDU
            sock.sendall(bytes.fromhex('030000130ee000000000000100080003000000'))
            response = sock.recv(64)
        short = 'open'
        long_ = f'[RDP :{PORT}]\n  Status : open\n  Bytes  : {len(response)} received'
    except (ConnectionRefusedError, socket.timeout, OSError):
        short = ''
        long_ = f'[RDP :{PORT}]  closed / filtered'
    except Exception as exc:
        short = 'ERR'
        long_ = f'[RDP :{PORT}]  {exc}'

    print(json.dumps({'short': short, 'long': long_}))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)
    if len(sys.argv) < 2:
        print(json.dumps({'short': 'ERR', 'long': 'Usage: rdp.py <ip>'}))
        sys.exit(1)
    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({'short': 'ERR', 'long': str(exc)}))
        sys.exit(1)
