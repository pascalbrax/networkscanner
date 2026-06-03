# Check for SSH servers and grab the server banner
import json
import socket
import sys

COLUMN_TITLE = 'SSH'
PORT = 22
TIMEOUT = 5


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def scan(ip: str) -> None:
    try:
        with socket.create_connection((ip, PORT), timeout=TIMEOUT) as sock:
            banner = sock.recv(256).decode('utf-8', errors='replace').strip()
        version = banner.split('\n')[0] if banner else 'open'
        short = version or 'open'
        long_ = f'[SSH :{PORT}]\n  Banner : {banner}\n  Port   : {PORT}'
    except (socket.timeout, ConnectionRefusedError, OSError):
        short = ''
        long_ = f'[SSH :{PORT}]  closed / filtered'
    except Exception as exc:
        short = 'ERR'
        long_ = f'[SSH :{PORT}]  {exc}'

    print(json.dumps({'short': short, 'long': long_}))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)
    if len(sys.argv) < 2:
        print(json.dumps({'short': 'ERR', 'long': 'Usage: ssh.py <ip>'}))
        sys.exit(1)
    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({'short': 'ERR', 'long': str(exc)}))
        sys.exit(1)
