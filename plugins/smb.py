# Check SMB/NetBIOS availability (ports 445 and 139)
import json
import socket
import struct
import sys

COLUMN_TITLE = 'SMB'
TIMEOUT = 4


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def _check_port(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            return True
    except OSError:
        return False


def _netbios_name(ip: str) -> str:
    """Send a NetBIOS Name Service stat query and return the workstation name."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        query = (
            b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01'
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 57:
            num_names = data[56]
            offset = 57
            for _ in range(num_names):
                if offset + 18 > len(data):
                    break
                name = data[offset:offset + 15].decode('ascii', errors='replace').strip()
                flag = struct.unpack('>H', data[offset + 16:offset + 18])[0]
                if not (flag & 0x8000):   # unique name (not group)
                    return name
                offset += 18
    except Exception:
        pass
    return ''


def scan(ip: str) -> None:
    p445 = _check_port(ip, 445)
    p139 = _check_port(ip, 139)

    if p445 or p139:
        nbname = _netbios_name(ip)
        open_ports = ', '.join(p for p, ok in [('445', p445), ('139', p139)] if ok)
        short = f'open: {open_ports}'
        if nbname:
            short = f'  {nbname}'
        long_lines = [
            '[SMB]',
            f'  Port 445 : {"open" if p445 else "closed"}',
            f'  Port 139 : {"open" if p139 else "closed"}',
        ]
        if nbname:
            long_lines.append(f'  NetBIOS  : {nbname}')
        long_ = '\n'.join(long_lines)
    else:
        short = ''
        long_ = '[SMB]\n  Ports 445, 139 closed / filtered'

    print(json.dumps({'short': short, 'long': long_}))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)
    if len(sys.argv) < 2:
        print(json.dumps({'short': 'ERR', 'long': 'Usage: smb.py <ip>'}))
        sys.exit(1)
    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({'short': 'ERR', 'long': str(exc)}))
        sys.exit(1)
