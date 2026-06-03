# Check common mail services on a host
import json
import sys
import socket
import ssl

COLUMN_TITLE = 'Mail'
TIMEOUT = 3
BANNER_BYTES = 512

# name, port, whether the service usually starts with TLS immediately
MAIL_PORTS = [
    ('SMTP', 25, False),
    ('SMTPS', 465, True),
    ('SMTP-SUB', 587, False),
    ('POP3', 110, False),
    ('POP3S', 995, True),
    ('IMAP', 143, False),
    ('IMAPS', 993, True),
]


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def clean_banner(data: bytes) -> str:
    text = data.decode('utf-8', errors='replace')
    text = text.replace('\r', '').replace('\n', ' | ')
    return text.strip()[:200]


def make_tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def read_banner(sock: socket.socket) -> str:
    try:
        data = sock.recv(BANNER_BYTES)
    except (socket.timeout, OSError):
        return ''
    return clean_banner(data)


def send_polite_quit(sock: socket.socket, service: str) -> None:
    """Close protocol sessions without authentication or intrusive commands."""
    try:
        if service.startswith('SMTP'):
            sock.sendall(b'QUIT\r\n')
        elif service.startswith('POP3'):
            sock.sendall(b'QUIT\r\n')
        elif service.startswith('IMAP'):
            sock.sendall(b'a001 LOGOUT\r\n')
    except OSError:
        pass


def probe(ip: str, service: str, port: int, implicit_tls: bool) -> dict:
    raw_sock = None
    sock = None

    try:
        raw_sock = socket.create_connection((ip, port), timeout=TIMEOUT)
        raw_sock.settimeout(TIMEOUT)

        if implicit_tls:
            ctx = make_tls_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=ip)
        else:
            sock = raw_sock

        banner = read_banner(sock)
        send_polite_quit(sock, service)

        return {
            'open': True,
            'service': service,
            'port': port,
            'tls': implicit_tls,
            'banner': banner,
        }

    except (socket.timeout, OSError, ssl.SSLError) as exc:
        return {
            'open': False,
            'service': service,
            'port': port,
            'error': str(exc),
        }

    finally:
        try:
            if sock is not None:
                sock.close()
            elif raw_sock is not None:
                raw_sock.close()
        except OSError:
            pass


def scan(ip: str) -> None:
    results = [
        probe(ip, service, port, implicit_tls)
        for service, port, implicit_tls in MAIL_PORTS
    ]

    open_results = [item for item in results if item.get('open')]

    if open_results:
        short = ','.join(str(item['port']) for item in open_results)
        if len(short) > 20:
            short = f'{len(open_results)} mail ports'
    else:
        short = ''

    long_lines = []

    for item in results:
        service = item['service']
        port = item['port']
        header = f'[{service}:{port}]'

        if item.get('open'):
            long_lines.append(header)
            long_lines.append('  Status : open')
            long_lines.append(f'  TLS    : {"implicit" if item.get("tls") else "no / STARTTLS possible"}')
            if item.get('banner'):
                long_lines.append(f'  Banner : {item["banner"]}')
            else:
                long_lines.append('  Banner : none / no greeting before timeout')
        else:
            long_lines.append(f'{header}  closed / filtered')

        long_lines.append('')

    print(json.dumps({
        'short': short,
        'long': '\n'.join(long_lines).rstrip()
    }))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(json.dumps({
            'short': 'ERR',
            'long': 'Usage: mail.py <ip>'
        }))
        sys.exit(1)

    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({
            'short': 'ERR',
            'long': str(exc)
        }))
        sys.exit(1)
