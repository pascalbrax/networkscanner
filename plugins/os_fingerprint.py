# Lightweight OS fingerprint plugin for the scanner framework.
# Use only on IPs/networks you own or have explicit permission to assess.
import ipaddress
import json
import re
import socket
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# ── Plugin identity ──────────────────────────────────────────────────────────
COLUMN_TITLE = 'OS'

# ── Tunables ─────────────────────────────────────────────────────────────────
CONNECT_TIMEOUT = 0.8
BANNER_TIMEOUT = 1.0

# Keep this list small so the plugin stays within the manager's default 10 s timeout.
PROBE_PORTS = {
    22: 'SSH',
    80: 'HTTP',
    135: 'MSRPC',
    139: 'NetBIOS',
    443: 'HTTPS',
    445: 'SMB',
    3389: 'RDP',
    5900: 'VNC',
    5985: 'WinRM',
    5986: 'WinRM-TLS',
    8080: 'HTTP-Alt',
}


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def valid_ip(value: str) -> str:
    """Return a normalized IP address or raise ValueError."""
    return str(ipaddress.ip_address(value))


def tcp_connect(ip: str, port: int) -> Optional[socket.socket]:
    """Open a TCP socket or return None when the port is closed/filtered."""
    try:
        sock = socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(BANNER_TIMEOUT)
        return sock
    except OSError:
        return None


def try_banner(ip: str, port: int) -> Tuple[bool, str]:
    """Return (open, banner). Banners are best effort and may be empty."""
    sock = tcp_connect(ip, port)
    if not sock:
        return False, ''

    banner = ''
    try:
        if port in (80, 8080):
            sock.sendall(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
        elif port == 443:
            # Plain HEAD sometimes still yields a useful reset/error on proxies; no TLS dependency here.
            sock.sendall(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
        try:
            data = sock.recv(256)
            banner = data.decode('utf-8', errors='replace').strip()
        except OSError:
            banner = ''
    finally:
        sock.close()
    return True, banner


def ping_ttl(ip: str) -> Optional[int]:
    """Extract TTL/hop-limit from one system ping, if available."""
    commands = [
        ['ping', '-c', '1', '-W', '1', ip],      # Linux/macOS-ish
        ['ping', '-n', '1', '-w', '1000', ip],  # Windows-ish
    ]
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        except Exception:
            continue
        output = result.stdout + result.stderr
        match = re.search(r'\bttl[=:\s](\d+)\b', output, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def ttl_os_hint(ttl: Optional[int]) -> Tuple[str, str]:
    """Convert observed TTL into a weak OS-family hint."""
    if ttl is None:
        return 'unknown', 'No ICMP TTL observed'
    if ttl <= 64:
        return 'Unix/Linux', f'Observed TTL {ttl}; commonly derived from initial TTL 64'
    if ttl <= 128:
        return 'Windows', f'Observed TTL {ttl}; commonly derived from initial TTL 128'
    return 'Network/Unix', f'Observed TTL {ttl}; commonly derived from initial TTL 255'


def score_os(open_ports: List[int], banners: Dict[int, str], ttl_hint: str) -> Tuple[str, int, List[str]]:
    scores = {'Windows': 0, 'Linux/Unix': 0, 'Network device': 0, 'Unknown': 0}
    reasons: List[str] = []

    if ttl_hint == 'Windows':
        scores['Windows'] += 2
        reasons.append('TTL pattern suggests Windows')
    elif ttl_hint == 'Unix/Linux':
        scores['Linux/Unix'] += 2
        reasons.append('TTL pattern suggests Unix/Linux')
    elif ttl_hint == 'Network/Unix':
        scores['Network device'] += 1
        scores['Linux/Unix'] += 1
        reasons.append('High TTL pattern often seen on network devices or Unix-like systems')

    windows_ports = {135, 139, 445, 3389, 5985, 5986}
    if windows_ports.intersection(open_ports):
        scores['Windows'] += 4
        reasons.append('Windows-oriented ports open: ' + ', '.join(str(p) for p in sorted(windows_ports.intersection(open_ports))))

    if 22 in open_ports:
        scores['Linux/Unix'] += 2
        reasons.append('SSH is open')

    for port, banner in banners.items():
        b = banner.lower()
        if not b:
            continue
        if 'openssh' in b:
            scores['Linux/Unix'] += 3
            reasons.append(f'Port {port} banner contains OpenSSH')
        if any(term in b for term in ('ubuntu', 'debian', 'centos', 'red hat', 'fedora', 'freebsd', 'openbsd')):
            scores['Linux/Unix'] += 3
            reasons.append(f'Port {port} banner contains Unix/Linux distribution hint')
        if any(term in b for term in ('microsoft', 'iis', 'winrm')):
            scores['Windows'] += 3
            reasons.append(f'Port {port} banner contains Microsoft/Windows hint')
        if any(term in b for term in ('cisco', 'mikrotik', 'routeros', 'juniper')):
            scores['Network device'] += 3
            reasons.append(f'Port {port} banner contains network-device hint')

    best = max(scores, key=scores.get)
    confidence = scores[best]
    if confidence <= 1:
        return '', confidence, reasons or ['No strong OS indicators found']
    return best, confidence, reasons


def scan(ip: str) -> None:
    ip = valid_ip(ip)
    open_ports: List[int] = []
    banners: Dict[int, str] = {}

    for port in PROBE_PORTS:
        is_open, banner = try_banner(ip, port)
        if is_open:
            open_ports.append(port)
            if banner:
                banners[port] = banner

    ttl = ping_ttl(ip)
    ttl_hint, ttl_reason = ttl_os_hint(ttl)
    os_guess, confidence, reasons = score_os(open_ports, banners, ttl_hint)

    if confidence >= 6:
        conf_label = 'high'
    elif confidence >= 3:
        conf_label = 'medium'
    elif confidence >= 2:
        conf_label = 'low'
    else:
        conf_label = 'weak'

    short = os_guess if os_guess != 'Linux/Unix' else 'Linux/Unix'
    if len(short) > 20:
        short = short[:17] + '...'

    open_port_text = ', '.join(f'{p}/{PROBE_PORTS[p]}' for p in sorted(open_ports)) or 'None detected'
    banner_lines = []
    for port in sorted(banners):
        safe_banner = banners[port].replace('\r', ' ').replace('\n', ' ')[:180]
        banner_lines.append(f'  {port}: {safe_banner}')

    long_ = (
        f'[OS_FINGERPRINT]\n'
        f'  Target     : {ip}\n'
        f'  Guess      : {os_guess}\n'
        f'  Confidence : {conf_label} (score {confidence})\n'
        f'  TTL hint   : {ttl_reason}\n'
        f'  Open ports : {open_port_text}\n'
        f'  Reasons    : ' + '; '.join(reasons) + '\n'
        f'  Banners    :\n' + ('\n'.join(banner_lines) if banner_lines else '  None captured')
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
