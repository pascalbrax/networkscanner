import re
import sys
import subprocess
import ipaddress
from typing import List, Optional


def parse_targets(target_str: str) -> List[str]:
    """
    Parse target into a list of IP strings.
    Accepts: CIDR (192.168.1.0/24), full range (192.168.1.1-192.168.1.50),
    short range (192.168.1.1-50), or single IP.
    """
    target_str = target_str.strip()

    # CIDR
    try:
        network = ipaddress.ip_network(target_str, strict=False)
        hosts = list(network.hosts())
        if not hosts:
            hosts = [network.network_address]
        return [str(h) for h in hosts]
    except ValueError:
        pass

    # Range with dash
    if '-' in target_str:
        parts = target_str.split('-', 1)
        start_str = parts[0].strip()
        end_str = parts[1].strip()
        try:
            start = ipaddress.ip_address(start_str)
            if '.' not in end_str:
                # Short form: 192.168.1.1-50
                prefix = '.'.join(start_str.split('.')[:3])
                end = ipaddress.ip_address(f'{prefix}.{end_str}')
            else:
                end = ipaddress.ip_address(end_str)

            start_int = int(start)
            end_int = int(end)
            if start_int > end_int:
                raise ValueError('Start IP is greater than end IP.')
            if end_int - start_int > 65535:
                raise ValueError('Range too large (max 65536 hosts).')
            return [str(ipaddress.ip_address(i)) for i in range(start_int, end_int + 1)]
        except ValueError as e:
            if 'Range too large' in str(e) or 'greater than' in str(e):
                raise
            pass

    # Single IP
    try:
        return [str(ipaddress.ip_address(target_str))]
    except ValueError:
        pass

    raise ValueError(
        f'Invalid target: "{target_str}"\n'
        'Accepted formats: 192.168.1.0/24 | 192.168.1.1-192.168.1.50 | 192.168.1.1-50 | 192.168.1.1'
    )


def ping_host(ip: str, timeout_ms: int = 1000) -> Optional[int]:
    """
    Ping a host once.  Returns the round-trip time in milliseconds if alive,
    or None if the host did not respond.
    """
    try:
        if sys.platform == 'win32':
            cmd = ['ping', '-n', '1', '-w', str(timeout_ms), ip]
            extra = {'creationflags': subprocess.CREATE_NO_WINDOW}
        else:
            timeout_s = max(1, timeout_ms // 1000)
            cmd = ['ping', '-c', '1', '-W', str(timeout_s), ip]
            extra = {}

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=(timeout_ms / 1000) + 3,
            **extra,
        )

        if result.returncode != 0:
            return None

        output = result.stdout

        # Language-agnostic parsing: match the punctuation, not the words.
        # Windows reply line:  "… durata<1ms …"  or  "… time=4ms …"
        # Linux/macOS stats:   "rtt … = min/avg/max/mdev ms"
        if sys.platform == 'win32':
            # Sub-millisecond: any word followed by "<1ms"
            if re.search(r'<\s*1\s*ms', output, re.IGNORECASE):
                return 1
            # Numeric RTT from reply line or stats (= Xms)
            m = re.search(r'=\s*(\d+)\s*ms', output)
            if m:
                return max(1, int(m.group(1)))
        else:
            # "rtt min/avg/max/mdev = 0.123/avg/…"
            m = re.search(r'=\s*[\d.]+/([\d.]+)/', output)
            if m:
                return max(1, round(float(m.group(1))))

        # ping succeeded but time couldn't be parsed
        return 1

    except Exception:
        return None
