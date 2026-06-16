# Checks the target IP and attempts to capture its MAC address (or vendor)
import ipaddress
import json
import re
import subprocess
import sys
from typing import Optional, Tuple

import requests

# ── Plugin identity ──────────────────────────────────────────────────────────
# This string appears as the column header in the results table.
COLUMN_TITLE = 'MAC Address'

# ── Protocol ─────────────────────────────────────────────────────────────────
# The scanner calls this script in up to three ways:
#
#   1. python <plugin>.py --title
#      Must respond with: {"title": "<column header>"}
#      Called once at startup to build the results table.
#
#   2. python <plugin>.py --options                          [optional]
#      Must respond with: {"options": [{...}, ...]}
#      Called once to discover configurable settings, shown in the
#      Plugins dialog. Plugins that skip this simply have no options.
#
#   3. python <plugin>.py <ip> [--opts <json>]
#      Must respond with: {"short": "<brief>", "long": "<detailed>"}
#      --opts carries the user's selected option values as a JSON object,
#      only appended when at least one option has been configured.
#      short : shown in the results table cell  (keep it under ~20 chars)
#      long  : shown in the Details panel on double-click
#      On error: {"short": "ERR", "long": "<reason>"}
#
# Output must be a single JSON line on stdout.
# Timeout is adaptive (15-90s, see plugin_manager.py).
# ─────────────────────────────────────────────────────────────────────────────

MAC_RE = re.compile(r'(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}')


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def get_options() -> None:
    print(json.dumps({'options': [
        {
            'name': 'mode',
            'label': 'Display',
            'type': 'choice',
            'choices': ['mac', 'vendor'],
            'default': 'mac',
        },
    ]}))


def vendor_for(mac: str) -> Optional[str]:
    """Look up the vendor for a MAC address via the braile.ch lookup service."""
    try:
        url = "https://braile.ch/mac.php?mac=" + mac
        r = requests.get(url, timeout=3)
        vendor = r.text.strip()
        return vendor or None
    except Exception:
        return None


def run_command(command: list[str], timeout: float = 3.0) -> Tuple[int, str]:
    """Run a command and return (exit_code, combined_output)."""
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = (completed.stdout or '') + (completed.stderr or '')
        return completed.returncode, output
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)


def ping_target(ip: str) -> bool:
    """Probe the target once to populate the local ARP/neighbour table."""
    if sys.platform.startswith('win'):
        command = ['ping', '-n', '1', '-w', '1000', ip]
    else:
        command = ['ping', '-c', '1', '-W', '1', ip]
    return run_command(command, timeout=3.0)[0] == 0


def find_mac_with_ip_neigh(ip: str) -> Optional[str]:
    """Linux: read the neighbour table for the target IP."""
    code, output = run_command(['ip', 'neigh', 'show', ip], timeout=2.0)
    if code != 0:
        return None
    match = MAC_RE.search(output)
    return match.group(0).lower() if match else None


def find_mac_with_arp(ip: str) -> Optional[str]:
    """Cross-platform fallback: read ARP cache for the target IP."""
    commands = [
        ['arp', '-n', ip],  # Linux/macOS often support this
        ['arp', '-a', ip],  # Windows and macOS
        ['arp', '-a'],      # broad fallback; parse only lines containing ip
    ]

    for command in commands:
        code, output = run_command(command, timeout=2.0)
        if code != 0 and not output:
            continue
        for line in output.splitlines():
            if ip in line:
                match = MAC_RE.search(line)
                if match:
                    return match.group(0).lower()
    return None


def lookup_mac(ip: str) -> Tuple[bool, Optional[str]]:
    """Return (host_responded_to_ping, mac_address_or_none)."""
    responded = ping_target(ip)

    mac = find_mac_with_ip_neigh(ip)
    if not mac:
        mac = find_mac_with_arp(ip)

    return responded, mac


def scan(ip: str, options: Optional[dict] = None) -> None:
    options = options or {}
    mode = options.get('mode', 'mac')   # 'mac' or 'vendor'

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(json.dumps({'short': 'ERR', 'long': f'Invalid IP address: {ip}'}))
        return

    responded, mac = lookup_mac(ip)
    status = 'reachable' if responded else 'no ping reply'

    if mac:
        vendor = vendor_for(mac)
        if mode == 'vendor':
            short = vendor or mac
        else:
            short = mac
        long_lines = [
            '[MAC_CAPTURE]',
            f'  Target : {ip}',
            f'  Status : {status}',
            f'  MAC    : {mac}',
            f'  Vendor : {vendor or "unknown (lookup failed or no match)"}',
        ]
        long_ = '\n'.join(long_lines)
    else:
        short = ''
        long_ = (
            '[MAC_CAPTURE]\n'
            f'  Target : {ip}\n'
            f'  Status : {status}\n'
            '  MAC    : not found\n'
            '  Note   : MAC lookup usually works only for hosts on the local L2 network/subnet.'
        )

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
