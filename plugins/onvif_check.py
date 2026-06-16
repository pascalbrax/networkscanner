# Find ONVIF camera devices
"""
ONVIF support checker plugin.

Protocol expected by the scanner:
  python onvif_check.py --title
  python onvif_check.py <ip>

The scan uses ONVIF WS-Discovery over UDP port 3702. Most ONVIF devices
respond to a Probe request sent directly to their IP address. The script does
not require third-party Python packages.
"""

from __future__ import annotations

import json
import re
import socket
import sys
import urllib.parse
import uuid
from xml.etree import ElementTree as ET

# ── Plugin identity ──────────────────────────────────────────────────────────
COLUMN_TITLE = "ONVIF"

# ── ONVIF / WS-Discovery settings ────────────────────────────────────────────
ONVIF_DISCOVERY_PORT = 3702
SOCKET_TIMEOUT_SECONDS = 4.0

WS_DISCOVERY_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:MessageID>uuid:{message_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""


def get_title() -> None:
    """Return the column title expected by the plugin manager."""
    print(json.dumps({"title": COLUMN_TITLE}))


def _xml_texts(xml_bytes: bytes, local_name: str) -> list[str]:
    """Extract text values for tags by local name, ignoring XML namespaces."""
    values: list[str] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return values

    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] == local_name and elem.text:
            values.append(elem.text.strip())
    return values


def _is_onvif_response(data: bytes) -> bool:
    """Detect whether a WS-Discovery response looks like an ONVIF response."""
    lower = data.lower()
    return b"onvif" in lower or b"networkvideotransmitter" in lower


def _first_url(text: str) -> str | None:
    match = re.search(r"https?://[^\s<>'\"]+", text)
    return match.group(0) if match else None


def _scope_value(scopes: list[str], category: str) -> str | None:
    """Return the last path segment of the first scope URI matching the category."""
    prefix = f"onvif://www.onvif.org/{category}/"
    for block in scopes:
        for uri in block.split():
            if uri.lower().startswith(prefix.lower()):
                value = urllib.parse.unquote(uri[len(prefix):]).strip("/")
                if value:
                    return value
    return None


def _short_label(scopes: list[str]) -> str:
    """Best short label: model (hardware/name) > manufacturer > fallback."""
    for category in ("hardware", "name"):
        val = _scope_value(scopes, category)
        if val:
            return val
    val = _scope_value(scopes, "manufacturer")
    if val:
        return val
    return "ONVIF"


def scan(ip: str) -> None:
    """Probe the specified IP address for ONVIF WS-Discovery support."""
    probe_xml = WS_DISCOVERY_PROBE.format(message_id=uuid.uuid4()).encode("utf-8")

    responses: list[tuple[bytes, tuple[str, int]]] = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        # Bind to an ephemeral local port so the device can reply directly.
        sock.bind(("", 0))
        sock.sendto(probe_xml, (ip, ONVIF_DISCOVERY_PORT))

        # Collect all replies until the timeout expires. Some devices send more
        # than one ProbeMatch.
        while True:
            try:
                data, addr = sock.recvfrom(65535)
                responses.append((data, addr))
            except socket.timeout:
                break

    matching = [(data, addr) for data, addr in responses if _is_onvif_response(data)]

    if not matching:
        short = ""
        long_ = (
            f"[ONVIF :{ONVIF_DISCOVERY_PORT}]\n"
            "  Status : no ONVIF WS-Discovery response\n"
            f"  Replies: {len(responses)}"
        )
        print(json.dumps({"short": short, "long": long_}))
        return

    data, addr = matching[0]
    scopes = _xml_texts(data, "Scopes")
    xaddrs = _xml_texts(data, "XAddrs")
    types = _xml_texts(data, "Types")

    xaddr_text = " ".join(xaddrs)
    service_url = _first_url(xaddr_text) or "not advertised"

    short = _short_label(scopes)
    long_lines = [
        f"[ONVIF :{ONVIF_DISCOVERY_PORT}]",
        "  Status : supported",
        f"  Reply  : {addr[0]}:{addr[1]}",
        f"  Service: {service_url}",
    ]

    if types:
        long_lines.append(f"  Types  : {' | '.join(types)}")
    if scopes:
        # Keep the details useful without making the UI panel huge.
        scope_text = " | ".join(scopes)
        if len(scope_text) > 800:
            scope_text = scope_text[:797] + "..."
        long_lines.append(f"  Scopes : {scope_text}")

    print(json.dumps({"short": short, "long": "\n".join(long_lines)}))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--title":
        get_title()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(json.dumps({"short": "ERR", "long": "Usage: <plugin>.py <ip>"}))
        sys.exit(1)

    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({"short": "", "long": str(exc)}))
        sys.exit(1)
