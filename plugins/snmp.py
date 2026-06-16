# SNMP discovery
import json
import sys
import asyncio
import socket

COLUMN_TITLE = "SNMP"
SNMP_PORT = 161


def get_title() -> None:
    print(json.dumps({"title": COLUMN_TITLE}))


async def snmp_get(ip: str, community: str):
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine,
        CommunityData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        get_cmd,
    )

    transport = await UdpTransportTarget.create(
        (ip, SNMP_PORT),
        timeout=1,
        retries=0,
    )

    return await get_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMP v2c
        transport,
        ContextData(),
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),  # sysName
        ObjectType(ObjectIdentity("1.3.6.1.2.1.1.2.0")),  # sysObjectID
    )


def udp_snmp_probe(ip: str, community: str = "public", timeout: float = 1.0):
    """
    Minimal SNMPv1 GET request for sysDescr.0.
    Used when pysnmp is unavailable.

    Returns:
        True  -> received an SNMP response
        False -> timeout / no response
    """

    # Minimal SNMP GET request for 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    packet = bytes.fromhex(
        "302602010004067075626c6963a019020401020304020100020100300b300906052b060102010100"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(packet, (ip, SNMP_PORT))
        data, _ = sock.recvfrom(4096)
        return len(data) > 0

    except socket.timeout:
        return False

    except OSError:
        return False

    finally:
        sock.close()


def fallback_scan(ip: str) -> None:
    details = [
        "pysnmp module not available",
        "Using raw UDP SNMP probe",
    ]

    found = False

    for community in ("public", "private"):
        if udp_snmp_probe(ip, community):
            found = True
            details.append(f"SNMP response detected (community: {community})")
            break

    if not found:
        details.append("No SNMP response detected")

    print(json.dumps({
        "short": "SNMP" if found else "",
        "long": "[SNMP]\n" + "\n".join(f"  {line}" for line in details)
    }))


def scan(ip: str) -> None:
    try:
        import pysnmp  # noqa: F401
        pysnmp_available = True
    except ImportError:
        pysnmp_available = False

    if not pysnmp_available:
        fallback_scan(ip)
        return

    communities = ["public", "private"]
    details = []
    found = False
    short = ""

    for community in communities:
        try:
            error_indication, error_status, error_index, var_binds = asyncio.run(
                snmp_get(ip, community)
            )

            if error_indication or error_status:
                continue

            found = True
            sysname = None

            for oid, value in var_binds:
                if str(oid) == "1.3.6.1.2.1.1.5.0":
                    sysname = str(value)

            short = sysname[:20] if sysname else f"SNMP:{community}"

            details.append(f"Community : {community}")

            for oid, value in var_binds:
                details.append(f"{oid} : {value}")

            break

        except Exception:
            continue

    if not found:
        details.append("No SNMP response detected")

    print(json.dumps({
        "short": short,
        "long": "[SNMP]\n" + "\n".join(f"  {line}" for line in details)
    }))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--title":
        get_title()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(json.dumps({
            "short": "ERR",
            "long": "Usage: snmp.py <ip>"
        }))
        sys.exit(1)

    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({
            "short": "ERR",
            "long": str(exc)
        }))
        sys.exit(1)