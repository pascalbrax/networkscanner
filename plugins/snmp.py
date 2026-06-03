# SNMP discovery
import json
import sys
import asyncio

COLUMN_TITLE = "SNMP"


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
        (ip, 161),
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


def scan(ip: str) -> None:
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

                if sysname:
                    short = sysname[:20]  # keep table readable
                else:
                    short = f"SNMP: {community}"

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