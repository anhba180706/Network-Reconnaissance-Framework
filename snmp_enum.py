#!/usr/bin/env python3

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    walk_cmd,
)
import asyncio


TARGET = "192.168.56.101"
COMMUNITY = "public"
PORT = 161


async def snmp_get(target, community, oid):
    print(
        f"[*] Querying {target} "
        f"with community '{community}' "
        f"for OID {oid}..."
    )

    snmp_engine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            (target, PORT),
            timeout=1,
            retries=1
        )

        error_indication, error_status, error_index, var_binds = await get_cmd(
            snmp_engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        if error_indication:
            print(f"[-] Error: {error_indication}")
            return

        if error_status:
            print(
                f"[-] Error Status: "
                f"{error_status.prettyPrint()}"
            )
            return

        for var_bind in var_binds:
            print(f" -> {var_bind.prettyPrint()}")

    finally:
        snmp_engine.close_dispatcher()


async def snmp_walk(target, community, oid):
    print(
        f"[*] Walking {target} "
        f"with community '{community}' "
        f"starting at OID {oid}..."
    )

    snmp_engine = SnmpEngine()

    try:
        transport = await UdpTransportTarget.create(
            (target, PORT),
            timeout=1,
            retries=1
        )

        async for (
            error_indication,
            error_status,
            error_index,
            var_binds,
        ) in walk_cmd(
            snmp_engine,
            CommunityData(community, mpModel=1),
            transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):

            if error_indication:
                print(f"[-] Error: {error_indication}")
                break

            if error_status:
                print(
                    f"[-] Error Status: "
                    f"{error_status.prettyPrint()}"
                )
                break

            for var_bind in var_binds:
                print(f" -> {var_bind.prettyPrint()}")

    finally:
        snmp_engine.close_dispatcher()


async def main():
    print("=" * 60)
    print("SNMP Enumerator")
    print("=" * 60)

    # 1. System Description
    print("\n[+] System Description")
    await snmp_get(
        TARGET,
        COMMUNITY,
        "1.3.6.1.2.1.1.1.0"
    )

    # 2. System Name
    print("\n[+] System Name")
    await snmp_get(
        TARGET,
        COMMUNITY,
        "1.3.6.1.2.1.1.5.0"
    )

    # 3. Running Processes
    print("\n[+] Running Processes")
    await snmp_walk(
        TARGET,
        COMMUNITY,
        "1.3.6.1.2.1.25.4.2.1.2"
    )


if __name__ == "__main__":
    asyncio.run(main())
