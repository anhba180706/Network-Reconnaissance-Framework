#!/usr/bin/env python3

from scapy.all import Ether, sniff, load_contrib

# Nạp hỗ trợ CDP và LLDP của Scapy
load_contrib("cdp")
load_contrib("lldp")

from scapy.contrib.cdp import (  # noqa: E402
    CDPMsgDeviceID,
    CDPMsgPortID,
    CDPMsgSoftwareVersion,
)
from scapy.contrib.lldp import (  # noqa: E402
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUSystemName,
)


def _text(value):
    """Chuyển bytes/str từ Scapy thành chuỗi in được."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def process_packet(packet):
    has_cdp = packet.haslayer(CDPMsgDeviceID)
    has_lldp = packet.haslayer(LLDPDUChassisID)

    # Bỏ qua mọi gói không phải CDP/LLDP
    if not (has_cdp or has_lldp):
        return

    print("\n" + "=" * 60)
    print("[+] Packet captured")
    print("=" * 60)

    # CDP
    if has_cdp:
        print("[CDP] Device ID:", _text(packet[CDPMsgDeviceID].val))

        if packet.haslayer(CDPMsgSoftwareVersion):
            print("[CDP] Software Version:",
                  _text(packet[CDPMsgSoftwareVersion].val))

        if packet.haslayer(CDPMsgPortID):
            print("[CDP] Port ID:", _text(packet[CDPMsgPortID].iface))

    # LLDP
    if has_lldp:
        print("[LLDP] Chassis ID:", _text(packet[LLDPDUChassisID].id))

        if packet.haslayer(LLDPDUPortID):
            print("[LLDP] Port ID:", _text(packet[LLDPDUPortID].id))

        if packet.haslayer(LLDPDUSystemName):
            print("[LLDP] System Name:",
                  _text(packet[LLDPDUSystemName].system_name))

    # Thông tin Ethernet cơ bản
    if packet.haslayer(Ether):
        print("[Ethernet] Source MAC:", packet[Ether].src)
        print("[Ethernet] Destination MAC:", packet[Ether].dst)


def main(iface=None):
    print("=" * 60)
    print("CDP/LLDP Passive Enumerator")
    print("=" * 60)

    print("[*] Listening for CDP/LLDP packets...")
    print("[*] Press Ctrl+C to stop.\n")

    sniff_kwargs = {
        "prn": process_packet,
        "store": False,
    }
    if iface:
        sniff_kwargs["iface"] = iface

    sniff(**sniff_kwargs)


if __name__ == "__main__":
    main()
