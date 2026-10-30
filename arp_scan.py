from scapy.all import ARP, Ether, srp
import sys


def arp_network_scan(target_network, iface=None):
    """Quét toàn bộ mạng LAN bằng ARP Request, trả về list {'ip', 'mac'}."""
    print(f"[*] Đang thực hiện ARP Scan trên mạng: {target_network}")

    # Gói ARP request cho dải IP đích, gửi broadcast ở Layer 2
    arp = ARP(pdst=target_network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # srp trả về (answered, unanswered); lấy phần answered.
    # Không chỉ định iface thì Scapy dùng interface mặc định (Windows & Linux).
    srp_kwargs = {"timeout": 2, "verbose": 0}
    if iface:
        srp_kwargs["iface"] = iface
    answered = srp(packet, **srp_kwargs)[0]

    devices = []
    for _sent, received in answered:
        # psrc: IP nguồn, hwsrc: MAC nguồn của thiết bị trả lời
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices


def display_results(devices):
    print("\nAvailable Devices in the Network:")
    print("IP Address" + " " * 18 + "MAC Address")
    print("-" * 45)
    for device in devices:
        print(f"{device['ip']:<25} {device['mac']}")


if __name__ == "__main__":
    # Cần quyền root/admin để gửi raw packet
    if len(sys.argv) < 2:
        print("Usage: python3 arp_scan.py <CIDR> [interface]")
        sys.exit(1)

    target = sys.argv[1]
    interface = sys.argv[2] if len(sys.argv) > 2 else None
    found_devices = arp_network_scan(target, iface=interface)
    display_results(found_devices)
