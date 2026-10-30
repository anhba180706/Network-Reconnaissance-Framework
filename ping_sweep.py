import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, ICMP, TCP, sr1
from ipaddress import ip_network
import concurrent.futures
import threading
import sys

print_lock = threading.Lock()


def icmp_probe(ip_str, timeout=1):
    """Gửi ICMP Echo Request để kiểm tra host."""
    try:
        pkt = IP(dst=ip_str) / ICMP()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        return resp is not None
    except Exception:
        return False


def tcp_syn_probe(ip_str, port=80, timeout=1):
    """
    Gửi TCP SYN tới một port.
    SYN-ACK hoặc RST đều cho biết host có phản hồi.
    """
    try:
        pkt = IP(dst=ip_str) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)
        return resp is not None
    except Exception:
        return False


def scan_host(ip):
    """
    Kiểm tra một host theo thứ tự:
    1. ICMP
    2. TCP SYN :80
    3. TCP SYN :443

    Trả về tuple (ip, method) hoặc None.
    """
    ip_str = str(ip)

    if icmp_probe(ip_str):
        return ip_str, "ICMP"

    if tcp_syn_probe(ip_str, 80):
        return ip_str, "TCP SYN:80"

    if tcp_syn_probe(ip_str, 443):
        return ip_str, "TCP SYN:443"

    return None


def sweep_network(network_cidr):
    print(f"[*] Scanning network: {network_cidr}")

    try:
        net = ip_network(network_cidr, strict=False)
    except ValueError as e:
        print(f"[-] Invalid network: {e}")
        return []

    hosts = list(net.hosts())

    if not hosts:
        print("[-] No usable hosts found.")
        return []

    discovered = []

    print(f"[*] Total hosts to scan: {len(hosts)}")

    # Không dùng quá nhiều thread để tránh gây tải không cần thiết
    max_workers = min(32, len(hosts))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {
            executor.submit(scan_host, ip): ip
            for ip in hosts
        }

        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]

            try:
                result = future.result()

                if result:
                    ip_str, method = result

                    with print_lock:
                        print(f"[+] {ip_str} is UP ({method})")

                    discovered.append({
                        "ip": ip_str,
                        "method": method
                    })

            except Exception as e:
                with print_lock:
                    print(f"[-] Error scanning {ip}: {e}")

    discovered.sort(key=lambda x: tuple(
        int(part) for part in x["ip"].split(".")
    ))

    print()
    print("[*] Scan completed.")
    print(f"[+] Hosts discovered: {len(discovered)}")

    return discovered


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 ping_sweep.py <CIDR>")
        sys.exit(1)

    sweep_network(sys.argv[1])
