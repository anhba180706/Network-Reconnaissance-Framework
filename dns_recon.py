#!/usr/bin/env python3

import sys

import dns.exception
import dns.query
import dns.resolver
import dns.xfr
import dns.zone


def dns_recon(domain):
    print(f"[*] DNS Reconnaissance cho: {domain}")

    # 1. Lấy danh sách Name Servers (NS)
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        ns_servers = [str(r.target).rstrip(".") for r in ns_answers]

        print(
            f"[+] Tìm thấy {len(ns_servers)} Name Servers: "
            f"{', '.join(ns_servers)}"
        )

    except Exception as e:
        print(f"[-] Lỗi lấy NS record: {e}")
        return

    # 2. Thử Zone Transfer trên từng NS
    for ns in ns_servers:
        print(f"\n[*] Đang thử Zone Transfer trên NS: {ns}")

        try:
            # Phân giải IP của Name Server
            ns_ip = dns.resolver.resolve(ns, "A")[0].address

            print(f"[*] NS IP: {ns_ip}")

            # Thực hiện AXFR request
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))

            print(f"[!!!] ZONE TRANSFER THÀNH CÔNG trên {ns} ({ns_ip})")
            print("[*] Danh sách bản ghi:")

            for name, node in zone.nodes.items():
                print(f"    {name}.{domain} : {node.to_text(name)}")

        except (dns.exception.FormError, dns.xfr.TransferError):
            print("[-] Bị từ chối (Refused).")

        except Exception as e:
            print(f"[-] Lỗi: {e}")


if __name__ == "__main__":
    # zonetransfer.me là domain demo được cho phép thử AXFR
    dns_recon(sys.argv[1] if len(sys.argv) > 1 else "zonetransfer.me")
