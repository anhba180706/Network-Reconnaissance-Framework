import nmap
import sys

def advanced_nmap_scan(target):
    """Sử dụng python-nmap để quét Service Version và OS Detection chi tiết."""
    nm = nmap.PortScanner()
    
    # -sV: Version Detection, -O: OS Detection, --version-intensity 5: Quét kỹ
    args = "-sV -O --version-intensity 5"
    print(f"[*] Running Nmap on {target} with args: {args}")
    
    try:
        nm.scan(target, arguments=args)
        
        for host in nm.all_hosts():
            print(f"\n[+] Host: {host} ({nm[host].hostname()})")
            
            # OS Detection
            if 'osmatch' in nm[host]:
                print("--- OS Matches ---")
                for match in nm[host]['osmatch']:
                    print(f" -> OS Match: {match['name']} (Accuracy: {match['accuracy']}%)")
            
            # Service Version
            for proto in nm[host].all_protocols():
                print(f"--- Protocol: {proto.upper()} ---")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    svc = nm[host][proto][port]
                    print(f" Port {port}: {svc['state']} | Service: {svc['product']} {svc['version']} {svc['extrainfo']}")
                    
    except Exception as e:
        print(f"[-] Lỗi khi chạy Nmap (Đảm bảo đã cài đặt nmap trên hệ thống): {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 active_fingerprint.py <IP>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    advanced_nmap_scan(target_ip)
