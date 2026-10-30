from scapy.all import IP, TCP, sr1
import sys


def guess_os_from_ttl(ttl):
    """Đoán họ hệ điều hành từ TTL quan sát được (TTL gốc giảm dần theo số hop)."""
    if ttl <= 64:
        return "Linux/Unix/Mac (Base TTL 64)"
    if ttl <= 128:
        return "Windows (Base TTL 128)"
    return "Cisco/Solaris (Base TTL 255)"


def analyze_os_passive(target_ip, port=80):
    """Gửi gói SYN và phân tích phản hồi (TTL + TCP window) để đoán OS."""
    print(f"[*] Fingerprinting {target_ip}:{port}...")

    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    ans = sr1(pkt, timeout=2, verbose=0)

    if ans is None:
        print("[-] Không có phản hồi (Host down hoặc Filtered).")
        return None

    if not ans.haslayer(IP):
        print("[-] Không nhận được gói IP phản hồi.")
        return None

    ttl = ans[IP].ttl
    window = ans[TCP].window if ans.haslayer(TCP) else "N/A"
    print(f"Received -> TTL: {ttl} | Window Size: {window}")

    os_guess = guess_os_from_ttl(ttl)
    print(f"[+] Predicted OS: {os_guess}")
    return os_guess


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 os_fingerprint.py <IP> [port]")
        sys.exit(1)

    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    analyze_os_passive(sys.argv[1], port)
