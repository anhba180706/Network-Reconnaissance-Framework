#!/usr/bin/env python3

import sys

import requests

# Header đặc trưng của một số WAF/CDN (tên header viết thường)
WAF_HEADER_SIGNATURES = {
    "Cloudflare": ("cf-ray",),
    "AWS CloudFront/ELB": ("x-amz-cf-id", "x-amzn-requestid"),
    "Akamai": ("x-akamai-transformed",),
    "Sucuri": ("x-sucuri-id",),
    "Imperva": ("x-iinfo",),
}

# Giá trị header Server gợi ý WAF/CDN
WAF_SERVER_HINTS = {
    "cloudflare": "Cloudflare",
    "awselb": "AWS ELB",
    "cloudfront": "AWS CloudFront",
    "akamaighost": "Akamai",
    "sucuri": "Sucuri",
}

BLOCK_STATUS_CODES = (403, 406, 429, 501)


def detect_waf(headers):
    """Trả về danh sách WAF/CDN nghi ngờ dựa trên response headers."""
    found = []
    header_names = {name.lower() for name in headers}

    for waf, names in WAF_HEADER_SIGNATURES.items():
        if any(n in header_names for n in names):
            found.append(waf)

    server = headers.get("Server", "").lower()
    for hint, waf in WAF_SERVER_HINTS.items():
        if hint in server and waf not in found:
            found.append(waf)

    return found


def web_recon(url):
    print(f"[*] Web Reconnaissance: {url}")

    try:
        # Request bình thường
        print("\n[*] Normal Request")
        normal = requests.get(url, timeout=5)

        print(f"[+] Status Code: {normal.status_code}")
        print(f"[+] Server: {normal.headers.get('Server', 'N/A')}")
        print(f"[+] X-Powered-By: {normal.headers.get('X-Powered-By', 'N/A')}")

        # Request với XSS test payload (requests tự encode & xử lý query có sẵn)
        payload = "<script>alert('XSS')</script>"

        print("\n[*] Testing WAF with XSS payload")
        malicious = requests.get(url, params={"q": payload}, timeout=5)

        print(f"[+] Status Code: {malicious.status_code}")

        wafs = detect_waf(malicious.headers) or detect_waf(normal.headers)
        if wafs:
            print(f"[+] Possible WAF/CDN: {', '.join(wafs)}")
        else:
            print("[-] No obvious WAF signature in headers")

        if (
            malicious.status_code in BLOCK_STATUS_CODES
            and normal.status_code not in BLOCK_STATUS_CODES
        ):
            print(
                "[!] Payload bị chặn (status khác request thường) "
                "-> có thể có WAF/IPS phía trước."
            )

    except requests.RequestException as e:
        print(f"[-] Request error: {e}")


if __name__ == "__main__":
    web_recon(sys.argv[1] if len(sys.argv) > 1 else "http://192.168.56.101")
