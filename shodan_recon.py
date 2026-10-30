#!/usr/bin/env python3

import os
import sys

import shodan
from dotenv import load_dotenv

# Đọc SHODAN_API_KEY từ file .env (nếu có) hoặc biến môi trường
load_dotenv()


def query_shodan_host(ip):
    api_key = os.environ.get("SHODAN_API_KEY", "").strip()

    if not api_key or api_key == "YOUR_API_KEY_HERE":
        print(
            "[-] Thiếu SHODAN_API_KEY. Tạo file .env từ .env.example "
            "hoặc chạy: export SHODAN_API_KEY=your_key"
        )
        return

    api = shodan.Shodan(api_key)

    try:
        host = api.host(ip)

        print(f"\n[*] Thông tin cho {ip}:")
        print(f"    OS: {host.get('os', 'n/a')}")
        print(f"    ISP: {host.get('isp', 'n/a')}")
        print(f"    Ports: {host.get('ports', [])}")

        print("\n[*] Services:")

        for item in host.get("data", []):
            if "product" in item:
                print(
                    f"    Port {item['port']}: "
                    f"{item['product']} "
                    f"{item.get('version', '')}"
                )

    except shodan.APIError as e:
        print(f"[-] Shodan API Error: {e}")


if __name__ == "__main__":
    # Shodan chỉ có dữ liệu cho IP public (IP lab sẽ không có)
    query_shodan_host(sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8")