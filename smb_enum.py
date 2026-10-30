#!/usr/bin/env python3

import sys

from impacket.smbconnection import SMBConnection

DEFAULT_TARGET = "192.168.56.101"


def enum_smb(target_ip):
    print(f"[*] Enumerating SMB on {target_ip}...")

    try:
        conn = SMBConnection(target_ip, target_ip)

        print("[*] Trying Null Session...")

        try:
            conn.login("", "")
            print("[+] Null Session Login thành công!")

        except Exception:
            print("[-] Null Session thất bại. Thử Guest...")

            try:
                conn.login("Guest", "")
                print("[+] Guest Login thành công!")

            except Exception:
                print("[-] Không thể truy cập SMB không cần mật khẩu.")
                return

        print("\n[*] Danh sách Shares:")

        shares = conn.listShares()

        for share in shares:
            share_name = share["shi1_netname"].rstrip("\x00")
            share_remark = share["shi1_remark"].rstrip("\x00")

            print(
                f"    Name: {share_name:<15} | "
                f"Remark: {share_remark}"
            )

        print(f"\n[*] Server OS: {conn.getServerOS()}")

        conn.logoff()

    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    enum_smb(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET)
