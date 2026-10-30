import socket
import sys

HTTP_PORTS = (80, 8080)


def get_service_banner(ip: str, port: int, timeout: int = 2) -> str:
    """Kết nối tới ip:port và lấy banner dịch vụ (không in gì ra màn hình)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Một số dịch vụ (như HTTP) cần gửi request trước mới có phản hồi
            if port in HTTP_PORTS:
                msg = (
                    f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                s.sendall(msg.encode())

            banner = s.recv(1024)

        return banner.decode("utf-8", errors="ignore").strip()

    except socket.timeout:
        return "TIMEOUT: Không nhận được phản hồi."
    except ConnectionRefusedError:
        return "CLOSED: Cổng đóng hoặc từ chối kết nối."
    except Exception as e:
        return f"ERROR: {e}"


if __name__ == "__main__":
    # Usage: python3 banner_grabber.py [ip] [port ...]
    target_ip = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.101"
    target_ports = (
        [int(p) for p in sys.argv[2:]] if len(sys.argv) > 2 else [21, 22, 23, 80]
    )

    print(f"--- Bắt đầu Banner Grabbing trên {target_ip} ---")
    for p in target_ports:
        print(f"[*] Đang kết nối đến {target_ip}:{p}...")
        print(f"[Port {p}]: {get_service_banner(target_ip, p)}")
