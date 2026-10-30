import asyncio
import sys
import time

from rich.console import Console
from rich.markup import escape

console = Console()


async def scan_port_async(ip: str, port: int, timeout: float = 1.0,
                          verbose: bool = False):
    """
    Quét một cổng bằng asyncio.open_connection (tương đương TCP Connect Scan).

    Trả về số cổng nếu mở, ngược lại trả về None.
    Hàm không in gì trừ khi verbose=True (khi đó sẽ lấy thêm banner sơ bộ).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout
        )
    except (asyncio.TimeoutError, OSError):
        # Cổng đóng, bị lọc hoặc không tới được host
        return None

    if verbose:
        banner = ""
        try:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(100), timeout=0.5)
            lines = data.decode("utf-8", errors="ignore").strip().splitlines()
            banner = lines[0] if lines else ""
        except Exception:
            banner = ""
        console.print(
            f"[green][+] Port {port} is OPEN - Service: "
            f"{escape(banner) or 'Unknown'}[/green]"
        )

    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass

    return port


async def scan_ports(ip: str, ports, timeout: float = 1.0,
                     concurrency: int = 500, verbose: bool = False):
    """
    Quét danh sách cổng với giới hạn số kết nối đồng thời (Semaphore)
    để không vượt quá giới hạn file descriptor của hệ điều hành.
    """
    sem = asyncio.Semaphore(concurrency)

    async def bounded(port):
        async with sem:
            return await scan_port_async(ip, port, timeout, verbose)

    results = await asyncio.gather(*(bounded(p) for p in ports))
    return sorted(p for p in results if p is not None)


async def run_scan(target_ip, start_port, end_port):
    print(f"[*] Starting Async Scan on {target_ip} "
          f"from port {start_port} to {end_port}")
    start_time = time.time()

    open_ports = await scan_ports(
        target_ip, range(start_port, end_port + 1), verbose=True
    )

    duration = time.time() - start_time
    print(f"\nScanning completed in {duration:.2f} seconds")
    print(f"Open ports: {open_ports}")


if __name__ == "__main__":
    # Usage: python3 async_scanner.py [target] [start_port] [end_port]
    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.101"
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 1024

    try:
        asyncio.run(run_scan(target, start, end))
    except KeyboardInterrupt:
        print("\nUser aborted.")
