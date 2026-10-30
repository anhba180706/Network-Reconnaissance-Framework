#!/usr/bin/env python3
"""
Network_Reconnaissance_Framework - CLI
Tổng hợp các module trong lab Network Reconnaissance.

Mục tiêu lab:
    Kali Linux  <->  VMnet1  <->  Metasploitable 2
    Ví dụ target: 192.168.56.101

Chạy:
    sudo python3 main.py --help
"""

import asyncio
import sys

if sys.platform == "win32":
    # Đảm bảo console Windows in tiếng Việt UTF-8 không bị lỗi charmap
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

# Các module recon được import trễ (lazy) bên trong từng command,
# nên thiếu một thư viện tùy chọn (ví dụ shodan) cũng không làm hỏng cả CLI.

app = typer.Typer(
    name="recon",
    help="Automated Network Reconnaissance CLI for the authorized lab.",
    no_args_is_help=True,
)

console = Console()


def parse_ports(ports: str):
    """Chuyển '1-1024' hoặc '22,80,443' thành list port. Ném ValueError nếu sai."""
    if "-" in ports:
        start, end = map(int, ports.split("-", 1))
        if not (1 <= start <= end <= 65535):
            raise ValueError("port range")
        return list(range(start, end + 1))

    port_list = sorted({int(p.strip()) for p in ports.split(",") if p.strip()})
    if not port_list or any(p < 1 or p > 65535 for p in port_list):
        raise ValueError("port list")
    return port_list


async def _snmp_queries(target, community, labels=False):
    from snmp_enum import snmp_get, snmp_walk

    if labels:
        console.print("[bold blue][+] System Description[/bold blue]")
    await snmp_get(target, community, "1.3.6.1.2.1.1.1.0")

    if labels:
        console.print("\n[bold blue][+] System Name[/bold blue]")
    await snmp_get(target, community, "1.3.6.1.2.1.1.5.0")

    if labels:
        console.print("\n[bold blue][+] Running Processes[/bold blue]")
    await snmp_walk(target, community, "1.3.6.1.2.1.25.4.2.1.2")


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="IP hoặc hostname mục tiêu"),
    ports: str = typer.Option(
        "1-1024",
        "--ports",
        "-p",
        help="Dải port, ví dụ: 1-1024 hoặc 22,80,443",
    ),
):
    """Async TCP Connect Scan (kèm banner cho các cổng mở)."""
    from async_scanner import scan_ports
    from banner_grabber import get_service_banner

    console.print(f"[bold blue][*] Async Port Scan: {escape(target)}[/bold blue]")

    try:
        port_list = parse_ports(ports)
    except ValueError:
        console.print(
            "[bold red][-] Port format không hợp lệ. "
            "Dùng 1-1024 hoặc 22,80,443.[/bold red]"
        )
        raise typer.Exit(code=1)

    try:
        open_ports = asyncio.run(scan_ports(target, port_list))
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Scan bị dừng bởi người dùng.[/yellow]")
        raise typer.Exit(code=130)

    table = Table(title=f"Open Ports - {target}")
    table.add_column("Port", style="cyan")
    table.add_column("State", style="green")
    table.add_column("Banner", style="magenta")

    for port in open_ports:
        banner = get_service_banner(target, port, timeout=2)
        banner = banner.replace("\n", " ").replace("\r", " ")[:100]
        table.add_row(str(port), "OPEN", escape(banner) or "Unknown")

    console.print(table)
    console.print(
        f"[bold green][+] Hoàn tất. Open ports: {open_ports}[/bold green]"
    )


@app.command("sweep")
def sweep(
    network: str = typer.Argument(
        ...,
        help="CIDR network, ví dụ 192.168.56.0/24",
    ),
):
    """Ping sweep bằng ICMP + TCP SYN probe."""
    from ping_sweep import sweep_network

    console.print(f"[bold blue][*] Host Discovery: {escape(network)}[/bold blue]")
    sweep_network(network)


@app.command("arp")
def arp(
    network: str = typer.Argument(
        ...,
        help="CIDR network, ví dụ 192.168.56.0/24",
    ),
    iface: str = typer.Option(
        None,
        "--iface",
        "-i",
        help="Tên network interface (để trống sẽ tự nhận diện)",
    ),
):
    """ARP discovery trong LAN."""
    from arp_scan import arp_network_scan

    console.print(f"[bold blue][*] ARP Scan: {escape(network)}[/bold blue]")

    try:
        devices = arp_network_scan(network, iface=iface)
    except PermissionError:
        console.print(
            "[bold red][-] Cần chạy bằng quyền Administrator (Windows) "
            "hoặc sudo (Linux) để gửi raw packet.[/bold red]"
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        console.print(f"[bold red][-] ARP error: {escape(str(exc))}[/bold red]")
        raise typer.Exit(code=1)

    table = Table(title=f"ARP Results - {network}")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="green")

    for device in devices:
        table.add_row(device["ip"], device["mac"])

    console.print(table)


@app.command("banner")
def banner(
    target: str = typer.Argument(..., help="IP/hostname"),
    port: int = typer.Argument(..., help="TCP port"),
):
    """Banner grabbing một TCP service."""
    from banner_grabber import get_service_banner

    result = get_service_banner(target, port)
    console.print(f"\n[bold cyan]Banner {escape(target)}:{port}[/bold cyan]")
    console.print(escape(result))


@app.command("os")
def os_fingerprint(
    target: str = typer.Argument(..., help="IP mục tiêu"),
):
    """Đoán OS đơn giản bằng TTL + TCP window (gửi SYN tới port 80)."""
    from os_fingerprint import analyze_os_passive

    analyze_os_passive(target)


@app.command("active")
def active(
    target: str = typer.Argument(..., help="IP mục tiêu"),
):
    """Nmap service/version + OS detection."""
    from active_fingerprint import advanced_nmap_scan

    advanced_nmap_scan(target)


@app.command("smb")
def smb(
    target: str = typer.Argument(..., help="IP SMB server"),
):
    """SMB enumeration + Null Session/Guest."""
    from smb_enum import enum_smb

    enum_smb(target)


@app.command("snmp")
def snmp(
    target: str = typer.Argument(..., help="IP SNMP server"),
    community: str = typer.Option(
        "public",
        "--community",
        "-c",
        help="SNMP community string",
    ),
):
    """SNMP GET + WALK cho System và Running Processes."""
    asyncio.run(_snmp_queries(target, community, labels=True))


@app.command("dns")
def dns(
    domain: str = typer.Argument(
        ...,
        help="Domain được phép kiểm thử DNS/AXFR",
    ),
):
    """DNS NS enumeration + thử AXFR."""
    from dns_recon import dns_recon

    dns_recon(domain)


@app.command("web")
def web(
    url: str = typer.Argument(
        ...,
        help="URL web được phép kiểm thử, ví dụ http://192.168.56.101",
    ),
):
    """HTTP headers + WAF heuristic + XSS test payload."""
    from web_waf_detect import web_recon

    web_recon(url)


@app.command("cdp")
def cdp(
    iface: str = typer.Option(
        None,
        "--iface",
        "-i",
        help="Tên network interface (để trống sẽ tự nhận diện)",
    ),
):
    """
    Passive CDP/LLDP listener.
    Nhấn Ctrl+C để dừng.
    """
    from cdp_lldp_enum import main as cdp_lldp_main

    console.print(
        "[bold yellow][*] Passive CDP/LLDP listener. "
        "Nhấn Ctrl+C để dừng.[/bold yellow]"
    )
    try:
        cdp_lldp_main(iface=iface)
    except KeyboardInterrupt:
        console.print("\n[green][+] Listener stopped.[/green]")


@app.command("shodan")
def shodan(
    target: str = typer.Argument(..., help="Public IP được phép tra cứu"),
):
    """
    Shodan host lookup (cần biến môi trường SHODAN_API_KEY).
    IP private như 192.168.56.101 không có dữ liệu trên Shodan.
    """
    from shodan_recon import query_shodan_host

    query_shodan_host(target)


@app.command("all")
def all_recon(
    target: str = typer.Argument(
        ...,
        help="IP mục tiêu trong lab, ví dụ 192.168.56.101",
    ),
    network: str = typer.Option(
        "192.168.56.0/24",
        "--network",
        "-n",
        help="LAN CIDR cho host discovery/ARP",
    ),
    ports: str = typer.Option(
        "1-1024",
        "--ports",
        "-p",
        help="Port range cho async scan",
    ),
    web_url: str = typer.Option(
        "",
        "--web-url",
        help="URL HTTP; mặc định http://<target>",
    ),
    community: str = typer.Option(
        "public",
        "--community",
        "-c",
        help="SNMP community",
    ),
    iface: str = typer.Option(
        None,
        "--iface",
        "-i",
        help="Tên network interface cho ARP (để trống sẽ tự nhận diện)",
    ),
):
    """
    Chạy chuỗi reconnaissance chính cho target trong lab.

    Không tự chạy CDP/LLDP và Shodan vì:
      - CDP/LLDP là passive listener và sẽ block cho tới Ctrl+C.
      - Shodan cần API key và dữ liệu public Internet.
    """
    from active_fingerprint import advanced_nmap_scan
    from arp_scan import arp_network_scan
    from async_scanner import scan_ports
    from banner_grabber import get_service_banner
    from os_fingerprint import analyze_os_passive
    from ping_sweep import sweep_network
    from smb_enum import enum_smb
    from web_waf_detect import web_recon

    console.rule("[bold blue]RECONNAISSANCE FRAMEWORK[/bold blue]")
    console.print(f"[bold]Target:[/bold] {escape(target)}")
    console.print(f"[bold]Network:[/bold] {escape(network)}")

    # 1. Host discovery
    console.rule("[cyan]1. Host Discovery[/cyan]")
    sweep_network(network)

    # 2. ARP
    console.rule("[cyan]2. ARP Discovery[/cyan]")
    try:
        devices = arp_network_scan(network, iface=iface)
        table = Table(title="ARP Results")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="green")
        for device in devices:
            table.add_row(device["ip"], device["mac"])
        console.print(table)
    except Exception as exc:
        console.print(f"[yellow][!] ARP skipped/error: {escape(str(exc))}[/yellow]")

    # 3. Async port scan
    console.rule("[cyan]3. Async Port Scan[/cyan]")
    try:
        port_list = parse_ports(ports)
        open_ports = asyncio.run(scan_ports(target, port_list))
        console.print(f"[+] Open ports: {open_ports}")
    except Exception as exc:
        console.print(f"[yellow][!] Async scan error: {escape(str(exc))}[/yellow]")
        open_ports = []

    # 4. Banner
    console.rule("[cyan]4. Banner Grabbing[/cyan]")
    for port in open_ports:
        result = get_service_banner(target, port, timeout=2)
        console.print(escape(f"[Port {port}] {result[:200]}"))

    # 5. OS fingerprint
    console.rule("[cyan]5. OS Fingerprint[/cyan]")
    analyze_os_passive(target)

    # 6. Nmap active fingerprint
    console.rule("[cyan]6. Active Fingerprint[/cyan]")
    advanced_nmap_scan(target)

    # 7. SMB
    console.rule("[cyan]7. SMB Enumeration[/cyan]")
    enum_smb(target)

    # 8. SNMP
    console.rule("[cyan]8. SNMP Enumeration[/cyan]")
    try:
        asyncio.run(_snmp_queries(target, community))
    except Exception as exc:
        console.print(f"[yellow][!] SNMP error: {escape(str(exc))}[/yellow]")

    # 9. Web
    console.rule("[cyan]9. Web Recon / WAF[/cyan]")
    web_recon(web_url or f"http://{target}")

    console.rule("[bold green]RECON COMPLETE[/bold green]")
    console.print(
        "[green][+] Hoàn tất các module active chính. "
        "CDP/LLDP và Shodan được để thành command riêng.[/green]"
    )


if __name__ == "__main__":
    app()
