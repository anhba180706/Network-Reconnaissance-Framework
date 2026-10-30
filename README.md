# Network_Reconnaissance_Framework (CLI)

Bộ công cụ tự động hóa do thám mạng (**Automated Network Reconnaissance CLI**) viết bằng Python, phục vụ mục đích học tập và kiểm thử an toàn thông tin trong môi trường phòng lab (ví dụ: máy tấn công Kali Linux kết nối tới máy chủ mục tiêu Metasploitable qua dải mạng LAN ảo).

Hỗ trợ chạy trên cả **Windows** (PowerShell / CMD) và **Linux** (Kali / Ubuntu).

---

## 🚀 Tính năng chính

| Module | Mô tả |
| :--- | :--- |
| **Ping Sweep** (`ping_sweep.py`) | Dò tìm máy sống (Host Discovery) bằng ICMP Echo Request kết hợp TCP SYN probe (port 80/443). |
| **ARP Scan** (`arp_scan.py`) | Quét tìm thiết bị trong mạng LAN ở Layer 2, lấy danh sách IP và MAC. |
| **Async Port Scan** (`async_scanner.py`) | Quét cổng TCP bất đồng bộ (`asyncio`), giới hạn số kết nối đồng thời bằng Semaphore. |
| **Banner Grabbing** (`banner_grabber.py`) | Kết nối socket và lấy banner dịch vụ (HTTP, SSH, FTP, Telnet...) để xác định phiên bản. |
| **OS Fingerprint (TTL/Window)** (`os_fingerprint.py`) | Gửi TCP SYN tới một cổng mở, đoán họ hệ điều hành từ TTL và TCP Window Size của phản hồi. |
| **Active Fingerprint** (`active_fingerprint.py`) | Dùng Nmap (`-sV -O`) để phát hiện phiên bản dịch vụ và hệ điều hành chi tiết. |
| **SMB Enumeration** (`smb_enum.py`) | Liệt kê Shares và kiểm tra xác thực Null Session / Guest trên SMB. |
| **SNMP Enumeration** (`snmp_enum.py`) | Truy vấn SNMP OID (System Description, Hostname, Running Processes) bằng community string. |
| **DNS Recon** (`dns_recon.py`) | Liệt kê Name Servers (NS) và thử Zone Transfer (AXFR). |
| **Web & WAF Detect** (`web_waf_detect.py`) | Đọc HTTP headers, nhận diện WAF/CDN phổ biến và gửi thử một XSS payload để xem có bị chặn không. |
| **CDP/LLDP Listener** (`cdp_lldp_enum.py`) | Lắng nghe thụ động gói CDP (Cisco Discovery Protocol) và LLDP để lấy thông tin thiết bị lân cận. |
| **Shodan Recon** (`shodan_recon.py`) | Tra cứu thông tin IP công cộng qua Shodan API (cần `SHODAN_API_KEY`). |

---

## 📁 Cấu trúc thư mục

```text
Network_Reconnaissance_Framework/
├── main.py                  # CLI điều khiển trung tâm (Typer + Rich)
├── ping_sweep.py            # Ping Sweep (ICMP & TCP SYN)
├── arp_scan.py              # ARP Scan Layer 2
├── async_scanner.py         # Async TCP Port Scanner
├── banner_grabber.py        # Banner Grabbing
├── os_fingerprint.py        # OS fingerprint bằng TTL/Window
├── active_fingerprint.py    # Nmap active fingerprint
├── smb_enum.py              # SMB Enumeration
├── snmp_enum.py             # SNMP Enumeration
├── dns_recon.py             # DNS Recon & Zone Transfer
├── web_waf_detect.py        # Web header & WAF detection
├── cdp_lldp_enum.py         # CDP/LLDP passive listener
├── shodan_recon.py          # Shodan host lookup
├── run.bat                  # Launcher cho Windows (CMD)
├── run.ps1                  # Launcher tương tác cho Windows (PowerShell)
├── run.sh                   # Launcher tương tác cho Linux / Kali
├── requirements.txt         # Thư viện Python phụ thuộc
├── .env.example             # Mẫu biến môi trường (Shodan API key)
├── LICENSE                  # MIT License
└── README.md
```

---

## 🛠️ Yêu cầu hệ thống

1. **Python** 3.10 trở lên.
2. **Quyền hạn**:
   - **Windows**: chạy terminal với quyền **Administrator** (để Scapy gửi raw packet).
   - **Linux**: chạy với `sudo`.
3. **Phần mềm bổ trợ**:
   - **Nmap** đã cài đặt và có trong `PATH`.
   - **Npcap** (Windows) để Scapy bắt và gửi raw packet.

---

## ⚡ Cài đặt & khởi chạy

### 🪟 Windows

1. Mở PowerShell bằng quyền Administrator.
2. Tạo môi trường ảo và cài thư viện:
   ```powershell
   cd Network_Reconnaissance_Framework
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
3. Khởi chạy:
   ```powershell
   .\run.ps1                      # menu tương tác (hoặc nhấp đúp run.bat)
   python main.py --help
   python main.py all 192.168.56.101 -n 192.168.56.0/24
   ```

### 🐧 Linux / Kali Linux

```bash
chmod +x run.sh
sudo ./run.sh                     # tự tạo venv, cài thư viện và mở menu
```

Hoặc chạy trực tiếp:

```bash
sudo python3 main.py all 192.168.56.101 -n 192.168.56.0/24
```

### Ví dụ lệnh riêng lẻ

```bash
sudo python3 main.py sweep 192.168.56.0/24
sudo python3 main.py scan 192.168.56.101 -p 1-1024
python3 main.py banner 192.168.56.101 21
sudo python3 main.py active 192.168.56.101
sudo python3 main.py cdp -i eth0
```

---

## 🔑 Cấu hình Shodan

Module Shodan đọc API key từ biến môi trường `SHODAN_API_KEY` (không bao giờ ghi key vào code).

```bash
cp .env.example .env              # rồi điền key thật vào .env
# hoặc: export SHODAN_API_KEY=your_key
python3 main.py shodan 8.8.8.8
```

`.env` đã nằm trong `.gitignore`. Lưu ý Shodan chỉ có dữ liệu cho **IP public**, không tra cứu được IP lab như `192.168.56.101`.

---

## ⚠️ Tuyên bố miễn trừ trách nhiệm (Disclaimer)

Dự án chỉ được thiết kế và sử dụng cho mục đích **nghiên cứu học tập** và kiểm thử trong các hệ thống lab được ủy quyền. Quét hoặc tấn công hệ thống mà không có sự cho phép trước bằng văn bản là vi phạm pháp luật. Tác giả không chịu trách nhiệm cho việc sử dụng sai mục đích.

## 📄 Giấy phép

Phân phối theo giấy phép MIT, xem file [LICENSE](LICENSE).
