# ============================================================
# Network_Reconnaissance_Framework - Windows PowerShell Launcher
# Chạy với quyền Administrator để hỗ trợ gửi raw packet (Scapy / Npcap / Nmap)
# ============================================================

[CmdletBinding()]
param (
    [string]$Target = "192.168.56.101",
    [string]$Network = "192.168.56.0/24"
)

$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8 = "1"

$ProjectDir = $PSScriptRoot
if (-not $ProjectDir) { $ProjectDir = Get-Location }
Set-Location $ProjectDir

$MainScript = Join-Path $ProjectDir "main.py"
$ReqFile = Join-Path $ProjectDir "requirements.txt"

# Tìm Python phù hợp trên Windows
function Get-PythonPath {
    # 1. Ưu tiên venv của Windows nếu đã tạo
    $winVenv = Join-Path $ProjectDir ".venv\Scripts\python.exe"
    if (Test-Path $winVenv) { return $winVenv }

    # 2. Kiểm tra Python trong .venv_win
    $customVenv = Join-Path $ProjectDir ".venv_win\Scripts\python.exe"
    if (Test-Path $customVenv) { return $customVenv }

    # 3. Kiểm tra uv cpython
    $uvPy = "$env:APPDATA\uv\python\cpython-3.12-windows-x86_64-none\python.exe"
    if (Test-Path $uvPy) { return $uvPy }

    # 4. python trong PATH
    $pyCmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($pyCmd) { return $pyCmd.Source }

    return $null
}

$Python = Get-PythonPath

function Write-Header {
    Clear-Host
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "            NETWORK_RECONNAISSANCE_FRAMEWORK                " -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Target IP : " -NoNewline; Write-Host $Target -ForegroundColor Green
    Write-Host "  Network   : " -NoNewline; Write-Host $Network -ForegroundColor Green
    Write-Host "  Python    : " -NoNewline; Write-Host $Python -ForegroundColor Gray

    # Check Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Host "  Privilege : Administrator (Full raw socket/Npcap ready)" -ForegroundColor Green
    } else {
        Write-Host "  Privilege : Standard User (Chạy bằng 'Run as Administrator' nếu cần ARP/Ping Scapy)" -ForegroundColor Yellow
    }
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Show-Menu {
    Write-Host " 1. Chạy toàn bộ (Run All Recon)" -ForegroundColor White
    Write-Host " 2. Host Discovery (Ping Sweep)" -ForegroundColor White
    Write-Host " 3. ARP Scan (LAN Devices)" -ForegroundColor White
    Write-Host " 4. Async Port Scan" -ForegroundColor White
    Write-Host " 5. Banner Grabbing" -ForegroundColor White
    Write-Host " 6. OS Fingerprint (TTL/Window)" -ForegroundColor White
    Write-Host " 7. Nmap Active Fingerprint (OS + Service)" -ForegroundColor White
    Write-Host " 8. SMB Enumeration" -ForegroundColor White
    Write-Host " 9. SNMP Enumeration" -ForegroundColor White
    Write-Host "10. Web Recon / WAF Test" -ForegroundColor White
    Write-Host "11. DNS Recon (zonetransfer.me)" -ForegroundColor White
    Write-Host "12. CDP/LLDP Passive Listener" -ForegroundColor White
    Write-Host "13. Shodan Host Lookup" -ForegroundColor White
    Write-Host "14. Đổi Target IP / Network" -ForegroundColor Cyan
    Write-Host " 0. Thoát" -ForegroundColor Red
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
}

if (-not $Python) {
    Write-Host "[-] Không tìm thấy Python trên hệ thống!" -ForegroundColor Red
    Write-Host "[*] Vui lòng cài đặt Python (https://www.python.org/) hoặc uv." -ForegroundColor Yellow
    pause
    exit 1
}

while ($true) {
    Write-Header
    Show-Menu
    $choice = Read-Host "Chọn chức năng [0-14]"

    switch ($choice) {
        "1" {
            & $Python $MainScript all $Target -n $Network
            pause
        }
        "2" {
            & $Python $MainScript sweep $Network
            pause
        }
        "3" {
            & $Python $MainScript arp $Network
            pause
        }
        "4" {
            $p = Read-Host "Nhập dải port [mặc định: 1-1024 hoặc ví dụ 21,22,80]"
            if (-not $p) { $p = "1-1024" }
            & $Python $MainScript scan $Target -p $p
            pause
        }
        "5" {
            $p = Read-Host "Nhập port cần lấy banner [mặc định: 80]"
            if (-not $p) { $p = "80" }
            & $Python $MainScript banner $Target $p
            pause
        }
        "6" {
            & $Python $MainScript os $Target
            pause
        }
        "7" {
            & $Python $MainScript active $Target
            pause
        }
        "8" {
            & $Python $MainScript smb $Target
            pause
        }
        "9" {
            $comm = Read-Host "Nhập community string [mặc định: public]"
            if (-not $comm) { $comm = "public" }
            & $Python $MainScript snmp $Target -c $comm
            pause
        }
        "10" {
            $url = Read-Host "Nhập URL [mặc định: http://$Target]"
            if (-not $url) { $url = "http://$Target" }
            & $Python $MainScript web $url
            pause
        }
        "11" {
            $domain = Read-Host "Nhập domain kiểm thử [mặc định: zonetransfer.me]"
            if (-not $domain) { $domain = "zonetransfer.me" }
            & $Python $MainScript dns $domain
            pause
        }
        "12" {
            & $Python $MainScript cdp
            pause
        }
        "13" {
            $ip = Read-Host "Nhập public IP tra cứu [mặc định: 8.8.8.8]"
            if (-not $ip) { $ip = "8.8.8.8" }
            & $Python $MainScript shodan $ip
            pause
        }
        "14" {
            $t = Read-Host "Target IP mới [$Target]"
            if ($t) { $Target = $t }
            $n = Read-Host "Network CIDR mới [$Network]"
            if ($n) { $Network = $n }
        }
        "0" {
            Write-Host "Tạm biệt!" -ForegroundColor Green
            exit 0
        }
        Default {
            Write-Host "Lựa chọn không hợp lệ." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}
