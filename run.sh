#!/usr/bin/env bash
set -u

# ============================================================
# Network_Reconnaissance_Framework - One-click launcher
# Usage:
#   ./run.sh
#   ./run.sh 192.168.56.101
#   ./run.sh 192.168.56.101 192.168.56.0/24
# ============================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$PROJECT_DIR/venv/bin/python3"
MAIN="$PROJECT_DIR/main.py"
REQ="$PROJECT_DIR/requirements.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

die() { echo -e "${RED}[!] $*${NC}"; exit 1; }
ok() { echo -e "${GREEN}[+] $*${NC}"; }
info() { echo -e "${CYAN}[*] $*${NC}"; }
warn() { echo -e "${YELLOW}[!] $*${NC}"; }
pause_screen() { echo; read -r -p "Press Enter to continue..." _; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

cd "$PROJECT_DIR" || die "Cannot enter project directory: $PROJECT_DIR"
[[ -f "$MAIN" ]] || die "main.py not found in $PROJECT_DIR"

if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    command_exists sudo || die "sudo is not installed."
    SUDO="sudo"
fi

ensure_venv() {
    if [[ ! -x "$PYTHON" ]]; then
        warn "Python virtual environment not found."
        read -r -p "Create venv automatically? [Y/n]: " answer
        answer="${answer:-Y}"
        [[ "$answer" =~ ^[Yy]$ ]] || die "venv is required. Cancelled."
        command_exists python3 || die "python3 is not installed."
        info "Creating virtual environment..."
        python3 -m venv "$PROJECT_DIR/venv" || die "Could not create venv."
        ok "venv created."
    fi
}

ensure_dependencies() {
    if ! command_exists nmap; then
        warn "System command 'nmap' was not found."
        echo "Install with: sudo apt update && sudo apt install -y nmap"
        read -r -p "Continue anyway? [y/N]: " answer
        [[ "$answer" =~ ^[Yy]$ ]] || exit 1
    fi

    if [[ -f "$REQ" ]]; then
        if ! "$PYTHON" -c "import typer, rich, scapy" >/dev/null 2>&1; then
            info "Installing Python dependencies from requirements.txt..."
            "$PYTHON" -m pip install -r "$REQ" || die "Dependency installation failed."
        fi
    else
        if ! "$PYTHON" -c "import typer, rich, scapy" >/dev/null 2>&1; then
            info "Installing core packages..."
            "$PYTHON" -m pip install typer rich scapy || die "Core dependency installation failed."
        fi
    fi

    "$PYTHON" -c "import nmap" >/dev/null 2>&1 || {
        info "Installing python-nmap..."
        "$PYTHON" -m pip install python-nmap || die "Could not install python-nmap."
    }

    "$PYTHON" -c "import pysnmp" >/dev/null 2>&1 || {
        info "Installing pysnmp..."
        "$PYTHON" -m pip install pysnmp || die "Could not install pysnmp."
    }

    "$PYTHON" -c "import requests" >/dev/null 2>&1 || {
        info "Installing requests..."
        "$PYTHON" -m pip install requests || die "Could not install requests."
    }

    ok "Environment ready."
}

valid_ipv4() {
    local ip="$1"
    local IFS=.
    local -a octets
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

default_network_from_ip() {
    echo "$1" | awk -F. '{print $1"."$2"."$3".0/24"}'
}

get_target() {
    local supplied_ip="${1:-}"
    local supplied_network="${2:-}"

    if [[ -n "$supplied_ip" ]]; then
        TARGET="$supplied_ip"
    else
        while true; do
            read -r -p "Target IP [192.168.56.101]: " TARGET
            TARGET="${TARGET:-192.168.56.101}"
            valid_ipv4 "$TARGET" && break
            warn "Invalid IPv4 address."
        done
    fi

    valid_ipv4 "$TARGET" || die "Invalid target IP: $TARGET"

    if [[ -n "$supplied_network" ]]; then
        NETWORK="$supplied_network"
    else
        DEFAULT_NETWORK="$(default_network_from_ip "$TARGET")"
        read -r -p "Network CIDR [$DEFAULT_NETWORK]: " NETWORK
        NETWORK="${NETWORK:-$DEFAULT_NETWORK}"
    fi

    echo
    info "Target  : $TARGET"
    info "Network : $NETWORK"
}

run_main() {
    "$SUDO" "$PYTHON" "$MAIN" "$@"
}

run_command() {
    local title="$1"
    shift
    echo
    echo "============================================================"
    echo " $title"
    echo "============================================================"
    echo
    run_main "$@"
    local rc=$?
    echo
    if [[ $rc -eq 0 ]]; then
        ok "$title completed."
    else
        warn "$title exited with code $rc."
    fi
    return "$rc"
}

show_header() {
    clear 2>/dev/null || true
    echo -e "${BLUE}"
    echo "============================================================"
    echo "           NETWORK_RECONNAISSANCE_FRAMEWORK"
    echo "============================================================"
    echo -e "${NC}"
    echo " Project : $PROJECT_DIR"
    echo " Python  : $PYTHON"
    echo " Target  : $TARGET"
    echo " Network : $NETWORK"
    echo
}

menu() {
    while true; do
        show_header
        echo "  [1]  Full Recon"
        echo "  [2]  Host Discovery / Ping Sweep"
        echo "  [3]  ARP Discovery"
        echo "  [4]  Async Port Scan"
        echo "  [5]  Banner Grabbing"
        echo "  [6]  OS Fingerprint"
        echo "  [7]  Active Nmap Fingerprint"
        echo "  [8]  SMB Enumeration"
        echo "  [9]  SNMP Enumeration"
        echo "  [10] DNS Recon"
        echo "  [11] Web Recon / WAF"
        echo "  [12] CDP / LLDP Listener"
        echo "  [13] Shodan Recon"
        echo "  [14] Environment Check"
        echo "  [0]  Exit"
        echo
        read -r -p "Select option: " choice
        echo

        case "$choice" in
            1)
                run_command "FULL RECON" all "$TARGET" \
                    --network "$NETWORK" \
                    --ports "1-1024" \
                    --web-url "http://$TARGET" \
                    --community "public"
                pause_screen ;;
            2)
                run_command "HOST DISCOVERY" sweep "$NETWORK"
                pause_screen ;;
            3)
                run_command "ARP DISCOVERY" arp "$NETWORK"
                pause_screen ;;
            4)
                read -r -p "Port range [1-1024]: " PORTS
                PORTS="${PORTS:-1-1024}"
                run_command "ASYNC PORT SCAN" scan "$TARGET" --ports "$PORTS"
                pause_screen ;;
            5)
                read -r -p "Port [80]: " PORT
                PORT="${PORT:-80}"
                run_command "BANNER GRABBING" banner "$TARGET" "$PORT"
                pause_screen ;;
            6)
                run_command "OS FINGERPRINT" os "$TARGET"
                pause_screen ;;
            7)
                run_command "ACTIVE NMAP FINGERPRINT" active "$TARGET"
                pause_screen ;;
            8)
                run_command "SMB ENUMERATION" smb "$TARGET"
                pause_screen ;;
            9)
                read -r -p "SNMP community [public]: " COMMUNITY
                COMMUNITY="${COMMUNITY:-public}"
                run_command "SNMP ENUMERATION" snmp "$TARGET" --community "$COMMUNITY"
                pause_screen ;;
            10)
                read -r -p "Domain [zonetransfer.me]: " DOMAIN
                DOMAIN="${DOMAIN:-zonetransfer.me}"
                run_command "DNS RECON" dns "$DOMAIN"
                pause_screen ;;
            11)
                read -r -p "URL [http://$TARGET]: " WEB_URL
                WEB_URL="${WEB_URL:-http://$TARGET}"
                run_command "WEB RECON / WAF" web "$WEB_URL"
                pause_screen ;;
            12)
                warn "CDP/LLDP is a passive listener. Press Ctrl+C to stop it."
                read -r -p "Press Enter to start..." _
                run_main cdp
                pause_screen ;;
            13)
                warn "Shodan requires a configured API key/public target."
                run_command "SHODAN RECON" shodan "$TARGET"
                pause_screen ;;
            14)
                echo "---------------- Environment ----------------"
                echo "Project : $PROJECT_DIR"
                echo "Python  : $PYTHON"
                "$PYTHON" --version
                echo
                echo "Python packages:"
                "$PYTHON" -c '
import importlib.util
mods = ["typer", "rich", "scapy", "nmap", "pysnmp", "requests"]
for m in mods:
    print(f"  {m:10} {'OK' if importlib.util.find_spec(m) else 'MISSING'}")
'
                echo
                if command_exists nmap; then
                    echo "Nmap    : $(nmap --version | head -n 1)"
                else
                    echo "Nmap    : MISSING"
                fi
                pause_screen ;;
            0)
                echo "Bye."
                exit 0 ;;
            *)
                warn "Invalid option."
                sleep 1 ;;
        esac
    done
}

ensure_venv
ensure_dependencies
get_target "${1:-}" "${2:-}"
menu
