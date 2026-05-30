#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  core/system.sh — OS validation, server profiling, firewall,
#                   service helpers, network utilities
#  Part of: singbox-manager  |  Author: Mehdi Hesami
# ═══════════════════════════════════════════════════════════════

# ── Pre-flight checks ─────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root."
        echo -e "  Run:  ${BOLD}sudo bash $0${NC}"
        exit 1
    fi
}

check_os() {
    if ! command -v apt-get &>/dev/null; then
        print_error "Only Ubuntu / Debian are supported."
        exit 1
    fi
    # Warn if Ubuntu < 20.04
    local ver
    ver=$(lsb_release -rs 2>/dev/null | cut -d. -f1 || echo "0")
    if (( ver > 0 && ver < 20 )); then
        print_warn "Ubuntu ${ver} detected. Ubuntu 20.04+ is recommended."
    fi
}

check_internet() {
    print_info "Checking internet connection..."
    local ok=false
    for host in github.com 8.8.8.8; do
        if curl -s --connect-timeout 5 "https://${host}" &>/dev/null; then
            ok=true; break
        fi
    done
    if ! $ok; then
        print_error "No internet access. GitHub must be reachable."
        exit 1
    fi
    print_success "Internet connection OK."
}

# ── Server profiling ──────────────────────────────────────────
# Populates SRV_* globals used by optimization and install modules.

SRV_RAM_MB=0
SRV_RAM_PROFILE=""    # low | mid | high
SRV_CPU_CORES=1
SRV_VIRT=""           # kvm | openvz | lxc | unknown
SRV_KERNEL=""
SRV_BBR_VERSION=0     # 1, 2, 3 or 0 (not available)
SRV_PUBLIC_IP=""
SRV_HOSTNAME=""
SRV_LOCATION=""       # country code from IP geolocation
SRV_BANDWIDTH_MBPS=0  # detected or estimated

probe_server() {
    print_info "Profiling server hardware..."

    # RAM
    SRV_RAM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)
    if   (( SRV_RAM_MB < 900  )); then SRV_RAM_PROFILE="low"
    elif (( SRV_RAM_MB < 3800 )); then SRV_RAM_PROFILE="mid"
    else                               SRV_RAM_PROFILE="high"
    fi

    # CPU
    SRV_CPU_CORES=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)

    # Virtualisation
    if   grep -qi "microsoft\|wsl" /proc/version 2>/dev/null;       then SRV_VIRT="wsl"
    elif [[ -f /proc/user_beancounters ]];                            then SRV_VIRT="openvz"
    elif grep -qi lxc /proc/1/environ 2>/dev/null;                   then SRV_VIRT="lxc"
    elif command -v systemd-detect-virt &>/dev/null; then
        SRV_VIRT=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    else
        SRV_VIRT="unknown"
    fi

    # Kernel version
    SRV_KERNEL=$(uname -r)

    # BBR version support
    local kernel_major kernel_minor
    kernel_major=$(uname -r | cut -d. -f1)
    kernel_minor=$(uname -r | cut -d. -f2)
    if   (( kernel_major > 6 || (kernel_major == 6 && kernel_minor >= 3) )); then SRV_BBR_VERSION=3
    elif (( kernel_major > 4 || (kernel_major == 4 && kernel_minor >= 9) )); then SRV_BBR_VERSION=1
    else                                                                          SRV_BBR_VERSION=0
    fi

    # Public IP (try IPv4, fall back to IPv6)
    SRV_PUBLIC_IP=$(get_public_ip)

    # Hostname
    SRV_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown")

    # Location via IP geo (lightweight, no API key required)
    SRV_LOCATION=$(curl -s --connect-timeout 5 "https://ipapi.co/${SRV_PUBLIC_IP}/country/" 2>/dev/null \
                   | tr -d '[:space:]' | head -c 5 || echo "XX")

    log_info "Server profile: RAM=${SRV_RAM_MB}MB profile=${SRV_RAM_PROFILE} cores=${SRV_CPU_CORES} virt=${SRV_VIRT} kernel=${SRV_KERNEL} BBR=${SRV_BBR_VERSION} ip=${SRV_PUBLIC_IP} loc=${SRV_LOCATION}"
}

# Estimate bandwidth from RAM profile if speedtest not available
# Returns Mbps ceiling for QUIC/Hysteria2 tuning
estimate_bandwidth() {
    case "$SRV_RAM_PROFILE" in
        low)  echo 100  ;;
        mid)  echo 500  ;;
        high) echo 1000 ;;
        *)    echo 200  ;;
    esac
}

# Compute Hysteria2 QUIC receive window based on bandwidth and RTT
# Usage: compute_quic_window <bandwidth_mbps> <rtt_ms>
compute_quic_window() {
    local bw_mbps="$1" rtt_ms="${2:-150}"  # default RTT 150ms (Iran ↔ Europe typical)
    # BDP = bandwidth × RTT  (in bytes)
    # bandwidth in bytes/s = bw_mbps × 1000000 / 8
    python3 -c "
bw = ${bw_mbps} * 1_000_000 / 8   # bytes/sec
rtt = ${rtt_ms} / 1000             # seconds
bdp = bw * rtt
# Window = 4× BDP, capped between 8MB and 128MB
win = max(8*1024*1024, min(128*1024*1024, int(bdp * 4)))
print(win)
" 2>/dev/null || echo "16777216"
}

# Compute sysctl buffer sizes based on RAM profile
compute_tcp_buffers() {
    case "$SRV_RAM_PROFILE" in
        low)
            echo "rmem_max=8388608 wmem_max=8388608 rmem_default=262144 wmem_default=262144"
            ;;
        mid)
            echo "rmem_max=33554432 wmem_max=33554432 rmem_default=524288 wmem_default=524288"
            ;;
        high)
            echo "rmem_max=134217728 wmem_max=134217728 rmem_default=1048576 wmem_default=1048576"
            ;;
    esac
}

# Summarize detected profile for display
show_server_profile() {
    print_header "Server Profile"
    echo -e "  IP Address   : ${CYAN}${SRV_PUBLIC_IP}${NC}"
    echo -e "  Location     : ${CYAN}${SRV_LOCATION}${NC}"
    echo -e "  Hostname     : ${DIM}${SRV_HOSTNAME}${NC}"
    echo -e "  RAM          : ${CYAN}${SRV_RAM_MB} MB${NC}  ${DIM}(profile: ${SRV_RAM_PROFILE})${NC}"
    echo -e "  CPU Cores    : ${CYAN}${SRV_CPU_CORES}${NC}"
    echo -e "  Kernel       : ${DIM}${SRV_KERNEL}${NC}"
    echo -e "  Virtualisation: ${DIM}${SRV_VIRT}${NC}"
    local bbr_label
    case "$SRV_BBR_VERSION" in
        3) bbr_label="${GREEN}BBRv3 supported${NC}" ;;
        1) bbr_label="${YELLOW}BBRv1 supported${NC}" ;;
        0) bbr_label="${DIM}not supported (kernel too old)${NC}" ;;
    esac
    echo -e "  BBR          : ${bbr_label}"
    echo ""
}

# ── Network utilities ─────────────────────────────────────────

get_public_ip() {
    local ip
    ip=$(curl -4 -s --connect-timeout 5 https://ifconfig.me 2>/dev/null) \
    || ip=$(curl -4 -s --connect-timeout 5 https://api.ipify.org 2>/dev/null) \
    || ip=$(curl -4 -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null) \
    || ip=$(curl -6 -s --connect-timeout 5 https://ifconfig.me 2>/dev/null) \
    || ip="unknown"
    echo "$ip"
}

# Measure RTT to a target (Iran-side test point for Iran-hosted servers)
measure_rtt() {
    local target="${1:-8.8.8.8}" count=5
    local avg
    avg=$(ping -c "$count" -q "$target" 2>/dev/null \
          | grep -oP 'avg.*?= \K[\d.]+' | head -1)
    echo "${avg:-150}"
}

# ── Firewall helpers ──────────────────────────────────────────

# open_port <port> <proto: tcp|udp|both>
open_port() {
    local port="$1" proto="${2:-tcp}"

    _ufw_open() {
        local p="$1" pr="$2"
        if [[ "$pr" == "both" ]]; then
            ufw allow "${p}/tcp" &>/dev/null
            ufw allow "${p}/udp" &>/dev/null
        else
            ufw allow "${p}/${pr}" &>/dev/null
        fi
    }

    _ipt_open() {
        local p="$1" pr="$2"
        local protos=("$pr")
        [[ "$pr" == "both" ]] && protos=("tcp" "udp")
        for pr2 in "${protos[@]}"; do
            iptables -I INPUT -p "$pr2" --dport "$p" -j ACCEPT 2>/dev/null || true
        done
    }

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        _ufw_open "$port" "$proto"
        print_success "Port ${port}/${proto} opened in UFW."
    elif command -v iptables &>/dev/null; then
        _ipt_open "$port" "$proto"
        print_info "Port ${port}/${proto} opened via iptables."
    else
        print_warn "No firewall tool found. Ensure port ${port} is accessible manually."
    fi
}

# close_port <port> <proto>
close_port() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw delete allow "${port}/${proto}" &>/dev/null || true
    elif command -v iptables &>/dev/null; then
        iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

# ── Service helpers ───────────────────────────────────────────

# service_start <name>
service_start() {
    local svc="$1"
    systemctl daemon-reload
    systemctl enable "$svc" &>/dev/null
    systemctl restart "$svc"
    sleep 2
    if systemctl is-active --quiet "$svc"; then
        print_success "Service '${svc}' is running."
        log_info "Service started: ${svc}"
    else
        print_error "Service '${svc}' failed to start."
        journalctl -u "$svc" --no-pager -n 20
        log_error "Service failed to start: ${svc}"
        return 1
    fi
}

# service_stop <name>
service_stop() {
    local svc="$1"
    systemctl stop "$svc" &>/dev/null || true
    print_info "Service '${svc}' stopped."
    log_info "Service stopped: ${svc}"
}

# service_status <name>  → prints colored status
service_status_line() {
    local svc="$1" label="${2:-$1}"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo -e "  $(pad_right 22 "$label") ${GREEN}●  running${NC}"
    else
        echo -e "  $(pad_right 22 "$label") ${DIM}○  stopped${NC}"
    fi
}

# ── Package helper ────────────────────────────────────────────

ensure_packages() {
    local -a missing=()
    for pkg in "$@"; do
        dpkg -l "$pkg" &>/dev/null || missing+=("$pkg")
    done
    if (( ${#missing[@]} > 0 )); then
        print_info "Installing: ${missing[*]}"
        apt-get update -qq &>/dev/null
        apt-get install -y "${missing[@]}" &>/dev/null || {
            print_error "Failed to install: ${missing[*]}"
            return 1
        }
    fi
}

# ── Version fetchers ──────────────────────────────────────────

# fetch_singbox_version [stable|prerelease]  → sets SINGBOX_VERSION
fetch_singbox_version() {
    local type="${1:-stable}" location ver
    if [[ "$type" == "prerelease" ]]; then
        ver=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" \
              | grep '"tag_name"' | head -1 | grep -oP '"v\K[0-9][^"]+' | head -1)
        if [[ -z "$ver" ]]; then
            ver=$(curl -s "https://github.com/SagerNet/sing-box/releases" \
                  | grep -oP 'tag/v\K[0-9]+\.[0-9]+\.[0-9]+-[^"]+' | head -1)
        fi
    else
        location=$(curl -sI "https://github.com/SagerNet/sing-box/releases/latest" \
                   | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
        ver=$(echo "$location" | grep -oP 'tag/v\K[0-9][^/\s]+' | head -1)
        if [[ -z "$ver" ]]; then
            ver=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
                  | grep '"tag_name"' | grep -oP '"v\K[0-9][^"]+' | head -1)
        fi
    fi
    SINGBOX_VERSION="$ver"
    [[ -z "$ver" ]] && { print_error "Could not fetch sing-box version."; return 1; }
    print_info "sing-box version: ${SINGBOX_VERSION}"
}

# fetch_hysteria2_version  → sets HY2_VERSION
fetch_hysteria2_version() {
    local location ver
    location=$(curl -sI "https://github.com/apernet/hysteria/releases/latest" \
               | grep -i '^location:' | tr -d '\r' | awk '{print $2}')
    ver=$(echo "$location" | grep -oP 'app/v\K[0-9][^/\s]+' | head -1)
    if [[ -z "$ver" ]]; then
        ver=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" \
              | grep '"tag_name"' | grep -oP 'app/v\K[0-9][^"]+' | head -1)
    fi
    if [[ -z "$ver" ]]; then
        ver=$(curl -s "https://github.com/apernet/hysteria/releases" \
              | grep -oP 'app/v\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi
    HY2_VERSION="$ver"
    [[ -z "$ver" ]] && { print_error "Could not fetch Hysteria2 version."; return 1; }
    print_info "Hysteria2 version: ${HY2_VERSION}"
}

# ── Arch detection ────────────────────────────────────────────
get_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        armv7l)  echo "armv7" ;;
        *)       echo "amd64" ;;  # fallback
    esac
}

# ── UUID / keypair ────────────────────────────────────────────
generate_uuid() {
    if [[ -x "$SINGBOX_BIN" ]]; then
        "$SINGBOX_BIN" generate uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid
    else
        cat /proc/sys/kernel/random/uuid
    fi
}

generate_keypair() {
    [[ -x "$SINGBOX_BIN" ]] && "$SINGBOX_BIN" generate reality-keypair 2>/dev/null || {
        print_error "sing-box binary not found. Install sing-box first."
        return 1
    }
}

generate_token() {
    # 32-char URL-safe random token for subscription URLs
    python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null \
    || cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32
}
