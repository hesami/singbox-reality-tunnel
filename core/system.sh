#!/usr/bin/env bash
# Minimal system helpers used by the production stack only.

check_root(){ [[ $EUID -eq 0 ]] || { print_error "Run as root: sudo bash manager.sh"; exit 1; }; }
check_os(){ command -v apt-get >/dev/null 2>&1 || { print_error "Only Ubuntu/Debian are supported."; exit 1; }; }
check_internet(){
    print_info "Checking internet connection..."
    curl -fsS --connect-timeout 6 https://github.com >/dev/null 2>&1 || { print_error "Internet/GitHub is not reachable."; return 1; }
    print_success "Internet connection OK."
}
ensure_packages(){
    local missing=() p
    for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
    ((${#missing[@]}==0)) && return 0
    print_info "Installing: ${missing[*]}"
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y "${missing[@]}" >/dev/null 2>&1 || { print_error "Package installation failed: ${missing[*]}"; return 1; }
}
get_public_ip(){
    local u ip
    for u in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
        ip=$(curl -4fsS --connect-timeout 5 "$u" 2>/dev/null | tr -d '[:space:]' || true)
        [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && { echo "$ip"; return 0; }
    done
    echo unknown; return 1
}
open_port(){
    local port="$1" proto="${2:-tcp}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
        print_info "Port ${port}/${proto} allowed in UFW."
    elif command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
        print_info "Port ${port}/${proto} allowed via iptables."
    else
        print_warn "No firewall manager found; verify port ${port}/${proto} manually."
    fi
}
service_status_line(){
    local svc="$1" label="${2:-$1}"
    if systemctl is-active --quiet "$svc" 2>/dev/null; then echo -e "  $(pad_right 28 "$label") ${GREEN}● running${NC}"; else echo -e "  $(pad_right 28 "$label") ${DIM}○ stopped${NC}"; fi
}
generate_uuid(){ command -v uuidgen >/dev/null 2>&1 && uuidgen | tr 'A-Z' 'a-z' || cat /proc/sys/kernel/random/uuid; }
generate_token(){ python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
}
valid_port(){ [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1>=1 && 10#$1<=65535)); }
valid_ipv4(){ [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }
