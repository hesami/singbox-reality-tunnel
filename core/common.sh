#!/usr/bin/env bash
# Shared UI helpers for Iran-Turkey Gateway Manager.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

MANAGER_VERSION="4.3.0"
MANAGER_AUTHOR="Mehdi Hesami"
BASE_DIR="/etc/singbox-manager"
DATA_DIR="${BASE_DIR}/data"
LOG_DIR="/var/log/singbox-manager"
MANAGER_LOG="${LOG_DIR}/manager.log"

print_banner() {
    clear 2>/dev/null || true
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    printf "  ║   Iran ↔ Turkey Gateway Manager  v%-13s║\n" "$MANAGER_VERSION"
    echo "  ║   Reverse SSH • Customer Gateway • User Control  ║"
    printf "  ║   %-47s ║\n" "Author: ${MANAGER_AUTHOR}"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}
print_step(){ echo -e "\n${BLUE}${BOLD}  ── Step $1/$2: $3${NC}"; }
print_success(){ echo -e "  ${GREEN}${BOLD}✔${NC}  $1"; }
print_error(){ echo -e "  ${RED}${BOLD}✖${NC}  $1"; }
print_warn(){ echo -e "  ${YELLOW}${BOLD}!${NC}  $1"; }
print_info(){ echo -e "  ${DIM}→  $1${NC}"; }
print_section(){ echo -e "\n  ${BOLD}── $1 ─${NC}"; }
print_header(){ echo -e "  ${BOLD}$1${NC}\n  ${DIM}───────────────────────────────────────────────────${NC}"; }

ask(){
    local __var="$1" prompt="$2" default="${3:-}" value
    if [[ -n "$default" ]]; then echo -ne "${prompt} [${default}]: "; else echo -ne "${prompt}: "; fi
    read -r value; value="${value:-$default}"; printf -v "$__var" '%s' "$value"
}
ask_secret(){ local __var="$1" prompt="$2" value; echo -ne "${prompt}: "; read -rs value; echo; printf -v "$__var" '%s' "$value"; }
confirm(){
    local msg="$1" default="${2:-y}" answer prompt
    [[ "$default" == y ]] && prompt="Y/n" || prompt="y/N"
    echo -ne "  ${YELLOW}${msg}${NC} [${prompt}]: "; read -r answer; answer="${answer:-$default}"; [[ "${answer,,}" == y ]]
}
press_enter(){ echo -ne "\n  ${DIM}Press Enter to continue...${NC}"; read -r; }
menu_prompt(){ echo; echo -ne "  ${YELLOW}Select option: ${NC}"; read -r MENU_CHOICE; }

print_qr(){
    local data="$1" label="${2:-Subscription}"
    if ! command -v qrencode >/dev/null 2>&1; then
        apt-get update -qq >/dev/null 2>&1 || true
        apt-get install -y qrencode >/dev/null 2>&1 || return 0
    fi
    echo -e "\n  ${BOLD}QR — ${label}${NC}\n"; qrencode -t ANSIUTF8 -m 2 "$data" || true; echo
}

bytes_to_human(){
    python3 - "$1" <<'PY'
import sys
n=int(float(sys.argv[1] or 0))
for u in ('B','KB','MB','GB','TB'):
    if n < 1024 or u == 'TB':
        print(f"{n:.0f} {u}" if u=='B' else f"{n:.2f} {u}"); break
    n/=1024
PY
}
pad_right(){ printf "%-${1}s" "$2"; }
valid_ipv4(){
    local ip="$1" part n
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    IFS=. read -r -a parts <<<"$ip"
    for part in "${parts[@]}"; do n=$((10#$part)); (( n <= 255 )) || return 1; done
}
valid_host(){
    local h="$1"
    [[ -n "$h" && "$h" != *$'\n'* && "$h" != *$'\r'* ]] || return 1
    valid_ipv4 "$h" && return 0
    [[ "$h" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]]
}
host_port(){
    local h="$1" p="$2"
    if [[ "$h" == *:* && "$h" != \[*\] ]]; then printf '[%s]:%s\n' "$h" "$p"; else printf '%s:%s\n' "$h" "$p"; fi
}
log(){ local level="$1"; shift; mkdir -p "$LOG_DIR"; echo "$(date '+%F %T') [$level] $*" >> "$MANAGER_LOG"; }
log_info(){ log INFO "$@"; }; log_warn(){ log WARN "$@"; }; log_error(){ log ERROR "$@"; }
