#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  core/common.sh — shared UI, print helpers, and input utils
#  Part of: singbox-manager  |  Author: Mehdi Hesami
# ═══════════════════════════════════════════════════════════════
# This file is sourced by all other modules. Do not execute directly.

# ── ANSI colors ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Version & metadata ─────────────────────────────────────────
MANAGER_VERSION="3.0.0"
MANAGER_AUTHOR="Mehdi Hesami"

# ── Global runtime paths (protocols override as needed) ────────
BASE_DIR="/etc/singbox-manager"
DATA_DIR="${BASE_DIR}/data"
LOG_DIR="/var/log/singbox-manager"

# ── Print helpers ──────────────────────────────────────────────
print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════════╗"
    echo "  ║          sing-box Proxy Manager  v${MANAGER_VERSION}          ║"
    echo "  ║      VLESS+Reality  │  Hysteria2  │  More soon    ║"
    printf "  ║      %-45s ║\n" "Author: ${MANAGER_AUTHOR}"
    echo "  ╚═══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# print_step <current> <total> <description>
print_step() {
    echo -e "\n${BLUE}${BOLD}  ── Step ${1}/${2}: ${NC}${BOLD}${3}${NC}"
}

print_success() { echo -e "  ${GREEN}${BOLD}✔${NC}  $1"; }
print_error()   { echo -e "  ${RED}${BOLD}✖${NC}  $1"; }
print_warn()    { echo -e "  ${YELLOW}${BOLD}!${NC}  $1"; }
print_info()    { echo -e "  ${DIM}→  $1${NC}"; }
print_section() { echo -e "\n  ${BOLD}── $1 ─${NC}"; }

# Section header with separator line that fits terminal width
print_header() {
    local title="$1"
    local width=51
    local line
    printf -v line '%*s' "$width" ''
    echo -e "\n  ${CYAN}${BOLD}${title}${NC}"
    echo -e "  ${DIM}${line// /─}${NC}"
}

# ── Interactive input ──────────────────────────────────────────

# ask <varname> <prompt> [default]
ask() {
    local varname="$1" prompt="$2" default="$3" value
    echo -ne "  ${CYAN}${prompt}${NC}"
    [[ -n "$default" ]] && echo -ne " ${DIM}[${default}]${NC}"
    echo -ne ": "
    read -r value
    value="${value:-$default}"
    # Sanitize: strip quotes and semicolons to prevent injection
    value="${value//\'/}"
    value="${value//\"/}"
    value="${value//;/}"
    printf -v "$varname" '%s' "$value"
}

# ask_secret <varname> <prompt>  — no echo
ask_secret() {
    local varname="$1" prompt="$2" value
    echo -ne "  ${CYAN}${prompt}${NC}: "
    read -rs value
    echo ""
    printf -v "$varname" '%s' "$value"
}

# confirm <message> [default:y]  — returns 0 for yes
confirm() {
    local msg="$1" default="${2:-y}" prompt answer
    [[ "$default" == "y" ]] && prompt="${GREEN}Y${NC}/n" || prompt="y/${RED}N${NC}"
    echo -ne "  ${YELLOW}${msg}${NC} [${prompt}]: "
    read -r answer
    answer="${answer:-$default}"
    [[ "${answer,,}" == "y" ]]
}

press_enter() {
    echo -ne "\n  ${DIM}Press Enter to continue...${NC}"
    read -r
}

# menu_prompt  — standardized "Select option:" input
menu_prompt() {
    echo ""
    echo -ne "  ${YELLOW}Select option: ${NC}"
    read -r MENU_CHOICE
}

# ── QR code ───────────────────────────────────────────────────
print_qr() {
    local data="$1" label="${2:-}"
    if ! command -v qrencode &>/dev/null; then
        print_info "Installing qrencode..."
        apt-get install -y qrencode &>/dev/null && print_success "qrencode installed." || {
            print_warn "Could not install qrencode. Skipping QR code."
            return
        }
    fi
    echo ""
    [[ -n "$label" ]] && echo -e "  ${BOLD}  QR Code — ${label}${NC}" \
                       || echo -e "  ${BOLD}  QR Code (scan with Hiddify / v2rayN):${NC}"
    echo ""
    qrencode -t ANSIUTF8 -m 2 "$data"
    echo ""
}

# ── String / format helpers ───────────────────────────────────

# bytes_to_human <bytes>
bytes_to_human() {
    local bytes="$1"
    if   (( bytes >= 1073741824 )); then printf "%.2f GB" "$(echo "scale=2; $bytes/1073741824" | bc)"
    elif (( bytes >= 1048576    )); then printf "%.2f MB" "$(echo "scale=2; $bytes/1048576"    | bc)"
    elif (( bytes >= 1024       )); then printf "%.2f KB" "$(echo "scale=2; $bytes/1024"       | bc)"
    else  printf "%d B" "$bytes"
    fi
}

# gb_to_bytes <gb_float>
gb_to_bytes() {
    python3 -c "print(int(float('${1}') * 1024**3))" 2>/dev/null || echo "0"
}

# zero-pad for table display: pad_right <width> <string>
pad_right() {
    printf "%-${1}s" "$2"
}

# ── Logging ───────────────────────────────────────────────────
mkdir -p "$LOG_DIR"
MANAGER_LOG="${LOG_DIR}/manager.log"

log() {
    local level="$1"; shift
    echo "$(date '+%Y/%m/%d %H:%M:%S') [${level}] $*" >> "$MANAGER_LOG"
}

log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { log "ERROR" "$@"; }
