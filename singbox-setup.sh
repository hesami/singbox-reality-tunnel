#!/bin/bash

# ============================================================
#  sing-box Setup Script
#  VLESS + REALITY Tunnel Manager
#  Version: 1.0.0
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_CONFIG="/etc/sing-box/config.json"
SINGBOX_VERSION=""

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  +-----------------------------------------------+"
    echo "  |       sing-box Setup & Manager v1.0.0        |"
    echo "  |       VLESS + REALITY Tunnel                  |"
    echo "  +-----------------------------------------------+"
    echo -e "${NC}"
}

print_step()    { echo -e "\n${BLUE}${BOLD}[ Step $1 ]${NC} $2"; }
print_success() { echo -e "${GREEN}${BOLD}[OK]${NC} $1"; }
print_error()   { echo -e "${RED}${BOLD}[ERROR]${NC} $1"; }
print_warn()    { echo -e "${YELLOW}${BOLD}[WARN]${NC} $1"; }
print_info()    { echo -e "${DIM}  -> $1${NC}"; }

confirm() {
    local msg="$1" default="${2:-y}" prompt
    [[ "$default" == "y" ]] && prompt="[Y/n]" || prompt="[y/N]"
    echo -ne "${YELLOW}${msg} ${prompt}: ${NC}"
    read -r answer; answer="${answer:-$default}"
    [[ "${answer,,}" == "y" ]]
}

ask() {
    local varname="$1" prompt="$2" default="$3" value
    echo -ne "${CYAN}${prompt}${NC}"
    [[ -n "$default" ]] && echo -ne " ${DIM}[default: ${default}]${NC}"
    echo -ne ": "
    read -r value; value="${value:-$default}"
    eval "$varname='$value'"
}

press_enter() {
    echo -ne "\n${DIM}Press Enter to continue...${NC}"
    read -r
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root."
        echo -e "  Please run: ${BOLD}sudo bash $0${NC}"
        exit 1
    fi
}

check_os() {
    if ! command -v apt-get &>/dev/null; then
        print_error "This script only supports Ubuntu/Debian."
        exit 1
    fi
}

check_internet() {
    print_info "Checking internet connection..."
    if ! curl -s --connect-timeout 5 https://github.com &>/dev/null; then
        print_error "No internet access or GitHub is unreachable."
        exit 1
    fi
    print_success "Internet connection is available."
}

get_latest_version() {
    local type="${1:-stable}"
    if [[ "$type" == "prerelease" ]]; then
        SINGBOX_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" \
            | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/')
    else
        SINGBOX_VERSION=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
            | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
    fi
    if [[ -z "$SINGBOX_VERSION" ]]; then
        print_error "Could not fetch version from GitHub."
        exit 1
    fi
    print_info "Version: ${SINGBOX_VERSION}"
}

install_singbox() {
    local version="$1"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    print_info "Downloading sing-box v${version}..."
    local url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-amd64.tar.gz"
    if ! curl -L --progress-bar -o "${tmp_dir}/sing-box.tar.gz" "$url"; then
        print_error "Download failed."
        rm -rf "$tmp_dir"; exit 1
    fi
    print_info "Installing binary..."
    tar -xzf "${tmp_dir}/sing-box.tar.gz" -C "$tmp_dir"
    cp "${tmp_dir}/sing-box-${version}-linux-amd64/sing-box" "$SINGBOX_BIN"
    chmod +x "$SINGBOX_BIN"
    rm -rf "$tmp_dir"
    mkdir -p /etc/sing-box
    print_success "sing-box v${version} installed."
}

generate_uuid()    { "$SINGBOX_BIN" generate uuid 2>/dev/null || cat /proc/sys/kernel/random/uuid; }
generate_keypair() { "$SINGBOX_BIN" generate reality-keypair 2>/dev/null; }

write_config() {
    mkdir -p /etc/sing-box
    echo "$1" > "$SINGBOX_CONFIG"
    print_success "Config saved to ${SINGBOX_CONFIG}"
}

create_service_server() {
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box service
After=network.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box &>/dev/null
    print_success "Service sing-box created and enabled."
}

create_service_client() {
    cat > /etc/systemd/system/sing-box-client.service << 'EOF'
[Unit]
Description=sing-box client service
After=network.target

[Service]
Environment=ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p /etc/systemd/system/sing-box-client.service.d
    cat > /etc/systemd/system/sing-box-client.service.d/override.conf << 'EOF'
[Service]
Environment=ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true
EOF
    systemctl daemon-reload
    systemctl enable sing-box-client &>/dev/null
    print_success "Service sing-box-client created and enabled."
}

start_service() {
    local svc="$1"
    systemctl restart "$svc"
    sleep 2
    if systemctl is-active --quiet "$svc"; then
        print_success "Service ${svc} is running."
    else
        print_error "Service ${svc} failed to start!"
        journalctl -u "$svc" --no-pager -n 15
        exit 1
    fi
}

open_firewall() {
    local port="$1"
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$port"/tcp &>/dev/null
        print_success "Port ${port} opened in UFW."
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        print_info "iptables rule added for port ${port}."
    fi
}

select_version() {
    echo -e "${CYAN}Select version:${NC}"
    echo "  1) Latest stable release (recommended)"
    echo "  2) Latest pre-release"
    echo -ne "${YELLOW}Choice [1]: ${NC}"
    read -r ver_choice; ver_choice="${ver_choice:-1}"
    check_internet
    [[ "$ver_choice" == "2" ]] && get_latest_version prerelease || get_latest_version stable
}

setup_server() {
    print_banner
    echo -e "${BOLD}  Install Outbound Server (e.g. Germany)${NC}\n"
    select_version

    print_step "1/5" "Installing sing-box..."
    install_singbox "$SINGBOX_VERSION"

    print_step "2/5" "Configure parameters..."
    echo ""
    local uuid port sni short_id
    uuid=$(generate_uuid)
    ask uuid     "  User UUID"             "$uuid"
    ask port     "  Listen port"           "443"
    ask sni      "  SNI (camouflage site)" "www.google.com"
    ask short_id "  Short ID"              "a1b2c3d4"

    print_step "3/5" "Generating REALITY keypair..."
    local keypair private_key public_key
    keypair=$(generate_keypair)
    private_key=$(echo "$keypair" | grep PrivateKey | awk '{print $2}')
    public_key=$(echo  "$keypair" | grep PublicKey  | awk '{print $2}')
    echo ""
    echo -e "${GREEN}${BOLD}Generated keypair:${NC}"
    echo -e "  PrivateKey: ${BOLD}${private_key}${NC}"
    echo -e "  PublicKey:  ${BOLD}${public_key}${NC}"
    echo -e "  ${YELLOW}[!] Save these keys!${NC}\n"

    print_step "4/5" "Writing config..."
    write_config "{
  \"log\": { \"level\": \"info\" },
  \"inbounds\": [{
    \"type\": \"vless\", \"tag\": \"vless-in\",
    \"listen\": \"0.0.0.0\", \"listen_port\": ${port},
    \"users\": [{\"uuid\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true, \"server_name\": \"${sni}\",
      \"reality\": {
        \"enabled\": true,
        \"handshake\": {\"server\": \"${sni}\", \"server_port\": 443},
        \"private_key\": \"${private_key}\",
        \"short_id\": [\"${short_id}\"]
      }
    }
  }],
  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}]
}"

    print_step "5/5" "Starting service..."
    create_service_server
    open_firewall "$port"
    start_service sing-box

    local server_ip
    server_ip=$(curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null || echo "unknown")
    local vless_link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#Outbound-Server"

    echo ""
    echo -e "${GREEN}${BOLD}+----------------------------------------------+"
    echo -e "|        Server installed successfully!        |"
    echo -e "+----------------------------------------------+${NC}"
    echo -e "\n${BOLD}Details:${NC}"
    echo -e "  IP: ${CYAN}${server_ip}${NC}  Port: ${CYAN}${port}${NC}  UUID: ${CYAN}${uuid}${NC}"
    echo -e "  PublicKey: ${CYAN}${public_key}${NC}"
    echo -e "  SNI: ${CYAN}${sni}${NC}  ShortID: ${CYAN}${short_id}${NC}"
    echo -e "\n${BOLD}VLESS link:${NC}\n  ${MAGENTA}${vless_link}${NC}\n"
    press_enter
}

setup_client() {
    print_banner
    echo -e "${BOLD}  Install Iran Client (tunnel to outbound server)${NC}\n"
    select_version

    print_step "1/5" "Installing sing-box..."
    install_singbox "$SINGBOX_VERSION"

    print_step "2/5" "Configure outbound server parameters..."
    echo ""
    local server_ip server_port uuid public_key short_id sni socks_port
    ask server_ip   "  Outbound server IP"   ""
    ask server_port "  Outbound server port" "443"
    ask uuid        "  UUID"                 ""
    ask public_key  "  PublicKey"            ""
    ask short_id    "  Short ID"             "a1b2c3d4"
    ask sni         "  SNI"                  "www.google.com"
    ask socks_port  "  Local SOCKS5 port"    "10808"

    if [[ -z "$server_ip" || -z "$uuid" || -z "$public_key" ]]; then
        print_error "Server IP, UUID and PublicKey are required."
        press_enter; return
    fi

    print_step "3/5" "Writing config..."
    write_config "{
  \"log\": { \"level\": \"info\" },
  \"inbounds\": [{
    \"type\": \"socks\", \"tag\": \"socks-in\",
    \"listen\": \"127.0.0.1\", \"listen_port\": ${socks_port}
  }],
  \"outbounds\": [
    {
      \"type\": \"vless\", \"tag\": \"vless-out\",
      \"server\": \"${server_ip}\", \"server_port\": ${server_port},
      \"uuid\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\",
      \"tls\": {
        \"enabled\": true, \"server_name\": \"${sni}\",
        \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"},
        \"reality\": {
          \"enabled\": true,
          \"public_key\": \"${public_key}\",
          \"short_id\": \"${short_id}\"
        }
      }
    },
    {\"type\": \"direct\", \"tag\": \"direct\"}
  ],
  \"route\": {\"final\": \"vless-out\"}
}"

    print_step "4/5" "Starting service..."
    create_service_client
    start_service sing-box-client

    print_step "5/5" "Testing tunnel..."
    sleep 2
    local test_ip
    test_ip=$(curl -s --connect-timeout 10 --socks5 "127.0.0.1:${socks_port}" https://ifconfig.me 2>/dev/null || echo "")
    if [[ -n "$test_ip" ]]; then
        print_success "Tunnel is working! Outbound IP: ${test_ip}"
    else
        print_warn "Connection test failed. Check logs with option 4."
        journalctl -u sing-box-client --no-pager -n 10
    fi

    echo ""
    echo -e "${GREEN}${BOLD}+----------------------------------------------+"
    echo -e "|        Client installed successfully!        |"
    echo -e "+----------------------------------------------+${NC}"
    echo -e "\n  Local SOCKS5: ${CYAN}127.0.0.1:${socks_port}${NC}\n"
    press_enter
}

add_user() {
    print_banner
    echo -e "${BOLD}  Add New User to Server${NC}\n"

    if [[ ! -f "$SINGBOX_CONFIG" ]]; then
        print_error "Config file not found: ${SINGBOX_CONFIG}"
        press_enter; return
    fi

    if ! grep -q '"reality"' "$SINGBOX_CONFIG" 2>/dev/null; then
        print_error "This config is not a REALITY server."
        press_enter; return
    fi

    local uuid label
    uuid=$(generate_uuid)
    ask uuid  "  New user UUID"   "$uuid"
    ask label "  Label"           "New-User"

    local public_key short_id sni port
    public_key=$(python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='vless':
        print(ib.get('tls',{}).get('reality',{}).get('public_key',''))
        break
" 2>/dev/null || echo "")

    short_id=$(python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='vless':
        ids=ib.get('tls',{}).get('reality',{}).get('short_id',['a1b2c3d4'])
        print(ids[0] if ids else 'a1b2c3d4')
        break
" 2>/dev/null || echo "a1b2c3d4")

    sni=$(python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='vless':
        print(ib.get('tls',{}).get('server_name','www.google.com'))
        break
" 2>/dev/null || echo "www.google.com")

    port=$(python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: c=json.load(f)
for ib in c.get('inbounds',[]):
    if ib.get('type')=='vless':
        print(ib.get('listen_port',443))
        break
" 2>/dev/null || echo "443")

    print_info "Adding user to config..."
    local result
    result=$(python3 -c "
import json, sys
with open('${SINGBOX_CONFIG}') as f: config=json.load(f)
for ib in config.get('inbounds',[]):
    if ib.get('type')=='vless':
        users=ib.get('users',[])
        if any(u.get('uuid')=='${uuid}' for u in users):
            print('DUPLICATE'); sys.exit(0)
        users.append({'uuid':'${uuid}','flow':'xtls-rprx-vision'})
        ib['users']=users; break
with open('${SINGBOX_CONFIG}','w') as f: json.dump(config,f,indent=2)
print('OK')
" 2>/dev/null || echo "ERROR")

    case "$result" in
        DUPLICATE) print_error "This UUID already exists."; press_enter; return ;;
        OK)        print_success "User added successfully." ;;
        *)         print_error "Failed to add user."; press_enter; return ;;
    esac

    systemctl is-active --quiet sing-box 2>/dev/null && systemctl restart sing-box || true

    local server_ip
    server_ip=$(curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null || echo "unknown")
    local vless_link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#${label}"

    echo -e "\n${BOLD}New user:${NC}"
    echo -e "  UUID: ${CYAN}${uuid}${NC}"
    echo -e "\n${BOLD}VLESS link:${NC}\n  ${MAGENTA}${vless_link}${NC}\n"
    press_enter
}

show_status() {
    print_banner
    echo -e "${BOLD}  Service Status${NC}\n"
    for svc in sing-box sing-box-client; do
        if systemctl list-unit-files "${svc}.service" &>/dev/null 2>&1; then
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo -e "  ${svc}: ${GREEN}${BOLD}[ACTIVE]${NC}"
            else
                echo -e "  ${svc}: ${RED}${BOLD}[INACTIVE]${NC}"
            fi
        fi
    done
    echo ""
    if [[ -f "$SINGBOX_BIN" ]]; then
        echo -e "${BOLD}Version:${NC}"
        "$SINGBOX_BIN" version 2>/dev/null | head -1 | sed 's/^/  /'
    fi
    echo ""
    for svc in sing-box sing-box-client; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "${BOLD}Recent log [ ${svc} ]:${NC}"
            journalctl -u "$svc" --no-pager -n 10 2>/dev/null | sed 's/^/  /'
            echo ""
        fi
    done
    press_enter
}

manage_service() {
    print_banner
    echo -e "${BOLD}  Service Management${NC}\n"

    local svc="sing-box"
    if systemctl is-active --quiet sing-box-client 2>/dev/null && \
       ! systemctl is-active --quiet sing-box 2>/dev/null; then
        svc="sing-box-client"
    fi

    echo -e "  Active service: ${CYAN}${svc}${NC}\n"
    echo "  1) Start"
    echo "  2) Stop"
    echo "  3) Restart"
    echo "  4) Live log (Ctrl+C to exit)"
    echo "  5) Switch to other service"
    echo "  0) Back"
    echo ""
    echo -ne "${YELLOW}Choice: ${NC}"
    read -r choice

    case "$choice" in
        1) systemctl start "$svc"   && print_success "Service started."   ; press_enter ;;
        2) systemctl stop "$svc"    && print_success "Service stopped."   ; press_enter ;;
        3) systemctl restart "$svc" && print_success "Service restarted." ; press_enter ;;
        4) journalctl -u "$svc" -f ;;
        5)
            [[ "$svc" == "sing-box" ]] && svc="sing-box-client" || svc="sing-box"
            print_info "Switched to: ${svc}"; manage_service ;;
        0) return ;;
        *) print_warn "Invalid choice." ; sleep 1 ;;
    esac
}

update_singbox() {
    print_banner
    echo -e "${BOLD}  Update sing-box${NC}\n"

    if [[ ! -f "$SINGBOX_BIN" ]]; then
        print_error "sing-box is not installed."
        press_enter; return
    fi

    check_internet

    echo -e "${CYAN}Select version:${NC}"
    echo "  1) Latest stable"
    echo "  2) Latest pre-release"
    echo -ne "${YELLOW}Choice [1]: ${NC}"
    read -r ver_choice; ver_choice="${ver_choice:-1}"
    [[ "$ver_choice" == "2" ]] && get_latest_version prerelease || get_latest_version stable

    local current
    current=$("$SINGBOX_BIN" version 2>/dev/null | grep -o '[0-9]*\.[0-9]*\.[0-9]*[^ ]*' | head -1 || echo "unknown")
    echo -e "  Current: ${YELLOW}${current}${NC}  ->  New: ${GREEN}${SINGBOX_VERSION}${NC}"

    if [[ "$current" == "$SINGBOX_VERSION" ]]; then
        print_info "Already on the latest version."; press_enter; return
    fi

    confirm "Proceed with update?" || return

    systemctl stop sing-box 2>/dev/null || true
    systemctl stop sing-box-client 2>/dev/null || true
    install_singbox "$SINGBOX_VERSION"
    systemctl start sing-box 2>/dev/null || true
    systemctl start sing-box-client 2>/dev/null || true

    print_success "Update completed."
    press_enter
}

uninstall() {
    print_banner
    echo -e "${RED}${BOLD}  Uninstall sing-box${NC}\n"
    confirm "Are you sure? This cannot be undone!" "n" || return

    systemctl stop sing-box 2>/dev/null || true
    systemctl stop sing-box-client 2>/dev/null || true
    systemctl disable sing-box 2>/dev/null || true
    systemctl disable sing-box-client 2>/dev/null || true
    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/systemd/system/sing-box-client.service
    rm -rf /etc/systemd/system/sing-box-client.service.d
    rm -f "$SINGBOX_BIN"
    rm -rf /etc/sing-box
    systemctl daemon-reload

    print_success "sing-box has been completely removed."
    press_enter
}

main_menu() {
    while true; do
        print_banner
        local sv cl
        sv=$(systemctl is-active sing-box 2>/dev/null || echo "inactive")
        cl=$(systemctl is-active sing-box-client 2>/dev/null || echo "inactive")
        [[ "$sv" == "active" ]] && echo -e "  Server:  ${GREEN}[ACTIVE]${NC}"
        [[ "$cl" == "active" ]] && echo -e "  Client:  ${GREEN}[ACTIVE]${NC}"
        echo ""
        echo -e "${BOLD}  --- Installation ---${NC}"
        echo -e "  ${CYAN}1)${NC} Install outbound server (e.g. Germany)"
        echo -e "  ${CYAN}2)${NC} Install Iran client (tunnel to outbound)"
        echo ""
        echo -e "${BOLD}  --- Management ---${NC}"
        echo -e "  ${CYAN}3)${NC} Add new user"
        echo -e "  ${CYAN}4)${NC} Show status & logs"
        echo -e "  ${CYAN}5)${NC} Manage service"
        echo -e "  ${CYAN}6)${NC} Update sing-box"
        echo -e "  ${CYAN}7)${NC} Uninstall"
        echo ""
        echo -e "  ${DIM}0) Exit${NC}"
        echo ""
        echo -ne "${YELLOW}Select option: ${NC}"
        read -r choice
        case "$choice" in
            1) setup_server ;;
            2) setup_client ;;
            3) add_user ;;
            4) show_status ;;
            5) manage_service ;;
            6) update_singbox ;;
            7) uninstall ;;
            0) echo -e "\n${DIM}Goodbye.${NC}\n"; exit 0 ;;
            *) print_warn "Invalid option."; sleep 1 ;;
        esac
    done
}

check_root
check_os
main_menu
