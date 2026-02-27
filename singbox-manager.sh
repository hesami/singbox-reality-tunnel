#!/bin/bash

# ============================================================
#  sing-box Setup & Manager v2.3.0
#  VLESS + REALITY + Hysteria2 Tunnel
#  Author: Mehdi Hesami
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
SERVER_INFO="/etc/sing-box/server.json"   # keypair + server settings
USERS_DB="/etc/sing-box/users.json"       # user list
SINGBOX_VERSION=""

# Hysteria2 paths
HY2_BIN="/usr/local/bin/hysteria"
HY2_CONFIG="/etc/hysteria/config.yaml"
HY2_SERVER_INFO="/etc/hysteria/server.json"

# ─── Helpers ──────────────────────────────────────────────

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  +-----------------------------------------------+"
    echo "  |       sing-box Setup & Manager v2.3.0        |"
    echo "  |       VLESS + REALITY + Hysteria2             |"
    echo "  |       Author: Mehdi Hesami                    |"
    echo "  +-----------------------------------------------+"
    echo -e "${NC}"
}

print_step()    { echo -e "\n${BLUE}${BOLD}[ Step $1 ]${NC} $2"; }
print_success() { echo -e "${GREEN}${BOLD}[OK]${NC} $1"; }
print_error()   { echo -e "${RED}${BOLD}[ERROR]${NC} $1"; }
print_warn()    { echo -e "${YELLOW}${BOLD}[WARN]${NC} $1"; }
print_info()    { echo -e "${DIM}  -> $1${NC}"; }

print_qr() {
    local data="$1"
    if ! command -v qrencode &>/dev/null; then
        print_info "Installing qrencode..."
        apt-get install -y qrencode &>/dev/null && print_success "qrencode installed." || {
            print_warn "Could not install qrencode. Skipping QR code."
            return
        }
    fi
    echo ""
    echo -e "${BOLD}  QR Code (scan with Hiddify / v2rayN mobile):${NC}"
    echo ""
    qrencode -t ANSIUTF8 -m 2 "$data"
    echo ""
}

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
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=20

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
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Environment=ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=20

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

get_ipv4() {
    local ip
    ip=$(curl -4 -s --connect-timeout 5 https://ifconfig.me 2>/dev/null) \
    || ip=$(curl -4 -s --connect-timeout 5 https://api.ipify.org 2>/dev/null) \
    || ip=$(curl -4 -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null) \
    || ip="unknown"
    echo "$ip"
}

# ─── Server Info (server.json) ────────────────────────────

init_server_info() {
    local public_key="$1" private_key="$2" short_id="$3" sni="$4" port="$5"
    mkdir -p /etc/sing-box
    python3 -c "
import json
data = {
    'public_key':  '${public_key}',
    'private_key': '${private_key}',
    'short_id':    '${short_id}',
    'sni':         '${sni}',
    'port':        int('${port}')
}
with open('${SERVER_INFO}', 'w') as f:
    json.dump(data, f, indent=2)
"
    print_success "Server info saved to ${SERVER_INFO}"
}

read_server_info() {
    if [[ ! -f "$SERVER_INFO" ]]; then
        print_error "server.json not found. Is this an outbound server?"
        return 1
    fi
    python3 -c "
import json
with open('${SERVER_INFO}') as f: d=json.load(f)
print(d.get('public_key',''))
print(d.get('private_key',''))
print(d.get('short_id','a1b2c3d4'))
print(d.get('sni','www.google.com'))
print(d.get('port',443))
"
}

# ─── Users DB (users.json) ────────────────────────────────

init_users_db() {
    if [[ ! -f "$USERS_DB" ]]; then
        echo '{"users":[]}' > "$USERS_DB"
    fi
}

save_user_to_db() {
    local uuid="$1" label="$2" quota_gb="$3"
    init_users_db
    python3 -c "
import json, time
with open('${USERS_DB}') as f: db=json.load(f)
db['users'].append({
    'uuid':       '${uuid}',
    'label':      '${label}',
    'quota_gb':   float('${quota_gb}'),
    'used_bytes': 0,
    'created':    int(time.time()),
    'enabled':    True
})
with open('${USERS_DB}','w') as f: json.dump(db,f,indent=2)
" 2>/dev/null || true
}

bytes_to_human() {
    python3 -c "
b=int('${1}')
for u in ['B','KB','MB','GB','TB']:
    if b<1024: print(f'{b:.2f} {u}'); break
    b/=1024
" 2>/dev/null || echo "${1} B"
}

# ─── VLESS Link Builder ───────────────────────────────────

build_vless_link() {
    local uuid="$1" label="$2"
    local server_ip public_key short_id sni port info
    server_ip=$(get_ipv4)
    info=$(read_server_info)
    public_key=$(echo "$info" | sed -n '1p')
    short_id=$(echo "$info"   | sed -n '3p')
    sni=$(echo "$info"        | sed -n '4p')
    port=$(echo "$info"       | sed -n '5p')
    local encoded_label
    encoded_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${label}'))" 2>/dev/null || echo "$label")
    echo "vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#${encoded_label}"
}

# ─── Install: Server ──────────────────────────────────────

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
    # Generate a secure random short_id (8 hex chars)
    local default_short_id
    default_short_id=$(openssl rand -hex 4 2>/dev/null || cat /dev/urandom | tr -dc 'a-f0-9' | head -c 8)
    echo -e "  ${YELLOW}[TIP] SNI should be a high-traffic TLS site to blend in with legitimate traffic.${NC}"
    echo -e "  ${DIM}Good choices: www.speedtest.net | addons.mozilla.org | www.bing.com | dl.google.com${NC}\n"
    ask uuid     "  User UUID"             "$uuid"
    ask port     "  Listen port"           "443"
    ask sni      "  SNI (camouflage site)" "www.speedtest.net"
    ask short_id "  Short ID (hex)"        "$default_short_id"

    print_step "3/5" "Generating REALITY keypair..."
    local keypair private_key public_key
    keypair=$(generate_keypair)
    private_key=$(echo "$keypair" | grep PrivateKey | awk '{print $2}')
    public_key=$(echo  "$keypair" | grep PublicKey  | awk '{print $2}')
    echo ""
    echo -e "${GREEN}${BOLD}Generated keypair:${NC}"
    echo -e "  PrivateKey: ${BOLD}${private_key}${NC}"
    echo -e "  PublicKey:  ${BOLD}${public_key}${NC}"
    echo -e "  ${YELLOW}[!] Saved to ${SERVER_INFO}${NC}\n"

    print_step "4/5" "Writing configs..."
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
    init_server_info "$public_key" "$private_key" "$short_id" "$sni" "$port"
    init_users_db
    save_user_to_db "$uuid" "default" "0"

    print_step "5/5" "Starting service..."
    create_service_server
    open_firewall "$port"
    start_service sing-box

    local server_ip vless_link
    server_ip=$(get_ipv4)
    local encoded_label
    encoded_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('Germany-Server'))" 2>/dev/null || echo "Germany-Server")
    vless_link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp&headerType=none#${encoded_label}"

    echo ""
    echo -e "${GREEN}${BOLD}+----------------------------------------------+"
    echo -e "|        Server installed successfully!        |"
    echo -e "+----------------------------------------------+${NC}"
    echo -e "\n${BOLD}Details:${NC}"
    echo -e "  IP:        ${CYAN}${server_ip}${NC}"
    echo -e "  Port:      ${CYAN}${port}${NC}"
    echo -e "  UUID:      ${CYAN}${uuid}${NC}"
    echo -e "  PublicKey: ${CYAN}${public_key}${NC}"
    echo -e "  SNI:       ${CYAN}${sni}${NC}"
    echo -e "  ShortID:   ${CYAN}${short_id}${NC}"
    echo ""
    echo -e "${BOLD}VLESS link (v2rayN compatible):${NC}"
    echo -e "  ${MAGENTA}${vless_link}${NC}"
    print_qr "$vless_link"
    press_enter
}

# ─── Install: Client ──────────────────────────────────────

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

# ─── Add User ─────────────────────────────────────────────

add_user() {
    print_banner
    echo -e "${BOLD}  Add New User${NC}\n"

    if [[ ! -f "$SINGBOX_CONFIG" ]]; then
        print_error "Config not found. Install server first."; press_enter; return
    fi
    if [[ ! -f "$SERVER_INFO" ]]; then
        print_error "server.json not found. Install server first."; press_enter; return
    fi

    local uuid label quota_gb
    uuid=$(generate_uuid)
    ask uuid     "  New user UUID"                   "$uuid"
    ask label    "  Label (for VLESS link)"           "New-User"
    ask quota_gb "  Traffic quota in GB (0=unlimited)" "0"

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
        OK)        print_success "User added to config." ;;
        *)         print_error "Failed to add user."; press_enter; return ;;
    esac

    save_user_to_db "$uuid" "$label" "$quota_gb"
    systemctl is-active --quiet sing-box 2>/dev/null && systemctl restart sing-box || true

    local vless_link
    vless_link=$(build_vless_link "$uuid" "$label")

    echo ""
    echo -e "${BOLD}New user details:${NC}"
    echo -e "  UUID:  ${CYAN}${uuid}${NC}"
    echo -e "  Label: ${CYAN}${label}${NC}"
    echo -e "  Quota: ${CYAN}${quota_gb} GB${NC} (0 = unlimited)"
    echo ""
    echo -e "${BOLD}VLESS link (v2rayN compatible):${NC}"
    echo -e "  ${MAGENTA}${vless_link}${NC}"
    print_qr "$vless_link"
    press_enter
}

# ─── User Manager ─────────────────────────────────────────

manage_users() {
    while true; do
        print_banner
        echo -e "${BOLD}  User Manager${NC}\n"
        init_users_db

        local user_count
        user_count=$(python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
print(len(db.get('users',[])))
" 2>/dev/null || echo "0")

        if [[ "$user_count" == "0" ]]; then
            echo -e "  ${YELLOW}No users found.${NC}\n"
        else
            printf "  %-4s %-36s %-20s %-12s %-10s %-8s\n" "No." "UUID" "Label" "Quota" "Used" "Status"
            echo "  $(printf '%.0s-' {1..95})"
            python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
for i,u in enumerate(db.get('users',[]),1):
    uuid=u.get('uuid','')[:36]
    label=u.get('label','')[:20]
    quota=u.get('quota_gb',0)
    used=u.get('used_bytes',0)
    enabled=u.get('enabled',True)
    quota_str='Unlimited' if quota==0 else f'{quota} GB'
    used_mb=used/1024/1024
    used_str=f'{used_mb:.1f} MB' if used_mb<1024 else f'{used_mb/1024:.2f} GB'
    status='ON' if enabled else 'OFF'
    print(f'  {i:<4} {uuid:<36} {label:<20} {quota_str:<12} {used_str:<10} {status}')
" 2>/dev/null
        fi

        echo ""
        echo -e "  ${CYAN}1)${NC}  Add new user"
        echo -e "  ${CYAN}2)${NC}  View user details & VLESS link"
        echo -e "  ${CYAN}3)${NC}  Edit user quota"
        echo -e "  ${CYAN}4)${NC}  Enable / Disable user"
        echo -e "  ${CYAN}5)${NC}  Delete user"
        echo -e "  ${CYAN}6)${NC}  Reset traffic counter"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice

        case "$choice" in
            1) add_user ;;
            2) view_user_details ;;
            3) edit_user_quota ;;
            4) toggle_user ;;
            5) delete_user ;;
            6) reset_user_traffic ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

get_user_by_index() {
    local idx="$1"
    python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
users=db.get('users',[])
i=int('${idx}')-1
if 0<=i<len(users):
    u=users[i]
    print(u.get('uuid',''))
    print(u.get('label',''))
    print(u.get('quota_gb',0))
    print(u.get('used_bytes',0))
    print(u.get('enabled',True))
else:
    print('INVALID')
" 2>/dev/null
}

view_user_details() {
    echo -ne "\n${CYAN}  Enter user number: ${NC}"
    read -r idx
    local info
    info=$(get_user_by_index "$idx")
    if [[ "$(echo "$info" | head -1)" == "INVALID" || -z "$info" ]]; then
        print_error "Invalid user number."; sleep 1; return
    fi
    local uuid label quota used enabled
    uuid=$(echo "$info"    | sed -n '1p')
    label=$(echo "$info"   | sed -n '2p')
    quota=$(echo "$info"   | sed -n '3p')
    used=$(echo "$info"    | sed -n '4p')
    enabled=$(echo "$info" | sed -n '5p')

    local vless_link
    vless_link=$(build_vless_link "$uuid" "$label")

    echo ""
    echo -e "${BOLD}  User Details:${NC}"
    echo -e "  UUID:    ${CYAN}${uuid}${NC}"
    echo -e "  Label:   ${CYAN}${label}${NC}"
    echo -e "  Quota:   ${CYAN}$([ "$quota" == "0.0" ] || [ "$quota" == "0" ] && echo "Unlimited" || echo "${quota} GB")${NC}"
    echo -e "  Used:    ${CYAN}$(bytes_to_human "$used")${NC}"
    echo -e "  Status:  $([ "$enabled" == "True" ] && echo "${GREEN}Enabled${NC}" || echo "${RED}Disabled${NC}")"
    echo ""
    echo -e "${BOLD}  VLESS link (v2rayN compatible):${NC}"
    echo -e "  ${MAGENTA}${vless_link}${NC}"
    print_qr "$vless_link"
    press_enter
}

edit_user_quota() {
    echo -ne "\n${CYAN}  Enter user number: ${NC}"
    read -r idx
    local info
    info=$(get_user_by_index "$idx")
    if [[ "$(echo "$info" | head -1)" == "INVALID" || -z "$info" ]]; then
        print_error "Invalid user number."; sleep 1; return
    fi
    local uuid new_quota
    uuid=$(echo "$info" | sed -n '1p')
    ask new_quota "  New quota in GB (0=unlimited)" "0"
    python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
for u in db.get('users',[]):
    if u['uuid']=='${uuid}':
        u['quota_gb']=float('${new_quota}')
        break
with open('${USERS_DB}','w') as f: json.dump(db,f,indent=2)
" 2>/dev/null && print_success "Quota updated." || print_error "Failed."
    sleep 1
}

toggle_user() {
    echo -ne "\n${CYAN}  Enter user number: ${NC}"
    read -r idx
    local info
    info=$(get_user_by_index "$idx")
    if [[ "$(echo "$info" | head -1)" == "INVALID" || -z "$info" ]]; then
        print_error "Invalid user number."; sleep 1; return
    fi
    local uuid enabled
    uuid=$(echo "$info"    | sed -n '1p')
    enabled=$(echo "$info" | sed -n '5p')

    python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
for u in db.get('users',[]):
    if u['uuid']=='${uuid}':
        u['enabled']=not u.get('enabled',True)
        break
with open('${USERS_DB}','w') as f: json.dump(db,f,indent=2)
" 2>/dev/null

    if [[ "$enabled" == "True" ]]; then
        python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: config=json.load(f)
for ib in config.get('inbounds',[]):
    if ib.get('type')=='vless':
        ib['users']=[u for u in ib.get('users',[]) if u.get('uuid')!='${uuid}']
        break
with open('${SINGBOX_CONFIG}','w') as f: json.dump(config,f,indent=2)
" 2>/dev/null
        print_success "User disabled."
    else
        python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: config=json.load(f)
for ib in config.get('inbounds',[]):
    if ib.get('type')=='vless':
        users=ib.get('users',[])
        if not any(u.get('uuid')=='${uuid}' for u in users):
            users.append({'uuid':'${uuid}','flow':'xtls-rprx-vision'})
        ib['users']=users
        break
with open('${SINGBOX_CONFIG}','w') as f: json.dump(config,f,indent=2)
" 2>/dev/null
        print_success "User enabled."
    fi
    systemctl is-active --quiet sing-box 2>/dev/null && systemctl restart sing-box || true
    sleep 1
}

delete_user() {
    echo -ne "\n${CYAN}  Enter user number: ${NC}"
    read -r idx
    local info
    info=$(get_user_by_index "$idx")
    if [[ "$(echo "$info" | head -1)" == "INVALID" || -z "$info" ]]; then
        print_error "Invalid user number."; sleep 1; return
    fi
    local uuid label
    uuid=$(echo "$info"  | sed -n '1p')
    label=$(echo "$info" | sed -n '2p')
    confirm "  Delete user '${label}'?" "n" || return
    python3 -c "
import json
with open('${SINGBOX_CONFIG}') as f: config=json.load(f)
for ib in config.get('inbounds',[]):
    if ib.get('type')=='vless':
        ib['users']=[u for u in ib.get('users',[]) if u.get('uuid')!='${uuid}']
        break
with open('${SINGBOX_CONFIG}','w') as f: json.dump(config,f,indent=2)
" 2>/dev/null
    python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
db['users']=[u for u in db.get('users',[]) if u.get('uuid')!='${uuid}']
with open('${USERS_DB}','w') as f: json.dump(db,f,indent=2)
" 2>/dev/null
    systemctl is-active --quiet sing-box 2>/dev/null && systemctl restart sing-box || true
    print_success "User deleted."
    sleep 1
}

reset_user_traffic() {
    echo -ne "\n${CYAN}  Enter user number: ${NC}"
    read -r idx
    local info
    info=$(get_user_by_index "$idx")
    if [[ "$(echo "$info" | head -1)" == "INVALID" || -z "$info" ]]; then
        print_error "Invalid user number."; sleep 1; return
    fi
    local uuid
    uuid=$(echo "$info" | sed -n '1p')
    python3 -c "
import json
with open('${USERS_DB}') as f: db=json.load(f)
for u in db.get('users',[]):
    if u['uuid']=='${uuid}':
        u['used_bytes']=0; break
with open('${USERS_DB}','w') as f: json.dump(db,f,indent=2)
" 2>/dev/null && print_success "Traffic counter reset." || print_error "Failed."
    sleep 1
}

# ─── Status ───────────────────────────────────────────────

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
    if [[ -f "$SERVER_INFO" ]]; then
        echo ""
        echo -e "${BOLD}Server Info:${NC}"
        local info
        info=$(read_server_info 2>/dev/null || echo "")
        [[ -n "$info" ]] && {
            echo -e "  PublicKey: ${CYAN}$(echo "$info" | sed -n '1p')${NC}"
            echo -e "  SNI:       ${CYAN}$(echo "$info" | sed -n '4p')${NC}"
            echo -e "  Port:      ${CYAN}$(echo "$info" | sed -n '5p')${NC}"
        }
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

# ─── Manage Service ───────────────────────────────────────

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
        1) systemctl start "$svc"   && print_success "Started."   ; press_enter ;;
        2) systemctl stop "$svc"    && print_success "Stopped."   ; press_enter ;;
        3) systemctl restart "$svc" && print_success "Restarted." ; press_enter ;;
        4) journalctl -u "$svc" -f ;;
        5) [[ "$svc" == "sing-box" ]] && svc="sing-box-client" || svc="sing-box"
           print_info "Switched to: ${svc}"; manage_service ;;
        0) return ;;
        *) print_warn "Invalid choice."; sleep 1 ;;
    esac
}

# ─── Network Optimization ─────────────────────────────────

# ─── Network & System Optimization ──────────────────────
# Main menu — shows live status summary for all subsystems

network_optimization() {
    while true; do
        print_banner
        echo -e "${BOLD}  Network & System Optimization${NC}\n"

        # ── Live status summary ──────────────────────────
        local cc qdisc rmem swappiness sb_nice fd_limit jsize
        cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
        qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
        rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
        swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "?")
        sb_nice=$(ps -eo comm,nice 2>/dev/null | awk '/^sing-box/{print $2}' | head -1)
        [[ -z "$sb_nice" ]] && sb_nice="not running"
        fd_limit=$(grep -E "^\*.*nofile|^root.*nofile" /etc/security/limits.conf 2>/dev/null \
                   | awk '{print $NF}' | tail -1 || echo "default")
        jsize=$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+[KMGT]' | tail -1 || echo "?")

        # Network row
        if [[ "$cc" == "bbr" ]]; then
            echo -e "  Network:  BBR ${GREEN}[ON]${NC}  qdisc:${qdisc}  buffers:$([ "$rmem" -gt 1000000 ] && echo "${GREEN}optimized${NC}" || echo "${YELLOW}default${NC}")"
        else
            echo -e "  Network:  BBR ${RED}[OFF]${NC} cc:${cc}  buffers:$([ "$rmem" -gt 1000000 ] && echo "${GREEN}optimized${NC}" || echo "${YELLOW}default${NC}")"
        fi
        # System row
        echo -e "  System:   swappiness:${CYAN}${swappiness}${NC}  sing-box nice:${CYAN}${sb_nice}${NC}"
        # Storage row
        echo -e "  Storage:  journal:${CYAN}${jsize}${NC}  fd-limit:${CYAN}${fd_limit}${NC}"

        echo ""
        echo -e "  ${CYAN}1)${NC}  Network  — BBR & TCP tuning"
        echo -e "  ${CYAN}2)${NC}  System   — Memory & CPU priority"
        echo -e "  ${CYAN}3)${NC}  Storage  — Logging & File descriptors"
        echo -e "  ${CYAN}──────────────────────────────────${NC}"
        echo -e "  ${CYAN}4)${NC}  ${BOLD}Apply ALL optimizations${NC}  (recommended)"
        echo -e "  ${CYAN}5)${NC}  Reset ALL to system defaults"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice
        case "$choice" in
            1) _menu_network ;;
            2) _menu_system ;;
            3) _menu_storage ;;
            4) _apply_all_optimizations ;;
            5) _reset_all_defaults ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

# ──────────────────────────────────────────────────────────
# SUB-MENU 1 : Network — BBR & TCP
# ──────────────────────────────────────────────────────────

_menu_network() {
    while true; do
        print_banner
        echo -e "${BOLD}  Network — BBR & TCP Tuning${NC}\n"

        local cc qdisc rmem
        cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
        qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
        rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")

        echo -e "  BBR:         $([[ "$cc" == "bbr" ]] && echo "${GREEN}[ACTIVE]${NC}" || echo "${RED}[INACTIVE]${NC}")  (cc: ${cc} / qdisc: ${qdisc})"
        echo -e "  TCP Buffers: $([[ "$rmem" -gt 1000000 ]] && echo "${GREEN}[OPTIMIZED]${NC}" || echo "${YELLOW}[DEFAULT]${NC}")"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Enable BBR + FQ"
        echo -e "  ${CYAN}2)${NC}  Disable BBR (revert to cubic)"
        echo -e "  ${CYAN}3)${NC}  Apply TCP buffer optimization"
        echo -e "  ${CYAN}4)${NC}  Apply both (BBR + TCP buffers)"
        echo -e "  ${CYAN}5)${NC}  Show all current network values"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice
        case "$choice" in
            1) enable_bbr ;;
            2) disable_bbr ;;
            3) apply_tcp_optimization ;;
            4) enable_bbr; apply_tcp_optimization ;;
            5) show_sysctl_values ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

enable_bbr() {
    print_info "Enabling BBR congestion control..."
    # Check if kernel supports BBR
    if ! modprobe tcp_bbr 2>/dev/null && \
       ! grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        print_warn "BBR module not available on this kernel. Trying anyway..."
    fi
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
    {
        echo "net.core.default_qdisc=fq"
        echo "net.ipv4.tcp_congestion_control=bbr"
    } >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    local active_cc
    active_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$active_cc" == "bbr" ]]; then
        print_success "BBR enabled successfully. (qdisc: fq)"
    else
        print_error "BBR could not be activated. Active cc: ${active_cc}"
    fi
    press_enter
}

disable_bbr() {
    print_info "Reverting to cubic..."
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
    echo "net.ipv4.tcp_congestion_control=cubic" >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    print_success "Congestion control reverted to cubic."
    press_enter
}

apply_tcp_optimization() {
    print_info "Applying TCP buffer & keepalive optimization for high-latency links..."
    for key in net.core.rmem_max net.core.wmem_max \
               net.ipv4.tcp_rmem net.ipv4.tcp_wmem \
               net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing \
               net.ipv4.tcp_slow_start_after_idle net.ipv4.tcp_no_metrics_save \
               net.ipv4.tcp_timestamps \
               net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl \
               net.ipv4.tcp_keepalive_probes net.ipv4.tcp_fin_timeout; do
        sed -i "/${key}/d" /etc/sysctl.conf 2>/dev/null || true
    done
    cat >> /etc/sysctl.conf << 'EOF'
# sing-box TCP optimization
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_timestamps=1
# Keepalive: keep idle connections alive through NAT/firewalls
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=6
net.ipv4.tcp_fin_timeout=15
EOF
    sysctl -p &>/dev/null
    print_success "TCP buffer & keepalive optimization applied."
    press_enter
}

show_sysctl_values() {
    echo ""
    echo -e "${BOLD}  Current network sysctl values:${NC}\n"
    for key in net.ipv4.tcp_congestion_control \
               net.core.default_qdisc \
               net.core.rmem_max \
               net.core.wmem_max \
               net.ipv4.tcp_rmem \
               net.ipv4.tcp_wmem \
               net.ipv4.tcp_fastopen \
               net.ipv4.tcp_mtu_probing \
               net.ipv4.tcp_slow_start_after_idle \
               net.ipv4.tcp_no_metrics_save \
               net.ipv4.tcp_timestamps; do
        local val
        val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        printf "  %-48s ${CYAN}%s${NC}\n" "$key" "$val"
    done
    press_enter
}

# ──────────────────────────────────────────────────────────
# SUB-MENU 2 : System — Memory & CPU
# ──────────────────────────────────────────────────────────

_menu_system() {
    while true; do
        print_banner
        echo -e "${BOLD}  System — Memory & CPU Priority${NC}\n"

        local swappiness oom_adj sb_nice sb_pid
        swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "?")
        sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
        if [[ -n "$sb_pid" ]]; then
            sb_nice=$(ps -o nice= -p "$sb_pid" 2>/dev/null | tr -d ' ' || echo "?")
            oom_adj=$(cat /proc/"${sb_pid}"/oom_score_adj 2>/dev/null || echo "?")
        else
            sb_nice="(not running)"; oom_adj="(not running)"
        fi

        echo -e "  vm.swappiness:        ${CYAN}${swappiness}${NC}  $([ "$swappiness" -le 10 ] 2>/dev/null && echo "${GREEN}[OPTIMIZED]${NC}" || echo "${YELLOW}[DEFAULT=60]${NC}")"
        echo -e "  sing-box nice value:  ${CYAN}${sb_nice}${NC}  $([ "$sb_nice" == "-5" ] 2>/dev/null && echo "${GREEN}[OPTIMIZED]${NC}" || echo "")"
        echo -e "  sing-box OOM score:   ${CYAN}${oom_adj}${NC}  $([ "$oom_adj" == "-500" ] 2>/dev/null && echo "${GREEN}[PROTECTED]${NC}" || echo "")"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Optimize swap behavior  (swappiness: 60 → 10)"
        echo -e "  ${CYAN}2)${NC}  Set CPU priority for sing-box  (nice: -5)"
        echo -e "  ${CYAN}3)${NC}  Protect sing-box from OOM killer"
        echo -e "  ${CYAN}4)${NC}  Apply all system optimizations"
        echo -e "  ${CYAN}5)${NC}  Show memory & CPU info"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice
        case "$choice" in
            1) _opt_swappiness ;;
            2) _opt_cpu_priority ;;
            3) _opt_oom_protect ;;
            4) _opt_swappiness; _opt_cpu_priority; _opt_oom_protect ;;
            5) _show_system_info ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

_opt_swappiness() {
    print_info "Setting vm.swappiness to 10 (reduces RAM-to-swap eviction)..."
    sed -i '/vm.swappiness/d' /etc/sysctl.conf 2>/dev/null || true
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    sysctl -w vm.swappiness=10 &>/dev/null
    print_success "swappiness set to 10. Kernel will avoid swap unless RAM is >90% used."

    # Also set vfs_cache_pressure to keep filesystem cache in RAM longer
    sed -i '/vm.vfs_cache_pressure/d' /etc/sysctl.conf 2>/dev/null || true
    echo "vm.vfs_cache_pressure=50" >> /etc/sysctl.conf
    sysctl -w vm.vfs_cache_pressure=50 &>/dev/null
    print_success "vfs_cache_pressure set to 50."
    press_enter
}

_opt_cpu_priority() {
    print_info "Setting CPU scheduling priority for sing-box..."

    # Set nice value in systemd service unit via drop-in
    mkdir -p /etc/systemd/system/sing-box.service.d
    cat > /etc/systemd/system/sing-box.service.d/priority.conf << 'EOF'
[Service]
Nice=-5
CPUSchedulingPolicy=other
IOSchedulingClass=best-effort
IOSchedulingPriority=2
EOF
    systemctl daemon-reload

    # Apply to running process immediately if active
    local sb_pid
    sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
    if [[ -n "$sb_pid" ]]; then
        renice -n -5 -p "$sb_pid" &>/dev/null && \
            print_success "CPU nice value set to -5 on running process (PID: ${sb_pid})." || \
            print_warn "Could not renice running process. Will apply on next restart."
    fi
    print_success "CPU priority drop-in saved. sing-box will start with nice=-5 on future restarts."

    # Restart to apply fully
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        print_info "Restarting sing-box to apply priority settings..."
        systemctl restart sing-box
        sleep 2
        systemctl is-active --quiet sing-box && print_success "sing-box restarted." || \
            print_error "sing-box failed to restart."
    fi
    press_enter
}

_opt_oom_protect() {
    print_info "Protecting sing-box from OOM killer..."

    # Set OOM score in systemd service drop-in
    mkdir -p /etc/systemd/system/sing-box.service.d
    # Append to existing drop-in or create new one
    if [[ -f /etc/systemd/system/sing-box.service.d/priority.conf ]]; then
        # Add OOMScoreAdjust to existing file if not present
        grep -q "OOMScoreAdjust" /etc/systemd/system/sing-box.service.d/priority.conf || \
            echo "OOMScoreAdjust=-500" >> /etc/systemd/system/sing-box.service.d/priority.conf
    else
        cat > /etc/systemd/system/sing-box.service.d/priority.conf << 'EOF'
[Service]
OOMScoreAdjust=-500
EOF
    fi
    systemctl daemon-reload

    # Apply to running process immediately
    local sb_pid
    sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
    if [[ -n "$sb_pid" ]]; then
        echo -500 > /proc/"${sb_pid}"/oom_score_adj 2>/dev/null && \
            print_success "OOM score set to -500 on running process. sing-box is now protected." || \
            print_warn "Could not set OOM score on running process."
    fi
    print_success "OOM protection drop-in saved. Will persist across restarts."
    press_enter
}

_show_system_info() {
    echo ""
    echo -e "${BOLD}  Memory & CPU Info:${NC}\n"

    # RAM usage
    local total used free cached
    read -r total used free _ cached _ < <(free -m | awk '/^Mem:/{print $2,$3,$4,$5,$6,$7}')
    echo -e "  RAM:         Total=${CYAN}${total}MB${NC}  Used=${CYAN}${used}MB${NC}  Free=${CYAN}${free}MB${NC}  Cached=${CYAN}${cached}MB${NC}"

    # Swap
    local swap_total swap_used
    read -r swap_total swap_used _ < <(free -m | awk '/^Swap:/{print $2,$3,$4}')
    echo -e "  Swap:        Total=${CYAN}${swap_total}MB${NC}  Used=${CYAN}${swap_used}MB${NC}"

    # CPU
    echo -e "  CPU cores:   ${CYAN}$(nproc)${NC}"
    local load
    load=$(uptime | awk -F'load average:' '{print $2}' | tr -d ' ')
    echo -e "  Load avg:    ${CYAN}${load}${NC}"

    # sing-box process
    local sb_pid
    sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
    if [[ -n "$sb_pid" ]]; then
        local sb_mem sb_cpu sb_nice_val sb_oom
        sb_mem=$(ps -o rss= -p "$sb_pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        sb_cpu=$(ps -o %cpu= -p "$sb_pid" 2>/dev/null | tr -d ' ')
        sb_nice_val=$(ps -o nice= -p "$sb_pid" 2>/dev/null | tr -d ' ')
        sb_oom=$(cat /proc/"${sb_pid}"/oom_score_adj 2>/dev/null || echo "?")
        echo ""
        echo -e "  sing-box PID:     ${CYAN}${sb_pid}${NC}"
        echo -e "  sing-box Memory:  ${CYAN}${sb_mem}${NC}"
        echo -e "  sing-box CPU%:    ${CYAN}${sb_cpu}%${NC}"
        echo -e "  sing-box Nice:    ${CYAN}${sb_nice_val}${NC}"
        echo -e "  sing-box OOM adj: ${CYAN}${sb_oom}${NC}"
    else
        echo -e "\n  sing-box: ${YELLOW}not running${NC}"
    fi

    echo ""
    echo -e "  vm.swappiness:        ${CYAN}$(sysctl -n vm.swappiness 2>/dev/null)${NC}"
    echo -e "  vm.vfs_cache_pressure:${CYAN}$(sysctl -n vm.vfs_cache_pressure 2>/dev/null)${NC}"
    press_enter
}

# ──────────────────────────────────────────────────────────
# SUB-MENU 3 : Storage — Logging & File Descriptors
# ──────────────────────────────────────────────────────────

_menu_storage() {
    while true; do
        print_banner
        echo -e "${BOLD}  Storage — Logging & File Descriptors${NC}\n"

        local jsize jmax fd_sys fd_proc sb_fd
        jsize=$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+\s*[KMGT]' | tail -1 || echo "?")
        jmax=$(grep "^SystemMaxUse" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2 || echo "default")
        fd_sys=$(sysctl -n fs.file-max 2>/dev/null || echo "?")
        local sb_pid
        sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
        if [[ -n "$sb_pid" ]]; then
            sb_fd=$(ls /proc/"${sb_pid}"/fd 2>/dev/null | wc -l || echo "?")
        else
            sb_fd="(not running)"
        fi

        echo -e "  Journal disk usage:  ${CYAN}${jsize}${NC}  (limit: ${CYAN}${jmax}${NC})"
        echo -e "  System fd limit:     ${CYAN}${fd_sys}${NC}"
        echo -e "  sing-box open fds:   ${CYAN}${sb_fd}${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Limit journald size  (cap at 50MB, rotate aggressively)"
        echo -e "  ${CYAN}2)${NC}  Optimize file descriptors  (raise ulimit)"
        echo -e "  ${CYAN}3)${NC}  Apply both"
        echo -e "  ${CYAN}4)${NC}  Show storage & fd info"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice
        case "$choice" in
            1) _opt_journald ;;
            2) _opt_file_descriptors ;;
            3) _opt_journald; _opt_file_descriptors ;;
            4) _show_storage_info ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

_opt_journald() {
    print_info "Limiting journald log size to 50MB..."

    # Backup original if not already backed up
    [[ ! -f /etc/systemd/journald.conf.orig ]] && \
        cp /etc/systemd/journald.conf /etc/systemd/journald.conf.orig 2>/dev/null || true

    # Patch journald.conf
    local conf="/etc/systemd/journald.conf"
    for key in SystemMaxUse SystemKeepFree SystemMaxFileSize \
               RuntimeMaxUse MaxRetentionSec MaxFileSec; do
        sed -i "/^#*${key}/d" "$conf" 2>/dev/null || true
    done
    cat >> "$conf" << 'EOF'
# sing-box optimization: keep journal small
SystemMaxUse=50M
SystemKeepFree=100M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
MaxRetentionSec=1week
MaxFileSec=1day
EOF
    systemctl restart systemd-journald 2>/dev/null
    sleep 1
    # Vacuum immediately to reclaim existing space
    journalctl --vacuum-size=50M &>/dev/null
    journalctl --vacuum-time=1week &>/dev/null
    local new_size
    new_size=$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+\s*[KMGT][B]*' | tail -1 || echo "?")
    print_success "journald capped at 50MB. Current usage: ${new_size}"
    press_enter
}

_opt_file_descriptors() {
    print_info "Raising file descriptor limits for sing-box..."

    # System-wide kernel limit
    sed -i '/fs.file-max/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/fs.nr_open/d' /etc/sysctl.conf 2>/dev/null || true
    {
        echo "fs.file-max=1048576"
        echo "fs.nr_open=1048576"
    } >> /etc/sysctl.conf
    sysctl -w fs.file-max=1048576 &>/dev/null
    sysctl -w fs.nr_open=1048576 &>/dev/null

    # PAM limits for all users
    sed -i '/nofile/d' /etc/security/limits.conf 2>/dev/null || true
    cat >> /etc/security/limits.conf << 'EOF'
# sing-box file descriptor optimization
*    soft nofile 1048576
*    hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

    # systemd service LimitNOFILE drop-in
    mkdir -p /etc/systemd/system/sing-box.service.d
    if [[ -f /etc/systemd/system/sing-box.service.d/priority.conf ]]; then
        grep -q "LimitNOFILE" /etc/systemd/system/sing-box.service.d/priority.conf || \
            echo "LimitNOFILE=1048576" >> /etc/systemd/system/sing-box.service.d/priority.conf
    else
        cat > /etc/systemd/system/sing-box.service.d/priority.conf << 'EOF'
[Service]
LimitNOFILE=1048576
EOF
    fi
    systemctl daemon-reload

    # Apply to running process if possible
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        print_info "Restarting sing-box to apply fd limits..."
        systemctl restart sing-box
        sleep 2
        systemctl is-active --quiet sing-box && print_success "sing-box restarted." || \
            print_error "sing-box failed to restart."
    fi
    print_success "File descriptor limit raised to 1,048,576."
    press_enter
}

_show_storage_info() {
    echo ""
    echo -e "${BOLD}  Storage & File Descriptor Info:${NC}\n"
    echo -e "  Disk usage:"
    df -h / 2>/dev/null | awk 'NR==2{printf "    /  total=%-8s  used=%-8s  free=%s\n",$2,$3,$4}'
    echo ""
    echo -e "  Journal usage:  ${CYAN}$(journalctl --disk-usage 2>/dev/null | grep -oP '[\d.]+\s*\S+' | tail -1)${NC}"
    echo -e "  Journal limit:  ${CYAN}$(grep "^SystemMaxUse" /etc/systemd/journald.conf 2>/dev/null | cut -d= -f2 || echo "default")${NC}"
    echo ""
    echo -e "  fs.file-max:    ${CYAN}$(sysctl -n fs.file-max 2>/dev/null)${NC}"
    echo -e "  PAM nofile:     ${CYAN}$(grep -E "^\*.*hard.*nofile" /etc/security/limits.conf 2>/dev/null | awk '{print $NF}' | tail -1 || echo "default")${NC}"

    local sb_pid
    sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
    if [[ -n "$sb_pid" ]]; then
        local hard_limit
        hard_limit=$(cat /proc/"${sb_pid}"/limits 2>/dev/null | awk '/Max open files/{print $5}')
        echo -e "  sing-box fd limit: ${CYAN}${hard_limit:-?}${NC}"
        echo -e "  sing-box open fds: ${CYAN}$(ls /proc/"${sb_pid}"/fd 2>/dev/null | wc -l)${NC}"
    fi
    press_enter
}

# ──────────────────────────────────────────────────────────
# Apply ALL  /  Reset ALL
# ──────────────────────────────────────────────────────────

_apply_all_optimizations() {
    print_banner
    echo -e "${BOLD}  Applying ALL Optimizations...${NC}\n"
    echo -e "  This will configure: BBR, TCP buffers, swappiness,"
    echo -e "  CPU/OOM priority, journald size, file descriptors.\n"

    echo -e "${BOLD}── 1/6  BBR + FQ ──────────────────────────────────${NC}"
    modprobe tcp_bbr 2>/dev/null || true
    sed -i '/net.core.default_qdisc/d;/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n' >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] \
        && print_success "BBR enabled." || print_warn "BBR could not be set (kernel may not support it)."

    echo -e "\n${BOLD}── 2/6  TCP Buffers & Keepalive ───────────────────${NC}"
    for key in net.core.rmem_max net.core.wmem_max \
               net.ipv4.tcp_rmem net.ipv4.tcp_wmem \
               net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing \
               net.ipv4.tcp_slow_start_after_idle net.ipv4.tcp_no_metrics_save \
               net.ipv4.tcp_timestamps \
               net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl \
               net.ipv4.tcp_keepalive_probes net.ipv4.tcp_fin_timeout; do
        sed -i "/${key}/d" /etc/sysctl.conf 2>/dev/null || true
    done
    cat >> /etc/sysctl.conf << 'EOF'
# sing-box TCP optimization
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=6
net.ipv4.tcp_fin_timeout=15
EOF
    sysctl -p &>/dev/null
    print_success "TCP buffers & keepalive optimized."

    echo -e "\n${BOLD}── 3/6  Swap & Cache ──────────────────────────────${NC}"
    sed -i '/vm.swappiness/d;/vm.vfs_cache_pressure/d' /etc/sysctl.conf 2>/dev/null || true
    printf 'vm.swappiness=10\nvm.vfs_cache_pressure=50\n' >> /etc/sysctl.conf
    sysctl -w vm.swappiness=10 &>/dev/null
    sysctl -w vm.vfs_cache_pressure=50 &>/dev/null
    print_success "swappiness=10, vfs_cache_pressure=50."

    echo -e "\n${BOLD}── 4/6  CPU & OOM Priority ────────────────────────${NC}"
    mkdir -p /etc/systemd/system/sing-box.service.d
    cat > /etc/systemd/system/sing-box.service.d/priority.conf << 'EOF'
[Service]
Nice=-5
CPUSchedulingPolicy=other
IOSchedulingClass=best-effort
IOSchedulingPriority=2
OOMScoreAdjust=-500
LimitNOFILE=1048576
EOF
    systemctl daemon-reload
    local sb_pid
    sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
    if [[ -n "$sb_pid" ]]; then
        renice -n -5 -p "$sb_pid" &>/dev/null || true
        echo -500 > /proc/"${sb_pid}"/oom_score_adj 2>/dev/null || true
    fi
    print_success "CPU nice=-5, OOM protect=-500, LimitNOFILE=1048576 set."

    echo -e "\n${BOLD}── 5/6  File Descriptors ──────────────────────────${NC}"
    sed -i '/fs.file-max/d;/fs.nr_open/d' /etc/sysctl.conf 2>/dev/null || true
    printf 'fs.file-max=1048576\nfs.nr_open=1048576\n' >> /etc/sysctl.conf
    sysctl -w fs.file-max=1048576 &>/dev/null
    sysctl -w fs.nr_open=1048576 &>/dev/null
    sed -i '/nofile/d' /etc/security/limits.conf 2>/dev/null || true
    cat >> /etc/security/limits.conf << 'EOF'
# sing-box file descriptor optimization
*    soft nofile 1048576
*    hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    print_success "File descriptor limit set to 1,048,576."

    echo -e "\n${BOLD}── 6/6  Journald Size ─────────────────────────────${NC}"
    [[ ! -f /etc/systemd/journald.conf.orig ]] && \
        cp /etc/systemd/journald.conf /etc/systemd/journald.conf.orig 2>/dev/null || true
    local jconf="/etc/systemd/journald.conf"
    for key in SystemMaxUse SystemKeepFree SystemMaxFileSize \
               RuntimeMaxUse MaxRetentionSec MaxFileSec; do
        sed -i "/^#*${key}/d" "$jconf" 2>/dev/null || true
    done
    cat >> "$jconf" << 'EOF'
# sing-box optimization
SystemMaxUse=50M
SystemKeepFree=100M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
MaxRetentionSec=1week
MaxFileSec=1day
EOF
    systemctl restart systemd-journald 2>/dev/null
    journalctl --vacuum-size=50M &>/dev/null
    print_success "journald capped at 50MB."

    # Final: restart sing-box to apply all service-level changes
    echo ""
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        print_info "Restarting sing-box to apply all changes..."
        systemctl restart sing-box
        sleep 2
        systemctl is-active --quiet sing-box \
            && print_success "sing-box restarted successfully." \
            || print_error "sing-box failed to restart — check logs."
    fi

    echo ""
    echo -e "${GREEN}${BOLD}+--------------------------------------------+"
    echo -e "|   All optimizations applied successfully!  |"
    echo -e "+--------------------------------------------+${NC}"
    press_enter
}

_reset_all_defaults() {
    print_banner
    echo -e "${BOLD}  Reset All Settings to System Defaults${NC}\n"
    echo -e "  ${YELLOW}This will remove all sing-box optimizations from:${NC}"
    echo -e "  /etc/sysctl.conf, /etc/security/limits.conf,"
    echo -e "  /etc/systemd/journald.conf, systemd drop-in files.\n"
    confirm "Are you sure you want to reset everything?" "n" || return

    # sysctl.conf — remove all blocks we added
    print_info "Removing sysctl tweaks..."
    for key in net.core.default_qdisc net.ipv4.tcp_congestion_control \
               net.core.rmem_max net.core.wmem_max \
               net.ipv4.tcp_rmem net.ipv4.tcp_wmem \
               net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing \
               net.ipv4.tcp_slow_start_after_idle net.ipv4.tcp_no_metrics_save \
               net.ipv4.tcp_timestamps \
               net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl \
               net.ipv4.tcp_keepalive_probes net.ipv4.tcp_fin_timeout \
               vm.swappiness vm.vfs_cache_pressure \
               fs.file-max fs.nr_open; do
        sed -i "/${key}/d" /etc/sysctl.conf 2>/dev/null || true
    done
    # Remove comment markers we added
    sed -i '/# sing-box TCP optimization/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/# sing-box optimization/d' /etc/sysctl.conf 2>/dev/null || true
    sysctl -p &>/dev/null
    print_success "sysctl.conf reset."

    # limits.conf
    print_info "Removing fd limits..."
    sed -i '/# sing-box file descriptor optimization/d' /etc/security/limits.conf 2>/dev/null || true
    sed -i '/nofile 1048576/d' /etc/security/limits.conf 2>/dev/null || true
    print_success "limits.conf reset."

    # journald — restore from backup if available
    print_info "Restoring journald config..."
    if [[ -f /etc/systemd/journald.conf.orig ]]; then
        cp /etc/systemd/journald.conf.orig /etc/systemd/journald.conf
        print_success "journald.conf restored from backup."
    else
        for key in SystemMaxUse SystemKeepFree SystemMaxFileSize \
                   RuntimeMaxUse MaxRetentionSec MaxFileSec; do
            sed -i "/^${key}/d" /etc/systemd/journald.conf 2>/dev/null || true
        done
        sed -i '/# sing-box optimization/d' /etc/systemd/journald.conf 2>/dev/null || true
        print_success "journald.conf cleaned."
    fi
    systemctl restart systemd-journald 2>/dev/null

    # Remove systemd drop-in
    print_info "Removing systemd service drop-in..."
    rm -f /etc/systemd/system/sing-box.service.d/priority.conf
    # Remove directory only if empty
    rmdir /etc/systemd/system/sing-box.service.d 2>/dev/null || true
    systemctl daemon-reload
    print_success "systemd drop-in removed."

    # Restart sing-box to apply
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        print_info "Restarting sing-box..."
        systemctl restart sing-box
        sleep 2
        systemctl is-active --quiet sing-box && print_success "sing-box restarted." || \
            print_error "sing-box failed to restart."
    fi

    print_success "All settings reset to system defaults."
    press_enter
}

# ─── Fail2ban ─────────────────────────────────────────────
# FIX: Completely rewritten to properly handle systemd journal logging
# sing-box writes logs to systemd journal (not /var/log/syslog)
# Solution: use systemd backend + write sing-box logs to a dedicated file

# Helper: detect the active sing-box service name
_get_singbox_service() {
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        echo "sing-box"
    elif systemctl is-active --quiet sing-box-client 2>/dev/null; then
        echo "sing-box-client"
    else
        # Service exists but inactive — return whichever unit file is present
        if systemctl list-unit-files sing-box.service &>/dev/null 2>&1; then
            echo "sing-box"
        else
            echo "sing-box"
        fi
    fi
}

# Helper: configure sing-box to also write logs to a dedicated log file
# so fail2ban can read them without needing systemd backend
_setup_singbox_logfile() {
    local log_dir="/var/log/sing-box"
    local log_file="${log_dir}/sing-box.log"

    # Create log directory
    mkdir -p "$log_dir"
    touch "$log_file"
    chmod 640 "$log_file"

    # Configure logrotate for sing-box logs
    cat > /etc/logrotate.d/sing-box << EOF
${log_file} {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
    postrotate
        systemctl kill -s HUP sing-box 2>/dev/null || true
        systemctl kill -s HUP sing-box-client 2>/dev/null || true
    endscript
}
EOF

    # Patch sing-box config to write logs to file (if config exists and server mode)
    if [[ -f "$SINGBOX_CONFIG" ]]; then
        python3 -c "
import json, sys
try:
    with open('${SINGBOX_CONFIG}') as f:
        config = json.load(f)
    log_cfg = config.get('log', {})
    log_cfg['level'] = log_cfg.get('level', 'info')
    log_cfg['output'] = '${log_file}'
    log_cfg['timestamp'] = True
    config['log'] = log_cfg
    with open('${SINGBOX_CONFIG}', 'w') as f:
        json.dump(config, f, indent=2)
    print('OK')
except Exception as e:
    print(f'WARN: {e}', file=sys.stderr)
    print('SKIP')
" 2>/dev/null || true
    fi

    echo "$log_file"
}

# Helper: setup rsyslog forwarding as alternative log source
_setup_rsyslog_forward() {
    local log_file="$1"
    # Forward sing-box journal entries to log file via rsyslog
    if command -v rsyslogd &>/dev/null || systemctl list-unit-files rsyslog.service &>/dev/null 2>&1; then
        cat > /etc/rsyslog.d/50-sing-box.conf << EOF
# Forward sing-box systemd journal entries to log file
:programname, isequal, "sing-box" ${log_file}
:programname, isequal, "sing-box-client" ${log_file}
& stop
EOF
        systemctl restart rsyslog 2>/dev/null || true
        print_info "rsyslog configured to forward sing-box logs."
    fi
}

fail2ban_menu() {
    while true; do
        print_banner
        echo -e "${BOLD}  Fail2ban - Intrusion Protection${NC}\n"
        local f2b_installed=false f2b_active=false
        command -v fail2ban-client &>/dev/null && f2b_installed=true
        $f2b_installed && systemctl is-active --quiet fail2ban 2>/dev/null && f2b_active=true

        if $f2b_active; then
            echo -e "  Fail2ban: ${GREEN}${BOLD}[ACTIVE]${NC}"
            local jail_status banned_count total_banned
            jail_status=$(fail2ban-client status singbox 2>/dev/null || echo "")
            if [[ -n "$jail_status" ]]; then
                banned_count=$(echo "$jail_status" | grep "Currently banned" | awk '{print $NF}')
                total_banned=$(echo "$jail_status" | grep "Total banned"     | awk '{print $NF}')
                echo -e "  Jail:     ${GREEN}[ACTIVE]${NC}"
                echo -e "  Banned now: ${CYAN}${banned_count}${NC}  |  Total banned: ${CYAN}${total_banned}${NC}"
            else
                echo -e "  Jail:     ${YELLOW}[NOT CONFIGURED]${NC}"
            fi
        elif $f2b_installed; then
            echo -e "  Fail2ban: ${YELLOW}${BOLD}[INSTALLED / INACTIVE]${NC}"
        else
            echo -e "  Fail2ban: ${RED}${BOLD}[NOT INSTALLED]${NC}"
        fi

        echo ""
        echo -e "  ${CYAN}1)${NC}  Install & configure fail2ban"
        echo -e "  ${CYAN}2)${NC}  Show banned IPs"
        echo -e "  ${CYAN}3)${NC}  Unban an IP"
        echo -e "  ${CYAN}4)${NC}  Change ban settings"
        echo -e "  ${CYAN}5)${NC}  Start / Stop fail2ban"
        echo -e "  ${CYAN}6)${NC}  Show fail2ban log (live)"
        echo -e "  ${CYAN}7)${NC}  Uninstall fail2ban"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice
        case "$choice" in
            1) install_fail2ban ;;
            2) show_banned_ips ;;
            3) unban_ip ;;
            4) change_ban_settings ;;
            5) toggle_fail2ban ;;
            6) tail -f /var/log/fail2ban.log 2>/dev/null || { print_error "Log not found."; press_enter; } ;;
            7) uninstall_fail2ban ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

install_fail2ban() {
    print_banner
    echo -e "${BOLD}  Install & Configure Fail2ban${NC}\n"

    # ── Step 1: Install fail2ban ──────────────────────────
    if ! command -v fail2ban-client &>/dev/null; then
        print_info "Updating package list..."
        apt-get update -qq
        print_info "Installing fail2ban..."
        apt-get install -y fail2ban &>/dev/null
        print_success "fail2ban installed."
    else
        print_info "fail2ban is already installed."
    fi

    # ── Step 2: Ensure rsyslog is available (needed for log file backend) ──
    if ! command -v rsyslogd &>/dev/null; then
        print_info "Installing rsyslog for log file support..."
        apt-get install -y rsyslog &>/dev/null && print_success "rsyslog installed." || \
            print_warn "rsyslog not available, will use systemd backend."
    fi

    # ── Step 3: Setup sing-box log file ──────────────────
    print_info "Configuring sing-box log file..."
    local log_file
    log_file=$(_setup_singbox_logfile)
    print_success "Log file: ${log_file}"

    # Setup rsyslog forwarding as secondary source
    _setup_rsyslog_forward "$log_file"

    # Restart sing-box to apply log config changes (if running)
    local sb_svc
    sb_svc=$(_get_singbox_service)
    if systemctl is-active --quiet "$sb_svc" 2>/dev/null; then
        print_info "Restarting ${sb_svc} to apply log config..."
        systemctl restart "$sb_svc" 2>/dev/null || true
        sleep 2
    fi

    # ── Step 4: Ask for ban settings ─────────────────────
    echo ""
    local maxretry bantime findtime
    ask maxretry "  Max failed attempts before ban"                  "5"
    ask findtime "  Time window in seconds"                         "60"
    ask bantime  "  Ban duration in seconds (3600=1h, 86400=1d)"   "3600"

    # ── Step 5: Write fail2ban filter ────────────────────
    print_info "Writing fail2ban filter..."
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/singbox.conf << 'EOF'
[INCLUDES]
before = common.conf

[Definition]
# Match REALITY invalid connection attempts (sing-box log format)
failregex = ^.*inbound connection from <HOST>:\d+.*REALITY.*invalid.*$
            ^.*\[.*\].*<HOST>.*connection rejected.*$
            ^.*tls.*handshake.*failed.*<HOST>.*$
            ^.*<HOST>.*tls.*error.*$

ignoreregex =

# Use ANSI date format for file-based logs
datepattern = {^LN-BEG}%%Y/%%m/%%d %%H:%%M:%%S
              {^LN-BEG}%%Y-%%m-%%dT%%H:%%M:%%S
              {^LN-BEG}\[%%Y-%%m-%%d %%H:%%M:%%S\]
EOF

    # ── Step 6: Write jail config ─────────────────────────
    print_info "Writing fail2ban jail config..."

    # Determine if systemd backend is available and preferred
    local use_systemd=false
    local f2b_version
    f2b_version=$(fail2ban-client version 2>/dev/null | grep -oP '\d+\.\d+' | head -1 || echo "0")
    # Check if log file is being populated (give it a moment)
    sleep 1
    if [[ -s "$log_file" ]]; then
        print_info "Using file-based log backend: ${log_file}"
        use_systemd=false
    else
        print_info "Log file empty; using systemd journal backend as primary."
        use_systemd=true
    fi

    if $use_systemd; then
        # systemd journal backend — does NOT need a log file
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}
backend   = systemd

[sshd]
enabled = false

[singbox]
enabled   = true
filter    = singbox
journalmatch = _SYSTEMD_UNIT=sing-box.service + _SYSTEMD_UNIT=sing-box-client.service
backend   = systemd
maxretry  = ${maxretry}
findtime  = ${findtime}
bantime   = ${bantime}
action    = iptables-allports[name=singbox, protocol=all]
EOF
    else
        # File-based backend
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}
backend   = auto

[sshd]
enabled = false

[singbox]
enabled   = true
filter    = singbox
logpath   = ${log_file}
            /var/log/syslog
backend   = auto
maxretry  = ${maxretry}
findtime  = ${findtime}
bantime   = ${bantime}
action    = iptables-allports[name=singbox, protocol=all]
EOF
    fi

    # ── Step 7: Validate config before starting ───────────
    print_info "Validating fail2ban configuration..."
    if ! fail2ban-client --test 2>/dev/null; then
        print_warn "Config validation warning — attempting fix..."
        # Fallback: use simplest possible systemd config
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}

[sshd]
enabled = false

[singbox]
enabled   = true
filter    = singbox
logpath   = /var/log/syslog
backend   = auto
maxretry  = ${maxretry}
findtime  = ${findtime}
bantime   = ${bantime}
action    = iptables-allports[name=singbox, protocol=all]
EOF
    fi

    # ── Step 8: Enable and start fail2ban ────────────────
    print_info "Enabling and starting fail2ban..."
    systemctl enable fail2ban &>/dev/null

    # Stop first to ensure clean start
    systemctl stop fail2ban 2>/dev/null || true
    sleep 1
    systemctl start fail2ban

    # Wait up to 10 seconds for fail2ban to become active
    local retries=0
    while [[ $retries -lt 10 ]]; do
        sleep 1
        if systemctl is-active --quiet fail2ban; then
            break
        fi
        retries=$((retries + 1))
    done

    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2ban is active and protecting your server."
        echo -e "\n  Max retries: ${CYAN}${maxretry}${NC} in ${CYAN}${findtime}${NC}s -> ban for ${CYAN}${bantime}${NC}s"
        echo -e "  Log source:  ${CYAN}$(${use_systemd} && echo 'systemd journal' || echo ${log_file})${NC}"

        # Show jail status
        sleep 2
        local jail_ok
        jail_ok=$(fail2ban-client status singbox 2>/dev/null | grep -c "singbox" || echo "0")
        if [[ "$jail_ok" -gt "0" ]]; then
            print_success "singbox jail is active."
        else
            print_warn "singbox jail may not be fully initialized yet. Check in a few seconds."
        fi
    else
        print_error "Fail2ban failed to start. Showing logs:"
        journalctl -u fail2ban --no-pager -n 20 2>/dev/null || \
            tail -20 /var/log/fail2ban.log 2>/dev/null || true
        echo ""
        print_warn "Attempting emergency fallback configuration..."
        _fail2ban_emergency_fallback "$bantime" "$findtime" "$maxretry"
    fi
    press_enter
}

# Emergency fallback: absolute minimal config guaranteed to work
_fail2ban_emergency_fallback() {
    local bantime="${1:-3600}" findtime="${2:-60}" maxretry="${3:-5}"
    # Write absolute minimal jail with only syslog
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}

[sshd]
enabled = false
EOF

    # Write simpler filter
    cat > /etc/fail2ban/filter.d/singbox.conf << 'EOF'
[Definition]
failregex = inbound connection from <HOST>
ignoreregex =
EOF

    # Try systemd backend only (no logpath needed)
    cat >> /etc/fail2ban/jail.local << EOF

[singbox]
enabled   = true
filter    = singbox
backend   = systemd
journalmatch = _SYSTEMD_UNIT=sing-box.service
maxretry  = ${maxretry}
findtime  = ${findtime}
bantime   = ${bantime}
action    = iptables-allports[name=singbox, protocol=all]
EOF

    systemctl restart fail2ban 2>/dev/null
    sleep 3
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2ban started with fallback configuration."
    else
        print_error "Fail2ban still cannot start. Check: journalctl -u fail2ban -n 30"
    fi
}

show_banned_ips() {
    print_banner
    echo -e "${BOLD}  Banned IPs${NC}\n"
    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_error "Fail2ban is not running."; press_enter; return
    fi
    local status
    status=$(fail2ban-client status singbox 2>/dev/null || echo "")
    [[ -z "$status" ]] && { print_warn "singbox jail not active."; press_enter; return; }
    echo "$status"
    echo ""
    local banned_list
    banned_list=$(echo "$status" | grep "Banned IP" | sed 's/.*Banned IP list:\s*//')
    if [[ -z "$banned_list" || "$banned_list" =~ ^[[:space:]]*$ ]]; then
        echo -e "  ${GREEN}No IPs are currently banned.${NC}"
    else
        echo -e "  ${BOLD}Currently banned:${NC}"
        for ip in $banned_list; do echo -e "  ${RED}  $ip${NC}"; done
    fi
    press_enter
}

unban_ip() {
    print_banner
    echo -e "${BOLD}  Unban an IP${NC}\n"
    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_error "Fail2ban is not running."; press_enter; return
    fi
    local banned_list
    banned_list=$(fail2ban-client status singbox 2>/dev/null | grep "Banned IP" | sed 's/.*Banned IP list:\s*//')
    if [[ -z "$banned_list" || "$banned_list" =~ ^[[:space:]]*$ ]]; then
        echo -e "  ${GREEN}No IPs are currently banned.${NC}"; press_enter; return
    fi
    echo -e "  ${BOLD}Currently banned:${NC}"
    for ip in $banned_list; do echo -e "  ${RED}  $ip${NC}"; done
    echo ""
    local target_ip
    ask target_ip "  Enter IP to unban" ""
    [[ -z "$target_ip" ]] && return
    fail2ban-client set singbox unbanip "$target_ip" &>/dev/null \
        && print_success "IP ${target_ip} unbanned." \
        || print_error "Failed to unban ${target_ip}."
    press_enter
}

change_ban_settings() {
    print_banner
    echo -e "${BOLD}  Change Ban Settings${NC}\n"
    local cur_maxretry cur_bantime cur_findtime
    cur_maxretry=$(grep "^maxretry" /etc/fail2ban/jail.local 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "5")
    cur_bantime=$(grep  "^bantime"  /etc/fail2ban/jail.local 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "3600")
    cur_findtime=$(grep "^findtime" /etc/fail2ban/jail.local 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "60")
    echo -e "  Current: maxretry=${CYAN}${cur_maxretry}${NC}  findtime=${CYAN}${cur_findtime}${NC}s  bantime=${CYAN}${cur_bantime}${NC}s\n"
    local maxretry bantime findtime
    ask maxretry "  New max retries"   "$cur_maxretry"
    ask findtime "  New find time (s)" "$cur_findtime"
    ask bantime  "  New ban time (s)"  "$cur_bantime"

    # Preserve existing backend setting when updating
    local current_backend
    current_backend=$(grep "^backend" /etc/fail2ban/jail.local 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "auto")
    local current_logpath
    current_logpath=$(grep "^logpath" /etc/fail2ban/jail.local 2>/dev/null | tail -1 | awk -F= '{print $2}' | tr -d ' ' || echo "")
    local current_journalmatch
    current_journalmatch=$(grep "^journalmatch" /etc/fail2ban/jail.local 2>/dev/null | tail -1 | sed 's/journalmatch\s*=\s*//' || echo "")

    if [[ "$current_backend" == "systemd" ]]; then
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}
backend   = systemd

[sshd]
enabled = false

[singbox]
enabled       = true
filter        = singbox
journalmatch  = ${current_journalmatch:-_SYSTEMD_UNIT=sing-box.service + _SYSTEMD_UNIT=sing-box-client.service}
backend       = systemd
maxretry      = ${maxretry}
findtime      = ${findtime}
bantime       = ${bantime}
action        = iptables-allports[name=singbox, protocol=all]
EOF
    else
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}
backend   = auto

[sshd]
enabled = false

[singbox]
enabled   = true
filter    = singbox
logpath   = ${current_logpath:-/var/log/sing-box/sing-box.log}
            /var/log/syslog
backend   = auto
maxretry  = ${maxretry}
findtime  = ${findtime}
bantime   = ${bantime}
action    = iptables-allports[name=singbox, protocol=all]
EOF
    fi

    systemctl restart fail2ban; sleep 2
    systemctl is-active --quiet fail2ban \
        && print_success "Settings updated and fail2ban restarted." \
        || print_error "Fail2ban failed to restart. Check: journalctl -u fail2ban -n 20"
    press_enter
}

toggle_fail2ban() {
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        systemctl stop fail2ban && print_success "Fail2ban stopped."
    else
        systemctl start fail2ban; sleep 2
        systemctl is-active --quiet fail2ban \
            && print_success "Fail2ban started." \
            || {
                print_error "Failed to start fail2ban."
                print_info "Check logs: journalctl -u fail2ban -n 20"
            }
    fi
    press_enter
}

uninstall_fail2ban() {
    confirm "Remove fail2ban completely?" "n" || return
    systemctl stop fail2ban 2>/dev/null || true
    systemctl disable fail2ban 2>/dev/null || true
    apt-get remove -y fail2ban &>/dev/null
    rm -f /etc/fail2ban/jail.local /etc/fail2ban/filter.d/singbox.conf
    rm -f /etc/rsyslog.d/50-sing-box.conf
    rm -f /etc/logrotate.d/sing-box
    # Remove log output from sing-box config (restore to stdout/journald)
    if [[ -f "$SINGBOX_CONFIG" ]]; then
        python3 -c "
import json
try:
    with open('${SINGBOX_CONFIG}') as f:
        config = json.load(f)
    if 'log' in config and 'output' in config['log']:
        del config['log']['output']
    with open('${SINGBOX_CONFIG}', 'w') as f:
        json.dump(config, f, indent=2)
except: pass
" 2>/dev/null || true
    fi
    # Restart rsyslog to remove sing-box forwarding
    systemctl restart rsyslog 2>/dev/null || true
    print_success "Fail2ban removed."
    press_enter
}

# ─── Speed Test ───────────────────────────────────────────

speed_test() {
    print_banner
    echo -e "${BOLD}  Server Speed Test${NC}\n"
    if ! command -v speedtest-cli &>/dev/null && ! command -v speedtest &>/dev/null; then
        print_warn "speedtest-cli is not installed."
        if confirm "Install speedtest-cli now?"; then
            apt-get update -qq && apt-get install -y speedtest-cli &>/dev/null
            print_success "speedtest-cli installed."
        else
            echo -e "\n${BOLD}  Quick bandwidth test (curl):${NC}\n"
            _curl_speed_test; return
        fi
    fi
    echo -e "  ${CYAN}1)${NC}  Full speed test (speedtest-cli)"
    echo -e "  ${CYAN}2)${NC}  Quick test (curl)"
    echo -e "  ${CYAN}0)${NC}  Back"
    echo ""
    echo -ne "${YELLOW}Choice: ${NC}"
    read -r choice
    case "$choice" in
        1)
            echo ""
            print_info "Running speed test... (30-60 seconds)"
            echo ""
            if command -v speedtest-cli &>/dev/null; then
                speedtest-cli 2>/dev/null || print_error "Speed test failed."
            else
                speedtest 2>/dev/null || print_error "Speed test failed."
            fi
            press_enter ;;
        2) echo ""; _curl_speed_test ;;
        0) return ;;
        *) print_warn "Invalid choice."; sleep 1 ;;
    esac
}

_curl_speed_test() {
    local server_ip
    server_ip=$(get_ipv4)
    echo -e "  Server IP: ${CYAN}${server_ip}${NC}\n"
    echo -ne "  ${BOLD}Download 10 MB:${NC}  "
    local s1
    s1=$(curl -4 -s -o /dev/null -w "%{speed_download}" "https://speed.cloudflare.com/__down?bytes=10000000" 2>/dev/null || echo "0")
    echo -e "${GREEN}$(python3 -c "print(f'{float(\"${s1}\")*8/1024/1024:.2f} Mbit/s')" 2>/dev/null)${NC}"
    echo -ne "  ${BOLD}Download 50 MB:${NC}  "
    local s2
    s2=$(curl -4 -s -o /dev/null -w "%{speed_download}" "https://speed.cloudflare.com/__down?bytes=50000000" 2>/dev/null || echo "0")
    echo -e "${GREEN}$(python3 -c "print(f'{float(\"${s2}\")*8/1024/1024:.2f} Mbit/s')" 2>/dev/null)${NC}"
    echo -ne "  ${BOLD}Latency 1.1.1.1:${NC} "
    local l1
    l1=$(ping -c 3 1.1.1.1 2>/dev/null | tail -1 | awk -F'/' '{print $5}' || echo "N/A")
    echo -e "${CYAN}${l1} ms${NC}"
    echo -ne "  ${BOLD}Latency 8.8.8.8:${NC} "
    local l2
    l2=$(ping -c 3 8.8.8.8 2>/dev/null | tail -1 | awk -F'/' '{print $5}' || echo "N/A")
    echo -e "${CYAN}${l2} ms${NC}"
    echo ""
    press_enter
}

# ─── Update ───────────────────────────────────────────────

update_singbox() {
    print_banner
    echo -e "${BOLD}  Update sing-box${NC}\n"
    if [[ ! -f "$SINGBOX_BIN" ]]; then
        print_error "sing-box is not installed."; press_enter; return
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
    [[ "$current" == "$SINGBOX_VERSION" ]] && { print_info "Already on latest."; press_enter; return; }
    confirm "Proceed with update?" || return
    systemctl stop sing-box 2>/dev/null || true
    systemctl stop sing-box-client 2>/dev/null || true
    install_singbox "$SINGBOX_VERSION"
    systemctl start sing-box 2>/dev/null || true
    systemctl start sing-box-client 2>/dev/null || true
    print_success "Update completed."
    press_enter
}

# ─── Uninstall ────────────────────────────────────────────

uninstall() {
    print_banner
    echo -e "${RED}${BOLD}  Uninstall sing-box${NC}\n"
    confirm "Are you sure? This cannot be undone!" "n" || return
    systemctl stop    sing-box 2>/dev/null || true
    systemctl stop    sing-box-client 2>/dev/null || true
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

# ─── Hysteria2 ────────────────────────────────────────────

get_latest_hy2_version() {
    local ver
    ver=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" \
        | grep '"tag_name"' | sed 's/.*"app\/v\([^"]*\)".*/\1/' | head -1)
    # fallback: try without app/ prefix
    if [[ -z "$ver" || "$ver" == *'"'* ]]; then
        ver=$(curl -s "https://api.github.com/repos/apernet/hysteria/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"[^/]*\/v\?\([0-9][^"]*\)".*/\1/')
    fi
    echo "$ver"
}

install_hysteria2_bin() {
    local ver="$1"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    print_info "Downloading Hysteria2 v${ver}..."
    local url="https://github.com/apernet/hysteria/releases/download/app%2Fv${ver}/hysteria-linux-amd64"
    if ! curl -L --progress-bar -o "${tmp_dir}/hysteria" "$url"; then
        print_error "Download failed. Check version or network."
        rm -rf "$tmp_dir"; return 1
    fi
    mv "${tmp_dir}/hysteria" "$HY2_BIN"
    chmod +x "$HY2_BIN"
    rm -rf "$tmp_dir"
    mkdir -p /etc/hysteria
    print_success "Hysteria2 v${ver} installed at ${HY2_BIN}."
}

create_hy2_service_server() {
    cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria2 Server
After=network.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-server &>/dev/null
    print_success "Service hysteria-server created and enabled."
}

# ─── Hysteria2 Performance Helpers ───────────────────────

# Measure download speed using curl against Cloudflare's speed endpoint (no external tools needed)
hy2_measure_bandwidth() {
    echo -e "\n${BOLD}  Measuring server bandwidth (native, no external tools)...${NC}"
    echo -e "  ${DIM}Downloading test data from Cloudflare edge — please wait (~15s)${NC}\n"

    # Download test: 50 MB from Cloudflare
    local dl_bps
    dl_bps=$(curl -4 -s -o /dev/null -w "%{speed_download}" \
        --max-time 12 \
        "https://speed.cloudflare.com/__down?bytes=52428800" 2>/dev/null || echo "0")

    # Upload test: POST 10 MB of zeros to Cloudflare
    local ul_bps
    ul_bps=$(dd if=/dev/zero bs=1M count=10 2>/dev/null \
        | curl -4 -s -o /dev/null -w "%{speed_upload}" \
            --max-time 12 -X POST \
            --data-binary @- \
            "https://speed.cloudflare.com/__up" 2>/dev/null || echo "0")

    # Convert bytes/s → Mbit/s
    local dl_mbit ul_mbit
    dl_mbit=$(python3 -c "v=float('${dl_bps}'); print(f'{v*8/1_000_000:.1f}')" 2>/dev/null || echo "0")
    ul_mbit=$(python3 -c "v=float('${ul_bps}'); print(f'{v*8/1_000_000:.1f}')" 2>/dev/null || echo "0")

    # Sanity check — if zero, fallback to a conservative estimate
    if [[ "$dl_mbit" == "0" || "$dl_mbit" == "0.0" ]]; then
        print_warn "Download measurement returned 0 — using conservative fallback (100 Mbit/s)."
        dl_mbit="100.0"
    fi
    if [[ "$ul_mbit" == "0" || "$ul_mbit" == "0.0" ]]; then
        print_warn "Upload measurement returned 0 — using conservative fallback (100 Mbit/s)."
        ul_mbit="100.0"
    fi

    echo -e "  ${BOLD}Results:${NC}"
    echo -e "    Download : ${GREEN}${dl_mbit} Mbit/s${NC}"
    echo -e "    Upload   : ${GREEN}${ul_mbit} Mbit/s${NC}"

    # Export results
    HY2_MEASURED_DL="$dl_mbit"
    HY2_MEASURED_UL="$ul_mbit"
}

# Calculate recommended bandwidth (85% of measured, rounded to nearest 10)
hy2_recommended_bw() {
    local measured="$1"
    python3 -c "
v = float('${measured}') * 0.85
# round to nearest 10, minimum 10
v = max(10, round(v / 10) * 10)
print(int(v))
" 2>/dev/null || echo "100"
}

# Calculate QUIC window profile based on available RAM
hy2_quic_profile() {
    local ram_mb
    ram_mb=$(free -m | awk '/^Mem:/{print $2}')

    local init_stream max_stream init_conn max_conn profile_name

    if   [[ "$ram_mb" -ge 3800 ]]; then
        profile_name="Large  (≥4 GB RAM)"
        init_stream=33554432   # 32 MB
        max_stream=67108864    # 64 MB
        init_conn=67108864     # 64 MB
        max_conn=134217728     # 128 MB
    elif [[ "$ram_mb" -ge 1800 ]]; then
        profile_name="Medium (2 GB RAM)"
        init_stream=16777216   # 16 MB
        max_stream=33554432    # 32 MB
        init_conn=33554432     # 32 MB
        max_conn=67108864      # 64 MB
    else
        profile_name="Small  (1 GB RAM)"
        init_stream=8388608    # 8 MB
        max_stream=16777216    # 16 MB
        init_conn=16777216     # 16 MB
        max_conn=33554432      # 32 MB
    fi

    echo "${profile_name}|${init_stream}|${max_stream}|${init_conn}|${max_conn}|${ram_mb}"
}

# Interactive parameter wizard — shows every param with explanation, suggested value, and range
hy2_optimize_wizard() {
    local skip_measure="${1:-no}"   # pass "skip" to reuse already-measured values

    print_banner
    echo -e "${BOLD}  Hysteria2 — Performance Optimization Wizard${NC}"
    echo -e "  ${DIM}Each parameter will be explained with a suggested value based on your hardware.${NC}\n"

    if [[ ! -f "$HY2_CONFIG" ]]; then
        print_error "Hysteria2 config not found at ${HY2_CONFIG}. Install Hysteria2 first."
        press_enter; return 1
    fi

    # ── Step 1: Bandwidth measurement ─────────────────────
    echo -e "${BOLD}  ── Step 1/3 : Bandwidth Measurement ──────────────────────${NC}"
    if [[ "$skip_measure" == "skip" && -n "$HY2_MEASURED_DL" ]]; then
        echo -e "  ${DIM}Using previously measured values.${NC}"
        echo -e "    Download : ${GREEN}${HY2_MEASURED_DL} Mbit/s${NC}"
        echo -e "    Upload   : ${GREEN}${HY2_MEASURED_UL} Mbit/s${NC}"
    else
        hy2_measure_bandwidth
    fi

    local rec_dl rec_ul
    rec_dl=$(hy2_recommended_bw "$HY2_MEASURED_DL")
    rec_ul=$(hy2_recommended_bw "$HY2_MEASURED_UL")

    # ── Step 2: QUIC profile ───────────────────────────────
    echo -e "\n${BOLD}  ── Step 2/3 : System Resource Analysis ────────────────────${NC}"
    local quic_raw profile_name init_stream max_stream init_conn max_conn ram_mb
    quic_raw=$(hy2_quic_profile)
    IFS='|' read -r profile_name init_stream max_stream init_conn max_conn ram_mb <<< "$quic_raw"
    echo -e "  RAM detected : ${CYAN}${ram_mb} MB${NC}"
    echo -e "  QUIC profile : ${GREEN}${profile_name}${NC}"

    # ── Step 3: Interactive parameter confirmation ─────────
    echo -e "\n${BOLD}  ── Step 3/3 : Parameter Configuration ─────────────────────${NC}"
    echo -e "  ${DIM}Review each parameter. Press Enter to accept the suggested value, or type your own.${NC}\n"

    local final_ul final_dl final_init_stream final_max_stream final_init_conn final_max_conn
    local final_idle_timeout final_keepalive

    # ── bandwidth.up ──
    echo -e "  ${CYAN}${BOLD}[ bandwidth.up ]${NC}"
    echo -e "  ${DIM}How much upload bandwidth Hysteria2 is allowed to use on this server.${NC}"
    echo -e "  ${DIM}Set slightly below the measured max to leave headroom for stability.${NC}"
    echo -e "  ${DIM}Range: 10 – 10000 Mbit/s   |   Measured: ${HY2_MEASURED_UL} Mbit/s${NC}"
    echo -ne "  ${YELLOW}Suggested [${rec_ul} mbps]: ${NC}"
    read -r inp; inp="${inp:-${rec_ul}}"
    # strip non-numeric suffix if user typed "200 mbps"
    inp=$(echo "$inp" | grep -oP '^\d+')
    final_ul="${inp:-$rec_ul}"
    echo ""

    # ── bandwidth.down ──
    echo -e "  ${CYAN}${BOLD}[ bandwidth.down ]${NC}"
    echo -e "  ${DIM}How much download bandwidth Hysteria2 is allowed to use on this server.${NC}"
    echo -e "  ${DIM}Clients use this to throttle their requests — keep it realistic.${NC}"
    echo -e "  ${DIM}Range: 10 – 10000 Mbit/s   |   Measured: ${HY2_MEASURED_DL} Mbit/s${NC}"
    echo -ne "  ${YELLOW}Suggested [${rec_dl} mbps]: ${NC}"
    read -r inp; inp="${inp:-${rec_dl}}"
    inp=$(echo "$inp" | grep -oP '^\d+')
    final_dl="${inp:-$rec_dl}"
    echo ""

    # ── quic.initStreamReceiveWindow ──
    local init_stream_mb
    init_stream_mb=$(python3 -c "print(f'{${init_stream}/1048576:.0f} MB')" 2>/dev/null)
    echo -e "  ${CYAN}${BOLD}[ quic.initStreamReceiveWindow ]${NC}"
    echo -e "  ${DIM}Initial receive buffer for each QUIC stream.${NC}"
    echo -e "  ${DIM}Larger = faster ramp-up on high-BDP links; too large wastes RAM on low-memory VPS.${NC}"
    echo -e "  ${DIM}Range: 1 MB – 64 MB   |   Profile suggests: ${init_stream_mb}${NC}"
    echo -ne "  ${YELLOW}Suggested [${init_stream}]: ${NC}"
    read -r inp; inp="${inp:-${init_stream}}"
    inp=$(echo "$inp" | grep -oP '^\d+')
    final_init_stream="${inp:-$init_stream}"
    echo ""

    # ── quic.maxStreamReceiveWindow ──
    local max_stream_mb
    max_stream_mb=$(python3 -c "print(f'{${max_stream}/1048576:.0f} MB')" 2>/dev/null)
    echo -e "  ${CYAN}${BOLD}[ quic.maxStreamReceiveWindow ]${NC}"
    echo -e "  ${DIM}Maximum the stream window can grow to. Must be ≥ initStreamReceiveWindow.${NC}"
    echo -e "  ${DIM}Range: initStream – 128 MB   |   Profile suggests: ${max_stream_mb}${NC}"
    echo -ne "  ${YELLOW}Suggested [${max_stream}]: ${NC}"
    read -r inp; inp="${inp:-${max_stream}}"
    inp=$(echo "$inp" | grep -oP '^\d+')
    final_max_stream="${inp:-$max_stream}"
    echo ""

    # ── quic.initConnReceiveWindow ──
    local init_conn_mb
    init_conn_mb=$(python3 -c "print(f'{${init_conn}/1048576:.0f} MB')" 2>/dev/null)
    echo -e "  ${CYAN}${BOLD}[ quic.initConnReceiveWindow ]${NC}"
    echo -e "  ${DIM}Initial receive buffer for the entire QUIC connection (sum of all streams).${NC}"
    echo -e "  ${DIM}Should be 2× initStreamReceiveWindow for typical single-user tunnels.${NC}"
    echo -e "  ${DIM}Range: 2 MB – 128 MB   |   Profile suggests: ${init_conn_mb}${NC}"
    echo -ne "  ${YELLOW}Suggested [${init_conn}]: ${NC}"
    read -r inp; inp="${inp:-${init_conn}}"
    inp=$(echo "$inp" | grep -oP '^\d+')
    final_init_conn="${inp:-$init_conn}"
    echo ""

    # ── quic.maxConnReceiveWindow ──
    local max_conn_mb
    max_conn_mb=$(python3 -c "print(f'{${max_conn}/1048576:.0f} MB')" 2>/dev/null)
    echo -e "  ${CYAN}${BOLD}[ quic.maxConnReceiveWindow ]${NC}"
    echo -e "  ${DIM}Maximum the connection window can grow to. Should be 2× maxStreamReceiveWindow.${NC}"
    echo -e "  ${DIM}Range: 4 MB – 256 MB   |   Profile suggests: ${max_conn_mb}${NC}"
    echo -ne "  ${YELLOW}Suggested [${max_conn}]: ${NC}"
    read -r inp; inp="${inp:-${max_conn}}"
    inp=$(echo "$inp" | grep -oP '^\d+')
    final_max_conn="${inp:-$max_conn}"
    echo ""

    # ── quic.maxIdleTimeout ──
    echo -e "  ${CYAN}${BOLD}[ quic.maxIdleTimeout ]${NC}"
    echo -e "  ${DIM}How long a connection can be idle before the server closes it.${NC}"
    echo -e "  ${DIM}60s is a good balance — too short causes reconnects, too long wastes resources.${NC}"
    echo -e "  ${DIM}Range: 15s – 300s${NC}"
    echo -ne "  ${YELLOW}Suggested [60s]: ${NC}"
    read -r inp; inp="${inp:-60s}"
    # ensure 's' suffix
    [[ "$inp" =~ ^[0-9]+$ ]] && inp="${inp}s"
    final_idle_timeout="$inp"
    echo ""

    # ── quic.keepAlivePeriod ──
    echo -e "  ${CYAN}${BOLD}[ quic.keepAlivePeriod ]${NC}"
    echo -e "  ${DIM}How often the server sends PING frames to keep the connection alive through NAT/firewalls.${NC}"
    echo -e "  ${DIM}20s is ideal for most Iranian ISP NAT tables which time out around 30s.${NC}"
    echo -e "  ${DIM}Range: 5s – 60s${NC}"
    echo -ne "  ${YELLOW}Suggested [20s]: ${NC}"
    read -r inp; inp="${inp:-20s}"
    [[ "$inp" =~ ^[0-9]+$ ]] && inp="${inp}s"
    final_keepalive="$inp"
    echo ""

    # ── Summary ───────────────────────────────────────────
    echo -e "\n${BOLD}  Summary of changes to be applied:${NC}"
    echo -e "  ┌──────────────────────────────────────────────────────┐"
    printf  "  │  %-35s %s\n" "bandwidth.up:"                "${final_ul} mbps"
    printf  "  │  %-35s %s\n" "bandwidth.down:"              "${final_dl} mbps"
    printf  "  │  %-35s %s\n" "quic.initStreamReceiveWindow:" "${final_init_stream}"
    printf  "  │  %-35s %s\n" "quic.maxStreamReceiveWindow:"  "${final_max_stream}"
    printf  "  │  %-35s %s\n" "quic.initConnReceiveWindow:"   "${final_init_conn}"
    printf  "  │  %-35s %s\n" "quic.maxConnReceiveWindow:"    "${final_max_conn}"
    printf  "  │  %-35s %s\n" "quic.maxIdleTimeout:"          "${final_idle_timeout}"
    printf  "  │  %-35s %s\n" "quic.keepAlivePeriod:"         "${final_keepalive}"
    echo -e "  └──────────────────────────────────────────────────────┘\n"

    confirm "Apply these settings to ${HY2_CONFIG}?" "y" || { print_info "Aborted. No changes made."; press_enter; return 0; }

    # ── Write optimized config via python3 ────────────────
    python3 << PYEOF
import re, sys

config_path = "${HY2_CONFIG}"

try:
    with open(config_path, 'r') as f:
        content = f.read()
except Exception as e:
    print(f"ERROR reading config: {e}")
    sys.exit(1)

# ── bandwidth block ──────────────────────────────────────
bw_block = """bandwidth:
  up: ${final_ul} mbps
  down: ${final_dl} mbps"""

if re.search(r'^bandwidth:', content, re.MULTILINE):
    content = re.sub(
        r'^bandwidth:.*?(?=^\S|\Z)',
        bw_block + '\n\n',
        content, flags=re.MULTILINE | re.DOTALL
    )
else:
    content = content.rstrip('\n') + '\n\n' + bw_block + '\n'

# ── quic block ───────────────────────────────────────────
quic_block = """quic:
  initStreamReceiveWindow: ${final_init_stream}
  maxStreamReceiveWindow: ${final_max_stream}
  initConnReceiveWindow: ${final_init_conn}
  maxConnReceiveWindow: ${final_max_conn}
  maxIdleTimeout: ${final_idle_timeout}
  keepAlivePeriod: ${final_keepalive}"""

if re.search(r'^quic:', content, re.MULTILINE):
    content = re.sub(
        r'^quic:.*?(?=^\S|\Z)',
        quic_block + '\n\n',
        content, flags=re.MULTILINE | re.DOTALL
    )
else:
    content = content.rstrip('\n') + '\n\n' + quic_block + '\n'

with open(config_path, 'w') as f:
    f.write(content)

print("OK")
PYEOF

    local py_result=$?
    if [[ $py_result -ne 0 ]]; then
        print_error "Failed to update config. Check ${HY2_CONFIG} manually."
        press_enter; return 1
    fi

    print_success "Config updated successfully."

    # Restart if running
    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        print_info "Restarting hysteria-server to apply changes..."
        systemctl restart hysteria-server
        sleep 2
        if systemctl is-active --quiet hysteria-server; then
            print_success "hysteria-server restarted and running with optimized config."
        else
            print_error "hysteria-server failed to restart — check: journalctl -u hysteria-server -n 20"
        fi
    else
        print_info "hysteria-server is not running. Start it from the menu when ready."
    fi

    press_enter
}

setup_hysteria2_server() {
    print_banner
    echo -e "${BOLD}  Install Hysteria2 Server${NC}\n"
    echo -e "  ${CYAN}Hysteria2 uses QUIC/UDP — much harder to detect than TCP-based protocols.${NC}\n"

    check_internet

    local hy2_ver
    print_info "Fetching latest Hysteria2 version..."
    hy2_ver=$(get_latest_hy2_version)
    if [[ -z "$hy2_ver" ]]; then
        print_warn "Could not auto-detect version. Using 2.6.1 as fallback."
        hy2_ver="2.6.1"
    fi
    echo -e "  Latest version: ${GREEN}${hy2_ver}${NC}\n"

    print_step "1/5" "Installing Hysteria2 binary..."
    install_hysteria2_bin "$hy2_ver" || { press_enter; return; }

    print_step "2/5" "Configure parameters..."
    echo ""
    local hy2_port hy2_password hy2_domain

    # Generate a strong random password
    local default_pass
    default_pass=$(openssl rand -base64 18 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c 24 \
                   || cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)

    ask hy2_port     "  UDP listen port"         "443"
    ask hy2_password "  Password"                 "$default_pass"
    ask hy2_domain   "  Domain/SNI for TLS cert (leave blank for self-signed)" ""

    if [[ -z "$hy2_domain" ]]; then
        print_warn "No domain provided. Using self-signed certificate (clients must set insecure=true)."
    fi

    print_step "3/5" "Generating TLS certificate & writing base config..."
    mkdir -p /etc/hysteria

    if [[ -n "$hy2_domain" ]]; then
        cat > "$HY2_CONFIG" << YAMLEOF
listen: :${hy2_port}

acme:
  domains:
    - ${hy2_domain}
  email: admin@${hy2_domain}

auth:
  type: password
  password: ${hy2_password}

masquerade:
  type: proxy
  proxy:
    url: https://www.speedtest.net
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps
YAMLEOF
    else
        print_info "Generating self-signed TLS certificate..."
        mkdir -p /etc/hysteria/certs
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout /etc/hysteria/certs/key.pem \
            -out /etc/hysteria/certs/cert.pem \
            -days 3650 -subj "/CN=hysteria" &>/dev/null \
            && print_success "Self-signed cert generated." \
            || { print_error "openssl not found. Install with: apt install openssl"; press_enter; return; }

        cat > "$HY2_CONFIG" << YAMLEOF
listen: :${hy2_port}

tls:
  cert: /etc/hysteria/certs/cert.pem
  key: /etc/hysteria/certs/key.pem

auth:
  type: password
  password: ${hy2_password}

masquerade:
  type: proxy
  proxy:
    url: https://www.speedtest.net
    rewriteHost: true

bandwidth:
  up: 1 gbps
  down: 1 gbps
YAMLEOF
    fi

    # Save server info for link generation
    local server_ip
    server_ip=$(get_ipv4)
    local selfcert_val
    [[ -z "$hy2_domain" ]] && selfcert_val="True" || selfcert_val="False"
    python3 -c "
import json
data = {
    'ip':       '${server_ip}',
    'port':     '${hy2_port}',
    'password': '${hy2_password}',
    'domain':   '${hy2_domain}',
    'selfcert': ${selfcert_val}
}
with open('${HY2_SERVER_INFO}', 'w') as f:
    json.dump(data, f, indent=2)
"
    print_success "Base config written to ${HY2_CONFIG}"

    print_step "4/5" "Opening firewall & starting service..."
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "${hy2_port}"/udp &>/dev/null
        ufw allow "${hy2_port}"/tcp &>/dev/null
        print_success "UFW: UDP+TCP port ${hy2_port} opened."
    elif command -v iptables &>/dev/null; then
        iptables -I INPUT -p udp --dport "$hy2_port" -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport "$hy2_port" -j ACCEPT 2>/dev/null || true
        print_info "iptables: UDP+TCP port ${hy2_port} opened."
    fi

    create_hy2_service_server
    systemctl restart hysteria-server
    sleep 2

    if systemctl is-active --quiet hysteria-server; then
        print_success "hysteria-server is running."
    else
        print_error "hysteria-server failed to start!"
        journalctl -u hysteria-server --no-pager -n 20
        press_enter; return
    fi

    # Build connection link for display
    local insecure_flag="" sni_part=""
    if [[ -z "$hy2_domain" ]]; then
        insecure_flag="&insecure=1"
        sni_part="sni=hysteria"
    else
        sni_part="sni=${hy2_domain}"
    fi
    local hy2_link="hysteria2://${hy2_password}@${server_ip}:${hy2_port}?${sni_part}${insecure_flag}#Hysteria2-Server"

    echo ""
    echo -e "${GREEN}${BOLD}+----------------------------------------------+"
    echo -e "|     Hysteria2 Server installed & running!    |"
    echo -e "+----------------------------------------------+${NC}"
    echo ""
    echo -e "${BOLD}Connection details:${NC}"
    echo -e "  IP:       ${CYAN}${server_ip}${NC}"
    echo -e "  Port:     ${CYAN}${hy2_port}/UDP${NC}"
    echo -e "  Password: ${CYAN}${hy2_password}${NC}"
    [[ -n "$hy2_domain" ]] \
        && echo -e "  Domain:   ${CYAN}${hy2_domain}${NC}" \
        || echo -e "  TLS:      ${YELLOW}Self-signed (insecure=true required on client)${NC}"
    echo ""
    echo -e "${BOLD}Hysteria2 link (v2rayN / Hiddify compatible):${NC}"
    echo -e "  ${MAGENTA}${hy2_link}${NC}"
    print_qr "$hy2_link"

    echo -e "\n${BOLD}${YELLOW}[IMPORTANT] UDP must be allowed in your VPS firewall panel too!${NC}"
    echo -e "${DIM}  Check your Hetzner/Vultr/DigitalOcean firewall rules for UDP ${hy2_port}.${NC}\n"

    # ── Step 5: Automatic performance optimization ──────
    print_step "5/5" "Performance optimization..."
    echo ""
    echo -e "  ${CYAN}The server is running with default bandwidth settings (1 gbps placeholder).${NC}"
    echo -e "  ${CYAN}Running the optimization wizard will measure real bandwidth and tune QUIC windows.${NC}\n"

    if confirm "Run Performance Optimization Wizard now? (recommended)" "y"; then
        hy2_optimize_wizard "no"
    else
        echo -e "\n  ${DIM}You can run this later from the Hysteria2 menu → Optimize Performance.${NC}"
        press_enter
    fi
}

show_hysteria2_status() {
    print_banner
    echo -e "${BOLD}  Hysteria2 Status${NC}\n"

    if ! command -v "$HY2_BIN" &>/dev/null; then
        print_warn "Hysteria2 is not installed."
        press_enter; return
    fi

    local ver
    ver=$("$HY2_BIN" version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "unknown")
    echo -e "  Version: ${CYAN}${ver}${NC}"

    if systemctl is-active --quiet hysteria-server 2>/dev/null; then
        echo -e "  Server:  ${GREEN}[ACTIVE]${NC}"
    else
        echo -e "  Server:  ${RED}[INACTIVE]${NC}"
    fi

    if [[ -f "$HY2_SERVER_INFO" ]]; then
        echo ""
        echo -e "  ${BOLD}Server info:${NC}"
        python3 -c "
import json
with open('${HY2_SERVER_INFO}') as f: d=json.load(f)
print(f\"  IP:       {d.get('ip','?')}\")
print(f\"  Port:     {d.get('port','?')}/UDP\")
print(f\"  Password: {d.get('password','?')}\")
print(f\"  Domain:   {d.get('domain','self-signed')}\")
" 2>/dev/null

        # Rebuild and show link
        local ip port password domain selfcert
        ip=$(python3 -c "import json; d=json.load(open('${HY2_SERVER_INFO}')); print(d.get('ip',''))" 2>/dev/null)
        port=$(python3 -c "import json; d=json.load(open('${HY2_SERVER_INFO}')); print(d.get('port',''))" 2>/dev/null)
        password=$(python3 -c "import json; d=json.load(open('${HY2_SERVER_INFO}')); print(d.get('password',''))" 2>/dev/null)
        domain=$(python3 -c "import json; d=json.load(open('${HY2_SERVER_INFO}')); print(d.get('domain',''))" 2>/dev/null)
        selfcert=$(python3 -c "import json; d=json.load(open('${HY2_SERVER_INFO}')); print(d.get('selfcert',True))" 2>/dev/null)

        local insecure_flag="" sni_part=""
        if [[ "$selfcert" == "True" || -z "$domain" ]]; then
            insecure_flag="&insecure=1"
            sni_part="sni=hysteria"
        else
            sni_part="sni=${domain}"
        fi
        local hy2_link="hysteria2://${password}@${ip}:${port}?${sni_part}${insecure_flag}#Hysteria2-Server"
        echo ""
        echo -e "  ${BOLD}Connection link:${NC}"
        echo -e "  ${MAGENTA}${hy2_link}${NC}"
        print_qr "$hy2_link"
    fi

    echo ""
    echo -e "  ${CYAN}1)${NC}  View logs (last 30 lines)"
    echo -e "  ${CYAN}2)${NC}  Restart service"
    echo -e "  ${CYAN}3)${NC}  Stop service"
    echo -e "  ${CYAN}0)${NC}  Back"
    echo ""
    echo -ne "${YELLOW}Choice: ${NC}"
    read -r choice
    case "$choice" in
        1) echo ""; journalctl -u hysteria-server --no-pager -n 30; press_enter ;;
        2) systemctl restart hysteria-server; sleep 2
           systemctl is-active --quiet hysteria-server \
               && print_success "hysteria-server restarted." \
               || print_error "Failed to restart."; press_enter ;;
        3) systemctl stop hysteria-server && print_success "hysteria-server stopped."; press_enter ;;
        0) return ;;
    esac
}

uninstall_hysteria2() {
    print_banner
    echo -e "${RED}${BOLD}  Uninstall Hysteria2${NC}\n"
    confirm "Remove Hysteria2 completely?" "n" || return
    systemctl stop    hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f "$HY2_BIN"
    rm -rf /etc/hysteria
    systemctl daemon-reload
    print_success "Hysteria2 completely removed."
    press_enter
}

hysteria2_menu() {
    while true; do
        print_banner
        local hy2_status="inactive"
        systemctl is-active --quiet hysteria-server 2>/dev/null && hy2_status="active"

        echo -e "${BOLD}  Hysteria2 — QUIC/UDP Protocol${NC}"
        echo -e "  ${DIM}Better DPI bypass than TCP-based protocols${NC}\n"

        [[ "$hy2_status" == "active" ]] \
            && echo -e "  Server: ${GREEN}[ACTIVE]${NC}\n" \
            || echo -e "  Server: ${RED}[INACTIVE]${NC}\n"

        echo -e "  ${CYAN}1)${NC}  Install / Setup Hysteria2 Server"
        echo -e "  ${CYAN}2)${NC}  Optimize Performance (bandwidth + QUIC tuning)"
        echo -e "  ${CYAN}3)${NC}  Status, logs & connection link"
        echo -e "  ${CYAN}4)${NC}  Uninstall Hysteria2"
        echo -e "  ${CYAN}0)${NC}  Back"
        echo ""
        echo -ne "${YELLOW}Choice: ${NC}"
        read -r choice
        case "$choice" in
            1) setup_hysteria2_server ;;
            2) hy2_optimize_wizard "no" ;;
            3) show_hysteria2_status ;;
            4) uninstall_hysteria2 ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

# ─── Main Menu ────────────────────────────────────────────

main_menu() {
    while true; do
        print_banner
        local sv cl f2b hy2
        sv=$(systemctl is-active sing-box         2>/dev/null || echo "inactive")
        cl=$(systemctl is-active sing-box-client  2>/dev/null || echo "inactive")
        f2b=$(systemctl is-active fail2ban        2>/dev/null || echo "inactive")
        hy2=$(systemctl is-active hysteria-server 2>/dev/null || echo "inactive")
        [[ "$sv"  == "active" ]] && echo -e "  VLESS/Reality : ${GREEN}[ACTIVE]${NC}"
        [[ "$cl"  == "active" ]] && echo -e "  Client        : ${GREEN}[ACTIVE]${NC}"
        [[ "$hy2" == "active" ]] && echo -e "  Hysteria2     : ${GREEN}[ACTIVE]${NC}"
        [[ "$f2b" == "active" ]] && echo -e "  Fail2ban      : ${GREEN}[ACTIVE]${NC}"
        echo ""
        echo -e "${BOLD}  --- Installation ---${NC}"
        echo -e "  ${CYAN}1)${NC}  Install VLESS+Reality server (outbound)"
        echo -e "  ${CYAN}2)${NC}  Install Iran relay client"
        echo -e "  ${CYAN}3)${NC}  Hysteria2 (QUIC/UDP) — better DPI bypass"
        echo ""
        echo -e "${BOLD}  --- Management ---${NC}"
        echo -e "  ${CYAN}4)${NC}  User management"
        echo -e "  ${CYAN}5)${NC}  Show status & logs"
        echo -e "  ${CYAN}6)${NC}  Manage service"
        echo -e "  ${CYAN}7)${NC}  Network optimization (BBR & TCP)"
        echo -e "  ${CYAN}8)${NC}  Fail2ban - intrusion protection"
        echo -e "  ${CYAN}9)${NC}  Speed test"
        echo -e "  ${CYAN}10)${NC} Update sing-box"
        echo -e "  ${CYAN}11)${NC} Uninstall sing-box"
        echo ""
        echo -e "  ${DIM}0)  Exit${NC}"
        echo ""
        echo -ne "${YELLOW}Select option: ${NC}"
        read -r choice
        case "$choice" in
            1)  setup_server ;;
            2)  setup_client ;;
            3)  hysteria2_menu ;;
            4)  manage_users ;;
            5)  show_status ;;
            6)  manage_service ;;
            7)  network_optimization ;;
            8)  fail2ban_menu ;;
            9)  speed_test ;;
            10) update_singbox ;;
            11) uninstall ;;
            0)  echo -e "\n${DIM}Goodbye.${NC}\n"; exit 0 ;;
            *)  print_warn "Invalid option."; sleep 1 ;;
        esac
    done
}

# ─── Entry Point ──────────────────────────────────────────

check_root
check_os
main_menu
