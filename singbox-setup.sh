#!/bin/bash

# ============================================================
#  sing-box Setup & Manager v2.1.0
#  VLESS + REALITY Tunnel
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

# ─── Helpers ──────────────────────────────────────────────

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  +-----------------------------------------------+"
    echo "  |       sing-box Setup & Manager v2.1.0        |"
    echo "  |       VLESS + REALITY Tunnel                  |"
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

get_ipv4() {
    local ip
    ip=$(curl -4 -s --connect-timeout 5 https://ifconfig.me 2>/dev/null) \
    || ip=$(curl -4 -s --connect-timeout 5 https://api.ipify.org 2>/dev/null) \
    || ip=$(curl -4 -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null) \
    || ip="unknown"
    echo "$ip"
}

# ─── Server Info (server.json) ────────────────────────────
# This file is the single source of truth for server settings.
# It is created once during server installation and never changes.
# Structure:
# {
#   "public_key":  "...",
#   "private_key": "...",
#   "short_id":    "...",
#   "sni":         "...",
#   "port":        443
# }

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
    # Returns: public_key private_key short_id sni port  (one per line)
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

network_optimization() {
    while true; do
        print_banner
        echo -e "${BOLD}  Network Optimization${NC}\n"
        local current_cc qdisc rmem
        current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
        qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
        rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "0")
        if [[ "$current_cc" == "bbr" ]]; then
            echo -e "  BBR:         ${GREEN}${BOLD}[ACTIVE]${NC} (qdisc: ${qdisc})"
        else
            echo -e "  BBR:         ${RED}${BOLD}[INACTIVE]${NC} (current: ${current_cc})"
        fi
        if [[ "$rmem" -gt "1000000" ]]; then
            echo -e "  TCP Buffers: ${GREEN}[OPTIMIZED]${NC}"
        else
            echo -e "  TCP Buffers: ${YELLOW}[DEFAULT]${NC}"
        fi
        echo ""
        echo -e "  ${CYAN}1)${NC}  Enable BBR + FQ"
        echo -e "  ${CYAN}2)${NC}  Disable BBR (revert to cubic)"
        echo -e "  ${CYAN}3)${NC}  Apply TCP buffer optimization"
        echo -e "  ${CYAN}4)${NC}  Apply all optimizations (BBR + TCP)"
        echo -e "  ${CYAN}5)${NC}  Show current sysctl values"
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
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    [[ "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)" == "bbr" ]] \
        && print_success "BBR enabled." \
        || print_error "Failed to enable BBR."
    press_enter
}

disable_bbr() {
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
    echo "net.ipv4.tcp_congestion_control=cubic" >> /etc/sysctl.conf
    sysctl -p &>/dev/null
    print_success "Reverted to cubic."
    press_enter
}

apply_tcp_optimization() {
    for key in net.core.rmem_max net.core.wmem_max net.ipv4.tcp_rmem net.ipv4.tcp_wmem net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing; do
        sed -i "/${key}/d" /etc/sysctl.conf 2>/dev/null || true
    done
    cat >> /etc/sysctl.conf << 'EOF'
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
EOF
    sysctl -p &>/dev/null
    print_success "TCP buffer optimization applied."
    press_enter
}

show_sysctl_values() {
    echo ""
    echo -e "${BOLD}  Current network sysctl values:${NC}\n"
    for key in net.ipv4.tcp_congestion_control net.core.default_qdisc \
               net.core.rmem_max net.core.wmem_max \
               net.ipv4.tcp_fastopen net.ipv4.tcp_mtu_probing; do
        local val
        val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        printf "  %-45s ${CYAN}%s${NC}\n" "$key" "$val"
    done
    press_enter
}

# ─── Fail2ban ─────────────────────────────────────────────

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
    if ! command -v fail2ban-client &>/dev/null; then
        print_info "Installing fail2ban..."
        apt-get update -qq && apt-get install -y fail2ban &>/dev/null
        print_success "fail2ban installed."
    else
        print_info "fail2ban is already installed."
    fi
    local maxretry bantime findtime
    ask maxretry "  Max failed attempts before ban"                  "5"
    ask findtime "  Time window in seconds"                         "60"
    ask bantime  "  Ban duration in seconds (3600=1h, 86400=1d)"   "3600"

    cat > /etc/fail2ban/filter.d/singbox.conf << 'EOF'
[Definition]
failregex = inbound connection from <HOST>:.*REALITY: processed invalid connection
ignoreregex =
EOF
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}

[sshd]
enabled = false

[singbox]
enabled  = true
filter   = singbox
logpath  = /var/log/syslog
maxretry = ${maxretry}
findtime = ${findtime}
bantime  = ${bantime}
action   = iptables-allports[name=singbox]
EOF
    systemctl enable fail2ban &>/dev/null
    systemctl restart fail2ban
    sleep 2
    if systemctl is-active --quiet fail2ban; then
        print_success "Fail2ban is active and protecting your server."
        echo -e "\n  Max retries: ${CYAN}${maxretry}${NC} in ${CYAN}${findtime}${NC}s -> ban for ${CYAN}${bantime}${NC}s"
    else
        print_error "Fail2ban failed to start."
    fi
    press_enter
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
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}

[sshd]
enabled = false

[singbox]
enabled  = true
filter   = singbox
logpath  = /var/log/syslog
maxretry = ${maxretry}
findtime = ${findtime}
bantime  = ${bantime}
action   = iptables-allports[name=singbox]
EOF
    systemctl restart fail2ban; sleep 1
    systemctl is-active --quiet fail2ban \
        && print_success "Settings updated." \
        || print_error "Fail2ban failed to restart."
    press_enter
}

toggle_fail2ban() {
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        systemctl stop fail2ban && print_success "Fail2ban stopped."
    else
        systemctl start fail2ban; sleep 1
        systemctl is-active --quiet fail2ban \
            && print_success "Fail2ban started." \
            || print_error "Failed to start fail2ban."
    fi
    press_enter
}

uninstall_fail2ban() {
    confirm "Remove fail2ban completely?" "n" || return
    systemctl stop fail2ban 2>/dev/null || true
    systemctl disable fail2ban 2>/dev/null || true
    apt-get remove -y fail2ban &>/dev/null
    rm -f /etc/fail2ban/jail.local /etc/fail2ban/filter.d/singbox.conf
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

# ─── Main Menu ────────────────────────────────────────────

main_menu() {
    while true; do
        print_banner
        local sv cl f2b
        sv=$(systemctl is-active sing-box        2>/dev/null || echo "inactive")
        cl=$(systemctl is-active sing-box-client 2>/dev/null || echo "inactive")
        f2b=$(systemctl is-active fail2ban       2>/dev/null || echo "inactive")
        [[ "$sv"  == "active" ]] && echo -e "  Server:   ${GREEN}[ACTIVE]${NC}"
        [[ "$cl"  == "active" ]] && echo -e "  Client:   ${GREEN}[ACTIVE]${NC}"
        [[ "$f2b" == "active" ]] && echo -e "  Fail2ban: ${GREEN}[ACTIVE]${NC}"
        echo ""
        echo -e "${BOLD}  --- Installation ---${NC}"
        echo -e "  ${CYAN}1)${NC}  Install outbound server (e.g. Germany)"
        echo -e "  ${CYAN}2)${NC}  Install Iran client (tunnel to outbound)"
        echo ""
        echo -e "${BOLD}  --- Management ---${NC}"
        echo -e "  ${CYAN}3)${NC}  User management"
        echo -e "  ${CYAN}4)${NC}  Show status & logs"
        echo -e "  ${CYAN}5)${NC}  Manage service"
        echo -e "  ${CYAN}6)${NC}  Network optimization (BBR & TCP)"
        echo -e "  ${CYAN}7)${NC}  Fail2ban - intrusion protection"
        echo -e "  ${CYAN}8)${NC}  Speed test"
        echo -e "  ${CYAN}9)${NC}  Update sing-box"
        echo -e "  ${CYAN}10)${NC} Uninstall"
        echo ""
        echo -e "  ${DIM}0)  Exit${NC}"
        echo ""
        echo -ne "${YELLOW}Select option: ${NC}"
        read -r choice
        case "$choice" in
            1)  setup_server ;;
            2)  setup_client ;;
            3)  manage_users ;;
            4)  show_status ;;
            5)  manage_service ;;
            6)  network_optimization ;;
            7)  fail2ban_menu ;;
            8)  speed_test ;;
            9)  update_singbox ;;
            10) uninstall ;;
            0)  echo -e "\n${DIM}Goodbye.${NC}\n"; exit 0 ;;
            *)  print_warn "Invalid option."; sleep 1 ;;
        esac
    done
}

# ─── Entry Point ──────────────────────────────────────────

check_root
check_os
main_menu
