#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  protocols/vless.sh — VLESS + Reality (sing-box)
#
#  Depends on: core/common.sh  core/system.sh  core/db.sh
#  Global vars consumed: SINGBOX_VERSION, SRV_PUBLIC_IP, SRV_*
#  Global vars exported: SINGBOX_BIN, SINGBOX_CONFIG, VLESS_INFO
# ═══════════════════════════════════════════════════════════════

# ── Paths ──────────────────────────────────────────────────────
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_CONFIG="/etc/sing-box/config.json"
VLESS_INFO="/etc/sing-box/server.json"       # public_key, sni, port, domain
VLESS_QUOTA_SCRIPT="/etc/sing-box/quota_enforce.py"

# ── Binary install ─────────────────────────────────────────────

vless_install_binary() {
    local version="$1"
    local arch tmp_dir url
    arch=$(get_arch)
    tmp_dir=$(mktemp -d)

    print_info "Downloading sing-box v${version} (${arch})..."
    url="https://github.com/SagerNet/sing-box/releases/download/v${version}/sing-box-${version}-linux-${arch}.tar.gz"

    if ! curl -L --progress-bar -o "${tmp_dir}/sing-box.tar.gz" "$url"; then
        print_error "Download failed. Check internet or version."
        rm -rf "$tmp_dir"; return 1
    fi

    print_info "Installing binary..."
    tar -xzf "${tmp_dir}/sing-box.tar.gz" -C "$tmp_dir"
    install -m 755 "${tmp_dir}/sing-box-${version}-linux-${arch}/sing-box" "$SINGBOX_BIN"
    rm -rf "$tmp_dir"
    mkdir -p /etc/sing-box
    print_success "sing-box v${version} installed."
}

# ── Config helpers ─────────────────────────────────────────────

vless_write_config() {
    local json="$1"
    mkdir -p /etc/sing-box
    echo "$json" > "$SINGBOX_CONFIG"
    print_success "Config saved → ${SINGBOX_CONFIG}"
}

# vless_save_server_info <public_key> <private_key> <short_id> <sni> <port> <domain>
vless_save_server_info() {
    local pub="$1" priv="$2" sid="$3" sni="$4" port="$5" domain="${6:-}"
    mkdir -p /etc/sing-box
    python3 - <<PYEOF
import json
data = {
    "public_key":  "${pub}",
    "private_key": "${priv}",
    "short_id":    "${sid}",
    "sni":         "${sni}",
    "port":        int("${port}"),
    "domain":      "${domain}"
}
with open("${VLESS_INFO}", "w") as f:
    json.dump(data, f, indent=2)
PYEOF
    print_success "Server info saved → ${VLESS_INFO}"
}

# vless_read_server_info → exports VINFO_* variables
vless_read_server_info() {
    [[ ! -f "$VLESS_INFO" ]] && return 1
    eval "$(python3 - <<'PYEOF'
import json
d = json.load(open("/etc/sing-box/server.json"))
print(f"VINFO_PUBKEY=\"{d.get('public_key','')}\"")
print(f"VINFO_PRIVKEY=\"{d.get('private_key','')}\"")
print(f"VINFO_SID=\"{d.get('short_id','')}\"")
print(f"VINFO_SNI=\"{d.get('sni','')}\"")
print(f"VINFO_PORT=\"{d.get('port',443)}\"")
print(f"VINFO_DOMAIN=\"{d.get('domain','')}\"")
PYEOF
)"
}

# Build canonical VLESS link for a user
# vless_build_link <uuid> <label>
vless_build_link() {
    local uuid="$1" label="$2"
    vless_read_server_info || { print_error "Server info not found."; return 1; }

    # Prefer domain over raw IP when available
    local host="${VINFO_DOMAIN:-}"
    [[ -z "$host" ]] && host=$(get_public_ip)

    local encoded_label
    encoded_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${label}'))" 2>/dev/null || echo "$label")

    echo "vless://${uuid}@${host}:${VINFO_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${VINFO_SNI}&fp=chrome&pbk=${VINFO_PUBKEY}&sid=${VINFO_SID}&type=tcp&headerType=none#${encoded_label}"
}

# ── systemd service ────────────────────────────────────────────

vless_create_service() {
    local mode="${1:-server}"   # server | client
    local svc_name unit_file exec_cmd

    if [[ "$mode" == "client" ]]; then
        svc_name="sing-box-client"
        unit_file="/etc/systemd/system/sing-box-client.service"
        exec_cmd="/usr/local/bin/sing-box run -c /etc/sing-box/config.json"
    else
        svc_name="sing-box"
        unit_file="/etc/systemd/system/sing-box.service"
        exec_cmd="/usr/local/bin/sing-box run -c /etc/sing-box/config.json"
    fi

    cat > "$unit_file" << EOF
[Unit]
Description=sing-box (${mode})
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=${exec_cmd}
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$svc_name" &>/dev/null
    print_success "systemd service '${svc_name}' created."
}

# ── Quota enforcement (cron) ───────────────────────────────────

vless_install_quota_enforcer() {
    cat > "$VLESS_QUOTA_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""VLESS quota enforcement — disables sing-box users who exceeded quota."""
import json, subprocess, sys, os

CONFIG_FILE = "/etc/sing-box/config.json"
DB_PATH     = "/etc/singbox-manager/data/users.db"

def load_json(path):
    with open(path) as f:
        return json.load(f)

def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)

def main():
    import sqlite3, datetime
    if not os.path.exists(CONFIG_FILE) or not os.path.exists(DB_PATH):
        sys.exit(0)

    conn   = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    config = load_json(CONFIG_FILE)
    now    = datetime.datetime.utcnow().isoformat()

    changed = False

    for row in conn.execute("SELECT uuid, quota_gb, used_bytes, enabled, expires_at FROM users"):
        uuid        = row["uuid"]
        quota_bytes = int(float(row["quota_gb"] or 0) * 1024**3)
        used_bytes  = int(row["used_bytes"] or 0)
        db_enabled  = bool(row["enabled"])

        # Check expiry
        expired = False
        if row["expires_at"]:
            try:
                exp = datetime.datetime.fromisoformat(row["expires_at"])
                expired = exp < datetime.datetime.utcnow()
            except Exception:
                pass

        over_quota = quota_bytes > 0 and used_bytes >= quota_bytes
        should_disable = (not db_enabled) or over_quota or expired

        for inbound in config.get("inbounds", []):
            for client in inbound.get("users", []):
                if client.get("uuid") == uuid:
                    was_disabled = client.get("disabled", False)
                    if should_disable and not was_disabled:
                        client["disabled"] = True
                        changed = True
                    elif not should_disable and was_disabled:
                        client["disabled"] = False
                        changed = True

    conn.close()

    if changed:
        save_json(CONFIG_FILE, config)
        subprocess.run(["systemctl", "reload-or-restart", "sing-box"],
                       check=False, capture_output=True)

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$VLESS_QUOTA_SCRIPT"

    local cron_line="*/5 * * * * /usr/bin/python3 ${VLESS_QUOTA_SCRIPT} >/dev/null 2>&1"
    { crontab -l 2>/dev/null || true; } \
        | { grep -v "vless_quota\|quota_enforce" || true; } > /tmp/vless_cron.tmp
    echo "$cron_line" >> /tmp/vless_cron.tmp
    crontab /tmp/vless_cron.tmp && rm -f /tmp/vless_cron.tmp
    print_success "Quota enforcer installed (cron every 5 min)."
}

# ── Add user to sing-box config ────────────────────────────────

# vless_config_add_user <uuid>  → "OK" | "DUPLICATE" | "ERROR"
vless_config_add_user() {
    local uuid="$1"
    python3 - <<PYEOF
import json, sys

config_file = "${SINGBOX_CONFIG}"
try:
    with open(config_file) as f:
        config = json.load(f)
except Exception as e:
    print(f"ERROR:{e}"); sys.exit(1)

for ib in config.get("inbounds", []):
    if ib.get("type") == "vless":
        users = ib.get("users", [])
        if any(u.get("uuid") == "${uuid}" for u in users):
            print("DUPLICATE"); sys.exit(0)
        users.append({"uuid": "${uuid}", "flow": "xtls-rprx-vision"})
        ib["users"] = users
        break

tmp = config_file + ".tmp"
with open(tmp, "w") as f:
    json.dump(config, f, indent=2)
import os; os.replace(tmp, config_file)
print("OK")
PYEOF
}

# vless_config_remove_user <uuid>
vless_config_remove_user() {
    local uuid="$1"
    python3 - <<PYEOF
import json, sys, os

config_file = "${SINGBOX_CONFIG}"
try:
    with open(config_file) as f:
        config = json.load(f)
except Exception as e:
    print(f"ERROR:{e}"); sys.exit(1)

for ib in config.get("inbounds", []):
    if ib.get("type") == "vless":
        ib["users"] = [u for u in ib.get("users", []) if u.get("uuid") != "${uuid}"]
        break

tmp = config_file + ".tmp"
with open(tmp, "w") as f:
    json.dump(config, f, indent=2)
os.replace(tmp, config_file)
print("OK")
PYEOF
}

# ── Traffic sync (cron) ────────────────────────────────────────
# sing-box does not expose a traffic API like Hysteria2.
# We read from journal logs and accumulate per-uuid bytes.
# A lightweight approach: parse "connection closed" lines.

VLESS_SYNC_SCRIPT="/etc/sing-box/traffic_sync.py"

vless_install_traffic_sync() {
    cat > "$VLESS_SYNC_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""
Parse sing-box journal for connection stats and write to central DB.
sing-box logs each closed connection with sent/received byte counts:
  inbound/vless[tag] connection closed ... uplink=1234 downlink=5678
"""
import subprocess, sqlite3, re, os, datetime, logging

DB_PATH  = "/etc/singbox-manager/data/users.db"
LOG_FILE = "/var/log/singbox-manager/vless_sync.log"

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

# Regex: capture uuid and byte counts from sing-box log lines
# Format: ... [uuid] ... uplink=N downlink=M
RE_CONN = re.compile(
    r'(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    r'.*?uplink=(?P<up>\d+).*?downlink=(?P<down>\d+)',
    re.IGNORECASE
)

def fetch_recent_logs():
    """Pull sing-box logs from the last 6 minutes to overlap with 5-min cron."""
    result = subprocess.run(
        ["journalctl", "-u", "sing-box", "--no-pager",
         "--since", "6 minutes ago", "--output", "short-unix"],
        capture_output=True, text=True
    )
    return result.stdout

def main():
    if not os.path.exists(DB_PATH):
        return

    logs = fetch_recent_logs()
    if not logs:
        return

    # Aggregate bytes per uuid
    totals = {}
    for line in logs.splitlines():
        m = RE_CONN.search(line)
        if m:
            uuid = m.group("uuid").lower()
            up   = int(m.group("up"))
            down = int(m.group("down"))
            totals[uuid] = totals.get(uuid, 0) + up + down

    if not totals:
        return

    conn = sqlite3.connect(DB_PATH)
    now  = datetime.datetime.utcnow().isoformat()
    try:
        for uuid, delta in totals.items():
            rows = conn.execute(
                "SELECT id FROM users WHERE uuid=?", (uuid,)
            ).fetchone()
            if rows:
                conn.execute(
                    "UPDATE users SET used_bytes=used_bytes+?, last_seen=? WHERE uuid=?",
                    (delta, now, uuid)
                )
                conn.execute(
                    "INSERT INTO traffic_log (uuid, engine, delta_bytes, recorded_at) VALUES (?,?,?,?)",
                    (uuid, "vless", delta, now)
                )
        conn.commit()
        logging.info(f"Synced traffic for {len(totals)} users.")
    except Exception as e:
        logging.error(f"Sync error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$VLESS_SYNC_SCRIPT"

    local cron_line="*/5 * * * * /usr/bin/python3 ${VLESS_SYNC_SCRIPT} >/dev/null 2>&1"
    { crontab -l 2>/dev/null || true; } \
        | { grep -v "vless_sync\|traffic_sync" || true; } > /tmp/vless_sync_cron.tmp
    echo "$cron_line" >> /tmp/vless_sync_cron.tmp
    crontab /tmp/vless_sync_cron.tmp && rm -f /tmp/vless_sync_cron.tmp
    print_success "Traffic sync installed (cron every 5 min)."
}

# ── Server install wizard ──────────────────────────────────────

vless_install_server() {
    print_banner
    print_header "Install VLESS + Reality — Outbound Server"
    echo -e "  ${DIM}This server will accept VLESS connections and forward traffic to the internet.${NC}"
    echo -e "  ${DIM}Install this on your foreign VPS (e.g. Germany, Netherlands).${NC}\n"

    # Step 1: binary
    print_step 1 5 "Installing sing-box binary"
    check_internet
    fetch_singbox_version stable
    vless_install_binary "$SINGBOX_VERSION" || { press_enter; return 1; }

    # Step 2: parameters
    print_step 2 5 "Configure server parameters"
    echo ""

    local uuid port sni short_id domain
    uuid=$(generate_uuid)

    local default_sid
    default_sid=$(openssl rand -hex 4 2>/dev/null \
                  || tr -dc 'a-f0-9' < /dev/urandom | head -c 8)

    echo -e "  ${YELLOW}TIP: SNI should be a high-traffic TLS site to camouflage your traffic.${NC}"
    echo -e "  ${DIM}Good choices: www.speedtest.net | addons.mozilla.org | dl.google.com${NC}\n"

    ask uuid     "  User UUID (auto-generated)"    "$uuid"
    ask port     "  Listen port"                   "443"
    ask sni      "  SNI (camouflage domain)"       "www.speedtest.net"
    ask short_id "  Short ID (hex, 4-16 chars)"    "$default_sid"
    ask domain   "  Your domain (blank = use IP)"  ""

    # Step 3: keypair
    print_step 3 5 "Generating REALITY keypair"
    local keypair private_key public_key
    keypair=$(generate_keypair) || { press_enter; return 1; }
    private_key=$(echo "$keypair" | awk '/PrivateKey/{print $2}')
    public_key=$(echo  "$keypair" | awk '/PublicKey/{print $2}')
    echo ""
    echo -e "  ${GREEN}${BOLD}PrivateKey:${NC} ${private_key}"
    echo -e "  ${GREEN}${BOLD}PublicKey: ${NC} ${public_key}"
    echo ""

    # Step 4: write config
    print_step 4 5 "Writing configuration"

    # Build the host field used in configs & links
    local host="${domain:-$(get_public_ip)}"

    vless_write_config "{
  \"log\": { \"level\": \"warn\", \"output\": \"/var/log/singbox-manager/sing-box.log\" },
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

    vless_save_server_info "$public_key" "$private_key" "$short_id" "$sni" "$port" "$domain"

    # Register first user in central DB
    local sub_token
    sub_token=$(generate_token)
    db_init
    db_add_user "$uuid" "default" "0" "$sub_token" '{"vless":true}'
    db_enable_engine "$uuid" "vless"

    # Step 5: service + firewall + cron
    print_step 5 5 "Starting service"
    mkdir -p "$LOG_DIR"
    vless_create_service server
    vless_install_quota_enforcer
    vless_install_traffic_sync
    open_port "$port" tcp
    service_start sing-box || { press_enter; return 1; }

    # ── Success ───────────────────────────────────────────────
    local vless_link
    vless_link=$(vless_build_link "$uuid" "default")

    echo ""
    echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║    VLESS + Reality Server — Ready!               ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Host      : ${CYAN}${host}${NC}"
    echo -e "  Port      : ${CYAN}${port}${NC}"
    echo -e "  SNI       : ${CYAN}${sni}${NC}"
    echo -e "  PublicKey : ${CYAN}${public_key}${NC}"
    echo -e "  ShortID   : ${CYAN}${short_id}${NC}"
    echo ""
    echo -e "  ${BOLD}Default user VLESS link:${NC}"
    echo -e "  ${MAGENTA}${vless_link}${NC}"
    print_qr "$vless_link" "VLESS"
    press_enter
}

# ── Tunnel client install ──────────────────────────────────────

vless_install_client() {
    print_banner
    print_header "Install VLESS + Reality — Iran Relay Client"
    echo -e "  ${DIM}This Iran-side node forwards traffic through a tunnel to your foreign server.${NC}"
    echo -e "  ${DIM}You need the foreign server details before proceeding.${NC}\n"

    print_step 1 4 "Installing sing-box binary"
    check_internet
    fetch_singbox_version stable
    vless_install_binary "$SINGBOX_VERSION" || { press_enter; return 1; }

    print_step 2 4 "Enter foreign server details"
    echo ""
    local server_host server_port uuid public_key short_id sni socks_port

    ask server_host  "  Foreign server host (IP or domain)" ""
    ask server_port  "  Foreign server port"                "443"
    ask uuid         "  UUID"                               ""
    ask public_key   "  PublicKey"                          ""
    ask short_id     "  Short ID"                           ""
    ask sni          "  SNI"                                "www.speedtest.net"
    ask socks_port   "  Local SOCKS5 port"                  "10808"

    if [[ -z "$server_host" || -z "$uuid" || -z "$public_key" ]]; then
        print_error "Server host, UUID and PublicKey are required."
        press_enter; return 1
    fi

    print_step 3 4 "Writing client configuration"
    vless_write_config "{
  \"log\": { \"level\": \"warn\" },
  \"inbounds\": [{
    \"type\": \"socks\", \"tag\": \"socks-in\",
    \"listen\": \"127.0.0.1\", \"listen_port\": ${socks_port}
  }],
  \"outbounds\": [
    {
      \"type\": \"vless\", \"tag\": \"vless-out\",
      \"server\": \"${server_host}\", \"server_port\": ${server_port},
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

    print_step 4 4 "Starting tunnel service"
    vless_create_service client
    service_start sing-box-client || { press_enter; return 1; }

    # Test tunnel
    print_info "Testing tunnel connectivity..."
    sleep 2
    local test_ip
    test_ip=$(curl -s --connect-timeout 10 --socks5 "127.0.0.1:${socks_port}" \
              https://ifconfig.me 2>/dev/null || echo "")
    echo ""
    if [[ -n "$test_ip" ]]; then
        print_success "Tunnel working! Outbound IP: ${test_ip}"
    else
        print_warn "Connection test failed. Check logs with: journalctl -u sing-box-client -n 30"
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}Tunnel client installed.${NC}"
    echo -e "  Local SOCKS5 : ${CYAN}127.0.0.1:${socks_port}${NC}"
    press_enter
}

# ── User management ────────────────────────────────────────────

# vless_add_user — interactive, writes to config + DB
vless_add_user() {
    print_banner
    print_header "VLESS + Reality — Add User"

    if [[ ! -f "$SINGBOX_CONFIG" ]]; then
        print_error "sing-box not installed. Run Install first."
        press_enter; return 1
    fi

    local uuid label quota_gb expiry_days
    uuid=$(generate_uuid)

    ask uuid        "  UUID (auto-generated)"              "$uuid"
    ask label       "  Label"                              "New-User"
    ask quota_gb    "  Traffic quota GB (0 = unlimited)"   "0"
    ask expiry_days "  Validity days    (0 = never)"       "0"

    local expiry_iso=""
    if [[ "$expiry_days" != "0" && -n "$expiry_days" ]]; then
        expiry_iso=$(python3 -c "
from datetime import datetime, timedelta, timezone
exp = datetime.now(timezone.utc) + timedelta(days=int('${expiry_days}'))
print(exp.isoformat())
" 2>/dev/null)
    fi

    # Add to sing-box config
    local result
    result=$(vless_config_add_user "$uuid")
    case "$result" in
        DUPLICATE) print_error "UUID already exists."; press_enter; return 1 ;;
        OK)        print_success "User added to sing-box config." ;;
        *)         print_error "Config update failed: ${result}"; press_enter; return 1 ;;
    esac

    # Add to central DB
    local sub_token
    sub_token=$(generate_token)
    db_add_user "$uuid" "$label" "$quota_gb" "$sub_token" '{"vless":true}' "$expiry_iso"

    # Reload sing-box
    systemctl is-active --quiet sing-box 2>/dev/null && systemctl reload-or-restart sing-box || true

    # Show link
    local vless_link
    vless_link=$(vless_build_link "$uuid" "$label")

    echo ""
    echo -e "  ${BOLD}User created:${NC}"
    echo -e "  Label   : ${CYAN}${label}${NC}"
    echo -e "  UUID    : ${DIM}${uuid}${NC}"
    echo -e "  Quota   : ${CYAN}$([ "$quota_gb" = "0" ] && echo "Unlimited" || echo "${quota_gb} GB")${NC}"
    [[ -n "$expiry_iso" ]] && echo -e "  Expires : ${CYAN}${expiry_iso:0:10}${NC}"
    echo ""
    echo -e "  ${BOLD}VLESS link:${NC}"
    echo -e "  ${MAGENTA}${vless_link}${NC}"
    print_qr "$vless_link" "$label"
    press_enter
}

# vless_delete_user <uuid>
vless_delete_user() {
    local uuid="$1"
    vless_config_remove_user "$uuid"
    db_delete_user "$uuid"
    systemctl is-active --quiet sing-box 2>/dev/null && systemctl reload-or-restart sing-box || true
    print_success "User removed."
}

# ── Status display ─────────────────────────────────────────────

vless_show_status() {
    print_banner
    print_header "VLESS + Reality — Status"

    service_status_line sing-box       "sing-box (server)"
    service_status_line sing-box-client "sing-box (client)"
    echo ""

    if [[ -f "$SINGBOX_BIN" ]]; then
        local ver
        ver=$("$SINGBOX_BIN" version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo -e "  Binary version : ${CYAN}${ver}${NC}"
    fi

    if vless_read_server_info 2>/dev/null; then
        echo ""
        echo -e "  Host      : ${CYAN}${VINFO_DOMAIN:-$(get_public_ip)}${NC}"
        echo -e "  Port      : ${CYAN}${VINFO_PORT}${NC}"
        echo -e "  SNI       : ${CYAN}${VINFO_SNI}${NC}"
        echo -e "  PublicKey : ${DIM}${VINFO_PUBKEY}${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Recent log:${NC}"
    journalctl -u sing-box --no-pager -n 15 2>/dev/null | sed 's/^/  /' \
        || echo "  (no log available)"
    echo ""
    press_enter
}

# ── Update ─────────────────────────────────────────────────────

vless_update() {
    print_banner
    print_header "Update sing-box"

    [[ ! -f "$SINGBOX_BIN" ]] && { print_error "sing-box not installed."; press_enter; return; }

    check_internet
    fetch_singbox_version stable

    local current
    current=$("$SINGBOX_BIN" version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
    echo -e "  Current: ${YELLOW}${current}${NC}  →  Available: ${GREEN}${SINGBOX_VERSION}${NC}"

    if [[ "$current" == "$SINGBOX_VERSION" ]]; then
        print_info "Already on latest version."
        press_enter; return
    fi

    confirm "Proceed with update?" "y" || return

    systemctl stop sing-box        2>/dev/null || true
    systemctl stop sing-box-client 2>/dev/null || true
    vless_install_binary "$SINGBOX_VERSION"
    systemctl start sing-box        2>/dev/null || true
    systemctl start sing-box-client 2>/dev/null || true
    print_success "Updated to v${SINGBOX_VERSION}."
    press_enter
}

# ── Uninstall ──────────────────────────────────────────────────

vless_uninstall() {
    print_banner
    echo -e "  ${RED}${BOLD}Uninstall VLESS + Reality${NC}\n"
    echo -e "  ${YELLOW}This will remove sing-box, all configs, and all users from this protocol.${NC}"
    echo -e "  ${DIM}The central user database will NOT be deleted (other protocols keep their data).${NC}\n"
    confirm "Proceed with uninstall?" "n" || return

    systemctl stop    sing-box        2>/dev/null || true
    systemctl stop    sing-box-client 2>/dev/null || true
    systemctl disable sing-box        2>/dev/null || true
    systemctl disable sing-box-client 2>/dev/null || true
    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/systemd/system/sing-box-client.service
    rm -f "$SINGBOX_BIN"
    rm -rf /etc/sing-box
    { crontab -l 2>/dev/null || true; } \
        | { grep -v "quota_enforce\|vless_sync\|traffic_sync" || true; } \
        | crontab - 2>/dev/null || true
    systemctl daemon-reload

    # Disable vless engine in DB for all users
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os
db_path = os.environ["DB_PATH"]
if not os.path.exists(db_path): exit()
conn = sqlite3.connect(db_path)
for row in conn.execute("SELECT uuid, engines FROM users").fetchall():
    try:
        engines = json.loads(row[1] or "{}")
    except:
        engines = {}
    engines["vless"] = False
    conn.execute("UPDATE users SET engines=? WHERE uuid=?",
                 (json.dumps(engines), row[0]))
conn.commit()
conn.close()
PYEOF

    print_success "VLESS + Reality uninstalled."
    press_enter
}

# ── Service control menu ───────────────────────────────────────

vless_service_menu() {
    while true; do
        print_banner
        print_header "VLESS — Service Control"
        service_status_line sing-box        "Server  (sing-box)"
        service_status_line sing-box-client "Client  (sing-box-client)"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Start server"
        echo -e "  ${CYAN}2)${NC}  Stop server"
        echo -e "  ${CYAN}3)${NC}  Restart server"
        echo -e "  ${CYAN}4)${NC}  Live log — server  ${DIM}(Ctrl+C to exit)${NC}"
        echo -e "  ${CYAN}5)${NC}  Restart client"
        echo -e "  ${CYAN}6)${NC}  Live log — client  ${DIM}(Ctrl+C to exit)${NC}"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) systemctl start   sing-box        && print_success "Started.";   press_enter ;;
            2) systemctl stop    sing-box        && print_success "Stopped.";   press_enter ;;
            3) systemctl restart sing-box        && print_success "Restarted."; press_enter ;;
            4) journalctl -u sing-box -f ;;
            5) systemctl restart sing-box-client && print_success "Restarted."; press_enter ;;
            6) journalctl -u sing-box-client -f ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}
