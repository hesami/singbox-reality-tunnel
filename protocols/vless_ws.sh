#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  protocols/vless_ws.sh — VLESS + WebSocket + TLS
#
#  Works through CDN (ArvanCloud / Cloudflare).
#  Traffic looks like normal HTTPS WebSocket — very hard to block.
#  Depends on: core/common.sh  core/system.sh  core/db.sh
#              protocols/vless.sh (reuses binary + service)
# ═══════════════════════════════════════════════════════════════

VWS_CONFIG="/etc/sing-box/config_ws.json"
VWS_INFO="/etc/sing-box/server_ws.json"
VWS_SERVICE="sing-box-ws"

# ── Check if installed ────────────────────────────────────────
vws_installed() { [[ -f "$VWS_INFO" && -f "$VWS_CONFIG" ]]; }

# ── Save / read server info ───────────────────────────────────
vws_save_info() {
    # vws_save_info <port> <path> <domain> <uuid>
    python3 -c "
import json
d={'port':int('${1}'),'path':'${2}','domain':'${3}','uuid':'${4}'}
open('${VWS_INFO}','w').write(json.dumps(d,indent=2))
"
}

vws_read_info() {
    [[ ! -f "$VWS_INFO" ]] && return 1
    eval "$(python3 -c "
import json
d=json.load(open('${VWS_INFO}'))
print(f\"VWS_PORT={d.get('port',443)}\")
print(f\"VWS_PATH={d.get('path','/ws')}\")
print(f\"VWS_DOMAIN={d.get('domain','')}\")
print(f\"VWS_UUID={d.get('uuid','')}\")
")"
}

# ── Build link ────────────────────────────────────────────────
vws_build_link() {
    local uuid="$1" label="$2"
    vws_read_info || return 1
    local host="${VWS_DOMAIN:-$(get_public_ip)}"
    local enc_label
    enc_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${label}'))")
    # TLS on 443 through CDN
    echo "vless://${uuid}@${host}:${VWS_PORT}?encryption=none&security=tls&sni=${VWS_DOMAIN}&fp=chrome&type=ws&path=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${VWS_PATH}'))")&host=${VWS_DOMAIN}#${enc_label}"
}

# ── Write config ──────────────────────────────────────────────
vws_write_config() {
    local port="$1" path="$2" domain="$3" uuid="$4"
    local cert_file key_file has_cert=false

    # Try to find SSL certificate
    local ssl_domain="${domain}"
    
    # Check if cert exists in our directory
    cert_file="${SSL_CERT_DIR}/${ssl_domain}/fullchain.pem"
    key_file="${SSL_CERT_DIR}/${ssl_domain}/key.pem"
    
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        has_cert=true
        print_success "Using SSL certificate: ${cert_file}"
    else
        # Check if certificate is cached in acme.sh
        print_info "Checking for cached SSL certificate..."
        if ssl_has_valid_cert "$domain"; then
            print_info "Cached certificate found for ${domain}"
            print_info "Run SSL wizard (option 4.1) to install it."
        fi
        
        print_warn "No SSL certificate found for ${domain}"
        print_info "Will use ACME auto-cert (built-in)"
    fi

    local tls_block
    if $has_cert; then
        tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"${domain}\",\"certificate_path\":\"${cert_file}\",\"key_path\":\"${key_file}\"}"
    else
        tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"${domain}\",\"acme\":{\"domain\":\"${domain}\",\"email\":\"acme@${domain}\"}}"
    fi

    cat > "$VWS_CONFIG" << EOF
{
  "log": {"level":"warn","output":"/var/log/singbox-manager/sing-box-ws.log"},
  "inbounds": [{
    "type": "vless", "tag": "vless-ws-in",
    "listen": "0.0.0.0", "listen_port": ${port},
    "users": [{"uuid": "${uuid}"}],
    "transport": {"type":"ws","path":"${path}","headers":{"Host":"${domain}"}},
    ${tls_block}
  }],
  "outbounds": [{"type":"direct","tag":"direct"}]
}
EOF
    print_success "WS config written → ${VWS_CONFIG}"
}

# ── systemd service ───────────────────────────────────────────
vws_create_service() {
    cat > "/etc/systemd/system/${VWS_SERVICE}.service" << EOF
[Unit]
Description=sing-box WS+TLS
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c ${VWS_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$VWS_SERVICE" &>/dev/null
    print_success "Service ${VWS_SERVICE} created."
}

# ── Add user to WS config ─────────────────────────────────────
vws_config_add_user() {
    local uuid="$1"
    VWS_CONFIG="$VWS_CONFIG" TARGET_UUID="$uuid" python3 - <<'PYEOF'
import json, os, sys
cf = os.environ["VWS_CONFIG"]
uuid = os.environ["TARGET_UUID"]
with open(cf) as f: c = json.load(f)
for ib in c.get("inbounds",[]):
    if ib.get("type")=="vless":
        users = ib.get("users",[])
        if any(u.get("uuid")==uuid for u in users):
            print("DUPLICATE"); sys.exit(0)
        users.append({"uuid":uuid})
        ib["users"]=users; break
import tempfile, os as _os
tmp=cf+".tmp"
with open(tmp,"w") as f: json.dump(c,f,indent=2)
_os.replace(tmp,cf)
print("OK")
PYEOF
}

vws_config_remove_user() {
    local uuid="$1"
    VWS_CONFIG="$VWS_CONFIG" TARGET_UUID="$uuid" python3 - <<'PYEOF'
import json, os
cf=os.environ["VWS_CONFIG"]; uuid=os.environ["TARGET_UUID"]
with open(cf) as f: c=json.load(f)
for ib in c.get("inbounds",[]):
    if ib.get("type")=="vless": ib["users"]=[u for u in ib.get("users",[]) if u.get("uuid")!=uuid]
tmp=cf+".tmp"
with open(tmp,"w") as f: json.dump(c,f,indent=2)
os.replace(tmp,cf)
PYEOF
}

# ── Install wizard ────────────────────────────────────────────
vws_install_server() {
    print_banner
    print_header "Install VLESS + WebSocket + TLS"
    echo -e "  ${DIM}Works through ArvanCloud / Cloudflare CDN.${NC}"
    echo -e "  ${DIM}Traffic looks like normal HTTPS — very hard to block.${NC}"
    echo -e "  ${YELLOW}Requires: domain with A record pointing to this server.${NC}\n"

    # Need sing-box binary — install if missing
    if [[ ! -f "$SINGBOX_BIN" ]]; then
        print_step 1 4 "Installing sing-box binary"
        check_internet
        fetch_singbox_version stable
        vless_install_binary "$SINGBOX_VERSION" || { press_enter; return 1; }
    fi

    print_step 2 4 "Configuration"
    echo ""

    ssl_load_domain 2>/dev/null || true
    local domain port path uuid

    ask domain "  Domain (must have A record here)" "${DOMAIN:-}"
    [[ -z "$domain" ]] && { print_error "Domain required for WS+TLS."; press_enter; return 1; }
    ask port   "  Listen port"                     "443"
    ask path   "  WebSocket path"                  "/$(openssl rand -hex 4 2>/dev/null || echo 'ws')"

    uuid=$(generate_uuid)

    print_step 3 4 "SSL Certificate"
    echo ""
    echo -e "  ${BOLD}SSL Certificate Status:${NC}"
    
    # Check certificate status
    local cert_status
    if ssl_cert_exists "$domain"; then
        print_success "Certificate already installed."
        cert_status="installed"
    elif ssl_has_valid_cert "$domain"; then
        print_info "Cached certificate found (not yet installed)"
        echo ""
        echo -e "  ${YELLOW}⚠ Cached certificate available in acme.sh${NC}"
        echo -e "  ${DIM}You can install it from the main menu:${NC}"
        echo -e "  ${DIM}  1. Go to option 4 (SSL Certificate)${NC}"
        echo -e "  ${DIM}  2. Select option 1 (Get Certificate)${NC}"
        echo -e "  ${DIM}  3. It will automatically use the cached certificate${NC}"
        echo ""
        if confirm "  Try to install the cached certificate now?" "y"; then
            if ssl_install_from_cache "$domain"; then
                print_success "Cached certificate installed!"
                cert_status="installed"
            else
                print_warn "Could not install cached certificate."
                cert_status="missing"
            fi
        else
            cert_status="cached"
        fi
    else
        print_warn "No certificate found."
        cert_status="missing"
    fi
    
    # Handle missing certificate
    if [[ "$cert_status" == "missing" ]]; then
        echo ""
        echo -e "  ${YELLOW}No SSL certificate for ${domain}${NC}"
        echo -e "  ${DIM}You have 3 options:${NC}"
        echo -e "  ${CYAN}1.${NC} Get free Let's Encrypt certificate"
        echo -e "  ${CYAN}2.${NC} Use ACME auto-cert (built-in)"
        echo -e "  ${CYAN}3.${NC} Use your own certificate"
        echo ""
        
        local choice
        echo -ne "  ${YELLOW}Choose option [2]: ${NC}"
        read -r choice
        choice="${choice:-2}"
        
        case "$choice" in
            1)
                print_info "Getting Let's Encrypt certificate..."
                if ssl_install_acme && ssl_issue "$domain"; then
                    print_success "Certificate installed!"
                else
                    print_warn "Certificate issuance failed. Using ACME auto-cert."
                    print_info "You can install SSL later from main menu → SSL Certificate"
                fi
                ;;
            2)
                print_info "Using ACME auto-cert (built-in)"
                ;;
            3)
                print_info "Using your own certificate"
                print_warn "You need to manually copy certificate files to:"
                print_warn "  Certificate: ${SSL_CERT_DIR}/${domain}/fullchain.pem"
                print_warn "  Private Key: ${SSL_CERT_DIR}/${domain}/key.pem"
                confirm "Continue with ACME auto-cert for now?" "y" || return 1
                ;;
            *)
                print_warn "Invalid choice. Using ACME auto-cert."
                ;;
        esac
    elif [[ "$cert_status" == "cached" ]]; then
        print_info "Will use ACME auto-cert for now."
        print_info "Install cached certificate later from SSL menu."
    fi

    print_step 4 4 "Writing config & starting service"
    vws_write_config "$port" "$path" "$domain" "$uuid"
    vws_save_info "$port" "$path" "$domain" "$uuid"
    vws_create_service

    # Register in DB
    local sub_token
    sub_token=$(generate_token)
    db_init
    local existing
    existing=$(db_get_user "$uuid" 2>/dev/null || echo "")
    if [[ -z "$existing" ]]; then
        db_add_user "$uuid" "default-ws" "0" "$sub_token" '{"vless_ws":true}'
    fi

    open_port "$port" tcp
    service_start "$VWS_SERVICE" || { press_enter; return 1; }

    local link
    link=$(vws_build_link "$uuid" "default-WS")

    echo ""
    echo -e "  ${GREEN}${BOLD}VLESS+WS+TLS Ready!${NC}"
    echo -e "  Domain  : ${CYAN}${domain}${NC}"
    echo -e "  Port    : ${CYAN}${port}${NC}"
    echo -e "  Path    : ${CYAN}${path}${NC}"
    echo ""
    echo -e "  ${BOLD}Link:${NC}"
    echo -e "  ${MAGENTA}${link}${NC}"
    print_qr "$link" "VLESS-WS"
    echo ""
    echo -e "  ${YELLOW}ArvanCloud setup:${NC}"
    echo -e "  ${DIM}1. Set A record for ${domain} → $(get_public_ip) (DNS-only, no CDN)${NC}"
    echo -e "  ${DIM}2. After confirming it works, enable CDN proxy in ArvanCloud${NC}"
    echo -e "  ${DIM}3. In ArvanCloud SSL settings: set to 'Full' or 'Full (strict)'${NC}"
    press_enter
}

# ── Status ────────────────────────────────────────────────────
vws_show_status() {
    service_status_line "$VWS_SERVICE" "VLESS+WS+TLS"
    if vws_read_info 2>/dev/null; then
        echo -e "  ${DIM}  domain=${VWS_DOMAIN} port=${VWS_PORT} path=${VWS_PATH}${NC}"
    fi
}

# ── Uninstall ─────────────────────────────────────────────────
vws_uninstall() {
    systemctl stop    "$VWS_SERVICE" 2>/dev/null || true
    systemctl disable "$VWS_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${VWS_SERVICE}.service"
    rm -f "$VWS_CONFIG" "$VWS_INFO"
    systemctl daemon-reload
    print_success "VLESS+WS+TLS removed."
}

# ── Service menu ──────────────────────────────────────────────
vws_service_menu() {
    while true; do
        print_banner
        print_header "VLESS+WS — Service Control"
        vws_show_status; echo ""
        echo -e "  ${CYAN}1)${NC}  Start    2)  Stop    3)  Restart    4)  Live log    ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) systemctl start   "$VWS_SERVICE" && print_success "Started.";   press_enter ;;
            2) systemctl stop    "$VWS_SERVICE" && print_success "Stopped.";   press_enter ;;
            3) systemctl restart "$VWS_SERVICE" && print_success "Restarted."; press_enter ;;
            4) journalctl -u "$VWS_SERVICE" -f ;;
            0) return ;;
        esac
    done
}
