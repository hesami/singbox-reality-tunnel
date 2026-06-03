#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  protocols/vless_grpc.sh — VLESS + gRPC + TLS
#
#  HTTP/2 gRPC transport — CDN compatible, lower latency than WS.
#  Depends on: core/common.sh  core/system.sh  core/db.sh
#              protocols/vless.sh (reuses binary)
#              features/ssl.sh
# ═══════════════════════════════════════════════════════════════

VGRPC_CONFIG="/etc/sing-box/config_grpc.json"
VGRPC_INFO="/etc/sing-box/server_grpc.json"
VGRPC_SERVICE="sing-box-grpc"

# ── Helpers ───────────────────────────────────────────────────
vgrpc_installed() { [[ -f "$VGRPC_INFO" && -f "$VGRPC_CONFIG" ]]; }

vgrpc_save_info() {
    # <port> <service_name> <domain>
    python3 -c "
import json
d={'port':int('${1}'),'service_name':'${2}','domain':'${3}'}
open('${VGRPC_INFO}','w').write(json.dumps(d,indent=2))
"
}

vgrpc_read_info() {
    [[ ! -f "$VGRPC_INFO" ]] && return 1
    eval "$(python3 -c "
import json
d=json.load(open('${VGRPC_INFO}'))
print(f\"VGRPC_PORT={d.get('port',443)}\")
print(f\"VGRPC_SVC={d.get('service_name','grpc')}\")
print(f\"VGRPC_DOMAIN={d.get('domain','')}\")
")"
}

vgrpc_build_link() {
    local uuid="$1" label="$2"
    vgrpc_read_info || return 1
    local enc_label
    enc_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${label}'))")
    echo "vless://${uuid}@${VGRPC_DOMAIN}:${VGRPC_PORT}?encryption=none&security=tls&sni=${VGRPC_DOMAIN}&fp=chrome&type=grpc&serviceName=${VGRPC_SVC}#${enc_label}"
}

# ── Write config ──────────────────────────────────────────────
vgrpc_write_config() {
    local port="$1" svc_name="$2" domain="$3" uuid="$4"

    ssl_load_domain 2>/dev/null || true
    local ssl_domain="${DOMAIN:-$domain}"
    local cert_file="${SSL_CERT_DIR}/${ssl_domain}/fullchain.pem"
    local key_file="${SSL_CERT_DIR}/${ssl_domain}/key.pem"

    local tls_block
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"${domain}\",\"certificate_path\":\"${cert_file}\",\"key_path\":\"${key_file}\"}"
        print_info "Using SSL cert: ${cert_file}"
    else
        tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"${domain}\",\"acme\":{\"domain\":\"${domain}\",\"email\":\"acme@${domain}\"}}"
        print_warn "No cert found — using ACME auto-cert."
    fi

    cat > "$VGRPC_CONFIG" << EOF
{
  "log": {"level":"warn","output":"/var/log/singbox-manager/sing-box-grpc.log"},
  "inbounds": [{
    "type": "vless", "tag": "vless-grpc-in",
    "listen": "0.0.0.0", "listen_port": ${port},
    "users": [{"uuid": "${uuid}"}],
    "transport": {"type":"grpc","service_name":"${svc_name}"},
    ${tls_block}
  }],
  "outbounds": [{"type":"direct","tag":"direct"}]
}
EOF
    print_success "gRPC config written → ${VGRPC_CONFIG}"
}

# ── systemd service ───────────────────────────────────────────
vgrpc_create_service() {
    cat > "/etc/systemd/system/${VGRPC_SERVICE}.service" << EOF
[Unit]
Description=sing-box gRPC+TLS
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c ${VGRPC_CONFIG}
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$VGRPC_SERVICE" &>/dev/null
    print_success "Service ${VGRPC_SERVICE} created."
}

# ── User management ───────────────────────────────────────────
vgrpc_config_add_user() {
    local uuid="$1"
    VG_CONFIG="$VGRPC_CONFIG" TARGET_UUID="$uuid" python3 - <<'PYEOF'
import json, os, sys
cf = os.environ["VG_CONFIG"]; uuid = os.environ["TARGET_UUID"]
with open(cf) as f: c = json.load(f)
for ib in c.get("inbounds",[]):
    if ib.get("type")=="vless":
        users = ib.get("users",[])
        if any(u.get("uuid")==uuid for u in users):
            print("DUPLICATE"); sys.exit(0)
        users.append({"uuid":uuid}); ib["users"]=users; break
tmp=cf+".tmp"
with open(tmp,"w") as f: json.dump(c,f,indent=2)
os.replace(tmp,cf); print("OK")
PYEOF
}

vgrpc_config_remove_user() {
    VG_CONFIG="$VGRPC_CONFIG" TARGET_UUID="$1" python3 - <<'PYEOF'
import json, os
cf=os.environ["VG_CONFIG"]; uuid=os.environ["TARGET_UUID"]
with open(cf) as f: c=json.load(f)
for ib in c.get("inbounds",[]):
    if ib.get("type")=="vless": ib["users"]=[u for u in ib.get("users",[]) if u.get("uuid")!=uuid]
tmp=cf+".tmp"
with open(tmp,"w") as f: json.dump(c,f,indent=2)
os.replace(tmp,cf)
PYEOF
}

# ── Install wizard ────────────────────────────────────────────
vgrpc_install_server() {
    print_banner
    print_header "Install VLESS + gRPC + TLS"
    echo -e "  ${DIM}HTTP/2 gRPC transport. CDN-compatible. Lower latency than WS.${NC}"
    echo -e "  ${YELLOW}Requires: domain with TLS certificate.${NC}\n"

    [[ ! -f "$SINGBOX_BIN" ]] && {
        check_internet; fetch_singbox_version stable
        vless_install_binary "$SINGBOX_VERSION" || { press_enter; return 1; }
    }

    ssl_load_domain 2>/dev/null || true
    local domain port svc_name uuid

    ask domain   "  Domain"               "${DOMAIN:-}"
    [[ -z "$domain" ]] && { print_error "Domain required for gRPC+TLS."; press_enter; return 1; }
    ask port     "  Listen port"          "443"
    svc_name=$(openssl rand -hex 8 2>/dev/null || cat /dev/urandom | tr -dc 'a-z0-9' | head -c 16)
    ask svc_name "  gRPC service name"    "$svc_name"
    uuid=$(generate_uuid)

    print_step 1 3 "SSL Certificate"
    if ! ssl_cert_exists "$domain"; then
        ssl_install_acme && ssl_issue "$domain" || print_warn "SSL failed — using ACME auto-cert."
    else
        print_success "Certificate exists for ${domain}."
    fi

    print_step 2 3 "Writing config & service"
    vgrpc_write_config "$port" "$svc_name" "$domain" "$uuid"
    vgrpc_save_info "$port" "$svc_name" "$domain"
    vgrpc_create_service

    print_step 3 3 "Starting service"
    local sub_token
    sub_token=$(generate_token)
    db_init
    local existing; existing=$(db_get_user "$uuid" 2>/dev/null || echo "")
    [[ -z "$existing" ]] && db_add_user "$uuid" "default-grpc" "0" "$sub_token" '{"vless_grpc":true}'

    open_port "$port" tcp
    service_start "$VGRPC_SERVICE" || { press_enter; return 1; }

    local link; link=$(vgrpc_build_link "$uuid" "default-gRPC")

    echo ""
    echo -e "  ${GREEN}${BOLD}VLESS+gRPC+TLS Ready!${NC}"
    echo -e "  Domain       : ${CYAN}${domain}${NC}"
    echo -e "  Port         : ${CYAN}${port}${NC}"
    echo -e "  Service name : ${CYAN}${svc_name}${NC}"
    echo ""
    echo -e "  ${BOLD}Link:${NC}"
    echo -e "  ${MAGENTA}${link}${NC}"
    print_qr "$link" "VLESS-gRPC"
    echo ""
    echo -e "  ${YELLOW}ArvanCloud / Cloudflare:${NC}"
    echo -e "  ${DIM}Enable gRPC in CDN settings. Set 'gRPC' toggle ON in the CDN panel.${NC}"
    echo -e "  ${DIM}In ArvanCloud: HTTPS settings → enable HTTP/2 and gRPC support.${NC}"
    press_enter
}

# ── Status ────────────────────────────────────────────────────
vgrpc_show_status() {
    service_status_line "$VGRPC_SERVICE" "VLESS+gRPC+TLS"
    if vgrpc_read_info 2>/dev/null; then
        echo -e "  ${DIM}  domain=${VGRPC_DOMAIN} port=${VGRPC_PORT} svc=${VGRPC_SVC}${NC}"
    fi
}

# ── Uninstall ─────────────────────────────────────────────────
vgrpc_uninstall() {
    systemctl stop    "$VGRPC_SERVICE" 2>/dev/null || true
    systemctl disable "$VGRPC_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${VGRPC_SERVICE}.service"
    rm -f "$VGRPC_CONFIG" "$VGRPC_INFO"
    systemctl daemon-reload
    print_success "VLESS+gRPC+TLS removed."
}

# ── Service menu ──────────────────────────────────────────────
vgrpc_service_menu() {
    while true; do
        print_banner; print_header "VLESS+gRPC — Service Control"
        vgrpc_show_status; echo ""
        echo -e "  ${CYAN}1)${NC}  Start  ${CYAN}2)${NC}  Stop  ${CYAN}3)${NC}  Restart  ${CYAN}4)${NC}  Live log  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) systemctl start   "$VGRPC_SERVICE" && print_success "Started.";   press_enter ;;
            2) systemctl stop    "$VGRPC_SERVICE" && print_success "Stopped.";   press_enter ;;
            3) systemctl restart "$VGRPC_SERVICE" && print_success "Restarted."; press_enter ;;
            4) journalctl -u "$VGRPC_SERVICE" -f ;;
            0) return ;;
        esac
    done
}
