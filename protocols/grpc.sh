#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  protocols/grpc.sh — VLESS + gRPC
#
#  gRPC is a high-performance RPC framework over HTTP/2.
#  It provides low latency and high throughput.
#  Works through CDN (Cloudflare / ArvanCloud with HTTP/2 support).
#  
#  Depends on: core/common.sh  core/system.sh  core/db.sh
#              protocols/vless.sh (reuses binary + service)
# ═══════════════════════════════════════════════════════════════

GRPC_CONFIG="/etc/sing-box/config_grpc.json"
GRPC_INFO="/etc/sing-box/server_grpc.json"
GRPC_SERVICE="sing-box-grpc"

# ── Check if installed ────────────────────────────────────────
grpc_installed() { [[ -f "$GRPC_INFO" && -f "$GRPC_CONFIG" ]]; }

# ── Save / read server info ───────────────────────────────────
grpc_save_info() {
    # grpc_save_info <port> <service_name> <domain> <uuid>
    python3 -c "
import json
d={
    'port': int('${1}'),
    'service_name': '${2}',
    'domain': '${3}',
    'uuid': '${4}'
}
open('${GRPC_INFO}','w').write(json.dumps(d, indent=2))
"
}

grpc_read_info() {
    [[ ! -f "$GRPC_INFO" ]] && return 1
    eval "$(python3 -c "
import json
d = json.load(open('${GRPC_INFO}'))
print(f\"GRPC_PORT={d.get('port', 443)}\")
print(f\"GRPC_SERVICE_NAME={d.get('service_name', 'grpc')}\")
print(f\"GRPC_DOMAIN={d.get('domain', '')}\")
print(f\"GRPC_UUID={d.get('uuid', '')}\")
")"
}

# ── Build link ────────────────────────────────────────────────
grpc_build_link() {
    local uuid="$1" label="$2"
    grpc_read_info || return 1
    local host="${GRPC_DOMAIN:-$(get_public_ip)}"
    local enc_label
    enc_label=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${label}'))")
    # TLS on 443 with gRPC multiplexing
    echo "vless://${uuid}@${host}:${GRPC_PORT}?encryption=none&security=tls&sni=${GRPC_DOMAIN}&alpn=h2&type=grpc&serviceName=${GRPC_SERVICE_NAME}#${enc_label}"
}

# ── Write config ──────────────────────────────────────────────
grpc_write_config() {
    local port="$1" service_name="$2" domain="$3" uuid="$4"
    local cert_file key_file has_cert=false

    # Try to find SSL certificate
    local ssl_domain="${domain}"
    
    # Check if cert exists in our directory
    cert_file="${SSL_CERT_DIR}/${ssl_domain}/fullchain.pem"
    key_file="${SSL_CERT_DIR}/${ssl_domain}/key.pem"
    
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        has_cert=true
        print_success "Using SSL certificate for gRPC: ${cert_file}"
    else
        print_info "Checking for cached SSL certificate for gRPC..."
        if ssl_has_valid_cert "$domain"; then
            print_info "Cached certificate found for ${domain}"
        fi
        
        print_warn "No SSL certificate found for ${domain}"
        print_info "Will attempt ACME auto-cert for gRPC"
    fi

    local tls_block
    if $has_cert; then
        tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"${domain}\",\"certificate_path\":\"${cert_file}\",\"key_path\":\"${key_file}\"}"
    else
        tls_block="\"tls\":{\"enabled\":true,\"server_name\":\"${domain}\",\"acme\":{\"domain\":\"${domain}\",\"email\":\"acme@${domain}\"}}"
    fi

    cat > "$GRPC_CONFIG" << EOF
{
  "log": {"level":"warn","output":"/var/log/singbox-manager/sing-box-grpc.log"},
  "inbounds": [{
    "type": "vless", "tag": "vless-grpc-in",
    "listen": "0.0.0.0", "listen_port": ${port},
    "users": [{"uuid": "${uuid}"}],
    "transport": {
      "type": "grpc",
      "service_name": "${service_name}",
      "idle_timeout": "15s",
      "ping_timeout": "15s",
      "permit_without_stream": false
    },
    ${tls_block}
  }],
  "outbounds": [{"type":"direct","tag":"direct"}]
}
EOF
    print_success "gRPC config written → ${GRPC_CONFIG}"
}

# ── Create systemd service ────────────────────────────────────
grpc_create_service() {
    local service_file="/etc/systemd/system/${GRPC_SERVICE}.service"
    
    cat > "$service_file" << 'SVCEOF'
[Unit]
Description=sing-box gRPC+TLS
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config_grpc.json
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable "$GRPC_SERVICE" 2>/dev/null
    print_success "gRPC service created: ${service_file}"
}

# ── Menu interaction ──────────────────────────────────────────
grpc_show_info() {
    local uuid="$1" label="$2"
    grpc_read_info || return 1
    
    echo ""
    echo -e "  ${BOLD}━━━ gRPC Configuration ━━━${NC}"
    echo -e "  ${CYAN}Service Name${NC}    : ${GRPC_SERVICE_NAME}"
    echo -e "  ${CYAN}Domain${NC}          : ${GRPC_DOMAIN}"
    echo -e "  ${CYAN}Port${NC}            : ${GRPC_PORT}"
    echo ""
    echo -e "  ${BOLD}Config Link${NC}:"
    local link
    link=$(grpc_build_link "$uuid" "$label")
    echo -e "  ${GREEN}${link}${NC}"
}
