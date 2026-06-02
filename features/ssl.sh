#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  features/ssl.sh — Free SSL certificate management via acme.sh
#
#  Depends on: core/common.sh  core/system.sh
# ═══════════════════════════════════════════════════════════════

ACME_HOME="/root/.acme.sh"
ACME_CMD="${ACME_HOME}/acme.sh"
SSL_CERT_DIR="/etc/singbox-manager/ssl"
SSL_DOMAIN_FILE="${BASE_DIR}/data/domain.conf"

# ── acme.sh install ────────────────────────────────────────────

ssl_install_acme() {
    if [[ -f "$ACME_CMD" ]]; then
        print_info "acme.sh already installed."
        return 0
    fi

    print_info "Installing dependencies..."
    apt-get update -qq &>/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl socat git openssl cron &>/dev/null || true
    systemctl enable cron  &>/dev/null || systemctl enable crond  &>/dev/null || true
    systemctl start  cron  &>/dev/null || systemctl start  crond  &>/dev/null || true

    print_info "Installing acme.sh..."
    # Simplest confirmed-working method: pipe to sh (installs to /root/.acme.sh)
    if curl -fsSL https://get.acme.sh | sh 2>&1 | tail -5; then
        [[ -f "$ACME_CMD" ]] && { print_success "acme.sh installed."; return 0; }
    fi

    # Fallback: git clone
    print_info "Trying git clone fallback..."
    local acme_src="/tmp/acme_src_$$"
    rm -rf "$acme_src"
    if git clone --depth=1 https://github.com/acmesh-official/acme.sh.git "$acme_src" &>/dev/null; then
        ( cd "$acme_src" && sh acme.sh --install 2>&1 | tail -3 )
        rm -rf "$acme_src"
    fi

    [[ -f "$ACME_CMD" ]] \
        && { print_success "acme.sh installed via git."; return 0; } \
        || { print_error "acme.sh install failed."; return 1; }
}

# ── Domain validation ──────────────────────────────────────────

# ssl_domain_resolves <domain>  → 0 if domain points to this server's IP
ssl_domain_resolves() {
    local domain="$1"
    local server_ip resolved_ip
    server_ip=$(get_public_ip)
    resolved_ip=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -1)
    [[ -z "$resolved_ip" ]] && \
        resolved_ip=$(curl -s --connect-timeout 5 "https://dns.google/resolve?name=${domain}&type=A" \
                      2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
ans=d.get('Answer',[])
print(ans[-1]['data'] if ans else '')
" 2>/dev/null || echo "")

    if [[ "$resolved_ip" == "$server_ip" ]]; then
        print_success "DNS verified: ${domain} → ${server_ip}"
        return 0
    else
        print_warn "DNS mismatch: ${domain} resolves to '${resolved_ip}', expected '${server_ip}'."
        print_warn "Make sure your DNS A record points to this server before getting a certificate."
        return 1
    fi
}

# ── Issue certificate ──────────────────────────────────────────

# ssl_issue <domain> [port:80]  → 0 on success
# Uses standalone mode (temporarily binds port 80)
ssl_issue() {
    local domain="$1" http_port="${2:-80}"
    local cert_dir="${SSL_CERT_DIR}/${domain}"
    mkdir -p "$cert_dir" "$LOG_DIR"

    # ── Already have a cert? Just install it ──────────────────
    local acme_cert_dir
    acme_cert_dir=$(
        ls -d "${ACME_HOME}/${domain}_ecc" "${ACME_HOME}/${domain}" 2>/dev/null | head -1 || true
    )
    if [[ -n "$acme_cert_dir" && -f "${acme_cert_dir}/${domain}.cer" ]]; then
        print_info "Certificate already in acme.sh cache — installing to ${cert_dir}..."
        "$ACME_CMD" --install-cert -d "$domain" \
            --cert-file      "${cert_dir}/cert.pem" \
            --key-file       "${cert_dir}/key.pem" \
            --fullchain-file "${cert_dir}/fullchain.pem" \
            --reloadcmd      "systemctl reload-or-restart hysteria-server 2>/dev/null; \
                              systemctl reload-or-restart sing-box 2>/dev/null; true" \
            2>&1 | sed 's/^/  /'
        if [[ -f "${cert_dir}/cert.pem" ]]; then
            print_success "Certificate installed → ${cert_dir}"
            ssl_save_domain "$domain"
            return 0
        fi
    fi

    # ── Issue new certificate ─────────────────────────────────
    print_info "Requesting certificate for ${domain} (port ${http_port})..."

    # Make sure port 80 is open
    open_port "$http_port" tcp &>/dev/null

    # Stop anything that might be using port 80
    for svc in nginx apache2 apache httpd; do
        systemctl stop "$svc" 2>/dev/null || true
    done

    local issue_output issue_rc
    # Ensure account has valid email (domain-based) before issuing
    "$ACME_CMD" --register-account --email "ssl@${domain}" \
        --server letsencrypt &>/dev/null \
        || "$ACME_CMD" --update-account --email "ssl@${domain}" &>/dev/null \
        || true

    issue_output=$( "$ACME_CMD" --issue \
        --standalone \
        --httpport "$http_port" \
        -d "$domain" \
        --server letsencrypt \
        --email "admin@${domain}" \
        --log "${LOG_DIR}/acme.log" \
        --force 2>&1 )
    issue_rc=$?

    # Show last 10 lines of output for visibility
    echo "$issue_output" | tail -10 | sed 's/^/  /'

    # Check success — either rc=0 or cert already exists
    acme_cert_dir=$(
        ls -d "${ACME_HOME}/${domain}_ecc" "${ACME_HOME}/${domain}" 2>/dev/null | head -1 || true
    )
    if [[ $issue_rc -eq 0 ]] || \
       [[ -n "$acme_cert_dir" && -f "${acme_cert_dir}/${domain}.cer" ]]; then
        "$ACME_CMD" --install-cert -d "$domain" \
            --cert-file      "${cert_dir}/cert.pem" \
            --key-file       "${cert_dir}/key.pem" \
            --fullchain-file "${cert_dir}/fullchain.pem" \
            --reloadcmd      "systemctl reload-or-restart hysteria-server 2>/dev/null; \
                              systemctl reload-or-restart sing-box 2>/dev/null; true" \
            &>/dev/null
        if [[ -f "${cert_dir}/cert.pem" ]]; then
            print_success "Certificate issued and installed → ${cert_dir}"
            ssl_save_domain "$domain"
            return 0
        fi
    fi

    print_error "Certificate issuance failed."
    # Detect rate limit and show helpful retry date
    if echo "$issue_output" | grep -q "rateLimited"; then
        local retry_after
        retry_after=$(echo "$issue_output" | grep -oP 'retry after \K[^"]+' | head -1)
        print_warn "Let's Encrypt rate limit reached (5 certs/week per domain)."
        [[ -n "$retry_after" ]] && print_warn "Retry after: ${retry_after}"
        print_info "WS+TLS will use sing-box built-in ACME cert as fallback."
    fi
    print_info "Full log: ${LOG_DIR}/acme.log"
    echo -e "  ${DIM}Common causes:${NC}"
    echo -e "  ${DIM}• Port 80 blocked in VPS provider firewall panel${NC}"
    echo -e "  ${DIM}• DNS A record not yet pointing to this server${NC}"
    echo -e "  ${DIM}• CDN proxy mode ON in ArvanCloud/Cloudflare (must be DNS-only)${NC}"
    return 1
}

# ── Revoke / remove ────────────────────────────────────────────

ssl_revoke() {
    local domain="$1"
    [[ ! -f "$ACME_CMD" ]] && { print_error "acme.sh not installed."; return 1; }
    "$ACME_CMD" --revoke -d "$domain" &>/dev/null || true
    "$ACME_CMD" --remove -d "$domain" &>/dev/null || true
    rm -rf "${SSL_CERT_DIR}/${domain}"
    print_success "Certificate for ${domain} removed."
}

# ── Auto-renew cron ────────────────────────────────────────────

ssl_setup_renew_cron() {
    # acme.sh installs its own cron automatically during --issue.
    # We add a wrapper that also reloads our services after renewal.
    local reload_hook="/etc/singbox-manager/ssl_reload_hook.sh"
    cat > "$reload_hook" << 'EOF'
#!/usr/bin/env bash
# Called by acme.sh after successful renewal
systemctl reload-or-restart hysteria-server 2>/dev/null || true
systemctl reload-or-restart sing-box        2>/dev/null || true
EOF
    chmod +x "$reload_hook"
    print_info "Service reload hook installed → ${reload_hook}"
}

# ── Domain configuration persistence ──────────────────────────

ssl_save_domain() {
    local domain="$1"
    mkdir -p "$(dirname "$SSL_DOMAIN_FILE")"
    echo "DOMAIN=${domain}" > "$SSL_DOMAIN_FILE"
}

ssl_load_domain() {
    [[ -f "$SSL_DOMAIN_FILE" ]] && source "$SSL_DOMAIN_FILE" || DOMAIN=""
}

ssl_get_cert_path() {
    local domain="$1"
    echo "${SSL_CERT_DIR}/${domain}/fullchain.pem"
}

ssl_get_key_path() {
    local domain="$1"
    echo "${SSL_CERT_DIR}/${domain}/key.pem"
}

ssl_cert_exists() {
    local domain="$1"
    [[ -f "${SSL_CERT_DIR}/${domain}/cert.pem" ]]
}

ssl_cert_expiry() {
    local domain="$1"
    local cert="${SSL_CERT_DIR}/${domain}/cert.pem"
    [[ -f "$cert" ]] || { echo "—"; return; }
    openssl x509 -enddate -noout -in "$cert" 2>/dev/null \
        | sed 's/notAfter=//' || echo "—"
}

# ── Interactive wizard ─────────────────────────────────────────

ssl_wizard() {
    print_banner
    print_header "SSL Certificate Setup"
    echo -e "  ${DIM}Issue a free Let's Encrypt certificate for your domain.${NC}"
    echo -e "  ${DIM}Your domain must have an A record pointing to this server.${NC}\n"

    ssl_load_domain
    local domain
    ask domain "  Your domain (e.g. vpn.example.com)" "${DOMAIN:-}"
    [[ -z "$domain" ]] && { print_error "Domain required."; press_enter; return 1; }

    print_step 1 4 "Validating DNS"
    if ! ssl_domain_resolves "$domain"; then
        confirm "DNS not confirmed. Try anyway? (may fail)" "n" || { press_enter; return 1; }
    fi

    print_step 2 4 "Installing acme.sh"
    ssl_install_acme || { press_enter; return 1; }

    print_step 3 4 "Issuing certificate"
    ssl_issue "$domain" || { press_enter; return 1; }

    print_step 4 4 "Setting up auto-renewal"
    ssl_setup_renew_cron
    print_success "Certificates auto-renew every 60 days."

    echo ""
    echo -e "  ${GREEN}${BOLD}Certificate ready!${NC}"
    echo -e "  Domain   : ${CYAN}${domain}${NC}"
    echo -e "  Cert     : ${DIM}${SSL_CERT_DIR}/${domain}/cert.pem${NC}"
    echo -e "  Key      : ${DIM}${SSL_CERT_DIR}/${domain}/key.pem${NC}"
    echo -e "  Expires  : ${CYAN}$(ssl_cert_expiry "$domain")${NC}"
    press_enter
}

# ── SSL status display ─────────────────────────────────────────

ssl_show_status() {
    ssl_load_domain
    print_header "SSL / Domain"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "  Domain  : ${CYAN}${DOMAIN}${NC}"
        if ssl_cert_exists "$DOMAIN"; then
            echo -e "  Cert    : ${GREEN}✔ valid${NC}"
            echo -e "  Expires : ${CYAN}$(ssl_cert_expiry "$DOMAIN")${NC}"
        else
            echo -e "  Cert    : ${YELLOW}not found — run SSL wizard${NC}"
        fi
    else
        echo -e "  Domain  : ${DIM}not configured — using IP address${NC}"
    fi
}

# ── Full SSL management menu ───────────────────────────────────

ssl_menu() {
    while true; do
        print_banner
        print_header "SSL Certificate Management"
        ssl_show_status
        echo ""
        echo -e "  ${CYAN}1)${NC}  Issue / Renew certificate  ${DIM}(Let's Encrypt)${NC}"
        echo -e "  ${CYAN}2)${NC}  Force renew now"
        echo -e "  ${CYAN}3)${NC}  Remove certificate"
        echo -e "  ${CYAN}4)${NC}  Check expiry"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        ssl_load_domain
        case "$MENU_CHOICE" in
            1) ssl_wizard ;;
            2)
                [[ -z "$DOMAIN" ]] && { print_warn "No domain configured."; press_enter; continue; }
                [[ -f "$ACME_CMD" ]] && \
                    "$ACME_CMD" --renew -d "$DOMAIN" --force &>/dev/null \
                    && print_success "Certificate renewed." \
                    || print_error "Renewal failed."
                press_enter
                ;;
            3)
                [[ -z "$DOMAIN" ]] && { print_warn "No domain configured."; press_enter; continue; }
                confirm "Remove certificate for ${DOMAIN}?" "n" && ssl_revoke "$DOMAIN"
                press_enter
                ;;
            4)
                [[ -z "$DOMAIN" ]] && { print_warn "No domain configured."; press_enter; continue; }
                echo -e "\n  ${BOLD}${DOMAIN}${NC} expires: ${CYAN}$(ssl_cert_expiry "$DOMAIN")${NC}\n"
                press_enter
                ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}
