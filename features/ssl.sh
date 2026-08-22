#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  features/ssl.sh — SSL certificate management (nginx-safe)
#
#  Rules:
#    • NEVER stop/reload/reconfigure nginx/apache.
#    • NEVER bind to ports 80/443 for certificate issuance.
#    • Prefer an existing Certbot certificate.
#    • If missing, issue via Certbot manual DNS-01 (no open ports required).
#    • Manager-owned paths are symlinks to Certbot live files so renewals
#      are picked up without copying stale certificates.
# ═══════════════════════════════════════════════════════════════

CERTBOT_BIN="$(command -v certbot 2>/dev/null || true)"
SSL_CERT_DIR="/etc/singbox-manager/ssl"
SSL_DOMAIN_FILE="${BASE_DIR}/data/domain.conf"

ssl_install_certbot() {
    if command -v certbot >/dev/null 2>&1; then
        CERTBOT_BIN="$(command -v certbot)"
        print_info "Certbot already installed."
        return 0
    fi

    print_info "Installing Certbot (DNS-01 capable; nginx will not be touched)..."
    apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot openssl ca-certificates >/dev/null 2>&1 || {
        print_error "Certbot installation failed."
        return 1
    }
    CERTBOT_BIN="$(command -v certbot 2>/dev/null || true)"
    [[ -n "$CERTBOT_BIN" ]] || { print_error "certbot binary not found after installation."; return 1; }
    print_success "Certbot installed."
}

# Compatibility alias for older callers. This function intentionally does
# NOT install or use acme.sh and never changes nginx.
ssl_install_acme() { ssl_install_certbot; }

ssl_domain_resolves() {
    local domain="$1" server_ip resolved_ip
    server_ip=$(get_public_ip 2>/dev/null || true)
    resolved_ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk 'NR==1{print $1}')
    if [[ -n "$server_ip" && -n "$resolved_ip" && "$resolved_ip" == "$server_ip" ]]; then
        print_success "DNS verified: ${domain} → ${server_ip}"
        return 0
    fi
    print_warn "DNS A record was not verified against this server (${resolved_ip:-unknown} / ${server_ip:-unknown})."
    return 1
}

ssl_certbot_live_cert() {
    local domain="$1" base
    # Certbot may create lineage names such as example.com-0001. Prefer the
    # exact name, then compatible suffixes, and verify the certificate covers
    # the requested hostname before reusing it.
    for base in "/etc/letsencrypt/live/${domain}" /etc/letsencrypt/live/${domain}-*; do
        [[ -d "$base" ]] || continue
        [[ -f "${base}/fullchain.pem" && -f "${base}/privkey.pem" ]] || continue
        if openssl x509 -in "${base}/fullchain.pem" -noout -checkhost "$domain" >/dev/null 2>&1; then
            echo "${base}/fullchain.pem|${base}/privkey.pem"
            return 0
        fi
        # Compatibility fallback for older OpenSSL builds without -checkhost.
        if openssl x509 -in "${base}/fullchain.pem" -noout -text 2>/dev/null             | grep -Fq "DNS:${domain}"; then
            echo "${base}/fullchain.pem|${base}/privkey.pem"
            return 0
        fi
    done
    return 1
}

ssl_link_certbot_cert() {
    local domain="$1" pair cert key dest
    pair=$(ssl_certbot_live_cert "$domain") || return 1
    cert="${pair%%|*}"; key="${pair#*|}"
    dest="${SSL_CERT_DIR}/${domain}"
    mkdir -p "$dest"
    ln -sfn "$cert" "${dest}/fullchain.pem"
    ln -sfn "$cert" "${dest}/cert.pem"
    ln -sfn "$key"  "${dest}/key.pem"
    ssl_save_domain "$domain"
    return 0
}

ssl_issue_dns01() {
    local domain="$1"
    ssl_install_certbot || return 1

    print_info "Starting Certbot DNS-01 validation for ${domain}."
    print_info "This does not use ports 80/443 and does not modify nginx."
    echo ""

    # Manual DNS-01 works with any DNS provider. It is intentionally
    # interactive because the user must create the TXT record shown by Certbot.
    "$CERTBOT_BIN" certonly \
        --manual \
        --preferred-challenges dns \
        --agree-tos \
        --register-unsafely-without-email \
        --keep-until-expiring \
        -d "$domain" || {
            print_error "Certbot DNS-01 certificate issuance failed."
            return 1
        }

    ssl_link_certbot_cert "$domain" || {
        print_error "Certbot finished but certificate files were not found for ${domain}."
        return 1
    }
    print_success "Certificate ready → /etc/letsencrypt/live/${domain}/"
}

# ssl_issue <domain> [ignored-port]
# Compatibility entrypoint. Never uses the supplied port.
ssl_issue() {
    local domain="$1"
    if ssl_link_certbot_cert "$domain"; then
        print_success "Using existing Certbot certificate for ${domain}."
        return 0
    fi
    ssl_issue_dns01 "$domain"
}

ssl_ensure_certificate() {
    local domain="$1"
    [[ -n "$domain" ]] || return 1

    # Manager path already valid.
    if ssl_cert_exists "$domain"; then
        return 0
    fi

    # Existing Certbot certificate (possibly already used by the website).
    if ssl_link_certbot_cert "$domain"; then
        print_success "Reusing existing Certbot certificate for ${domain}; nginx unchanged."
        return 0
    fi

    print_warn "No existing certificate found for ${domain}."
    if confirm "Obtain one now with Certbot DNS-01?" "y"; then
        ssl_issue_dns01 "$domain"
        return $?
    fi
    return 1
}

# Detach only. Never revoke/delete the Certbot certificate because it may be
# shared by the user's website/nginx.
ssl_revoke() {
    local domain="$1"
    rm -rf "${SSL_CERT_DIR:?}/${domain}"
    if [[ -f "$SSL_DOMAIN_FILE" ]] && grep -q "^DOMAIN=${domain}$" "$SSL_DOMAIN_FILE" 2>/dev/null; then
        rm -f "$SSL_DOMAIN_FILE"
    fi
    print_success "Certificate detached from sing-box manager. Certbot/nginx files were not changed."
}

ssl_setup_renew_cron() {
    # Do not alter Certbot's own renewal configuration. Only install a deploy
    # hook so already-automated Certbot certificates reload proxy services.
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    local hook="${hook_dir}/singbox-manager-reload.sh"
    mkdir -p "$hook_dir"
    cat > "$hook" <<'HOOK'
#!/usr/bin/env bash
systemctl reload-or-restart hysteria-server 2>/dev/null || true
systemctl reload-or-restart sing-box 2>/dev/null || true
HOOK
    chmod 755 "$hook"
    print_info "Certbot deploy hook installed (nginx is not modified)."
}

ssl_save_domain() {
    local domain="$1"
    mkdir -p "$(dirname "$SSL_DOMAIN_FILE")"
    printf 'DOMAIN=%q\n' "$domain" > "$SSL_DOMAIN_FILE"
}

ssl_load_domain() {
    DOMAIN=""
    [[ -f "$SSL_DOMAIN_FILE" ]] && source "$SSL_DOMAIN_FILE" || true
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
    local cert="${SSL_CERT_DIR}/${domain}/fullchain.pem"
    local key="${SSL_CERT_DIR}/${domain}/key.pem"
    [[ -f "$cert" && -f "$key" ]] || return 1
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$key" -noout >/dev/null 2>&1 || return 1
    return 0
}

ssl_cert_expiry() {
    local domain="$1" cert="${SSL_CERT_DIR}/${domain}/fullchain.pem"
    [[ -f "$cert" ]] || { echo "—"; return; }
    openssl x509 -enddate -noout -in "$cert" 2>/dev/null | sed 's/notAfter=//' || echo "—"
}

ssl_wizard() {
    print_banner
    print_header "SSL Certificate Setup — nginx-safe"
    echo -e "  ${DIM}Uses an existing Certbot certificate or Certbot DNS-01.${NC}"
    echo -e "  ${DIM}Ports 80/443 and nginx configuration are never changed.${NC}\n"

    ssl_load_domain
    local domain
    ask domain "  Your domain (e.g. vpn.example.com)" "${DOMAIN:-}"
    [[ -z "$domain" ]] && { print_error "Domain required."; press_enter; return 1; }

    print_step 1 3 "Checking existing certificate"
    if ssl_link_certbot_cert "$domain"; then
        print_success "Existing Certbot certificate detected and linked."
    else
        print_step 2 3 "Obtaining certificate with DNS-01"
        ssl_issue_dns01 "$domain" || { press_enter; return 1; }
    fi

    print_step 3 3 "Installing renewal deploy hook"
    ssl_setup_renew_cron
    ssl_save_domain "$domain"

    echo ""
    print_success "Certificate ready for ${domain}."
    echo -e "  Cert    : ${DIM}$(ssl_get_cert_path "$domain")${NC}"
    echo -e "  Key     : ${DIM}$(ssl_get_key_path "$domain")${NC}"
    echo -e "  Expires : ${CYAN}$(ssl_cert_expiry "$domain")${NC}"
    press_enter
}

ssl_show_status() {
    ssl_load_domain
    print_header "SSL / Domain"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "  Domain  : ${CYAN}${DOMAIN}${NC}"
        if ssl_cert_exists "$DOMAIN"; then
            echo -e "  Cert    : ${GREEN}✔ valid${NC}"
            echo -e "  Expires : ${CYAN}$(ssl_cert_expiry "$DOMAIN")${NC}"
        else
            echo -e "  Cert    : ${YELLOW}not linked/found${NC}"
        fi
    else
        echo -e "  Domain  : ${DIM}not configured${NC}"
    fi
}

ssl_menu() {
    while true; do
        print_banner
        print_header "SSL Certificate Management — nginx-safe"
        ssl_show_status
        echo ""
        echo -e "  ${CYAN}1)${NC}  Detect / obtain certificate ${DIM}(Certbot DNS-01; no ports)${NC}"
        echo -e "  ${CYAN}2)${NC}  Re-link existing Certbot certificate"
        echo -e "  ${CYAN}3)${NC}  Detach from manager ${DIM}(does not delete website certificate)${NC}"
        echo -e "  ${CYAN}4)${NC}  Check expiry"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        ssl_load_domain
        case "$MENU_CHOICE" in
            1) ssl_wizard ;;
            2)
                [[ -z "$DOMAIN" ]] && { print_warn "No domain configured."; press_enter; continue; }
                ssl_link_certbot_cert "$DOMAIN" \
                    && print_success "Certificate linked." \
                    || print_error "No Certbot certificate found for ${DOMAIN}."
                press_enter
                ;;
            3)
                [[ -z "$DOMAIN" ]] && { print_warn "No domain configured."; press_enter; continue; }
                confirm "Detach certificate from this manager only?" "n" && ssl_revoke "$DOMAIN"
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
