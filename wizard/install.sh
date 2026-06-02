#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  wizard/install.sh — First-time setup wizard
#
#  Flow:
#    Goal selection → Protocol selection → Domain/SSL
#    → Protocol install → Optimization (optional)
#
#  Depends on: all core/ + all protocols/ + features/ssl.sh
#              features/optimization.sh
# ═══════════════════════════════════════════════════════════════

wizard_install() {
    check_root
    check_os

    print_banner
    echo -e "  ${BOLD}Welcome to the sing-box Proxy Manager setup wizard.${NC}"
    echo -e "  ${DIM}Answer a few questions and everything will be configured automatically.${NC}\n"

    # ══════════════════════════════════════════════════════════
    #  STEP 1 — What do you want to set up?
    # ══════════════════════════════════════════════════════════
    print_header "Step 1 of 4 — What are you setting up?"
    echo ""
    echo -e "  ${CYAN}${BOLD}1)${NC}  ${BOLD}Direct Proxy${NC}  ${DIM}— one server abroad, clients connect directly${NC}"
    echo -e "     ${DIM}Typical setup: you rent a VPS in Germany/Netherlands/etc.${NC}"
    echo -e "     ${DIM}→ Clients connect from Iran directly to that server.${NC}"
    echo ""
    echo -e "  ${CYAN}${BOLD}2)${NC}  ${BOLD}Tunnel (two servers)${NC}  ${DIM}— Iran relay + foreign server${NC}"
    echo -e "     ${DIM}Use this when your foreign server's IP is blocked in Iran.${NC}"
    echo -e "     ${DIM}→ Iran server receives traffic, tunnels it abroad.${NC}"
    echo -e "     ${DIM}  (Run this wizard separately on each server.)${NC}"
    echo ""
    menu_prompt

    local goal
    case "$MENU_CHOICE" in
        1) goal="proxy"  ;;
        2) goal="tunnel" ;;
        *) print_warn "Invalid choice. Defaulting to Direct Proxy."; goal="proxy" ;;
    esac

    # Tunnel mode is handled by wizard/tunnel.sh
    if [[ "$goal" == "tunnel" ]]; then
        wizard_tunnel
        return
    fi

    # ══════════════════════════════════════════════════════════
    #  STEP 2 — Which protocol(s)?
    # ══════════════════════════════════════════════════════════
    print_banner
    print_header "Step 2 of 4 — Choose protocol(s)"
    echo ""
    echo -e "  ${CYAN}${BOLD}1)${NC}  ${BOLD}VLESS + Reality${NC}  ${DIM}(TCP — stable, disguised as HTTPS)${NC}"
    echo -e "  ${CYAN}${BOLD}2)${NC}  ${BOLD}Hysteria2${NC}  ${DIM}(QUIC/UDP — fast on lossy networks)${NC}"
    echo -e "  ${CYAN}${BOLD}3)${NC}  ${BOLD}VLESS + WebSocket + TLS${NC}  ${DIM}(works through ArvanCloud CDN)${NC}"
    echo -e "  ${CYAN}${BOLD}4)${NC}  ${BOLD}All three${NC}  ${DIM}(recommended — client picks best automatically)${NC}"
    echo -e "  ${CYAN}${BOLD}5)${NC}  ${BOLD}Reality + Hysteria2${NC}  ${DIM}(no CDN needed)${NC}"
    echo ""
    menu_prompt

    local install_vless=false install_hy2=false install_ws=false
    case "$MENU_CHOICE" in
        1) install_vless=true ;;
        2) install_hy2=true ;;
        3) install_ws=true ;;
        4|"") install_vless=true; install_hy2=true; install_ws=true ;;
        5) install_vless=true; install_hy2=true ;;
        *) print_warn "Invalid — installing Reality + Hysteria2."; install_vless=true; install_hy2=true ;;
    esac

    # ══════════════════════════════════════════════════════════
    #  STEP 3 — Domain & SSL
    # ══════════════════════════════════════════════════════════
    print_banner
    print_header "Step 3 of 4 — Domain & SSL"
    echo ""
    echo -e "  ${BOLD}Do you have a domain pointing to this server?${NC}"
    echo -e "  ${DIM}Example: vpn.yourdomain.com → $(get_public_ip)${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC}  ${BOLD}Yes — use domain + free Let's Encrypt SSL${NC}  ${DIM}(recommended)${NC}"
    echo -e "     ${DIM}Subscription links and configs will use your domain.${NC}"
    echo -e "     ${DIM}Enables future CDN/proxy support (ArvanCloud, Cloudflare).${NC}"
    echo ""
    echo -e "  ${CYAN}2)${NC}  ${BOLD}No — use IP address${NC}"
    echo -e "     ${DIM}Self-signed certificate for Hysteria2. Less ideal but works.${NC}"
    echo ""
    menu_prompt

    local use_domain=false domain=""
    if [[ "$MENU_CHOICE" == "1" ]]; then
        use_domain=true
        echo ""
        ask domain "  Your domain (e.g. vpn.example.com)" ""
        if [[ -z "$domain" ]]; then
            print_warn "No domain entered — falling back to IP mode."
            use_domain=false
        else
            ssl_load_domain
            if ! ssl_domain_resolves "$domain"; then
                echo ""
                print_warn "DNS check failed. Make sure the A record is set before continuing."
                if ! confirm "Continue anyway? (TLS cert may fail)" "n"; then
                    use_domain=false; domain=""
                fi
            fi
        fi
    fi

    # Issue SSL cert if domain confirmed
    if $use_domain && [[ -n "$domain" ]]; then
        print_step "3a" "—" "Issuing SSL certificate"
        ssl_install_acme || print_warn "acme.sh install failed — will retry after protocol install."
        ssl_issue "$domain" && ssl_setup_renew_cron \
            || print_warn "Certificate issuance failed. You can retry later from the SSL menu."
        ssl_save_domain "$domain"
    fi

    # ══════════════════════════════════════════════════════════
    #  STEP 4 — Install protocols
    # ══════════════════════════════════════════════════════════
    print_banner
    print_header "Step 4 of 4 — Installing"
    check_internet
    db_init

    # ── VLESS ────────────────────────────────────────────────
    if $install_vless; then
        echo ""
        echo -e "  ${BOLD}─── VLESS + Reality ───────────────────────────────${NC}"
        fetch_singbox_version stable
        vless_install_binary "$SINGBOX_VERSION" || {
            print_error "VLESS binary install failed."; press_enter; return 1
        }

        # Get port + SNI
        local vless_port vless_sni vless_sid
        local default_sid
        default_sid=$(openssl rand -hex 4 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 8)
        echo ""
        ask vless_port "  VLESS listen port"          "443"
        ask vless_sni  "  Camouflage SNI domain"      "www.speedtest.net"
        ask vless_sid  "  Short ID (hex)"             "$default_sid"

        # Generate keypair and first user
        local keypair private_key public_key uuid sub_token
        keypair=$(generate_keypair)
        private_key=$(echo "$keypair" | awk '/PrivateKey/{print $2}')
        public_key=$(echo  "$keypair" | awk '/PublicKey/{print $2}')
        uuid=$(generate_uuid)
        sub_token=$(generate_token)

        local vhost="${domain:-$(get_public_ip)}"

        vless_write_config "{
  \"log\": { \"level\": \"warn\", \"output\": \"/var/log/singbox-manager/sing-box.log\" },
  \"inbounds\": [{
    \"type\": \"vless\", \"tag\": \"vless-in\",
    \"listen\": \"0.0.0.0\", \"listen_port\": ${vless_port},
    \"users\": [{\"uuid\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true, \"server_name\": \"${vless_sni}\",
      \"reality\": {
        \"enabled\": true,
        \"handshake\": {\"server\": \"${vless_sni}\", \"server_port\": 443},
        \"private_key\": \"${private_key}\",
        \"short_id\": [\"${vless_sid}\"]
      }
    }
  }],
  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}]
}"
        vless_save_server_info "$public_key" "$private_key" "$vless_sid" \
                               "$vless_sni" "$vless_port" "$domain"

        vless_create_service server
        vless_install_quota_enforcer
        vless_install_traffic_sync
        open_port "$vless_port" tcp
        service_start sing-box || print_warn "sing-box service failed to start. Check logs."

        # Add first user to DB with all enabled engines
        local hy2_flag ws_flag
        $install_hy2 && hy2_flag="true" || hy2_flag="false"
        $install_ws  && ws_flag="true"  || ws_flag="false"
        local init_engines="{"vless":true,"hysteria2":${hy2_flag},"vless_ws":${ws_flag}}"

        db_add_user "$uuid" "default" "0" "$sub_token" "$init_engines"

        # Auth + Subscription API must run even in VLESS-only mode
        # because it serves the /sub/<token> endpoint for all protocols
        if ! $install_hy2; then
            print_info "Starting Subscription API (required for /sub links)..."
            hy2_write_auth_api
            hy2_create_auth_service
            open_port "$HY2_AUTH_PORT" tcp
            service_start hysteria-auth || print_warn "hysteria-auth failed to start."
        fi

        print_success "VLESS server ready."
    fi

    # ── Hysteria2 ────────────────────────────────────────────
    if $install_hy2; then
        echo ""
        echo -e "  ${BOLD}─── Hysteria2 ─────────────────────────────────────${NC}"
        fetch_hysteria2_version
        hy2_install_binary "$HY2_VERSION" || {
            print_error "Hysteria2 binary install failed."; press_enter; return 1
        }

        ensure_packages python3 python3-pip openssl
        hy2_install_deps || { print_error "Flask install failed."; press_enter; return 1; }

        local hy2_port
        echo ""
        ask hy2_port "  Hysteria2 UDP port" "8443"

        # Probe server for QUIC params
        probe_server
        local bw rtt quic
        bw=$(estimate_bandwidth)
        rtt=$(measure_rtt "8.8.8.8")
        quic=$(hy2_compute_quic_params "$bw" "$rtt")
        IFS='|' read -r is ms ic mc <<< "$quic"
        local up=$(( bw * 85 / 100 )) down=$(( bw * 85 / 100 ))

        local hy2_domain=""
        $use_domain && hy2_domain="$domain"

        hy2_write_config "$hy2_port" "$hy2_domain" "$up" "$down" \
                         "$is" "$ms" "$ic" "$mc" "60s" "20s"

        local server_ip
        server_ip=$(get_public_ip)
        local selfcert_py="True"
        [[ -n "$hy2_domain" ]] && selfcert_py="False"
        hy2_save_server_info "$server_ip" "$hy2_port" "$hy2_domain" "$selfcert_py"

        hy2_write_auth_api
        hy2_write_sync_script
        hy2_create_server_service
        hy2_create_auth_service
        hy2_install_sync_cron
        open_port "$hy2_port" both
        open_port "$HY2_AUTH_PORT" tcp

        service_start hysteria-server || print_warn "hysteria-server failed to start."
        service_start hysteria-auth   || print_warn "hysteria-auth failed to start."

        # If VLESS was installed, hysteria2 engine already flagged on that user.
        # If standalone, add a new user.
        if ! $install_vless; then
            local hy2_uuid hy2_token
            hy2_uuid=$(generate_uuid)
            hy2_token=$(generate_token)
            db_add_user "$hy2_uuid" "default" "0" "$hy2_token" '{"vless":false,"hysteria2":true}'
        fi

        print_success "Hysteria2 server ready."
    fi

    # ── VLESS+WS+TLS ─────────────────────────────────────────
    if $install_ws; then
        echo ""
        echo -e "  ${BOLD}─── VLESS + WebSocket + TLS ────────────────────────${NC}"
        [[ ! -f "$SINGBOX_BIN" ]] && { fetch_singbox_version stable; vless_install_binary "$SINGBOX_VERSION"; }
        local ws_domain="${domain:-}"
        [[ -z "$ws_domain" ]] && ask ws_domain "  Domain for WS+TLS" ""
        if [[ -n "$ws_domain" ]]; then
            local ws_port ws_path ws_uuid ws_token
            ask ws_port "  WS listen port" "443"
            ws_path="/$(openssl rand -hex 4 2>/dev/null || echo 'ws')"
            ws_uuid=$(generate_uuid)
            ws_token=$(generate_token)
            ! ssl_cert_exists "$ws_domain" && ssl_install_acme && ssl_issue "$ws_domain" || true
            vws_write_config "$ws_port" "$ws_path" "$ws_domain" "$ws_uuid"
            vws_save_info "$ws_port" "$ws_path" "$ws_domain" "$ws_uuid"
            vws_create_service
            open_port "$ws_port" tcp
            service_start "$VWS_SERVICE" || print_warn "sing-box-ws failed to start."
            # Add to DB or add engine to existing user
            if $install_vless || $install_hy2; then
                db_enable_engine "$uuid" "vless_ws" 2>/dev/null || true
            else
                db_init
                db_add_user "$ws_uuid" "default" "0" "$ws_token" '{"vless_ws":true}'
            fi
            print_success "VLESS+WS+TLS ready on port ${ws_port}."
            # Reload auth API so subscription includes the new WS config
            systemctl restart hysteria-auth 2>/dev/null || true
        else
            print_warn "Skipping WS+TLS — domain required."
        fi
    fi

    # Optional: optimization
    # ══════════════════════════════════════════════════════════
    echo ""
    if confirm "Apply server optimizations now? (BBR, TCP tuning — recommended)" "y"; then
        probe_server &>/dev/null
        opt_apply_all
    fi

    # ══════════════════════════════════════════════════════════
    #  Summary
    # ══════════════════════════════════════════════════════════
    _wizard_print_summary "$install_vless" "$install_hy2" "$install_ws" "$domain"
}

_wizard_print_summary() {
    local install_vless="$1" install_hy2="$2" install_ws="$3" domain="${4:-}"
    local server_ip
    server_ip=$(get_public_ip)

    print_banner
    echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║          Installation Complete!                  ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Server IP : ${CYAN}${server_ip}${NC}"
    [[ -n "$domain" ]] && echo -e "  Domain    : ${CYAN}${domain}${NC}"
    echo ""

    # Fetch first user from DB
    local first_json sub_token label
    first_json=$(DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os
conn = sqlite3.connect(os.environ["DB_PATH"])
row = conn.execute("SELECT sub_token, label FROM users ORDER BY created_at LIMIT 1").fetchone()
if row: print(json.dumps({"sub_token": row[0], "label": row[1]}))
conn.close()
PYEOF
)

    if [[ -n "$first_json" ]]; then
        sub_token=$(echo "$first_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['sub_token'])")
        label=$(echo     "$first_json" | python3 -c "import json,sys; print(json.load(sys.stdin)['label'])")
        local sub_url
        sub_url=$(users_sub_url "$sub_token" 2>/dev/null || echo "")

        echo -e "  ${BOLD}First user: ${CYAN}${label}${NC}"
        echo ""
        if [[ -n "$sub_url" ]]; then
            echo -e "  ${BOLD}Subscription URL ${DIM}(add to Hiddify / v2rayN / NekoBox):${NC}"
            echo -e "  ${GREEN}${BOLD}${sub_url}${NC}"
            print_qr "$sub_url" "${label} — Subscription"
        fi
    fi

    echo ""
    echo -e "  ${BOLD}What's next:${NC}"
    echo -e "  ${DIM}• Use the main menu → User Management to add more users${NC}"
    echo -e "  ${DIM}• Use Security menu to install fail2ban${NC}"
    $install_hy2 && echo -e "  ${DIM}• ${YELLOW}Remember to allow UDP port in your VPS provider's firewall!${NC}"
    $install_ws  && echo -e "  ${DIM}• To use with ArvanCloud: enable CDN proxy after confirming direct connection works${NC}"
    echo ""
    press_enter
}
