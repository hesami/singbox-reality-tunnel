#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  wizard/install.sh — Install binaries & dependencies only
#  Inbound configuration is handled separately via Inbound Management
# ═══════════════════════════════════════════════════════════════

wizard_install() {
    check_root
    check_os

    print_banner
    print_header "Install — Binaries & Dependencies"
    echo -e "  ${DIM}This installs sing-box, Hysteria2, and all required packages.${NC}"
    echo -e "  ${DIM}After this, use 'Inbound Management' to add proxy configurations.${NC}\n"

    print_step 1 4 "Checking system"
    check_internet
    probe_server
    show_server_profile
    db_init

    print_step 2 4 "Installing sing-box"
    local ver_choice
    echo -e "  ${CYAN}1)${NC}  Latest stable ${DIM}(recommended)${NC}"
    echo -e "  ${CYAN}2)${NC}  Latest pre-release"
    menu_prompt; ver_choice="$MENU_CHOICE"
    [[ "$ver_choice" == "2" ]] && fetch_singbox_version prerelease || fetch_singbox_version stable
    vless_install_binary "$SINGBOX_VERSION" || { press_enter; return 1; }
    vless_create_service server
    vless_install_quota_enforcer
    vless_install_traffic_sync
    print_success "sing-box ${SINGBOX_VERSION} installed."

    print_step 3 4 "Installing Hysteria2"
    fetch_hysteria2_version
    hy2_install_binary "$HY2_VERSION" || { press_enter; return 1; }
    ensure_packages python3 python3-pip openssl
    hy2_install_deps || { print_error "Flask install failed."; press_enter; return 1; }
    hy2_write_auth_api
    hy2_write_sync_script
    hy2_create_server_service
    hy2_create_auth_service
    hy2_install_sync_cron
    print_success "Hysteria2 ${HY2_VERSION} installed."

    print_step 4 4 "System optimization"
    if confirm "Apply optimizations now? (BBR, TCP tuning)" "y"; then
        opt_apply_all
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}Installation complete!${NC}"
    echo ""
    echo -e "  ${BOLD}Next step:${NC}"
    echo -e "  ${CYAN}Go to Main Menu → Inbound Management → Add Inbound${NC}"
    echo -e "  ${DIM}Add one or more inbounds with their own domain/port settings.${NC}"
    echo ""
    press_enter
}

wizard_tunnel() {
    print_banner
    print_header "Tunnel Setup — Two-Server Mode"
    echo ""
    echo -e "  ${BOLD}How a tunnel works:${NC}\n"
    echo -e "   [Client in Iran] → [Iran relay server] → [Foreign server] → [Internet]\n"
    echo -e "  ${YELLOW}Run this wizard on each server separately.${NC}\n"
    echo -e "  ${CYAN}1)${NC}  Foreign server  ${DIM}(run first — installs proxy + shows settings)${NC}"
    echo -e "  ${CYAN}2)${NC}  Iran server     ${DIM}(run second — install relay client)${NC}"
    echo -e "  ${CYAN}0)${NC}  Back"
    menu_prompt
    case "$MENU_CHOICE" in
        1) _wizard_tunnel_foreign ;;
        2) _wizard_tunnel_iran ;;
        0) return ;;
    esac
}

_wizard_tunnel_foreign() {
    print_banner
    print_header "Tunnel — Foreign Server"
    echo -e "  ${DIM}Installs binaries, then opens Inbound Management.${NC}\n"
    wizard_install
    echo ""
    print_info "Now add your inbound via Inbound Management."
    inbounds_menu
}

_wizard_tunnel_iran() {
    print_banner
    print_header "Tunnel — Iran Relay Client"
    echo -e "  ${DIM}Enter foreign server details to set up the relay.${NC}\n"
    check_internet
    fetch_singbox_version stable
    vless_install_binary "$SINGBOX_VERSION" || { press_enter; return; }

    local foreign_ip server_port uuid public_key short_id sni socks_port proto
    echo -e "  ${CYAN}1)${NC}  VLESS + Reality  ${CYAN}2)${NC}  Hysteria2  ${CYAN}3)${NC}  gRPC+TLS"
    menu_prompt; proto="$MENU_CHOICE"

    ask foreign_ip  "  Foreign server IP/domain" ""
    ask socks_port  "  Local SOCKS5 port"        "10808"

    local outbounds_json final_tag

    case "$proto" in
        1)
            ask server_port "  VLESS port"  "443"
            ask uuid        "  UUID"        ""
            ask public_key  "  PublicKey"   ""
            ask short_id    "  Short ID"    ""
            ask sni         "  SNI"         "dl.google.com"
            outbounds_json="[{\"type\":\"vless\",\"tag\":\"out\",\"server\":\"${foreign_ip}\",\"server_port\":${server_port},\"uuid\":\"${uuid}\",\"flow\":\"xtls-rprx-vision\",\"tls\":{\"enabled\":true,\"server_name\":\"${sni}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"},\"reality\":{\"enabled\":true,\"public_key\":\"${public_key}\",\"short_id\":\"${short_id}\"}}},{\"type\":\"direct\",\"tag\":\"direct\"}]"
            final_tag="out"
            ;;
        2)
            ask server_port "  HY2 port"   "8443"
            ask uuid        "  UUID"        ""
            local h_token; ask h_token "  Token"  ""
            outbounds_json="[{\"type\":\"hysteria2\",\"tag\":\"out\",\"server\":\"${foreign_ip}\",\"server_port\":${server_port},\"password\":\"${uuid}:${h_token}\",\"tls\":{\"enabled\":true,\"insecure\":true}},{\"type\":\"direct\",\"tag\":\"direct\"}]"
            final_tag="out"
            ;;
        3)
            ask server_port "  gRPC port"  "443"
            ask uuid        "  UUID"        ""
            local g_svc; ask g_svc "  Service name" ""
            local g_domain; ask g_domain "  Domain" "$foreign_ip"
            outbounds_json="[{\"type\":\"vless\",\"tag\":\"out\",\"server\":\"${foreign_ip}\",\"server_port\":${server_port},\"uuid\":\"${uuid}\",\"transport\":{\"type\":\"grpc\",\"service_name\":\"${g_svc}\"},\"tls\":{\"enabled\":true,\"server_name\":\"${g_domain}\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}}},{\"type\":\"direct\",\"tag\":\"direct\"}]"
            final_tag="out"
            ;;
        *) print_error "Invalid."; press_enter; return ;;
    esac

    cat > /etc/sing-box/config.json << EOF
{
  "log": {"level":"warn"},
  "inbounds": [{"type":"socks","tag":"socks-in","listen":"0.0.0.0","listen_port":${socks_port}}],
  "outbounds": ${outbounds_json},
  "route": {"final":"${final_tag}"}
}
EOF

    vless_create_service client
    service_start sing-box-client || { press_enter; return; }

    print_info "Testing tunnel..."
    sleep 3
    local exit_ip
    exit_ip=$(curl -s --connect-timeout 15 --socks5 "127.0.0.1:${socks_port}" https://ifconfig.me 2>/dev/null || echo "")
    [[ -n "$exit_ip" ]] \
        && print_success "Tunnel working! Exit IP: ${exit_ip}" \
        || print_warn "Test failed. Check: journalctl -u sing-box-client -n 30"
    press_enter
}
