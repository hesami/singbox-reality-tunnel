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

# NOTE: the two-server tunnel wizard (wizard_tunnel, _wizard_tunnel_foreign,
# _wizard_tunnel_iran) lives in wizard/tunnel.sh. It used to be duplicated
# here with a much thinner implementation; that duplicate silently shadowed
# (or was shadowed by, depending on source order) the real one and has been
# removed to avoid the two copies drifting apart.
