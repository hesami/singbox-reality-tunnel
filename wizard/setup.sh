#!/usr/bin/env bash
# First-run guided setup.

guided_setup(){
    print_banner; print_header "Guided Setup"
    echo -e "  ${BOLD}Which server are you configuring?${NC}\n"
    echo -e "  ${CYAN}1)${NC} Turkey / Foreign Exit ${DIM}(run this first)${NC}"
    echo -e "  ${CYAN}2)${NC} Iran Gateway ${DIM}(paste the Pairing Code from Turkey)${NC}"
    echo -e "  ${CYAN}3)${NC} Check existing installation"
    echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
    case "$MENU_CHOICE" in
      1) _tunnel_turkey_setup ;;
      2)
        _tunnel_iran_setup || return
        if rssh_test_socks "$(rssh_socks_port)" 10 >/dev/null 2>&1; then
            if confirm "Tunnel works. Configure the v2rayN Customer Gateway now?" y; then
                cgw_setup
                if systemctl is-active --quiet "$CGW_SERVICE" 2>/dev/null && confirm "Gateway is ready. Create the first customer now?" y; then users_add; fi
            fi
        fi
        ;;
      3) overall_health; press_enter ;;
      0) return ;;
      *) print_warn "Invalid choice."; sleep 1 ;;
    esac
}
