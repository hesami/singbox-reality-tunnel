#!/usr/bin/env bash
# Iran-Turkey Gateway Manager v4.2.0 — minimal production edition.
set -uo pipefail
trap 'echo "ERROR: command failed near line $LINENO" >&2' ERR
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_src(){ source "${SCRIPT_DIR}/$1" || { echo "ERROR: cannot load $1" >&2; exit 1; }; }
_src core/common.sh
_src core/system.sh
_src core/db.sh
_src protocols/xray.sh
_src protocols/reverse_ssh.sh
_src protocols/customer_gateway.sh
_src features/users.sh
_src wizard/tunnel.sh
_src features/operations.sh
_src wizard/setup.sh

mkdir -p "$BASE_DIR" "$DATA_DIR" "$LOG_DIR"; check_root; check_os; db_init >/dev/null 2>&1 || true

_status_bar(){
    local role exit users
    role=$(infer_role); users=$(db_user_count 2>/dev/null || echo 0); exit=$(rssh_test_socks 10808 3 2>/dev/null || true)
    echo -e "  ${DIM}Role:${NC} ${CYAN}${role}${NC}   ${DIM}Customers:${NC} ${CYAN}${users}${NC}   ${DIM}Turkey exit:${NC} $([[ -n "$exit" ]] && echo -e "${GREEN}${exit}${NC}" || echo -e "${DIM}not verified${NC}")"
    echo
}
main_menu(){
    while true; do
        print_banner; _status_bar
        echo -e "  ${BOLD}Start here${NC}"
        echo -e "  ${CYAN}1)${NC} Guided Setup ${DIM}(recommended for first install)${NC}"
        echo
        echo -e "  ${BOLD}Operate${NC}"
        echo -e "  ${CYAN}2)${NC} Reverse SSH Tunnel"
        echo -e "  ${CYAN}3)${NC} Customer Gateway ${DIM}(v2rayN access on Iran)${NC}"
        echo -e "  ${CYAN}4)${NC} Customer Management ${DIM}(quota, expiry, subscription)${NC}"
        echo -e "  ${CYAN}5)${NC} System Health"
        echo
        echo -e "  ${BOLD}Administration${NC}"
        echo -e "  ${CYAN}6)${NC} Security & Performance"
        echo -e "  ${CYAN}7)${NC} Maintenance ${DIM}(backup, logs, cleanup)${NC}"
        echo -e "  ${CYAN}0)${NC} Exit"; menu_prompt
        case "$MENU_CHOICE" in
          1)guided_setup;;2)tunnel_menu;;3)cgw_menu;;4)users_menu;;5)overall_health;press_enter;;6)ops_security_menu;;7)maintenance_menu;;0)echo;exit 0;;*)print_warn "Invalid choice.";sleep 1;;esac
    done
}
main_menu
