#!/usr/bin/env bash
# Manual tunnel management. Guided first-time flow lives in wizard/setup.sh.

_tunnel_turkey_setup(){
    print_banner; print_header "Turkey Exit — Reverse SSH Connector"
    check_internet || { press_enter; return 1; }; ensure_packages curl openssh-client ca-certificates python3 || { press_enter; return 1; }
    rssh_generate_key || { print_error "SSH key generation failed."; press_enter; return 1; }
    local iran_host ssh_port socks_port turkey_ip pair
    ask iran_host "  Iran server IP/hostname" ""
    [[ -n "$iran_host" ]] || { print_error "Iran server address is required."; press_enter; return 1; }
    ask ssh_port "  Dedicated tunnel SSH port on Iran" "$RSSH_SSHD_PORT_DEFAULT"; valid_port "$ssh_port" || { print_error "Invalid SSH port."; press_enter; return 1; }
    ask socks_port "  Local SOCKS5 port to create on Iran" "10808"; valid_port "$socks_port" || { print_error "Invalid SOCKS port."; press_enter; return 1; }
    turkey_ip=$(rssh_public_ip 2>/dev/null || echo unknown); valid_ipv4 "$turkey_ip" || { print_error "Could not detect Turkey public IPv4."; press_enter; return 1; }
    confirm "Apply safe BBR/TCP tuning on Turkey?" y && print_success "Network tuning: $(rssh_apply_performance)"
    rssh_write_foreign_service "$iran_host" "$ssh_port" "$socks_port" || { print_error "Could not create connector service."; press_enter; return 1; }
    pair=$(rssh_pair_code "$turkey_ip" "$ssh_port" "$socks_port" "$(rssh_public_key)") || { print_error "Pairing code generation failed."; press_enter; return 1; }
    LAST_PAIR_CODE="$pair"
    echo; print_success "Turkey side prepared. The service will reconnect automatically until Iran is configured."
    echo -e "\n  ${BOLD}PAIRING CODE — copy this entire line to the Iran server:${NC}\n"
    echo -e "  ${GREEN}${BOLD}${pair}${NC}\n"
    echo -e "  Turkey IP : ${CYAN}${turkey_ip}${NC}\n  Iran SSH  : ${CYAN}${ssh_port}/tcp${NC}\n  Iran SOCKS: ${CYAN}127.0.0.1:${socks_port}${NC}"
    press_enter
}

_tunnel_iran_setup(){
    print_banner; print_header "Iran Gateway — Pair with Turkey"
    ensure_packages curl openssh-server ca-certificates python3 iptables || { press_enter; return 1; }
    local code turkey_ip ssh_port socks_port pubkey vals
    echo -e "  ${DIM}Paste the Pairing Code printed by the Turkey server. This avoids manually copying IP, key and ports.${NC}\n"
    ask code "  Pairing Code" ""
    mapfile -t vals < <(rssh_parse_pair_code "$code" 2>/dev/null) || true
    ((${#vals[@]}==4)) || { print_error "Invalid Pairing Code."; press_enter; return 1; }
    turkey_ip="${vals[0]}"; ssh_port="${vals[1]}"; socks_port="${vals[2]}"; pubkey="${vals[3]}"
    valid_ipv4 "$turkey_ip" && valid_port "$ssh_port" && valid_port "$socks_port" && rssh_validate_public_key "$pubkey" || { print_error "Pairing data failed validation."; press_enter; return 1; }
    print_info "Turkey IP: $turkey_ip | dedicated SSH: $ssh_port | local SOCKS: $socks_port"
    rssh_authorize_on_iran "$pubkey" "$socks_port" || { print_error "Could not authorize Turkey key."; press_enter; return 1; }
    rssh_install_dedicated_sshd "$turkey_ip" "$ssh_port" "$socks_port" || { print_error "Dedicated tunnel sshd failed validation/start."; press_enter; return 1; }
    confirm "Apply safe BBR/TCP tuning on Iran?" y && print_success "Network tuning: $(rssh_apply_performance)"
    print_info "Waiting for the Turkey connector to reconnect..."
    rssh_wait_listener "$socks_port" 50 || { print_error "Tunnel did not appear on 127.0.0.1:${socks_port}. Check Turkey connector status/logs."; press_enter; return 1; }
    local exit; exit=$(rssh_test_socks "$socks_port" 20 || true)
    [[ -n "$exit" ]] || { print_error "SOCKS listener exists, but Turkey egress health check failed."; press_enter; return 1; }
    print_success "Tunnel verified. Internet exit IP: $exit"
    echo -e "  Local exit SOCKS: ${CYAN}127.0.0.1:${socks_port}${NC}\n  Dedicated SSH   : ${CYAN}${ssh_port}/tcp${NC} ${DIM}(Turkey IP only)${NC}"
    press_enter
}

_tunnel_status(){
    print_banner; print_header "Tunnel Status"
    service_status_line "$RSSH_SERVICE" "Turkey connector service"
    service_status_line "$RSSH_SSHD_SERVICE" "Iran dedicated SSH receiver"
    local p; p=$(rssh_socks_port) ip
    [[ -f "$RSSH_ENV" ]] && p=$(awk -F= '$1=="IRAN_SOCKS_PORT"{print $2}' "$RSSH_ENV" 2>/dev/null || true); valid_port "$p" || p=$(rssh_socks_port)
    ip=$(rssh_test_socks "$p" 10 || true)
    [[ -n "$ip" ]] && print_success "Verified Turkey egress: $ip" || print_warn "No healthy Turkey egress detected on 127.0.0.1:${p}."
    press_enter
}

_tunnel_rotate(){
    print_banner; print_header "Rotate Turkey Tunnel Key"
    confirm "Rotate the Turkey SSH key? Iran must be paired again with the new code." n || return 0
    rssh_rotate_key || { print_error "Key rotation failed."; press_enter; return 1; }
    local turkey_ip ssh_port socks_port pair
    turkey_ip=$(rssh_public_ip 2>/dev/null || echo unknown); ssh_port=$(awk -F= '$1=="IRAN_SSH_PORT"{print $2}' "$RSSH_ENV" 2>/dev/null); socks_port=$(awk -F= '$1=="IRAN_SOCKS_PORT"{print $2}' "$RSSH_ENV" 2>/dev/null)
    pair=$(rssh_pair_code "$turkey_ip" "${ssh_port:-22022}" "${socks_port:-$(rssh_socks_port)}" "$(rssh_public_key)")
    echo -e "\n  ${BOLD}New Pairing Code:${NC}\n  ${GREEN}${pair}${NC}\n"; press_enter
}

_tunnel_remove(){
    print_banner; print_header "Remove Tunnel Components"
    echo -e "  ${CYAN}1)${NC} Remove Turkey connector/key"
    echo -e "  ${CYAN}2)${NC} Remove Iran authorization/dedicated sshd"
    echo -e "  ${CYAN}0)${NC} Cancel"; menu_prompt
    case "$MENU_CHOICE" in
      1) confirm "Remove Turkey connector?" n || return; systemctl disable --now "$RSSH_SERVICE" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/${RSSH_SERVICE}"; rm -rf "$RSSH_DIR"; systemctl daemon-reload; print_success "Turkey connector removed." ;;
      2) confirm "Remove Iran tunnel receiver? Customer Gateway will stop having Turkey egress." n || return; rssh_remove_iran_authorization; systemctl disable --now "$RSSH_SSHD_SERVICE" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/${RSSH_SSHD_SERVICE}" "$RSSH_SSHD_CONFIG"; systemctl daemon-reload; print_success "Iran tunnel receiver removed." ;;
      0) return;;
    esac
    press_enter
}

tunnel_menu(){
    while true; do
        print_banner; print_header "Reverse SSH Tunnel"
        echo -e "  ${DIM}Only the transport proven to work in this deployment is included.${NC}\n"
        echo -e "  ${CYAN}1)${NC} Setup Turkey connector ${DIM}(run first)${NC}"
        echo -e "  ${CYAN}2)${NC} Pair Iran receiver ${DIM}(paste Pairing Code)${NC}"
        echo -e "  ${CYAN}3)${NC} Status / health check"
        echo -e "  ${CYAN}4)${NC} Security audit"
        echo -e "  ${CYAN}5)${NC} Apply TCP/BBR tuning"
        echo -e "  ${CYAN}6)${NC} Rotate tunnel key"
        echo -e "  ${CYAN}7)${NC} Remove tunnel components"
        echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
        case "$MENU_CHOICE" in 1)_tunnel_turkey_setup;;2)_tunnel_iran_setup;;3)_tunnel_status;;4)print_banner;print_header "Tunnel Security Audit";rssh_security_audit "$(rssh_socks_port)";press_enter;;5)print_banner;print_header "TCP / BBR Tuning";print_success "Applied: $(rssh_apply_performance)";press_enter;;6)_tunnel_rotate;;7)_tunnel_remove;;0)return;;*)print_warn "Invalid choice.";sleep 1;;esac
    done
}
