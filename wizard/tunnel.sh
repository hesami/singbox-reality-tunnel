#!/usr/bin/env bash
# Production two-server tunnel wizard — Reverse SSH architecture.
# The foreign/Turkey server initiates a persistent SSH connection to Iran and
# creates a remote dynamic SOCKS5 listener on Iran. This direction was verified
# on the target path and avoids the QUIC/REALITY filtering seen in the reverse
# direction. nginx, websites, TLS and ports 80/443 are never changed.

wizard_tunnel() {
    while true; do
        print_banner
        print_header "Tunnel Setup — Reverse SSH (Turkey → Iran)"
        echo -e "  ${DIM}Stable mode: foreign server initiates the connection to Iran.${NC}"
        echo -e "  ${DIM}nginx, websites and ports 80/443 are not modified.${NC}\n"
        echo -e "  ${CYAN}1)${NC}  Foreign/Turkey setup  ${DIM}(run first — generates key)${NC}"
        echo -e "  ${CYAN}2)${NC}  Iran relay setup      ${DIM}(run second — authorizes key)${NC}"
        echo -e "  ${CYAN}3)${NC}  Status / health check"
        echo -e "  ${CYAN}4)${NC}  Remove reverse tunnel"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) _wizard_rssh_foreign ;;
            2) _wizard_rssh_iran ;;
            3) _wizard_rssh_status ;;
            4) _wizard_rssh_remove ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

_wizard_rssh_foreign() {
    print_banner
    print_header "Tunnel — Step 1: Foreign/Turkey Connector"
    echo -e "  ${DIM}This creates a dedicated SSH key and a persistent systemd connector.${NC}"
    echo -e "  ${DIM}The service may retry until Step 2 is completed on the Iran server.${NC}\n"

    check_internet || { press_enter; return 1; }
    rssh_generate_key || { print_error "Could not generate reverse-tunnel SSH key."; press_enter; return 1; }

    local iran_host ssh_port socks_port pubkey
    ask iran_host "  Iran server IP/hostname" ""
    [[ -n "$iran_host" ]] || { print_error "Iran server address is required."; press_enter; return 1; }
    ask ssh_port "  Iran SSH port" "22"
    ask socks_port "  SOCKS5 port to create on Iran" "10808"

    if ! [[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -ge 1 && "$ssh_port" -le 65535 ]]; then
        print_error "Invalid SSH port."; press_enter; return 1
    fi
    if ! [[ "$socks_port" =~ ^[0-9]+$ && "$socks_port" -ge 1 && "$socks_port" -le 65535 ]]; then
        print_error "Invalid SOCKS5 port."; press_enter; return 1
    fi

    rssh_write_foreign_service "$iran_host" "$ssh_port" "$socks_port" || {
        print_error "Could not create reverse SSH systemd service."; press_enter; return 1;
    }
    pubkey=$(rssh_public_key)

    echo ""
    print_success "Foreign connector installed."
    echo -e "  ${YELLOW}Complete Step 2 on the Iran server using this exact public key:${NC}\n"
    echo -e "${CYAN}${pubkey}${NC}\n"
    echo -e "  Iran target : ${BOLD}${iran_host}:${ssh_port}${NC}"
    echo -e "  Iran SOCKS5 : ${BOLD}127.0.0.1:${socks_port}${NC}"
    echo -e "  Service     : ${BOLD}${RSSH_SERVICE}${NC}"
    echo -e "\n  ${DIM}It is normal for the service to retry until the key is authorized on Iran.${NC}"
    press_enter
}

_wizard_rssh_iran() {
    print_banner
    print_header "Tunnel — Step 2: Iran Relay Receiver"
    echo -e "  ${DIM}Paste the public key printed by Step 1 on the Turkey server.${NC}\n"

    if ! rssh_sshd_forwarding_ok; then
        print_error "OpenSSH remote TCP forwarding is disabled or sshd configuration is invalid."
        echo -e "  ${DIM}Expected sshd setting: AllowTcpForwarding yes/all/remote${NC}"
        press_enter
        return 1
    fi

    local pubkey socks_port
    ask pubkey "  Turkey tunnel public key" ""
    [[ -n "$pubkey" ]] || { print_error "Public key is required."; press_enter; return 1; }
    ask socks_port "  SOCKS5 port on this Iran server" "10808"

    if ! [[ "$socks_port" =~ ^[0-9]+$ && "$socks_port" -ge 1 && "$socks_port" -le 65535 ]]; then
        print_error "Invalid SOCKS5 port."; press_enter; return 1
    fi
    if ! rssh_authorize_on_iran "$pubkey" "$socks_port"; then
        print_error "Invalid SSH public key or authorization failed."
        press_enter
        return 1
    fi
    print_success "Restricted reverse-tunnel key authorized."
    print_info "Waiting for Turkey connector to establish the remote SOCKS5 listener..."

    if ! rssh_wait_listener "$socks_port" 35; then
        print_error "Reverse tunnel did not connect within 35 seconds."
        echo -e "  ${DIM}On Turkey: systemctl status ${RSSH_SERVICE} --no-pager -l${NC}"
        echo -e "  ${DIM}On Turkey: journalctl -u ${RSSH_SERVICE} -n 50 --no-pager${NC}"
        press_enter
        return 1
    fi

    local exit_ip
    exit_ip=$(rssh_test_socks "$socks_port" 20 || true)
    if [[ -z "$exit_ip" ]]; then
        print_error "SOCKS5 listener exists, but egress verification failed."
        cat /tmp/reverse-ssh-curl.err 2>/dev/null || true
        press_enter
        return 1
    fi

    echo ""
    print_success "IRAN RELAY VERIFIED — Exit IP: ${exit_ip}"
    echo -e "  SOCKS5 : ${CYAN}127.0.0.1:${socks_port}${NC}"
    echo -e "  Mode   : ${GREEN}Reverse SSH — persistent/reconnecting${NC}"
    echo -e "  Access : ${GREEN}loopback only (not exposed publicly)${NC}"
    echo ""
    press_enter
}

_wizard_rssh_status() {
    print_banner
    print_header "Tunnel — Status / Health Check"

    if systemctl list-unit-files "$RSSH_SERVICE" >/dev/null 2>&1 && [[ -f "/etc/systemd/system/${RSSH_SERVICE}" ]]; then
        if systemctl is-active --quiet "$RSSH_SERVICE"; then
            print_success "Turkey connector service: running"
        else
            print_warn "Turkey connector service: not connected/running"
        fi
        [[ -f "$RSSH_ENV" ]] && { echo ""; sed 's/^/  /' "$RSSH_ENV"; }
        echo ""
    fi

    local found=false port
    for port in 10808 10809 10810; do
        if ss -H -ltn 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {found=1} END{exit !found}'; then
            found=true
            local ip; ip=$(rssh_test_socks "$port" 12 || true)
            if [[ -n "$ip" ]]; then
                print_success "Iran SOCKS5 127.0.0.1:${port} works — Exit IP: ${ip}"
            else
                print_warn "Listener exists on 127.0.0.1:${port}, but health check failed."
            fi
        fi
    done
    $found || print_warn "No known reverse SOCKS5 listener detected on this server."
    echo ""
    press_enter
}

_wizard_rssh_remove() {
    print_banner
    print_header "Tunnel — Remove Reverse SSH"
    echo -e "  ${CYAN}1)${NC}  Remove Turkey connector service + dedicated key"
    echo -e "  ${CYAN}2)${NC}  Remove Iran authorization entry"
    echo -e "  ${CYAN}0)${NC}  Cancel"
    menu_prompt
    case "$MENU_CHOICE" in
        1)
            systemctl disable --now "$RSSH_SERVICE" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${RSSH_SERVICE}"
            rm -rf "$RSSH_DIR"
            systemctl daemon-reload
            print_success "Turkey connector removed."
            ;;
        2)
            rssh_remove_iran_authorization
            print_success "Manager-owned Iran authorization removed."
            ;;
        0) return ;;
        *) print_warn "Invalid choice." ;;
    esac
    press_enter
}
