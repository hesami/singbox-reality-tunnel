#!/usr/bin/env bash
# Health, security, backups and maintenance for the retained production stack.

infer_role(){
    if [[ -s "$CGW_STATE" || -f "$RSSH_SSHD_CONFIG" ]]; then echo "Iran Gateway"; elif [[ -s "$RSSH_KEY" || -f "/etc/systemd/system/${RSSH_SERVICE}" ]]; then echo "Turkey Exit"; else echo "Not configured"; fi
}
overall_health(){
    print_banner; print_header "System Health"
    local role ip exit users enabled
    role=$(infer_role); ip=$(get_public_ip 2>/dev/null || echo unknown); users=$(db_user_count 2>/dev/null || echo 0); enabled=$(db_enabled_count 2>/dev/null || echo 0)
    echo -e "  Role                    : ${CYAN}${role}${NC}"
    echo -e "  Public IP               : ${CYAN}${ip}${NC}"
    echo -e "  Customers               : ${CYAN}${users}${NC} total / ${CYAN}${enabled}${NC} enabled\n"
    service_status_line "$RSSH_SERVICE" "Turkey reverse connector"
    service_status_line "$RSSH_SSHD_SERVICE" "Iran dedicated SSH receiver"
    service_status_line "$CGW_SERVICE" "Customer VLESS gateway"
    service_status_line "$CGW_SUB_SERVICE" "Subscription service"
    service_status_line customer-gateway-watchdog.timer "Gateway kill-switch"
    echo
    exit=$(rssh_test_socks "$(rssh_socks_port)" 10 || true)
    [[ -n "$exit" ]] && print_success "End-to-end Turkey exit works: $exit" || print_warn "No verified Turkey exit on 127.0.0.1:$(rssh_socks_port)."
    if [[ -s "$CGW_STATE" ]]; then
        echo -e "  Client endpoint         : ${CYAN}$(cgw_client_host):$(cgw_state_get port)${NC}"
        echo -e "  Subscription endpoint   : ${CYAN}$(cgw_state_get sub_scheme)://$(cgw_state_get sub_host):$(cgw_state_get sub_port)/sub/<token>${NC}"
        echo -e "  Server Xray data-plane  : ${CYAN}pinned v26.7.28${NC}"
        if ss -H -ltn 2>/dev/null | grep -qE ":$(cgw_state_get port)[[:space:]]"; then print_success "Customer port is listening locally: $(cgw_state_get port)/tcp"; else print_warn "Customer port is NOT listening locally: $(cgw_state_get port)/tcp"; fi
        cgw_reality_target_test && print_success "REALITY target reachable from Iran." || print_warn "REALITY target check failed."
        local rt rc; rt=$(cgw_local_client_test 2>&1); rc=$?
        case "$rc" in
          0) print_success "Local VLESS/REALITY → Turkey path works: $rt" ;;
          4) print_info "VLESS/REALITY self-test skipped: no active customer." ;;
          *) print_warn "VLESS/REALITY self-test failed: $rt" ;;
        esac
        echo -e "  ${DIM}External port check (Windows PowerShell): Test-NetConnection $(cgw_client_host) -Port $(cgw_state_get port)${NC}"
    fi
}

ops_security_menu(){
    while true; do
        print_banner; print_header "Security & Performance"
        echo -e "  ${CYAN}1)${NC} Full security audit"
        echo -e "  ${CYAN}2)${NC} Apply safe BBR/TCP tuning"
        echo -e "  ${CYAN}3)${NC} Rotate Turkey tunnel key"
        echo -e "  ${CYAN}4)${NC} Show listening ports"
        echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
        case "$MENU_CHOICE" in
          1) print_banner;print_header "Security Audit";echo -e "${BOLD}Tunnel:${NC}";rssh_security_audit "$(rssh_socks_port)" | sed 's/^/  /';echo;echo -e "${BOLD}Gateway:${NC}";cgw_security_audit 2>/dev/null || print_info "Customer Gateway not configured.";press_enter ;;
          2) print_banner;print_header "Safe TCP Tuning";print_success "Applied: $(rssh_apply_performance)";press_enter ;;
          3) _tunnel_rotate ;;
          4) print_banner;print_header "Listening Ports";ss -lntup 2>/dev/null | sed -n '1,80p';press_enter ;;
          0) return;; *)print_warn "Invalid choice.";sleep 1;;
        esac
    done
}

ops_backup(){
    local d="${BASE_DIR}/backups" f list; mkdir -p "$d"; db_checkpoint || { print_error "Could not checkpoint the SQLite database."; return 1; }; f="$d/full-stack-$(date +%Y%m%d-%H%M%S).tar.gz"; list=$(mktemp)
    for p in "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm" "$CGW_DIR" "$RSSH_DIR" "$RSSH_SSHD_CONFIG" "$RSSH_HOME/.ssh/authorized_keys" "/etc/systemd/system/${RSSH_SERVICE}" "/etc/systemd/system/${RSSH_SSHD_SERVICE}" "/etc/systemd/system/${CGW_SERVICE}" "/etc/systemd/system/${CGW_SUB_SERVICE}" /etc/systemd/system/customer-gateway-watchdog.service /etc/systemd/system/customer-gateway-watchdog.timer; do [[ -e "$p" ]] && echo "${p#/}" >>"$list"; done
    [[ -s "$list" ]] || { rm -f "$list"; print_error "Nothing to back up."; return 1; }
    tar -C / -czf "$f" -T "$list" || { rm -f "$list"; return 1; }; rm -f "$list"; chmod 600 "$f"; print_success "Backup created: $f"
}
ops_restore(){
    local f; f=$(ls -1t "${BASE_DIR}/backups"/full-stack-*.tar.gz 2>/dev/null | head -1 || true); [[ -n "$f" ]] || { print_error "No full-stack backup found."; return 1; }
    confirm "Restore latest backup: $f ?" n || return 0
    tar -C / -xzf "$f" || return 1; systemctl daemon-reload
    [[ -x "$CGW_REBUILD" ]] && "$CGW_REBUILD" --force >/dev/null 2>&1 || true
    systemctl restart "$RSSH_SERVICE" "$RSSH_SSHD_SERVICE" "$CGW_SUB_SERVICE" customer-gateway-watchdog.timer >/dev/null 2>&1 || true
    print_success "Backup restored. Run Health Check now."
}
ops_logs(){
    while true; do
        print_banner; print_header "Logs"
        echo -e "  ${CYAN}1)${NC} Turkey reverse connector"
        echo -e "  ${CYAN}2)${NC} Iran dedicated SSH receiver"
        echo -e "  ${CYAN}3)${NC} Customer gateway"
        echo -e "  ${CYAN}4)${NC} Subscription service"
        echo -e "  ${CYAN}5)${NC} Gateway error/access files"
        echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
        case "$MENU_CHOICE" in
          1) journalctl -u "$RSSH_SERVICE" -n 100 --no-pager;press_enter;;
          2) journalctl -u "$RSSH_SSHD_SERVICE" -n 100 --no-pager;press_enter;;
          3) journalctl -u "$CGW_SERVICE" -n 100 --no-pager;press_enter;;
          4) journalctl -u "$CGW_SUB_SERVICE" -n 100 --no-pager;press_enter;;
          5) tail -100 /var/log/customer-gateway-error.log /var/log/customer-gateway-access.log 2>/dev/null;press_enter;;
          0)return;; *)print_warn "Invalid choice.";sleep 1;;
        esac
    done
}
ops_service_control(){
    print_banner; print_header "Restart Production Services"
    echo -e "  ${CYAN}1)${NC} Restart services detected on this server"
    echo -e "  ${CYAN}0)${NC} Back"; menu_prompt; [[ "$MENU_CHOICE" == 1 ]] || return
    local s
    for s in "$RSSH_SERVICE" "$RSSH_SSHD_SERVICE" "$CGW_SERVICE" "$CGW_SUB_SERVICE" customer-gateway-watchdog.timer; do
        systemctl list-unit-files "$s" >/dev/null 2>&1 || continue; systemctl restart "$s" >/dev/null 2>&1 && print_success "Restarted $s" || true
    done
    press_enter
}
ops_cleanup_legacy(){
    print_banner; print_header "Cleanup Legacy Experimental Services"
    echo -e "  ${YELLOW}This only targets old proxy/tunnel experiments from earlier versions.${NC}"
    echo -e "  ${BOLD}nginx, Apache, websites, ports 80/443 and the current Reverse SSH/Customer Gateway are NOT modified.${NC}\n"
    echo "  Candidates: sing-box, sing-box-client, sing-box-ws, sing-box-grpc, hysteria-server, hysteria-auth, xray-tunnel-client, xray-tunnel-server"
    confirm "Disable and remove those legacy service units/config directories?" n || return 0
    local s
    for s in sing-box sing-box-client sing-box-ws sing-box-grpc hysteria-server hysteria-auth xray-tunnel-client xray-tunnel-server; do systemctl disable --now "$s" >/dev/null 2>&1 || true; rm -f "/etc/systemd/system/${s}.service"; done
    rm -rf /etc/hysteria /etc/xray-tunnel
    # Only remove old sing-box configs; never touch nginx or website data.
    rm -rf /etc/sing-box
    systemctl daemon-reload; print_success "Legacy experimental components removed."; press_enter
}
ops_remove_stack(){
    print_banner; print_header "Remove Current Production Stack"
    echo -e "  ${RED}This removes Reverse SSH and Customer Gateway services/configs.${NC}\n  User database is kept unless you explicitly choose to delete it."
    confirm "Continue?" n || return
    systemctl disable --now "$RSSH_SERVICE" "$RSSH_SSHD_SERVICE" "$CGW_SERVICE" "$CGW_SUB_SERVICE" customer-gateway-watchdog.timer >/dev/null 2>&1 || true
    rssh_remove_iran_authorization 2>/dev/null || true
    rm -f "/etc/systemd/system/${RSSH_SERVICE}" "/etc/systemd/system/${RSSH_SSHD_SERVICE}" "/etc/systemd/system/${CGW_SERVICE}" "/etc/systemd/system/${CGW_SUB_SERVICE}" /etc/systemd/system/customer-gateway-watchdog.{service,timer}
    rm -rf "$RSSH_DIR" "$CGW_DIR"; rm -f "$RSSH_SSHD_CONFIG"; systemctl daemon-reload
    if confirm "Also delete all customer records/traffic database?" n; then rm -f "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm"; fi
    print_success "Production stack removed."; press_enter
}

maintenance_menu(){
    while true; do
        print_banner; print_header "Maintenance"
        echo -e "  ${CYAN}1)${NC} Backup full configuration + users"
        echo -e "  ${CYAN}2)${NC} Restore latest backup"
        echo -e "  ${CYAN}3)${NC} View logs"
        echo -e "  ${CYAN}4)${NC} Restart production services"
        echo -e "  ${CYAN}5)${NC} Cleanup legacy experimental components"
        echo -e "  ${CYAN}6)${NC} Remove current production stack"
        echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
        case "$MENU_CHOICE" in 1)ops_backup;press_enter;;2)ops_restore;press_enter;;3)ops_logs;;4)ops_service_control;;5)ops_cleanup_legacy;;6)ops_remove_stack;;0)return;;*)print_warn "Invalid choice.";sleep 1;;esac
    done
}
