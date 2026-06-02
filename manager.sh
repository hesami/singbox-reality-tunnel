#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  manager.sh — sing-box Proxy Manager  v3.0.0
#
#  Usage:  sudo bash manager.sh
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Source modules ─────────────────────────────────────────────
_src() { source "${SCRIPT_DIR}/$1" || { echo "ERROR: cannot load $1"; exit 1; }; }

_src core/common.sh
_src core/system.sh
_src core/db.sh
_src protocols/vless.sh
_src protocols/hysteria2.sh
_src protocols/vless_ws.sh
_src features/ssl.sh
_src features/users.sh
_src features/optimization.sh
_src features/security.sh
_src wizard/install.sh
_src wizard/tunnel.sh

mkdir -p "$BASE_DIR" "$DATA_DIR" "$LOG_DIR"
check_root

# ── Status display ─────────────────────────────────────────────

_print_status_bar() {
    local vless_svc vws_svc hy2_svc auth_svc f2b_svc

    systemctl is-active --quiet sing-box          2>/dev/null \
        && vless_svc="${GREEN}●${NC}" || vless_svc="${DIM}○${NC}"
    systemctl is-active --quiet sing-box-ws       2>/dev/null \
        && vws_svc="${GREEN}●${NC}"   || vws_svc="${DIM}○${NC}"
    systemctl is-active --quiet hysteria-server   2>/dev/null \
        && hy2_svc="${GREEN}●${NC}"   || hy2_svc="${DIM}○${NC}"
    systemctl is-active --quiet hysteria-auth     2>/dev/null \
        && auth_svc="${GREEN}●${NC}"  || auth_svc="${DIM}○${NC}"
    systemctl is-active --quiet fail2ban          2>/dev/null \
        && f2b_svc="${GREEN}●${NC}"   || f2b_svc="${DIM}○${NC}"

    local user_count
    user_count=$(db_user_count 2>/dev/null || echo "0")

    ssl_load_domain 2>/dev/null || true
    local domain_label="${DOMAIN:-(IP only)}"

    echo -e "  ${DIM}Status:${NC} ${vless_svc}VLESS ${vws_svc}WS+TLS ${hy2_svc}HY2 ${auth_svc}API ${f2b_svc}F2B"
    echo -e "  ${DIM}Users: ${CYAN}${user_count}${NC}   Domain: ${CYAN}${domain_label}${NC}"
    echo ""
}

# ── Main menu ──────────────────────────────────────────────────

main_menu() {
    while true; do
        print_banner
        _print_status_bar

        echo -e "  ${BOLD}Install & Setup ──────────────────────────────────${NC}"
        echo -e "  ${CYAN}1)${NC}  Setup Wizard           ${DIM}New install${NC}"
        echo ""
        echo -e "  ${BOLD}User Management ──────────────────────────────────${NC}"
        echo -e "  ${CYAN}2)${NC}  Manage Users           ${DIM}Add/edit/delete${NC}"
        echo -e "  ${CYAN}3)${NC}  Service Control        ${DIM}Start/stop/restart${NC}"
        echo ""
        echo -e "  ${BOLD}Configuration ────────────────────────────────────${NC}"
        echo -e "  ${CYAN}4)${NC}  SSL Certificate        ${DIM}Let's Encrypt${NC}"
        echo -e "  ${CYAN}5)${NC}  Optimization           ${DIM}BBR/TCP tuning${NC}"
        echo -e "  ${CYAN}6)${NC}  Security               ${DIM}Fail2ban${NC}"
        echo ""
        echo -e "  ${BOLD}System ───────────────────────────────────────────${NC}"
        echo -e "  ${CYAN}7)${NC}  Update                 ${DIM}Binaries${NC}"
        echo -e "  ${CYAN}8)${NC}  Uninstall              ${DIM}Remove protocols${NC}"
        echo -e "  ${CYAN}9)${NC}  View Logs              ${DIM}Services${NC}"
        echo ""
        echo -e "  ${DIM}0)  Exit${NC}"
        menu_prompt

        case "$MENU_CHOICE" in
            1) wizard_install ;;
            2) users_menu ;;
            3) _service_control_menu ;;
            4) ssl_menu ;;
            5) opt_menu ;;
            6) sec_menu ;;
            7) _update_menu ;;
            8) _uninstall_menu ;;
            9) _logs_menu ;;
            0) echo ""; exit 0 ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

# ── Service control ────────────────────────────────────────────

_service_control_menu() {
    while true; do
        print_banner
        print_header "Service Control"
        echo ""
        service_status_line sing-box          "VLESS Reality"
        service_status_line sing-box-ws       "WS+TLS"
        service_status_line sing-box-client   "Tunnel Client"
        service_status_line hysteria-server   "Hysteria2"
        service_status_line hysteria-auth     "Auth API"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Restart All"
        echo -e "  ${CYAN}2)${NC}  VLESS Reality"
        echo -e "  ${CYAN}3)${NC}  WS+TLS"
        echo -e "  ${CYAN}4)${NC}  Hysteria2"
        echo -e "  ${CYAN}5)${NC}  Auth API"
        echo -e "  ${CYAN}6)${NC}  Tunnel Client"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1)
                for svc in sing-box sing-box-ws hysteria-server hysteria-auth sing-box-client; do
                    systemctl is-active --quiet "$svc" 2>/dev/null && {
                        systemctl restart "$svc" && print_success "Restarted: ${svc}"
                    } || true
                done
                press_enter
                ;;
            2) vless_service_menu ;;
            3) vws_service_menu ;;
            4) hy2_service_menu ;;
            5) _simple_service_menu "hysteria-auth" "Auth API" ;;
            6) _simple_service_menu "sing-box-client" "Tunnel Client" ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

_simple_service_menu() {
    local svc="$1" label="$2"
    while true; do
        print_banner
        print_header "${label}"
        service_status_line "$svc" "$label"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Start"
        echo -e "  ${CYAN}2)${NC}  Stop"
        echo -e "  ${CYAN}3)${NC}  Restart"
        echo -e "  ${CYAN}4)${NC}  Live Log  ${DIM}(Ctrl+C to exit)${NC}"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) systemctl start   "$svc" && print_success "Started.";   press_enter ;;
            2) systemctl stop    "$svc" && print_success "Stopped.";   press_enter ;;
            3) systemctl restart "$svc" && print_success "Restarted."; press_enter ;;
            4) journalctl -u "$svc" -f ;;
            0) return ;;
            *) print_warn "Invalid."; sleep 1 ;;
        esac
    done
}

# ── Update menu ────────────────────────────────────────────────

_update_menu() {
    while true; do
        print_banner
        print_header "Update Binaries"

        local sb_ver="—" hy2_ver="—"
        [[ -f "$SINGBOX_BIN" ]] && \
            sb_ver=$("$SINGBOX_BIN" version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "?")
        [[ -f "$HY2_BIN" ]] && \
            hy2_ver=$("$HY2_BIN" version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "?")

        echo -e "  sing-box   : ${CYAN}${sb_ver}${NC}"
        echo -e "  hysteria2  : ${CYAN}${hy2_ver}${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Update sing-box"
        echo -e "  ${CYAN}2)${NC}  Update Hysteria2"
        echo -e "  ${CYAN}3)${NC}  Update Both"
        echo -e "  ${CYAN}4)${NC}  Update Manager"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) vless_update ;;
            2) hy2_update ;;
            3) vless_update; hy2_update ;;
            4) _self_update ;;
            0) return ;;
            *) print_warn "Invalid."; sleep 1 ;;
        esac
    done
}

_self_update() {
    print_header "Update Manager"
    local url="https://raw.githubusercontent.com/hesami/singbox-reality-tunnel/main/singbox-manager"
    print_info "Checking for updates..."

    local tmp_dir
    tmp_dir=$(mktemp -d)

    local failed=0
    for file in \
        core/common.sh core/system.sh core/db.sh \
        protocols/vless.sh protocols/hysteria2.sh protocols/vless_ws.sh \
        features/ssl.sh features/users.sh \
        features/optimization.sh features/security.sh \
        wizard/install.sh wizard/tunnel.sh \
        manager.sh; do

        local dir
        dir="${tmp_dir}/$(dirname "$file")"
        mkdir -p "$dir"
        curl -s --connect-timeout 10 "${url}/${file}" -o "${tmp_dir}/${file}" 2>/dev/null || {
            print_warn "Could not fetch ${file}"
            (( failed++ )) || true
        }
    done

    if (( failed > 3 )); then
        print_error "Too many files failed to download."
        rm -rf "$tmp_dir"; press_enter; return
    fi

    confirm "Apply update?" "y" || { rm -rf "$tmp_dir"; return; }

    local backup_dir="${SCRIPT_DIR}/../singbox-manager-backup-$(date +%Y%m%d%H%M)"
    cp -r "$SCRIPT_DIR" "$backup_dir" 2>/dev/null || true
    print_info "Backup: ${backup_dir}"

    for file in \
        core/common.sh core/system.sh core/db.sh \
        protocols/vless.sh protocols/hysteria2.sh protocols/vless_ws.sh \
        features/ssl.sh features/users.sh \
        features/optimization.sh features/security.sh \
        wizard/install.sh wizard/tunnel.sh \
        manager.sh; do
        [[ -f "${tmp_dir}/${file}" ]] && \
            cp "${tmp_dir}/${file}" "${SCRIPT_DIR}/${file}" && \
            chmod +x "${SCRIPT_DIR}/${file}" 2>/dev/null || true
    done

    rm -rf "$tmp_dir"
    print_success "Update applied. Re-launch: sudo bash ${SCRIPT_DIR}/manager.sh"
    exit 0
}

# ── Uninstall menu ─────────────────────────────────────────────

_uninstall_menu() {
    while true; do
        print_banner
        print_header "Uninstall"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Remove VLESS Reality"
        echo -e "  ${CYAN}2)${NC}  Remove WS+TLS"
        echo -e "  ${CYAN}3)${NC}  Remove Hysteria2"
        echo -e "  ${CYAN}4)${NC}  ${RED}Factory Reset${NC}  ${DIM}(everything)${NC}"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) vless_uninstall ;;
            2) vws_uninstall; press_enter ;;
            3) hy2_uninstall ;;
            4) _uninstall_all ;;
            0) return ;;
            *) print_warn "Invalid."; sleep 1 ;;
        esac
    done
}

_uninstall_all() {
    print_banner
    echo -e "  ${RED}${BOLD}Factory Reset${NC}\n"
    echo -e "  ${YELLOW}This will remove everything installed by this manager:${NC}"
    echo -e "  ${DIM}• sing-box & Hysteria2 binaries${NC}"
    echo -e "  ${DIM}• All config files and databases${NC}"
    echo -e "  ${DIM}• SSL certificates (acme.sh)${NC}"
    echo -e "  ${DIM}• systemd services${NC}"
    echo -e "  ${DIM}• cron jobs${NC}"
    echo -e "  ${DIM}• fail2ban config${NC}"
    echo ""
    confirm "Are you absolutely sure?" "n" || return

    print_info "Stopping all services..."
    for svc in sing-box sing-box-ws sing-box-client hysteria-server hysteria-auth fail2ban; do
        systemctl stop    "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done

    print_info "Removing service files..."
    rm -f /etc/systemd/system/sing-box.service
    rm -f /etc/systemd/system/sing-box-ws.service
    rm -f /etc/systemd/system/sing-box-client.service
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/hysteria-auth.service
    for svc in sing-box sing-box-client hysteria-server hysteria-auth; do
        rm -rf "/etc/systemd/system/${svc}.service.d"
    done
    systemctl daemon-reload

    print_info "Removing binaries..."
    rm -f /usr/local/bin/sing-box
    rm -f /usr/local/bin/hysteria

    print_info "Removing config & data directories..."
    rm -rf /etc/sing-box
    rm -rf /etc/hysteria
    rm -rf "$BASE_DIR"
    rm -rf "$LOG_DIR"

    print_info "Removing SSL certificates..."
    rm -rf /root/.acme.sh
    for rc in /root/.bashrc /root/.bash_profile /root/.zshrc; do
        [[ -f "$rc" ]] && sed -i '/acme.sh/d' "$rc" 2>/dev/null || true
    done

    print_info "Removing cron jobs..."
    { crontab -l 2>/dev/null || true; } \
        | grep -v "quota_enforce\|traffic_sync\|hy2_sync\|vless_sync\|acme.sh" \
        | crontab - 2>/dev/null || true

    print_info "Reverting optimizations..."
    rm -f /etc/sysctl.d/99-singbox.conf
    sed -i '/singbox-manager/d' /etc/security/limits.conf 2>/dev/null || true

    print_info "Removing fail2ban config..."
    rm -f /etc/fail2ban/jail.local
    rm -f /etc/fail2ban/filter.d/singbox.conf
    systemctl start fail2ban 2>/dev/null || true

    print_info "Removing packages..."
    apt-get remove -y fail2ban qrencode 2>/dev/null || true
    pip3 uninstall -y flask 2>/dev/null || true

    rm -f /etc/singbox-manager/ssl_reload_hook.sh 2>/dev/null || true

    echo ""
    print_success "Reset complete. The server is now clean."
    echo -e "  ${DIM}You can now run the wizard again for a fresh install.${NC}"
    press_enter
    exit 0
}

# ── Logs menu ──────────────────────────────────────────────────

_logs_menu() {
    while true; do
        print_banner
        print_header "Logs"
        echo ""
        echo -e "  ${CYAN}1)${NC}  VLESS Log"
        echo -e "  ${CYAN}2)${NC}  Hysteria2 Log"
        echo -e "  ${CYAN}3)${NC}  Auth API Log"
        echo -e "  ${CYAN}4)${NC}  Traffic Logs"
        echo -e "  ${CYAN}5)${NC}  Manager Log"
        echo -e "  ${CYAN}6)${NC}  Fail2ban Log"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) journalctl -u sing-box -f ;;
            2) journalctl -u hysteria-server -f ;;
            3) journalctl -u hysteria-auth -f ;;
            4)
                echo ""
                for f in "${LOG_DIR}/hy2_sync.log" "${LOG_DIR}/vless_sync.log"; do
                    [[ -f "$f" ]] && echo -e "  ${BOLD}${f}:${NC}" && tail -50 "$f" | sed 's/^/  /'
                done
                echo ""
                press_enter
                ;;
            5)
                [[ -f "$MANAGER_LOG" ]] && tail -50 "$MANAGER_LOG" | sed 's/^/  /' || echo "  (empty)"
                echo ""; press_enter
                ;;
            6) journalctl -u fail2ban -f ;;
            0) return ;;
            *) print_warn "Invalid."; sleep 1 ;;
        esac
    done
}

main_menu
