#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  features/security.sh — Fail2ban setup and management
#
#  Depends on: core/common.sh  core/system.sh
# ═══════════════════════════════════════════════════════════════

SEC_LOG_DIR="/var/log/singbox-manager"
SEC_LOG_FILE="${SEC_LOG_DIR}/sing-box.log"

# ── sing-box log file setup ────────────────────────────────────

sec_setup_singbox_logfile() {
    mkdir -p "$SEC_LOG_DIR"
    # Patch config.json to write to file if not already
    for config in /etc/sing-box/config.json; do
        [[ ! -f "$config" ]] && continue
        python3 - <<PYEOF
import json, os

path = "${config}"
with open(path) as f:
    c = json.load(f)

log = c.setdefault("log", {})
if log.get("output") != "${SEC_LOG_FILE}":
    log["output"] = "${SEC_LOG_FILE}"
    log.setdefault("level", "warn")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(c, f, indent=2)
    os.replace(tmp, path)
    print("patched")
else:
    print("already set")
PYEOF
    done
    # Ensure file exists and is writable
    touch "$SEC_LOG_FILE"
    print_success "sing-box log file: ${SEC_LOG_FILE}"
}

# ── Write fail2ban filter ──────────────────────────────────────

sec_write_filter() {
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/singbox.conf << 'EOF'
[INCLUDES]
before = common.conf

[Definition]
# sing-box v1.8+ log format:
#   2025/01/01 12:00:00 ERR inbound/vless[tag] connection rejected from 1.2.3.4:12345
#   2025/01/01 12:00:00 ERR inbound/reality[tag] REALITY: invalid session from 1.2.3.4:12345
#   2025/01/01 12:00:00 ERR inbound/hysteria2[tag] tls: failed to verify from 1.2.3.4:12345
failregex = ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ERR .*connection rejected from <HOST>:\d+.*$
            ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ERR .*connection rejected.* <HOST>:\d+.*$
            ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ERR .*REALITY.*invalid.*<HOST>:\d+.*$
            ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ERR .*tls.*failed.*<HOST>:\d+.*$
            ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ERR .*<HOST>:\d+.*tls.*error.*$
            ^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} WARN .*<HOST>:\d+.*rejected.*$

ignoreregex =

datepattern = {^LN-BEG}%%Y/%%m/%%d %%H:%%M:%%S
              {^LN-BEG}%%Y-%%m-%%dT%%H:%%M:%%S
              {^LN-BEG}\[%%Y-%%m-%%d %%H:%%M:%%S\]
EOF
    print_success "fail2ban filter written."
}

# ── Write jail config ──────────────────────────────────────────

sec_write_jail() {
    local maxretry="$1" findtime="$2" bantime="$3"

    # Choose backend: prefer systemd journal if log file is empty
    local use_systemd=false
    sleep 1
    [[ -s "$SEC_LOG_FILE" ]] || use_systemd=true

    if $use_systemd; then
        print_info "Using systemd journal backend."
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}
backend   = systemd

[sshd]
enabled = false

[singbox]
enabled      = true
filter       = singbox
journalmatch = _SYSTEMD_UNIT=sing-box.service + _SYSTEMD_UNIT=hysteria-server.service
backend      = systemd
maxretry     = ${maxretry}
findtime     = ${findtime}
bantime      = ${bantime}
action       = iptables-allports[name=singbox, protocol=all]
EOF
    else
        print_info "Using file-based log backend."
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${bantime}
findtime  = ${findtime}
maxretry  = ${maxretry}
backend   = auto

[sshd]
enabled = false

[singbox]
enabled  = true
filter   = singbox
logpath  = ${SEC_LOG_FILE}
backend  = auto
maxretry = ${maxretry}
findtime = ${findtime}
bantime  = ${bantime}
action   = iptables-allports[name=singbox, protocol=all]
EOF
    fi
    print_success "fail2ban jail config written."
}

# ── Install ────────────────────────────────────────────────────

sec_install_fail2ban() {
    print_banner
    print_header "Install & Configure Fail2ban"

    # Step 1: install package
    print_step 1 5 "Installing fail2ban"
    if ! command -v fail2ban-client &>/dev/null; then
        apt-get update -qq &>/dev/null
        apt-get install -y fail2ban &>/dev/null \
            && print_success "fail2ban installed." \
            || { print_error "Installation failed."; press_enter; return 1; }
    else
        print_info "fail2ban already installed."
    fi

    # Step 2: rsyslog (optional — needed for file backend on some systems)
    print_step 2 5 "Checking rsyslog"
    if ! command -v rsyslogd &>/dev/null; then
        apt-get install -y rsyslog &>/dev/null \
            && print_success "rsyslog installed." \
            || print_info "rsyslog not available — systemd backend will be used."
    else
        print_info "rsyslog already present."
    fi

    # Step 3: configure log file
    print_step 3 5 "Configuring log output"
    sec_setup_singbox_logfile

    # Restart services to apply log config
    for svc in sing-box sing-box-client hysteria-server; do
        systemctl is-active --quiet "$svc" 2>/dev/null && \
            systemctl restart "$svc" 2>/dev/null || true
    done
    sleep 2

    # Step 4: ban parameters
    print_step 4 5 "Ban parameters"
    echo ""
    local maxretry bantime findtime
    ask maxretry "  Max failed attempts before ban"                "5"
    ask findtime "  Time window in seconds"                        "60"
    ask bantime  "  Ban duration  (3600=1h, 86400=1d, -1=forever)" "3600"

    sec_write_filter
    sec_write_jail "$maxretry" "$findtime" "$bantime"

    # Step 5: validate & start
    print_step 5 5 "Starting fail2ban"
    if fail2ban-client --test &>/dev/null; then
        print_success "Config validation passed."
    else
        print_warn "Config validation warning — attempting simplified config..."
        # Fallback to minimal systemd-only config
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime  = ${bantime}
findtime = ${findtime}
maxretry = ${maxretry}

[singbox]
enabled      = true
filter       = singbox
journalmatch = _SYSTEMD_UNIT=sing-box.service
backend      = systemd
action       = iptables-allports[name=singbox, protocol=all]
EOF
    fi

    systemctl enable fail2ban &>/dev/null
    systemctl restart fail2ban
    sleep 2

    if systemctl is-active --quiet fail2ban; then
        print_success "fail2ban is running."
    else
        print_error "fail2ban failed to start. Check: journalctl -u fail2ban -n 30"
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}Fail2ban configured!${NC}"
    echo -e "  Max attempts : ${CYAN}${maxretry}${NC}"
    echo -e "  Find window  : ${CYAN}${findtime}s${NC}"
    echo -e "  Ban duration : ${CYAN}${bantime}s${NC}"
    press_enter
}

# ── Status ─────────────────────────────────────────────────────

sec_show_status() {
    print_header "Fail2ban Status"
    service_status_line fail2ban "fail2ban"
    echo ""

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo -e "  ${BOLD}Jail status:${NC}"
        fail2ban-client status singbox 2>/dev/null | sed 's/^/  /' \
            || echo "  (singbox jail not active)"
        echo ""
        echo -e "  ${BOLD}Currently banned IPs:${NC}"
        fail2ban-client status singbox 2>/dev/null \
            | grep "Banned IP" | sed 's/^/  /' || echo "  (none)"
    else
        print_warn "fail2ban is not running."
    fi
    echo ""
}

# ── Unban IP ───────────────────────────────────────────────────

sec_unban_ip() {
    local ip
    ask ip "  IP address to unban" ""
    [[ -z "$ip" ]] && return
    fail2ban-client set singbox unbanip "$ip" 2>&1 | sed 's/^/  /'
    print_success "Unban request sent for ${ip}."
}

# ── List banned IPs ────────────────────────────────────────────

sec_list_banned() {
    print_header "Banned IP Addresses"
    if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_warn "fail2ban not running."; return
    fi
    fail2ban-client status singbox 2>/dev/null | sed 's/^/  /' || echo "  (jail not found)"
    echo ""
}

# ── Uninstall ──────────────────────────────────────────────────

sec_uninstall_fail2ban() {
    confirm "Remove fail2ban and all its configs?" "n" || return
    systemctl stop    fail2ban &>/dev/null || true
    systemctl disable fail2ban &>/dev/null || true
    apt-get remove -y fail2ban &>/dev/null || true
    rm -f /etc/fail2ban/jail.local
    rm -f /etc/fail2ban/filter.d/singbox.conf
    print_success "fail2ban removed."
}

# ── Security menu ──────────────────────────────────────────────

sec_menu() {
    while true; do
        print_banner
        print_header "Security — Fail2ban"
        sec_show_status

        echo -e "  ${CYAN}1)${NC}  Install & configure fail2ban"
        echo -e "  ${CYAN}2)${NC}  Show banned IPs"
        echo -e "  ${CYAN}3)${NC}  Unban an IP"
        echo -e "  ${CYAN}4)${NC}  Restart fail2ban"
        echo -e "  ${CYAN}5)${NC}  Live log  ${DIM}(Ctrl+C to exit)${NC}"
        echo -e "  ${CYAN}6)${NC}  Remove fail2ban"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) sec_install_fail2ban ;;
            2) sec_list_banned; press_enter ;;
            3) sec_unban_ip; press_enter ;;
            4)
                systemctl restart fail2ban \
                    && print_success "Restarted." \
                    || print_error "Restart failed."
                press_enter
                ;;
            5) journalctl -u fail2ban -f ;;
            6) sec_uninstall_fail2ban; press_enter ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}
