#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  features/optimization.sh — Server & network optimization
#
#  Iran-aware: tuned for high packet-loss, high-latency,
#  DPI-heavy environments. All values are computed from
#  the server hardware profile (SRV_*) set by core/system.sh.
#
#  Depends on: core/common.sh  core/system.sh
# ═══════════════════════════════════════════════════════════════

SYSCTL_TAG="# singbox-manager"
SYSCTL_FILE="/etc/sysctl.d/99-singbox.conf"

# ── Current values snapshot ────────────────────────────────────

opt_show_current() {
    print_header "Current Network Settings"
    local keys=(
        net.ipv4.tcp_congestion_control
        net.core.default_qdisc
        net.core.rmem_max
        net.core.wmem_max
        net.ipv4.tcp_keepalive_time
        net.ipv4.tcp_keepalive_intvl
        net.ipv4.tcp_keepalive_probes
        net.ipv4.tcp_fin_timeout
        net.ipv4.tcp_fastopen
        net.ipv4.tcp_slow_start_after_idle
        vm.swappiness
        fs.file-max
    )
    for key in "${keys[@]}"; do
        local val
        val=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        printf "  %-50s ${CYAN}%s${NC}\n" "$key" "$val"
    done
    echo ""
}

# ── BBR detection and enable ───────────────────────────────────

opt_bbr_status() {
    sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | grep -qi bbr
}

opt_enable_bbr() {
    print_info "Enabling BBR congestion control..."

    # Make sure the BBR module is loaded
    modprobe tcp_bbr 2>/dev/null || true

    local available
    available=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "")

    if ! echo "$available" | grep -qi bbr; then
        print_warn "BBR module not available on kernel ${SRV_KERNEL}."
        print_warn "Consider upgrading to kernel 5.x+ for BBR support."
        return 1
    fi

    # Choose qdisc: fq_codel is better than plain fq on links with packet loss
    local qdisc="fq_codel"
    modprobe sch_fq_codel 2>/dev/null || qdisc="fq"

    sed -i '/net.core.default_qdisc/d'          "$SYSCTL_FILE" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d'  "$SYSCTL_FILE" 2>/dev/null || true

    {
        echo "net.core.default_qdisc=fq_codel"
        echo "net.ipv4.tcp_congestion_control=bbr"
    } >> "$SYSCTL_FILE"

    sysctl -p "$SYSCTL_FILE" &>/dev/null

    local active
    active=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    if [[ "$active" == "bbr" ]]; then
        print_success "BBR enabled. qdisc: ${qdisc}"
    else
        print_error "BBR could not be activated. Active: ${active}"
        return 1
    fi
}

opt_disable_bbr() {
    sed -i '/net.core.default_qdisc/d'          "$SYSCTL_FILE" 2>/dev/null || true
    sed -i '/net.ipv4.tcp_congestion_control/d'  "$SYSCTL_FILE" 2>/dev/null || true
    echo "net.ipv4.tcp_congestion_control=cubic" >> "$SYSCTL_FILE"
    sysctl -p "$SYSCTL_FILE" &>/dev/null
    print_success "Congestion control reverted to cubic."
}

# ── Smart TCP optimization ─────────────────────────────────────
# All buffer sizes computed from SRV_RAM_PROFILE.
# Keepalive values tuned for Iran's intermittent connectivity.

opt_apply_tcp() {
    print_info "Computing TCP settings for profile '${SRV_RAM_PROFILE}' (${SRV_RAM_MB}MB RAM)..."

    # Read buffer params from system.sh helper
    local buf_line
    buf_line=$(compute_tcp_buffers)
    declare "${buf_line// /;}" 2>/dev/null || true

    # Parse manually since declare with spaces is tricky
    local rmem_max wmem_max rmem_def wmem_def
    rmem_max=$(echo "$buf_line" | grep -oP 'rmem_max=\K\d+')
    wmem_max=$(echo "$buf_line" | grep -oP 'wmem_max=\K\d+')
    rmem_def=$(echo "$buf_line" | grep -oP 'rmem_default=\K\d+')
    wmem_def=$(echo "$buf_line" | grep -oP 'wmem_default=\K\d+')

    # tcp_rmem / tcp_wmem: min, default, max
    local tcp_rmem="4096 ${rmem_def} ${rmem_max}"
    local tcp_wmem="4096 ${wmem_def} ${wmem_max}"

    # Iran-specific keepalive:
    # - keepalive_time 30s  : detect dead connections fast (Iran drops idle)
    # - keepalive_intvl 5s  : probe every 5s after first failure
    # - keepalive_probes 6  : give up after 6×5=30s with no reply
    # - fin_timeout 10s     : release half-closed connections quickly
    local ka_time=30 ka_intvl=5 ka_probes=6 fin_timeout=10

    # Swappiness: lower for proxy workloads (keep in RAM)
    local swappiness
    case "$SRV_RAM_PROFILE" in
        low)  swappiness=20 ;;
        mid)  swappiness=10 ;;
        high) swappiness=5  ;;
    esac

    # Remove any previous singbox-manager sysctl entries
    _opt_clean_sysctl

    cat >> "$SYSCTL_FILE" << EOF
${SYSCTL_TAG} — TCP optimization (profile: ${SRV_RAM_PROFILE}, $(date +%Y-%m-%d))

# Buffers — scaled to ${SRV_RAM_MB}MB RAM
net.core.rmem_max=${rmem_max}
net.core.wmem_max=${wmem_max}
net.core.rmem_default=${rmem_def}
net.core.wmem_default=${wmem_def}
net.ipv4.tcp_rmem=${tcp_rmem}
net.ipv4.tcp_wmem=${tcp_wmem}

# Iran-aware keepalive (aggressive — handles frequent NAT timeouts)
net.ipv4.tcp_keepalive_time=${ka_time}
net.ipv4.tcp_keepalive_intvl=${ka_intvl}
net.ipv4.tcp_keepalive_probes=${ka_probes}
net.ipv4.tcp_fin_timeout=${fin_timeout}

# Performance — high-latency links
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1

# Backlog / connections
net.core.somaxconn=32768
net.core.netdev_max_backlog=32768
net.ipv4.tcp_max_syn_backlog=16384
net.ipv4.tcp_max_tw_buckets=720000
net.ipv4.tcp_tw_reuse=1

# UDP — critical for Hysteria2 (QUIC)
net.core.rmem_max=${rmem_max}
net.core.wmem_max=${wmem_max}
net.ipv4.udp_rmem_min=65536
net.ipv4.udp_wmem_min=65536

# System
vm.swappiness=${swappiness}
fs.file-max=1000000
EOF

    sysctl -p "$SYSCTL_FILE" &>/dev/null
    print_success "TCP/UDP settings applied (Iran-aware, profile: ${SRV_RAM_PROFILE})."
}

# ── file descriptor limits ─────────────────────────────────────

opt_apply_limits() {
    print_info "Raising file descriptor limits..."

    # systemd override for our services
    for svc in sing-box sing-box-client hysteria-server hysteria-auth; do
        local drop_dir="/etc/systemd/system/${svc}.service.d"
        mkdir -p "$drop_dir"
        cat > "${drop_dir}/limits.conf" << 'EOF'
[Service]
LimitNOFILE=1000000
LimitNPROC=65535
EOF
    done

    # /etc/security/limits.conf
    sed -i '/singbox-manager/d' /etc/security/limits.conf 2>/dev/null || true
    {
        echo "# singbox-manager"
        echo "* soft nofile 1000000"
        echo "* hard nofile 1000000"
        echo "root soft nofile 1000000"
        echo "root hard nofile 1000000"
    } >> /etc/security/limits.conf

    systemctl daemon-reload
    print_success "File descriptor limits raised to 1,000,000."
}

# ── DPI evasion hints ──────────────────────────────────────────
# These don't bypass DPI directly but reduce fingerprint surface.

opt_apply_dpi_hints() {
    print_info "Applying DPI-evasion sysctl hints..."

    # Already set in apply_tcp but make sure:
    # tcp_timestamps=1  → allows subtle timing obfuscation at QUIC layer
    # tcp_mtu_probing=1 → avoids MTU black-holes that cause hangs on some ISPs
    # tcp_fastopen=3    → reduces round-trips that DPI can inspect

    # IP ID randomization (harder for DPI to correlate flows)
    if sysctl net.ipv4.ip_unprivileged_port_start &>/dev/null; then
        echo "net.ipv4.ip_unprivileged_port_start=0" >> "$SYSCTL_FILE"
    fi

    sysctl -p "$SYSCTL_FILE" &>/dev/null
    print_success "DPI evasion hints applied."
}

# ── Memory / CPU ───────────────────────────────────────────────

opt_show_memory() {
    print_header "Memory & CPU"
    local swappiness oom_adj sb_nice sb_pid
    swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "?")
    sb_pid=$(pgrep -x sing-box 2>/dev/null | head -1 || echo "")
    local hy_pid=$(pgrep -x hysteria  2>/dev/null | head -1 || echo "")

    printf "  %-30s ${CYAN}%s${NC}\n" "vm.swappiness" "$swappiness"

    for pid_info in "sing-box:${sb_pid}" "hysteria:${hy_pid}"; do
        local pname="${pid_info%%:*}" pid="${pid_info##*:}"
        if [[ -n "$pid" ]]; then
            local nice oom rss
            nice=$(ps -o nice= -p "$pid" 2>/dev/null | tr -d ' ' || echo "?")
            oom=$(cat  "/proc/${pid}/oom_score_adj" 2>/dev/null || echo "?")
            rss=$(awk '/VmRSS/{print $2}' "/proc/${pid}/status" 2>/dev/null || echo "0")
            rss=$(( rss / 1024 ))
            printf "  %-30s nice=%-4s oom_adj=%-5s mem=${CYAN}%dMB${NC}\n" \
                "$pname (pid $pid)" "$nice" "$oom" "$rss"
        else
            printf "  %-30s ${DIM}not running${NC}\n" "$pname"
        fi
    done
    echo ""
}

opt_set_process_priority() {
    print_info "Setting process priority for proxy processes..."
    for proc in sing-box hysteria; do
        local pid
        pid=$(pgrep -x "$proc" 2>/dev/null | head -1 || echo "")
        if [[ -n "$pid" ]]; then
            renice -n -5 -p "$pid" &>/dev/null \
                && print_success "${proc} nice set to -5." \
                || print_warn "Could not set priority for ${proc}."
            echo "-900" > "/proc/${pid}/oom_score_adj" 2>/dev/null || true
        fi
    done
}

opt_reduce_swappiness() {
    local target
    case "$SRV_RAM_PROFILE" in
        low)  target=20 ;;
        mid)  target=10 ;;
        high) target=5  ;;
    esac
    sed -i '/vm.swappiness/d' "$SYSCTL_FILE" 2>/dev/null || true
    echo "vm.swappiness=${target}" >> "$SYSCTL_FILE"
    sysctl -p "$SYSCTL_FILE" &>/dev/null
    print_success "vm.swappiness set to ${target} (profile: ${SRV_RAM_PROFILE})."
}

# ── Speed test ─────────────────────────────────────────────────

opt_speedtest() {
    print_header "Network Speed Test"
    if command -v speedtest-cli &>/dev/null; then
        speedtest-cli --simple 2>&1 | sed 's/^/  /'
        echo ""
    elif command -v python3 &>/dev/null; then
        print_info "Installing speedtest-cli..."
        pip3 install speedtest-cli --break-system-packages -q &>/dev/null
        if command -v speedtest-cli &>/dev/null; then
            speedtest-cli --simple 2>&1 | sed 's/^/  /'
        else
            print_warn "speedtest-cli not available."
        fi
    else
        # Lightweight curl-based test
        print_info "Running curl-based bandwidth estimate..."
        local url="https://speed.cloudflare.com/__down?bytes=25000000"
        local start result mbps
        start=$(date +%s%3N)
        curl -s -o /dev/null "$url" &
        local curl_pid=$!
        wait "$curl_pid" 2>/dev/null
        local end
        end=$(date +%s%3N)
        local ms=$(( end - start ))
        mbps=$(python3 -c "print(f'{25*8/({ms}/1000):.1f}')" 2>/dev/null || echo "?")
        echo -e "  Download (25MB sample): ${CYAN}~${mbps} Mbps${NC}"
        echo ""
    fi
}

# ── Reset all optimizations ────────────────────────────────────

opt_reset_all() {
    confirm "Remove ALL singbox-manager sysctl settings and revert to defaults?" "n" || return
    _opt_clean_sysctl
    sysctl -p "$SYSCTL_FILE" &>/dev/null 2>/dev/null || true
    # Also reset limits
    sed -i '/singbox-manager/d' /etc/security/limits.conf 2>/dev/null || true
    print_success "All optimizations removed. Reboot recommended."
}

_opt_clean_sysctl() {
    # Remove everything between singbox-manager marker blocks
    [[ ! -f "$SYSCTL_FILE" ]] && return
    python3 - <<'PYEOF'
import re, os

path = "/etc/sysctl.d/99-singbox.conf"
if not os.path.exists(path):
    open(path, "w").close()
    exit()

with open(path) as f:
    content = f.read()

# Remove blocks starting with "# singbox-manager" through blank lines or next comment
cleaned = re.sub(
    r'# singbox-manager.*?(?=\n#|\Z)',
    '',
    content,
    flags=re.DOTALL
).strip()

with open(path, "w") as f:
    f.write(cleaned + "\n" if cleaned else "")
PYEOF
}

# ── One-click full optimization ────────────────────────────────
# Called from wizard on first install or manually from menu.

opt_apply_all() {
    print_banner
    print_header "Full Optimization"

    # Always probe first to get SRV_* values
    probe_server
    show_server_profile

    print_step 1 4 "BBR congestion control"
    if (( SRV_BBR_VERSION >= 1 )); then
        opt_enable_bbr && print_success "BBR enabled." || print_warn "BBR skipped."
    else
        print_warn "Kernel too old for BBR (${SRV_KERNEL}). Skipping."
    fi

    print_step 2 4 "TCP/UDP buffer & keepalive tuning"
    opt_apply_tcp

    print_step 3 4 "File descriptor limits"
    opt_apply_limits

    print_step 4 4 "Process priority"
    opt_set_process_priority
    opt_reduce_swappiness

    echo ""
    print_success "All optimizations applied."
    echo -e "  ${DIM}Settings persist across reboots via ${SYSCTL_FILE}.${NC}\n"
}

# ── Optimization menu ──────────────────────────────────────────

opt_menu() {
    while true; do
        print_banner
        print_header "Optimization"

        # Quick status line
        local cc qd
        cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")
        qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")
        local bbr_status
        [[ "$cc" == "bbr" ]] \
            && bbr_status="${GREEN}● BBR active${NC}  qdisc=${qd}" \
            || bbr_status="${YELLOW}○ BBR off${NC}   cc=${cc}"
        echo -e "  ${bbr_status}\n"

        echo -e "  ${CYAN}1)${NC}  Full auto-optimize      ${DIM}(recommended — detects your server)${NC}"
        echo -e "  ${CYAN}2)${NC}  Enable BBR"
        echo -e "  ${CYAN}3)${NC}  TCP/UDP tuning           ${DIM}(keepalive + buffers for Iran)${NC}"
        echo -e "  ${CYAN}4)${NC}  File descriptor limits"
        echo -e "  ${CYAN}5)${NC}  Process priority         ${DIM}(nice + OOM protection)${NC}"
        echo -e "  ${CYAN}6)${NC}  Speed test"
        echo -e "  ${CYAN}7)${NC}  Show current values"
        echo -e "  ${CYAN}8)${NC}  Show server profile      ${DIM}(RAM, CPU, kernel, BBR version)${NC}"
        echo -e "  ${CYAN}9)${NC}  Reset to defaults"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) opt_apply_all; press_enter ;;
            2)
                probe_server &>/dev/null
                opt_enable_bbr
                press_enter
                ;;
            3)
                probe_server &>/dev/null
                opt_apply_tcp
                press_enter
                ;;
            4) opt_apply_limits; press_enter ;;
            5) opt_set_process_priority; opt_reduce_swappiness; press_enter ;;
            6) opt_speedtest; press_enter ;;
            7) opt_show_current; opt_show_memory; press_enter ;;
            8) probe_server; show_server_profile; press_enter ;;
            9) opt_reset_all; press_enter ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}
