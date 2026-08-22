#!/usr/bin/env bash
# Two-server tunnel wizard. Reality tunnel uses Xray-core end-to-end.
# Existing nginx, web sites and the normal sing-box server are never modified.

_tunnel_tcp_port_busy() {
    local port="$1" line
    line=$(ss -H -ltnp 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {print}' | head -n1)
    [[ -n "$line" && "$line" != *"xray"* ]]
}

_tunnel_test_socks() {
    local port="$1" timeout="${2:-20}" out
    out=$(curl -fsS --max-time "$timeout" --connect-timeout 10 \
        --socks5-hostname "127.0.0.1:${port}" https://api.ipify.org 2>/tmp/tunnel-curl.err \
        | tr -d '[:space:]' || true)
    [[ "$out" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$out" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    printf '%s\n' "$out"
}

_tunnel_hy2_client_service() {
    local ip="$1" port="$2" uuid="$3" token="$4" listen_host="$5" socks_port="$6"
    mkdir -p /etc/hysteria
    cat > /etc/hysteria/tunnel-client.yaml <<EOF2
server: ${ip}:${port}
auth: "${uuid}:${token}"
tls:
  insecure: true
socks5:
  listen: ${listen_host}:${socks_port}
EOF2
    cat > /etc/systemd/system/hysteria-tunnel-client.service <<EOF2
[Unit]
Description=Hysteria2 Tunnel Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria client -c /etc/hysteria/tunnel-client.yaml --log-level info
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF2
    systemctl daemon-reload
    systemctl enable hysteria-tunnel-client >/dev/null 2>&1 || true
    systemctl restart hysteria-tunnel-client
}

_tunnel_frontend_write() {
    local public_port="$1" reality_port="$2" hy2_port="$3" reality_ok="$4" hy2_ok="$5"
    local outbounds final
    if [[ "$reality_ok" == "true" && "$hy2_ok" == "true" ]]; then
        outbounds="[
    {\"type\":\"socks\",\"tag\":\"reality-local\",\"server\":\"127.0.0.1\",\"server_port\":${reality_port}},
    {\"type\":\"socks\",\"tag\":\"hy2-local\",\"server\":\"127.0.0.1\",\"server_port\":${hy2_port}},
    {\"type\":\"urltest\",\"tag\":\"auto-out\",\"outbounds\":[\"reality-local\",\"hy2-local\"],\"url\":\"https://www.gstatic.com/generate_204\",\"interval\":\"30s\",\"tolerance\":100,\"interrupt_exist_connections\":true},
    {\"type\":\"direct\",\"tag\":\"direct\"}
  ]"
        final="auto-out"
    elif [[ "$reality_ok" == "true" ]]; then
        outbounds="[{\"type\":\"socks\",\"tag\":\"reality-local\",\"server\":\"127.0.0.1\",\"server_port\":${reality_port}},{\"type\":\"direct\",\"tag\":\"direct\"}]"
        final="reality-local"
    elif [[ "$hy2_ok" == "true" ]]; then
        outbounds="[{\"type\":\"socks\",\"tag\":\"hy2-local\",\"server\":\"127.0.0.1\",\"server_port\":${hy2_port}},{\"type\":\"direct\",\"tag\":\"direct\"}]"
        final="hy2-local"
    else
        return 1
    fi

    vless_write_config "{
  \"log\":{\"level\":\"warn\"},
  \"inbounds\":[{\"type\":\"socks\",\"tag\":\"socks-in\",\"listen\":\"0.0.0.0\",\"listen_port\":${public_port}}],
  \"outbounds\":${outbounds},
  \"route\":{\"final\":\"${final}\"}
}"
    /usr/local/bin/sing-box check -c /etc/sing-box/config.json >/tmp/tunnel-front-check.log 2>&1 || return 1
    vless_create_service client
    systemctl restart sing-box-client
}

wizard_tunnel() {
    print_banner
    print_header "Tunnel Setup — Iran ↔ Foreign"
    echo -e "  ${CYAN}1)${NC}  Foreign server setup ${DIM}(run first)${NC}"
    echo -e "  ${CYAN}2)${NC}  Iran relay setup     ${DIM}(run second)${NC}"
    echo -e "  ${CYAN}0)${NC}  Back"
    menu_prompt
    case "$MENU_CHOICE" in
        1) _wizard_tunnel_foreign ;;
        2) _wizard_tunnel_iran ;;
        0) return ;;
        *) print_warn "Invalid choice."; sleep 1 ;;
    esac
}

_wizard_tunnel_foreign() {
    print_banner
    print_header "Tunnel — Step 1: Foreign Server Setup"
    echo -e "  ${DIM}Reality uses a dedicated Xray-core service. nginx/site/sing-box are not modified.${NC}\n"
    echo -e "  ${CYAN}1)${NC}  ${BOLD}VLESS + Reality (Xray-core)${NC}  ${DIM}recommended${NC}"
    echo -e "  ${CYAN}2)${NC}  Hysteria2                 ${DIM}QUIC/UDP${NC}"
    echo -e "  ${CYAN}3)${NC}  Both"
    menu_prompt

    local do_xray=false do_hy2=false
    case "$MENU_CHOICE" in
        1) do_xray=true ;;
        2) do_hy2=true ;;
        3|"") do_xray=true; do_hy2=true ;;
        *) print_error "Invalid choice."; press_enter; return 1 ;;
    esac

    check_internet || { press_enter; return 1; }
    db_init
    local server_ip; server_ip=$(get_public_ip)
    local uuid="" token="" vport="" sni="" sid="" priv="" password=""

    if $do_xray; then
        print_section "Xray VLESS + REALITY"
        fetch_xray_version
        xray_install_binary "$XRAY_VERSION" || { press_enter; return 1; }
        ask vport "  Reality TCP port" "10443"
        while _tunnel_tcp_port_busy "$vport"; do
            print_warn "TCP ${vport} is occupied. Existing services will not be touched."
            ask vport "  Choose another Reality TCP port" "10443"
        done
        ask sni "  REALITY target/SNI" "www.speedtest.net"
        sid=$(openssl rand -hex 4)
        uuid=$($XRAY_BIN uuid 2>/dev/null || generate_uuid)
        local kp
        kp=$(xray_generate_reality_keypair) || { print_error "Could not generate Xray REALITY keypair."; press_enter; return 1; }
        priv="${kp%%|*}"; password="${kp#*|}"
        xray_write_server_config "$vport" "$uuid" "$sni" "$priv" "$sid"
        if ! xray_check_config "$XRAY_SERVER_CONFIG" >/tmp/xray-server-check.log 2>&1; then
            print_error "Xray server config validation failed."; cat /tmp/xray-server-check.log; press_enter; return 1
        fi
        xray_create_service server
        open_port "$vport" tcp
        systemctl restart xray-tunnel-server
        sleep 2
        if ! systemctl is-active --quiet xray-tunnel-server; then
            print_error "xray-tunnel-server failed."; journalctl -u xray-tunnel-server -n 30 --no-pager; press_enter; return 1
        fi
        print_success "Xray REALITY tunnel server is running on TCP/${vport}."
    fi

    if $do_hy2; then
        print_section "Hysteria2"
        fetch_hysteria2_version || { press_enter; return 1; }
        hy2_install_binary "$HY2_VERSION" || { press_enter; return 1; }
        ensure_packages python3 python3-pip openssl
        hy2_install_deps || { press_enter; return 1; }
        local hport bw rtt quic is ms ic mc up down
        ask hport "  Hysteria2 UDP port" "8443"
        probe_server
        bw=$(estimate_bandwidth); rtt=$(measure_rtt "8.8.8.8")
        quic=$(hy2_compute_quic_params "$bw" "$rtt"); IFS='|' read -r is ms ic mc <<< "$quic"
        up=$((bw*85/100)); down=$((bw*85/100))
        hy2_write_config "$hport" "" "$up" "$down" "$is" "$ms" "$ic" "$mc" "60s" "20s"
        hy2_save_server_info "$server_ip" "$hport" "" "True"
        hy2_write_auth_api; hy2_write_sync_script; hy2_create_server_service; hy2_create_auth_service; hy2_install_sync_cron
        open_port "$hport" udp
        systemctl restart hysteria-auth hysteria-server
        sleep 2
        if ! systemctl is-active --quiet hysteria-server || ! systemctl is-active --quiet hysteria-auth; then
            print_error "Hysteria2 services failed."; press_enter; return 1
        fi
        if [[ -z "$uuid" ]]; then uuid=$(generate_uuid); fi
        token=$(generate_token)
        db_add_user "$uuid" "tunnel-default" "0" "$token" '{"vless":false,"hysteria2":true}' >/dev/null 2>&1 || true
        print_success "Hysteria2 server is running on UDP/${hport}."
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}FOREIGN SERVER READY${NC}"
    echo -e "  Foreign IP : ${CYAN}${server_ip}${NC}"
    if $do_xray; then
        echo -e "\n  ${BOLD}Xray VLESS + Reality${NC}"
        echo -e "  Port       : ${CYAN}${vport}/TCP${NC}"
        echo -e "  UUID       : ${CYAN}${uuid}${NC}"
        echo -e "  Password/PublicKey : ${CYAN}${password}${NC}"
        echo -e "  Short ID   : ${CYAN}${sid}${NC}"
        echo -e "  SNI        : ${CYAN}${sni}${NC}"
    fi
    if $do_hy2; then
        [[ -n "$token" ]] || token=$(DB_PATH="$DB_PATH" UUID="$uuid" python3 - <<'PY'
import os, sqlite3
c=sqlite3.connect(os.environ['DB_PATH']); r=c.execute('select sub_token from users where uuid=? order by id desc limit 1',(os.environ['UUID'],)).fetchone(); print(r[0] if r else '')
PY
)
        echo -e "\n  ${BOLD}Hysteria2${NC}"
        echo -e "  Port       : ${CYAN}${hport}/UDP${NC}"
        echo -e "  UUID       : ${CYAN}${uuid}${NC}"
        echo -e "  Token      : ${CYAN}${token}${NC}"
    fi
    echo ""
    press_enter
}

_wizard_tunnel_iran() {
    print_banner
    print_header "Tunnel — Step 2: Iran Relay Server Setup"
    echo -e "  ${CYAN}1)${NC}  VLESS + Reality (Xray-core)"
    echo -e "  ${CYAN}2)${NC}  Hysteria2"
    echo -e "  ${CYAN}3)${NC}  Both"
    menu_prompt
    local use_xray=false use_hy2=false
    case "$MENU_CHOICE" in
        1) use_xray=true ;;
        2) use_hy2=true ;;
        3|"") use_xray=true; use_hy2=true ;;
        *) print_error "Invalid choice."; press_enter; return 1 ;;
    esac

    check_internet || { press_enter; return 1; }
    local foreign_ip public_socks
    ask foreign_ip "  Foreign server IP" ""
    [[ -n "$foreign_ip" ]] || { print_error "Foreign IP is required."; press_enter; return 1; }
    ask public_socks "  Public/local SOCKS5 port on Iran server" "10808"

    local xport xuuid xpassword xsid xsni hport huuid htoken
    if $use_xray; then
        print_section "Xray REALITY details"
        ask xport "  Reality TCP port" "10443"
        ask xuuid "  UUID" ""
        ask xpassword "  Password/PublicKey" ""
        ask xsid "  Short ID" ""
        ask xsni "  SNI" "www.speedtest.net"
    fi
    if $use_hy2; then
        print_section "Hysteria2 details"
        ask hport "  Hysteria2 UDP port" "8443"
        ask huuid "  UUID" "${xuuid:-}"
        ask htoken "  Token" ""
    fi

    local x_internal="$public_socks" h_internal="$public_socks"
    if $use_xray && $use_hy2; then x_internal=$((public_socks+2)); h_internal=$((public_socks+3)); fi
    local reality_ok=false hy2_ok=false reality_ip="" hy2_ip=""

    if $use_xray; then
        print_section "Installing Xray Reality client"
        fetch_xray_version
        xray_install_binary "$XRAY_VERSION" || { press_enter; return 1; }
        local xlisten="0.0.0.0"; $use_hy2 && xlisten="127.0.0.1"
        xray_write_client_config "$foreign_ip" "$xport" "$xuuid" "$xsni" "$xpassword" "$xsid" "$xlisten" "$x_internal"
        if ! xray_check_config "$XRAY_CLIENT_CONFIG" >/tmp/xray-client-check.log 2>&1; then
            print_error "Xray client config validation failed."; cat /tmp/xray-client-check.log
        else
            xray_create_service client
            systemctl restart xray-tunnel-client
            sleep 2
            if systemctl is-active --quiet xray-tunnel-client; then
                reality_ip=$(_tunnel_test_socks "$x_internal" 20 || true)
                if [[ -n "$reality_ip" ]]; then reality_ok=true; print_success "Reality path works. Exit IP: ${reality_ip}";
                else print_warn "Reality path did not produce egress."; tail -30 /var/log/xray-tunnel/client-error.log 2>/dev/null || true; fi
            else
                print_warn "xray-tunnel-client is not running."; journalctl -u xray-tunnel-client -n 30 --no-pager || true
            fi
        fi
    fi

    if $use_hy2; then
        print_section "Installing Hysteria2 client"
        fetch_hysteria2_version
        hy2_install_binary "$HY2_VERSION" || true
        local hlisten="0.0.0.0"; $use_xray && hlisten="127.0.0.1"
        if _tunnel_hy2_client_service "$foreign_ip" "$hport" "$huuid" "$htoken" "$hlisten" "$h_internal"; then
            sleep 2
            hy2_ip=$(_tunnel_test_socks "$h_internal" 15 || true)
            if [[ -n "$hy2_ip" ]]; then hy2_ok=true; print_success "Hysteria2 path works. Exit IP: ${hy2_ip}";
            else print_warn "Hysteria2 path failed health test (QUIC may be filtered)."; fi
        fi
    fi

    if $use_xray && $use_hy2; then
        print_section "Building automatic local failover"
        fetch_singbox_version stable
        vless_install_binary "$SINGBOX_VERSION" || { press_enter; return 1; }
        if ! _tunnel_frontend_write "$public_socks" "$x_internal" "$h_internal" "$reality_ok" "$hy2_ok"; then
            print_error "No healthy tunnel path is available; frontend was not activated."
            press_enter; return 1
        fi
        sleep 2
    elif $use_xray && [[ "$reality_ok" != "true" ]]; then
        print_error "Reality tunnel failed verification."; press_enter; return 1
    elif $use_hy2 && [[ "$hy2_ok" != "true" ]]; then
        print_error "Hysteria2 tunnel failed verification."; press_enter; return 1
    fi

    local final_ip; final_ip=$(_tunnel_test_socks "$public_socks" 20 || true)
    if [[ -z "$final_ip" ]]; then
        print_error "Final tunnel verification failed."
        press_enter; return 1
    fi
    echo ""
    print_success "IRAN RELAY VERIFIED — Exit IP: ${final_ip}"
    echo -e "  SOCKS5 : ${CYAN}0.0.0.0:${public_socks}${NC}"
    if $use_xray && $use_hy2; then
        $reality_ok && echo -e "  Reality : ${GREEN}healthy${NC}" || echo -e "  Reality : ${RED}failed${NC}"
        $hy2_ok && echo -e "  Hysteria2: ${GREEN}healthy${NC}" || echo -e "  Hysteria2: ${YELLOW}unavailable${NC}"
    fi
    echo ""
    press_enter
}
