#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  wizard/tunnel.sh — Two-server tunnel setup wizard
#
#  Step 1: Run on foreign server  → installs proxy, shows info
#  Step 2: Run on Iran server     → installs relay client
#
#  Depends on: core/*  protocols/vless.sh  protocols/hysteria2.sh
# ═══════════════════════════════════════════════════════════════

wizard_tunnel() {
    print_banner
    print_header "Tunnel Setup — Two-Server Mode"
    echo ""
    echo -e "  ${BOLD}How a tunnel works:${NC}"
    echo ""
    echo -e "   [Client in Iran]"
    echo -e "         ↓  connects to Iran relay"
    echo -e "   [Iran server]  ←── you need a cheap Iranian VPS"
    echo -e "         ↓  encrypted tunnel"
    echo -e "   [Foreign server]  ←── your main VPS abroad (Germany/NL/etc.)"
    echo -e "         ↓  normal traffic to the internet"
    echo -e "   [Internet]"
    echo ""
    echo -e "  ${YELLOW}${BOLD}This wizard must be run TWICE:${NC}"
    echo -e "  ${DIM}Once on the foreign server, once on the Iran server.${NC}"
    echo ""

    print_header "Which server are you on right now?"
    echo ""
    echo -e "  ${CYAN}1)${NC}  ${BOLD}Foreign server${NC}  ${DIM}(abroad — Germany, Netherlands, etc.)${NC}"
    echo -e "     ${DIM}→ Run this FIRST. It will install the proxy and show you the${NC}"
    echo -e "       ${DIM}settings you need to enter on the Iran server.${NC}"
    echo ""
    echo -e "  ${CYAN}2)${NC}  ${BOLD}Iran server${NC}  ${DIM}(relay — inside Iran)${NC}"
    echo -e "     ${DIM}→ Run this SECOND. You will need the output from Step 1.${NC}"
    echo -e "       ${DIM}Installs the relay client that tunnels through the foreign server.${NC}"
    echo ""
    echo -e "  ${CYAN}0)${NC}  Back"
    menu_prompt

    case "$MENU_CHOICE" in
        1) _wizard_tunnel_foreign ;;
        2) _wizard_tunnel_iran    ;;
        0) return ;;
        *) print_warn "Invalid choice."; sleep 1; wizard_tunnel ;;
    esac
}

# Persist tunnel-created inbounds in the same DB used by User Management
# and the unified subscription API. Re-running updates the same record.
_tunnel_upsert_inbound() {
    local tag="$1" proto="$2" domain="$3" port="$4" cfg="$5"
    TAG="$tag" PROTO="$proto" DOMAIN="$domain" PORT="$port" CFG="$cfg" \
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.execute("""
INSERT INTO inbounds (tag, protocol, domain, port, enabled, config_json)
VALUES (?, ?, ?, ?, 1, ?)
ON CONFLICT(tag) DO UPDATE SET
    protocol=excluded.protocol,
    domain=excluded.domain,
    port=excluded.port,
    enabled=1,
    config_json=excluded.config_json
""", (
    os.environ["TAG"], os.environ["PROTO"], os.environ["DOMAIN"],
    int(os.environ["PORT"]), os.environ["CFG"]
))
conn.commit()
conn.close()
PYEOF
}

# ══════════════════════════════════════════════════════════════
#  Foreign server — installs proxy, prints settings for Iran side
# ══════════════════════════════════════════════════════════════

_wizard_tunnel_foreign() {
    print_banner
    print_header "Tunnel — Step 1: Foreign Server Setup"
    echo -e "  ${DIM}You are on the foreign VPS. This will install the proxy server.${NC}\n"

    # Choose protocol
    print_header "Which protocol for the tunnel?"
    echo ""
    echo -e "  ${CYAN}1)${NC}  ${BOLD}VLESS + Reality${NC}  ${DIM}(TCP — stable, works on most ISPs)${NC}"
    echo -e "  ${CYAN}2)${NC}  ${BOLD}Hysteria2${NC}  ${DIM}(QUIC/UDP — better for high-loss links)${NC}"
    echo -e "  ${CYAN}3)${NC}  ${BOLD}Both${NC}  ${DIM}(most resilient — Iran relay picks best)${NC}"
    echo ""
    menu_prompt

    local proto_vless=false proto_hy2=false
    case "$MENU_CHOICE" in
        1) proto_vless=true ;;
        2) proto_hy2=true ;;
        3|"") proto_vless=true; proto_hy2=true ;;
        *) proto_vless=true ;;
    esac

    check_internet
    db_init

    local server_ip handoff_uuid="" handoff_token=""
    server_ip=$(get_public_ip)

    # ── Install VLESS ────────────────────────────────────────
    if $proto_vless; then
        echo ""
        echo -e "  ${BOLD}─── VLESS + Reality ───────────────────────────────${NC}"
        fetch_singbox_version stable
        vless_install_binary "$SINGBOX_VERSION"

        local vport vsni vsid
        local def_sid
        def_sid=$(openssl rand -hex 4 2>/dev/null || tr -dc 'a-f0-9' < /dev/urandom | head -c 8)
        ask vport "  VLESS listen port" "443"
        ask vsni  "  Camouflage SNI"    "www.speedtest.net"
        ask vsid  "  Short ID (hex)"    "$def_sid"

        local kp priv pub uuid sub_token
        kp=$(generate_keypair)
        priv=$(echo "$kp" | awk '/PrivateKey/{print $2}')
        pub=$(echo  "$kp" | awk '/PublicKey/{print $2}')
        uuid=$(generate_uuid)
        sub_token=$(generate_token)

        vless_write_config "{
  \"log\": { \"level\": \"warn\", \"output\": \"/var/log/singbox-manager/sing-box.log\" },
  \"inbounds\": [{
    \"type\": \"vless\", \"tag\": \"vless-in\",
    \"listen\": \"0.0.0.0\", \"listen_port\": ${vport},
    \"users\": [{\"uuid\": \"${uuid}\", \"flow\": \"xtls-rprx-vision\"}],
    \"tls\": {
      \"enabled\": true, \"server_name\": \"${vsni}\",
      \"reality\": {
        \"enabled\": true,
        \"handshake\": {\"server\": \"${vsni}\", \"server_port\": 443},
        \"private_key\": \"${priv}\",
        \"short_id\": [\"${vsid}\"]
      }
    }
  }],
  \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}]
}"
        vless_save_server_info "$pub" "$priv" "$vsid" "$vsni" "$vport" ""
        vless_create_service server
        vless_install_quota_enforcer
        vless_install_traffic_sync
        open_port "$vport" tcp
        service_start sing-box

        local init_eng
        $proto_hy2 \
            && init_eng='{"vless":true,"hysteria2":true}' \
            || init_eng='{"vless":true,"hysteria2":false}'
        if ! db_add_user "$uuid" "tunnel-default" "0" "$sub_token" "$init_eng"; then
            print_error "Failed to create tunnel credentials in the database."
            press_enter; return 1
        fi
        handoff_uuid="$uuid"
        handoff_token="$sub_token"

        local tunnel_vless_json
        tunnel_vless_json=$(VPORT="$vport" UUID="$uuid" VSNI="$vsni" PRIV="$priv" \
            VSID="$vsid" HOST="$server_ip" PUB="$pub" python3 - <<'PYEOF'
import json, os
ib = {
    "type": "vless",
    "tag": "vless-in",
    "listen": "0.0.0.0",
    "listen_port": int(os.environ["VPORT"]),
    "users": [{"uuid": os.environ["UUID"], "flow": "xtls-rprx-vision"}],
    "tls": {
        "enabled": True,
        "server_name": os.environ["VSNI"],
        "reality": {
            "enabled": True,
            "handshake": {"server": os.environ["VSNI"], "server_port": 443},
            "private_key": os.environ["PRIV"],
            "short_id": [os.environ["VSID"]]
        }
    },
    "_meta": {
        "protocol": "vless_reality",
        "host": os.environ["HOST"],
        "port": int(os.environ["VPORT"]),
        "public_key": os.environ["PUB"],
        "sni": os.environ["VSNI"],
        "short_ids": [os.environ["VSID"]]
    }
}
print(json.dumps(ib, separators=(",", ":")))
PYEOF
        ) || { print_error "Failed to serialize tunnel Reality inbound."; press_enter; return 1; }
        _tunnel_upsert_inbound "tunnel-vless-reality" "vless_reality" "$server_ip" "$vport" "$tunnel_vless_json" || {
            print_error "Failed to register tunnel Reality inbound in database."
            press_enter; return 1
        }
    fi

    # ── Install Hysteria2 ────────────────────────────────────
    if $proto_hy2; then
        echo ""
        echo -e "  ${BOLD}─── Hysteria2 ─────────────────────────────────────${NC}"
        fetch_hysteria2_version
        hy2_install_binary "$HY2_VERSION"
        ensure_packages python3 python3-pip openssl
        hy2_install_deps

        local hport
        ask hport "  Hysteria2 UDP port" "8443"

        probe_server
        local bw rtt quic up down
        bw=$(estimate_bandwidth); rtt=$(measure_rtt "8.8.8.8")
        quic=$(hy2_compute_quic_params "$bw" "$rtt")
        IFS='|' read -r is ms ic mc <<< "$quic"
        up=$(( bw * 85 / 100 )); down=$(( bw * 85 / 100 ))

        hy2_write_config "$hport" "" "$up" "$down" "$is" "$ms" "$ic" "$mc" "60s" "20s"
        hy2_save_server_info "$server_ip" "$hport" "" "True"
        hy2_write_auth_api
        hy2_write_sync_script
        hy2_create_server_service
        hy2_create_auth_service
        hy2_install_sync_cron
        open_port "$hport" both
        open_port "$HY2_AUTH_PORT" tcp
        service_start hysteria-server
        service_start hysteria-auth

        # If no VLESS, create credentials for Hysteria2 only.
        # In Both mode the VLESS credential above is shared by Hysteria2.
        if ! $proto_vless; then
            local h_uuid h_token
            h_uuid=$(generate_uuid)
            h_token=$(generate_token)
            if ! db_add_user "$h_uuid" "tunnel-default" "0" "$h_token" '{"vless":false,"hysteria2":true}'; then
                print_error "Failed to create Hysteria2 tunnel credentials in the database."
                press_enter; return 1
            fi
            handoff_uuid="$h_uuid"
            handoff_token="$h_token"
        fi

        local tunnel_hy2_json
        tunnel_hy2_json=$(HY2_PORT="$hport" HY2_IP="$server_ip" python3 - <<'PYEOF'
import json, os
print(json.dumps({"_meta": {
    "port": int(os.environ["HY2_PORT"]),
    "domain": "",
    "ip": os.environ["HY2_IP"],
    "selfcert": True,
    "hop_range": ""
}}, separators=(",", ":")))
PYEOF
        ) || { print_error "Failed to serialize tunnel Hysteria2 inbound."; press_enter; return 1; }
        _tunnel_upsert_inbound "tunnel-hysteria2" "hysteria2" "$server_ip" "$hport" "$tunnel_hy2_json" || {
            print_error "Failed to register tunnel Hysteria2 inbound in database."
            press_enter; return 1
        }
    fi

    # ── Print handoff card ───────────────────────────────────
    echo ""
    echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║  FOREIGN SERVER READY — Copy this info to Iran server    ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}${BOLD}→ Save this information — you need it in Step 2 (Iran server)${NC}"
    echo ""
    echo -e "  Foreign server IP : ${CYAN}${BOLD}${server_ip}${NC}"
    echo ""

    if $proto_vless && vless_read_server_info 2>/dev/null; then
        echo -e "  ${BOLD}── VLESS + Reality ──────────────────────────${NC}"
        echo -e "  Port      : ${CYAN}${VINFO_PORT}${NC}"
        echo -e "  UUID      : ${CYAN}${uuid}${NC}"
        echo -e "  PublicKey : ${CYAN}${VINFO_PUBKEY}${NC}"
        echo -e "  ShortID   : ${CYAN}${VINFO_SID}${NC}"
        echo -e "  SNI       : ${CYAN}${VINFO_SNI}${NC}"
        echo ""
    fi

    if $proto_hy2 && hy2_read_server_info 2>/dev/null; then
        # Use credentials captured at creation time. Fall back to the DB for
        # interrupted/legacy runs; avoid JSON shell parsing entirely.
        if [[ -z "$handoff_uuid" || -z "$handoff_token" ]]; then
            local db_creds
            db_creds=$(DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
row = conn.execute(
    "SELECT uuid, sub_token FROM users WHERE label='tunnel-default' ORDER BY id DESC LIMIT 1"
).fetchone()
if row:
    print(row[0] + "\t" + row[1])
conn.close()
PYEOF
)
            if [[ "$db_creds" == *$'\t'* ]]; then
                handoff_uuid="${db_creds%%$'\t'*}"
                handoff_token="${db_creds#*$'\t'}"
            fi
        fi

        if [[ -z "$handoff_uuid" || -z "$handoff_token" ]]; then
            print_error "Tunnel credentials could not be loaded; refusing to print an unusable handoff card."
            press_enter; return 1
        fi

        echo -e "  ${BOLD}── Hysteria2 ────────────────────────────────${NC}"
        echo -e "  Port      : ${CYAN}${HINFO_PORT}/UDP${NC}"
        echo -e "  UUID      : ${CYAN}${handoff_uuid}${NC}"
        echo -e "  Token     : ${CYAN}${handoff_token}${NC}"
        echo -e "  TLS       : ${YELLOW}self-signed (set insecure=true on client)${NC}"
        echo ""
    fi

    echo -e "  ${DIM}Now go to your IRAN server and run this script again.${NC}"
    echo -e "  ${DIM}Choose: Tunnel → I'm on the IRAN server.${NC}"
    echo ""
    press_enter
}

# ══════════════════════════════════════════════════════════════
#  Iran server — installs relay client pointing to foreign server
# ══════════════════════════════════════════════════════════════

_wizard_tunnel_iran() {
    print_banner
    print_header "Tunnel — Step 2: Iran Relay Server Setup"
    echo -e "  ${DIM}You are on the Iran-side VPS. Enter the foreign server details.${NC}\n"
    echo -e "  ${YELLOW}You need the information printed by Step 1 (foreign server).${NC}\n"

    print_header "Which protocol did you install on the foreign server?"
    echo ""
    echo -e "  ${CYAN}1)${NC}  VLESS + Reality"
    echo -e "  ${CYAN}2)${NC}  Hysteria2"
    echo -e "  ${CYAN}3)${NC}  Both"
    menu_prompt

    local relay_vless=false relay_hy2=false
    case "$MENU_CHOICE" in
        1) relay_vless=true ;;
        2) relay_hy2=true ;;
        3|"") relay_vless=true; relay_hy2=true ;;
    esac

    check_internet
    fetch_singbox_version stable

    # ── Collect foreign server details ───────────────────────
    local foreign_ip
    ask foreign_ip "  Foreign server IP" ""
    [[ -z "$foreign_ip" ]] && { print_error "Foreign server IP required."; press_enter; return; }

    # ── Build outbounds based on selected protocols ──────────
    local outbounds_json socks_port
    ask socks_port "  Local SOCKS5 port (for routing on Iran server)" "10808"

    if $relay_vless && $relay_hy2; then
        # Collect both sets of credentials
        local v_port v_uuid v_pubkey v_sid v_sni
        echo -e "\n  ${BOLD}VLESS details:${NC}"
        ask v_port   "  VLESS port"    "443"
        ask v_uuid   "  VLESS UUID"    ""
        ask v_pubkey "  PublicKey"     ""
        ask v_sid    "  Short ID"      ""
        ask v_sni    "  SNI"           "www.speedtest.net"

        local h_port h_uuid h_token
        echo -e "\n  ${BOLD}Hysteria2 details:${NC}"
        ask h_port  "  Hysteria2 UDP port" "8443"
        ask h_uuid  "  UUID"               ""
        ask h_token "  Token (password)"   ""

        outbounds_json="[
    {
      \"type\": \"vless\", \"tag\": \"vless-out\",
      \"server\": \"${foreign_ip}\", \"server_port\": ${v_port},
      \"uuid\": \"${v_uuid}\", \"flow\": \"xtls-rprx-vision\",
      \"tls\": {
        \"enabled\": true, \"server_name\": \"${v_sni}\",
        \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"},
        \"reality\": {\"enabled\": true, \"public_key\": \"${v_pubkey}\", \"short_id\": \"${v_sid}\"}
      }
    },
    {
      \"type\": \"hysteria2\", \"tag\": \"hy2-out\",
      \"server\": \"${foreign_ip}\", \"server_port\": ${h_port},
      \"password\": \"${h_uuid}:${h_token}\",
      \"tls\": {\"enabled\": true, \"insecure\": true}
    },
    {\"type\": \"direct\", \"tag\": \"direct\"}
  ]"

    elif $relay_vless; then
        local v_port v_uuid v_pubkey v_sid v_sni
        echo -e "\n  ${BOLD}VLESS details:${NC}"
        ask v_port   "  VLESS port" "443"
        ask v_uuid   "  UUID"       ""
        ask v_pubkey "  PublicKey"  ""
        ask v_sid    "  Short ID"   ""
        ask v_sni    "  SNI"        "www.speedtest.net"

        outbounds_json="[
    {
      \"type\": \"vless\", \"tag\": \"vless-out\",
      \"server\": \"${foreign_ip}\", \"server_port\": ${v_port},
      \"uuid\": \"${v_uuid}\", \"flow\": \"xtls-rprx-vision\",
      \"tls\": {
        \"enabled\": true, \"server_name\": \"${v_sni}\",
        \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"},
        \"reality\": {\"enabled\": true, \"public_key\": \"${v_pubkey}\", \"short_id\": \"${v_sid}\"}
      }
    },
    {\"type\": \"direct\", \"tag\": \"direct\"}
  ]"

    else  # Hysteria2 only
        local h_port h_uuid h_token
        ask h_port  "  Hysteria2 UDP port" "8443"
        ask h_uuid  "  UUID"               ""
        ask h_token "  Token"              ""

        outbounds_json="[
    {
      \"type\": \"hysteria2\", \"tag\": \"hy2-out\",
      \"server\": \"${foreign_ip}\", \"server_port\": ${h_port},
      \"password\": \"${h_uuid}:${h_token}\",
      \"tls\": {\"enabled\": true, \"insecure\": true}
    },
    {\"type\": \"direct\", \"tag\": \"direct\"}
  ]"
    fi

    # ── Determine final tag for routing ──────────────────────
    local final_tag
    $relay_vless && final_tag="vless-out" || final_tag="hy2-out"

    # ── Install binary and write client config ───────────────
    print_step 1 2 "Installing sing-box binary"
    vless_install_binary "$SINGBOX_VERSION" || { press_enter; return; }

    print_step 2 2 "Writing relay client configuration"
    vless_write_config "{
  \"log\": { \"level\": \"warn\" },
  \"inbounds\": [{
    \"type\": \"socks\", \"tag\": \"socks-in\",
    \"listen\": \"0.0.0.0\", \"listen_port\": ${socks_port}
  }],
  \"outbounds\": ${outbounds_json},
  \"route\": {\"final\": \"${final_tag}\"}
}"

    vless_create_service client
    service_start sing-box-client || { press_enter; return; }

    # ── Test connectivity ────────────────────────────────────
    print_info "Testing tunnel (20s timeout)..."
    sleep 3
    local exit_ip
    exit_ip=$(curl -sf --connect-timeout 20 \
              --socks5 "127.0.0.1:${socks_port}" https://ifconfig.me 2>/dev/null | tr -d '[:space:]')
    [[ "$exit_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$exit_ip" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*$ ]] || exit_ip=""

    echo ""
    if [[ -n "$exit_ip" ]]; then
        print_success "Tunnel is working! Exit IP: ${exit_ip}"
    else
        print_warn "Connection test failed. Check logs with:"
        echo -e "  ${DIM}journalctl -u sing-box-client -n 50${NC}"
    fi

    echo ""
    echo -e "  ${GREEN}${BOLD}Iran relay configured.${NC}"
    echo -e "  Local SOCKS5 : ${CYAN}127.0.0.1:${socks_port}${NC}"
    echo -e "  Foreign IP   : ${CYAN}${foreign_ip}${NC}"
    echo ""
    echo -e "  ${DIM}Point your clients to the IRAN server.${NC}"
    echo -e "  ${DIM}Go to the FOREIGN server's manager to add/manage users.${NC}"
    echo ""
    press_enter
}
