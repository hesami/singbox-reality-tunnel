#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  features/inbounds.sh — Inbound Management
#
#  Each inbound is stored in the DB. On every add/edit/delete,
#  rebuild_singbox_config() regenerates /etc/sing-box/config.json
#  from all active inbounds and reloads the single sing-box service.
#
#  Depends on: core/common.sh  core/system.sh  core/db.sh
#              features/ssl.sh
# ═══════════════════════════════════════════════════════════════

SINGBOX_CONFIG="/etc/sing-box/config.json"
SINGBOX_LOG="/var/log/singbox-manager/sing-box.log"

# ── DB helpers ─────────────────────────────────────────────────

inbound_db_init() {
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.execute("""
CREATE TABLE IF NOT EXISTS inbounds (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tag         TEXT    NOT NULL UNIQUE,
    protocol    TEXT    NOT NULL,
    domain      TEXT    DEFAULT '',
    port        INTEGER NOT NULL,
    enabled     INTEGER DEFAULT 1,
    config_json TEXT    NOT NULL DEFAULT '{}',
    created_at  TEXT    DEFAULT (datetime('now'))
)
""")
conn.commit()
conn.close()
print("OK")
PYEOF
}

inbound_db_add() {
    # <tag> <protocol> <domain> <port> <config_json>
    local tag="$1" proto="$2" domain="$3" port="$4"
    local cfg="$5"
    TAG="$tag" PROTO="$proto" DOMAIN="$domain" PORT="$port" CFG="$cfg" \
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os, sys
conn = sqlite3.connect(os.environ["DB_PATH"])
try:
    conn.execute(
        "INSERT INTO inbounds (tag,protocol,domain,port,config_json) VALUES (?,?,?,?,?)",
        (os.environ["TAG"], os.environ["PROTO"],
         os.environ["DOMAIN"], int(os.environ["PORT"]),
         os.environ["CFG"])
    )
    conn.commit(); print("OK")
except sqlite3.IntegrityError as e:
    print(f"ERROR:{e}"); sys.exit(1)
finally:
    conn.close()
PYEOF
}

inbound_db_update() {
    # <tag> <field> <value>
    local tag="$1" field="$2" value="$3"
    case "$field" in
        domain|port|enabled|config_json|tag) ;;
        *) print_error "Invalid field: $field"; return 1 ;;
    esac
    TAG="$tag" FIELD="$field" VALUE="$value" DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
field = os.environ["FIELD"]
conn.execute(f"UPDATE inbounds SET {field}=? WHERE tag=?",
             (os.environ["VALUE"], os.environ["TAG"]))
conn.commit(); conn.close(); print("OK")
PYEOF
}

inbound_db_delete() {
    TAG="$1" DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.execute("DELETE FROM inbounds WHERE tag=?", (os.environ["TAG"],))
conn.commit(); conn.close()
PYEOF
}

inbound_db_list() {
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT * FROM inbounds ORDER BY created_at").fetchall()
print(json.dumps([dict(r) for r in rows]))
conn.close()
PYEOF
}

inbound_db_get() {
    TAG="$1" DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT * FROM inbounds WHERE tag=?", (os.environ["TAG"],)).fetchone()
if row: print(json.dumps(dict(row)))
conn.close()
PYEOF
}

# ── Config rebuild ─────────────────────────────────────────────

rebuild_singbox_config() {
    mkdir -p /etc/sing-box "$(dirname "$SINGBOX_LOG")"

    DB_PATH="$DB_PATH" SINGBOX_CONFIG="$SINGBOX_CONFIG" \
    SINGBOX_LOG="$SINGBOX_LOG" python3 - <<'PYEOF'
import sqlite3, json, os

db_path    = os.environ["DB_PATH"]
cfg_path   = os.environ["SINGBOX_CONFIG"]
log_path   = os.environ["SINGBOX_LOG"]

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
rows = conn.execute(
    "SELECT * FROM inbounds WHERE enabled=1 ORDER BY created_at"
).fetchall()
conn.close()

inbounds = []
for row in rows:
    try:
        ib = json.loads(row["config_json"])
        inbounds.append(ib)
    except Exception as e:
        print(f"WARN: skipping inbound {row['tag']}: {e}")

config = {
    "log": {"level": "warn", "output": log_path},
    "inbounds": inbounds,
    "outbounds": [{"type": "direct", "tag": "direct"}]
}

tmp = cfg_path + ".tmp"
with open(tmp, "w") as f:
    json.dump(config, f, indent=2)
os.replace(tmp, cfg_path)
print(f"OK: {len(inbounds)} inbound(s) written")
PYEOF

    local result=$?
    if [[ $result -eq 0 ]]; then
        # Validate before reloading
        if sing-box check -c "$SINGBOX_CONFIG" &>/dev/null; then
            systemctl is-active --quiet sing-box 2>/dev/null \
                && systemctl reload-or-restart sing-box \
                || systemctl start sing-box 2>/dev/null || true
            print_success "Config rebuilt and service reloaded."
        else
            print_error "Config validation failed. Service NOT reloaded."
            sing-box check -c "$SINGBOX_CONFIG" 2>&1 | sed 's/^/  /'
            return 1
        fi
    fi
}

# ── Unique tag generator ───────────────────────────────────────

_inbound_gen_tag() {
    local proto="$1" idx
    idx=$(DB_PATH="$DB_PATH" python3 -c "
import sqlite3, os
conn = sqlite3.connect(os.environ['DB_PATH'])
n = conn.execute(\"SELECT COUNT(*) FROM inbounds WHERE protocol=?\", ('${proto}',)).fetchone()[0]
conn.close(); print(n+1)
" 2>/dev/null || echo "1")
    echo "${proto}-${idx}"
}

# ── Per-protocol inbound builders ─────────────────────────────

# Returns inbound JSON + saves to DB
# Each function: interactive, calls inbound_db_add, calls rebuild

_inbound_add_vless_reality() {
    print_header "Add Inbound — VLESS + Reality"
    echo -e "  ${DIM}Direct proxy. Uses real TLS camouflage. No CDN.${NC}\n"

    [[ ! -f "$SINGBOX_BIN" ]] && {
        print_error "sing-box not installed. Run Install first."
        press_enter; return 1
    }

    local port sni sid domain uuid tag
    local def_sid; def_sid=$(openssl rand -hex 4 2>/dev/null || echo "abc12345")

    ask port "  Listen port"            "443"
    ask sni  "  Camouflage SNI"         "dl.google.com"
    ask sid  "  Short ID (hex, or press Enter to generate 4 random)" ""

    # Generate multiple short_ids if user left blank
    local short_ids_json
    if [[ -z "$sid" ]]; then
        short_ids_json=$(python3 -c "
import subprocess, json
ids = []
for _ in range(4):
    r = subprocess.run(['openssl','rand','-hex','4'], capture_output=True, text=True)
    ids.append(r.stdout.strip())
print(json.dumps(ids))
" 2>/dev/null || echo '["abc1","def2","ghi3","jkl4"]')
        print_info "Generated 4 short_ids: ${short_ids_json}"
    else
        short_ids_json=$(python3 -c "import json; print(json.dumps(['${sid}']))")
    fi

    # Domain for config link (optional — uses IP if blank)
    ssl_load_domain 2>/dev/null || true
    ask domain "  Domain for client links (blank = use IP)" "${DOMAIN:-}"
    local host="${domain:-$(get_public_ip)}"

    # Keypair
    print_info "Generating REALITY keypair..."
    local kp priv pub
    kp=$(generate_keypair) || { press_enter; return 1; }
    priv=$(echo "$kp" | awk '/PrivateKey/{print $2}')
    pub=$(echo  "$kp" | awk '/PublicKey/{print $2}')

    uuid=$(generate_uuid)
    tag=$(_inbound_gen_tag "vless_reality")

    local config_json
    config_json=$(python3 - <<PYEOF
import json
ib = {
    "type": "vless", "tag": "${tag}",
    "listen": "0.0.0.0", "listen_port": int("${port}"),
    "tcp_keep_alive": "10s", "sniff": False,
    "users": [{"uuid": "${uuid}", "flow": "xtls-rprx-vision"}],
    "multiplex": {"enabled": True, "padding": True},
    "tls": {
        "enabled": True, "server_name": "${sni}",
        "reality": {
            "enabled": True,
            "handshake": {"server": "${sni}", "server_port": 443},
            "private_key": "${priv}",
            "short_id": ${short_ids_json}
        }
    }
}
print(json.dumps(ib))
PYEOF
)

    local meta_json
    meta_json=$(python3 -c "
import json
print(json.dumps({'public_key':'${pub}','sni':'${sni}','host':'${host}','uuid':'${uuid}','short_ids':${short_ids_json},'port':int('${port}')}))
")

    # Save: config_json is the full inbound block; meta is for building client links
    local full_json
    full_json=$(python3 -c "
import json
c = json.loads('''${config_json}''')
c['_meta'] = json.loads('''${meta_json}''')
print(json.dumps(c))
")

    inbound_db_add "$tag" "vless_reality" "$host" "$port" "$full_json" || {
        press_enter; return 1
    }

    # Register first user in users table
    local sub_token; sub_token=$(generate_token)
    db_add_user "$uuid" "default" "0" "$sub_token" '{"vless":true}' 2>/dev/null || true
    db_enable_engine "$uuid" "vless" 2>/dev/null || true

    open_port "$port" tcp
    rebuild_singbox_config

    # Show link
    local link
    link="vless://${uuid}@${host}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pub}&sid=$(echo "$short_ids_json" | python3 -c "import json,sys; ids=json.load(sys.stdin); print(ids[0])")&type=tcp#${tag}"

    echo ""
    echo -e "  ${GREEN}${BOLD}Inbound created: ${tag}${NC}"
    echo -e "  Host : ${CYAN}${host}:${port}${NC}  SNI: ${CYAN}${sni}${NC}"
    echo -e "  ${BOLD}VLESS link:${NC}\n  ${MAGENTA}${link}${NC}"
    print_qr "$link" "$tag"
    press_enter
}

_inbound_add_vless_ws() {
    print_header "Add Inbound — VLESS + WebSocket + TLS"
    echo -e "  ${DIM}CDN-compatible. Use a domain with CDN proxy ON.${NC}\n"

    [[ ! -f "$SINGBOX_BIN" ]] && { print_error "sing-box not installed."; press_enter; return 1; }

    local port path domain uuid tag
    ask domain "  Domain (CDN proxy ON in ArvanCloud/Cloudflare)" ""
    [[ -z "$domain" ]] && { print_error "Domain required."; press_enter; return 1; }
    ask port   "  Listen port"   "443"
    ask path   "  WebSocket path" "/$(openssl rand -hex 4 2>/dev/null || echo 'ws')"
    uuid=$(generate_uuid)
    tag=$(_inbound_gen_tag "vless_ws")

    # SSL
    ssl_cert_exists "$domain" || { ssl_install_acme && ssl_issue "$domain" || print_warn "SSL failed — using ACME auto-cert."; }

    ssl_load_domain 2>/dev/null || true
    local cert_file="${SSL_CERT_DIR}/${domain}/fullchain.pem"
    local key_file="${SSL_CERT_DIR}/${domain}/key.pem"
    local tls_block
    if [[ -f "$cert_file" ]]; then
        tls_block="{\"enabled\":true,\"server_name\":\"${domain}\",\"certificate_path\":\"${cert_file}\",\"key_path\":\"${key_file}\"}"
    else
        tls_block="{\"enabled\":true,\"server_name\":\"${domain}\",\"acme\":{\"domain\":\"${domain}\",\"email\":\"acme@${domain}\"}}"
    fi

    local config_json
    config_json=$(python3 - <<PYEOF
import json
tls = json.loads("""${tls_block}""")
ib = {
    "type": "vless", "tag": "${tag}",
    "listen": "0.0.0.0", "listen_port": int("${port}"),
    "tcp_keep_alive": "10s", "sniff": False,
    "users": [{"uuid": "${uuid}"}],
    "transport": {"type": "ws", "path": "${path}", "headers": {"Host": "${domain}"}},
    "tls": tls,
    "_meta": {"domain": "${domain}", "port": int("${port}"), "path": "${path}", "uuid": "${uuid}"}
}
print(json.dumps(ib))
PYEOF
)

    inbound_db_add "$tag" "vless_ws" "$domain" "$port" "$config_json" || { press_enter; return 1; }

    local enc_path; enc_path=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${path}'))")
    local enc_tag;  enc_tag=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${tag}'))")
    local link="vless://${uuid}@${domain}:${port}?encryption=none&security=tls&sni=${domain}&fp=chrome&type=ws&path=${enc_path}&host=${domain}#${enc_tag}"

    open_port "$port" tcp
    rebuild_singbox_config

    echo ""
    echo -e "  ${GREEN}${BOLD}Inbound created: ${tag}${NC}"
    echo -e "  ${BOLD}WS link:${NC}\n  ${MAGENTA}${link}${NC}"
    print_qr "$link" "$tag"
    press_enter
}

_inbound_add_vless_grpc() {
    print_header "Add Inbound — VLESS + gRPC + TLS"
    echo -e "  ${DIM}CDN-compatible. Use a domain with CDN proxy ON.${NC}\n"

    [[ ! -f "$SINGBOX_BIN" ]] && { print_error "sing-box not installed."; press_enter; return 1; }

    local port svc domain uuid tag
    ask domain "  Domain (CDN proxy ON)" ""
    [[ -z "$domain" ]] && { print_error "Domain required."; press_enter; return 1; }
    ask port "  Listen port"  "443"
    svc=$(openssl rand -hex 8 2>/dev/null || cat /dev/urandom | tr -dc 'a-z0-9' | head -c 16)
    ask svc  "  gRPC service name" "$svc"
    uuid=$(generate_uuid)
    tag=$(_inbound_gen_tag "vless_grpc")

    ssl_cert_exists "$domain" || { ssl_install_acme && ssl_issue "$domain" || print_warn "SSL failed."; }
    local cert_file="${SSL_CERT_DIR}/${domain}/fullchain.pem"
    local key_file="${SSL_CERT_DIR}/${domain}/key.pem"
    local tls_block
    if [[ -f "$cert_file" ]]; then
        tls_block="{\"enabled\":true,\"server_name\":\"${domain}\",\"certificate_path\":\"${cert_file}\",\"key_path\":\"${key_file}\"}"
    else
        tls_block="{\"enabled\":true,\"server_name\":\"${domain}\",\"acme\":{\"domain\":\"${domain}\",\"email\":\"acme@${domain}\"}}"
    fi

    local config_json
    config_json=$(python3 - <<PYEOF
import json
tls = json.loads("""${tls_block}""")
ib = {
    "type": "vless", "tag": "${tag}",
    "listen": "0.0.0.0", "listen_port": int("${port}"),
    "tcp_keep_alive": "10s", "sniff": False,
    "users": [{"uuid": "${uuid}"}],
    "transport": {
        "type": "grpc", "service_name": "${svc}",
        "idle_timeout": "15s", "ping_timeout": "15s",
        "permit_without_stream": True
    },
    "tls": tls,
    "_meta": {"domain": "${domain}", "port": int("${port}"), "service_name": "${svc}", "uuid": "${uuid}"}
}
print(json.dumps(ib))
PYEOF
)

    inbound_db_add "$tag" "vless_grpc" "$domain" "$port" "$config_json" || { press_enter; return 1; }

    local enc_svc; enc_svc=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${svc}'))")
    local enc_tag; enc_tag=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${tag}'))")
    local link="vless://${uuid}@${domain}:${port}?encryption=none&security=tls&sni=${domain}&fp=chrome&type=grpc&serviceName=${enc_svc}#${enc_tag}"

    open_port "$port" tcp
    rebuild_singbox_config

    echo ""
    echo -e "  ${GREEN}${BOLD}Inbound created: ${tag}${NC}"
    echo -e "  ${BOLD}gRPC link:${NC}\n  ${MAGENTA}${link}${NC}"
    print_qr "$link" "$tag"
    press_enter
}

_inbound_add_hysteria2() {
    print_header "Add Inbound — Hysteria2"
    echo -e "  ${DIM}QUIC/UDP. Direct connection (no CDN).${NC}\n"

    [[ ! -f "$HY2_BIN" ]] && { print_error "Hysteria2 not installed."; press_enter; return 1; }

    local port domain hop_range tag
    ask port   "  UDP port"    "8443"
    ask domain "  Domain (blank = self-signed)" ""
    tag=$(_inbound_gen_tag "hysteria2")

    # Port hopping
    local hop_range=""
    if confirm "Enable port hopping?" "y"; then
        local h_start h_end
        ask h_start "  Hop range start" "20000"
        ask h_end   "  Hop range end"   "30000"
        hop_range="${h_start}-${h_end}"
    fi

    # Compute QUIC params
    probe_server &>/dev/null || true
    local bw rtt quic
    bw=$(estimate_bandwidth); rtt=$(measure_rtt "8.8.8.8")
    quic=$(hy2_compute_quic_params "$bw" "$rtt")
    IFS='|' read -r is ms ic mc <<< "$quic"
    local up=$(( bw * 85 / 100 )) down=$(( bw * 85 / 100 ))

    local selfcert="True"
    [[ -n "$domain" ]] && selfcert="False"

    local meta_json
    meta_json=$(python3 -c "
import json
print(json.dumps({'port':'${port}','domain':'${domain}','selfcert':${selfcert},'hop_range':'${hop_range}'}))
")

    # Store meta for auth_api to build hy2 links
    inbound_db_add "$tag" "hysteria2" "${domain:-$(get_public_ip)}" "$port" "$meta_json" || {
        press_enter; return 1
    }

    # Write hysteria2 config file (different format — YAML)
    hy2_write_config "$port" "$domain" "$up" "$down" "$is" "$ms" "$ic" "$mc" "60s" "20s" "$hop_range"
    local server_ip; server_ip=$(get_public_ip)
    hy2_save_server_info "$server_ip" "$port" "$domain" "$selfcert"

    open_port "$port" both
    [[ -n "$hop_range" ]] && {
        local h_s="${hop_range%-*}" h_e="${hop_range#*-}"
        open_port "${h_s}:${h_e}" udp 2>/dev/null || true
    }

    systemctl is-active --quiet hysteria-server 2>/dev/null \
        && systemctl restart hysteria-server \
        || systemctl start hysteria-server 2>/dev/null || true
    systemctl restart hysteria-auth 2>/dev/null || true

    echo ""
    print_success "Hysteria2 inbound created: ${tag}"
    [[ -n "$hop_range" ]] && print_warn "Remember: open UDP ${hop_range} in VPS provider firewall!"
    press_enter
}

# ── Edit inbound ───────────────────────────────────────────────

inbound_edit() {
    inbound_list_table
    echo ""
    echo -ne "  ${YELLOW}Tag to edit (exact tag name): ${NC}"
    local tag; read -r tag
    [[ -z "$tag" ]] && return

    local json; json=$(inbound_db_get "$tag")
    [[ -z "$json" ]] && { print_error "Inbound not found."; press_enter; return; }

    local proto; proto=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['protocol'])" 2>/dev/null)

    print_banner
    print_header "Edit Inbound — ${tag}  (${proto})"
    echo -e "  ${DIM}Leave blank to keep current value.${NC}\n"

    local cfg_json; cfg_json=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['config_json'])" 2>/dev/null)

    case "$proto" in
        vless_reality) _inbound_edit_reality "$tag" "$cfg_json" ;;
        vless_ws)      _inbound_edit_ws      "$tag" "$cfg_json" ;;
        vless_grpc)    _inbound_edit_grpc    "$tag" "$cfg_json" ;;
        hysteria2)     _inbound_edit_hy2     "$tag" "$cfg_json" ;;
        *) print_error "Unknown protocol: $proto" ;;
    esac
}

_inbound_edit_reality() {
    local tag="$1" cfg="$2"

    local cur_port cur_sni cur_pub
    cur_port=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('listen_port',''))" 2>/dev/null)
    cur_sni=$(echo "$cfg"  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('tls',{}).get('server_name',''))" 2>/dev/null)

    local new_port new_sni regen_keys
    ask new_port "  Port"              "$cur_port"
    ask new_sni  "  Camouflage SNI"    "$cur_sni"

    confirm "Regenerate keypair + short_ids?" "n" && regen_keys=true || regen_keys=false

    NEW_PORT="$new_port" NEW_SNI="$new_sni" REGEN="$regen_keys" \
    CFG_JSON="$cfg" SINGBOX_BIN="$SINGBOX_BIN" python3 - <<'PYEOF'
import json, subprocess, os

cfg     = json.loads(os.environ["CFG_JSON"])
port    = os.environ["NEW_PORT"] or str(cfg.get("listen_port"))
sni     = os.environ["NEW_SNI"]  or cfg["tls"]["server_name"]
regen   = os.environ["REGEN"] == "true"

cfg["listen_port"] = int(port)
cfg["tls"]["server_name"] = sni
cfg["tls"]["reality"]["handshake"]["server"] = sni

if regen:
    kp = subprocess.run([os.environ["SINGBOX_BIN"],"generate","reality-keypair"],
                        capture_output=True, text=True).stdout
    priv = next(l.split()[1] for l in kp.splitlines() if "PrivateKey" in l)
    pub  = next(l.split()[1] for l in kp.splitlines() if "PublicKey"  in l)
    cfg["tls"]["reality"]["private_key"] = priv

    import secrets
    ids = [secrets.token_hex(4) for _ in range(4)]
    cfg["tls"]["reality"]["short_id"] = ids

    if "_meta" in cfg:
        cfg["_meta"]["public_key"] = pub if regen else cfg["_meta"].get("public_key","")
        cfg["_meta"]["sni"] = sni
        cfg["_meta"]["port"] = int(port)

print(json.dumps(cfg))
PYEOF
    local new_cfg
    new_cfg=$(NEW_PORT="$new_port" NEW_SNI="$new_sni" REGEN="$regen_keys" \
              CFG_JSON="$cfg" SINGBOX_BIN="$SINGBOX_BIN" python3 - <<'PYEOF'
import json, subprocess, os
cfg  = json.loads(os.environ["CFG_JSON"])
port = os.environ["NEW_PORT"] or str(cfg.get("listen_port"))
sni  = os.environ["NEW_SNI"]  or cfg["tls"]["server_name"]
regen = os.environ["REGEN"] == "true"
cfg["listen_port"] = int(port)
cfg["tls"]["server_name"] = sni
cfg["tls"]["reality"]["handshake"]["server"] = sni
if regen:
    kp = subprocess.run([os.environ["SINGBOX_BIN"],"generate","reality-keypair"],
                        capture_output=True, text=True).stdout
    priv = next(l.split()[1] for l in kp.splitlines() if "PrivateKey" in l)
    pub  = next(l.split()[1] for l in kp.splitlines() if "PublicKey"  in l)
    cfg["tls"]["reality"]["private_key"] = priv
    import secrets
    cfg["tls"]["reality"]["short_id"] = [secrets.token_hex(4) for _ in range(4)]
    if "_meta" in cfg:
        cfg["_meta"].update({"public_key": pub, "sni": sni, "port": int(port)})
else:
    if "_meta" in cfg:
        cfg["_meta"].update({"sni": sni, "port": int(port)})
print(json.dumps(cfg))
PYEOF
)
    inbound_db_update "$tag" "port"        "$new_port"
    inbound_db_update "$tag" "config_json" "$new_cfg"
    rebuild_singbox_config
    print_success "Inbound '${tag}' updated."
    press_enter
}

_inbound_edit_ws() {
    local tag="$1" cfg="$2"
    local cur_port cur_path
    cur_port=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('listen_port',''))" 2>/dev/null)
    cur_path=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('transport',{}).get('path',''))" 2>/dev/null)

    local new_port new_path
    ask new_port "  Port" "$cur_port"
    ask new_path "  Path" "$cur_path"

    local new_cfg
    new_cfg=$(NEW_PORT="$new_port" NEW_PATH="$new_path" CFG_JSON="$cfg" python3 - <<'PYEOF'
import json, os
cfg = json.loads(os.environ["CFG_JSON"])
port = os.environ["NEW_PORT"] or str(cfg.get("listen_port"))
path = os.environ["NEW_PATH"] or cfg["transport"]["path"]
cfg["listen_port"] = int(port)
cfg["transport"]["path"] = path
if "_meta" in cfg: cfg["_meta"].update({"port": int(port), "path": path})
print(json.dumps(cfg))
PYEOF
)
    inbound_db_update "$tag" "port"        "$new_port"
    inbound_db_update "$tag" "config_json" "$new_cfg"
    rebuild_singbox_config
    print_success "Inbound '${tag}' updated."
    press_enter
}

_inbound_edit_grpc() {
    local tag="$1" cfg="$2"
    local cur_port cur_svc
    cur_port=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('listen_port',''))" 2>/dev/null)
    cur_svc=$(echo  "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('transport',{}).get('service_name',''))" 2>/dev/null)

    local new_port new_svc
    ask new_port "  Port"         "$cur_port"
    ask new_svc  "  Service name" "$cur_svc"

    local new_cfg
    new_cfg=$(NEW_PORT="$new_port" NEW_SVC="$new_svc" CFG_JSON="$cfg" python3 - <<'PYEOF'
import json, os
cfg = json.loads(os.environ["CFG_JSON"])
port = os.environ["NEW_PORT"] or str(cfg.get("listen_port"))
svc  = os.environ["NEW_SVC"]  or cfg["transport"]["service_name"]
cfg["listen_port"] = int(port)
cfg["transport"]["service_name"] = svc
if "_meta" in cfg: cfg["_meta"].update({"port": int(port), "service_name": svc})
print(json.dumps(cfg))
PYEOF
)
    inbound_db_update "$tag" "port"        "$new_port"
    inbound_db_update "$tag" "config_json" "$new_cfg"
    rebuild_singbox_config
    print_success "Inbound '${tag}' updated."
    press_enter
}

_inbound_edit_hy2() {
    local tag="$1" cfg="$2"
    local cur_port cur_hop
    cur_port=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('port',''))" 2>/dev/null)
    cur_hop=$(echo  "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('hop_range',''))" 2>/dev/null)

    local new_port new_hop
    ask new_port "  Port"        "$cur_port"
    ask new_hop  "  Hop range"   "$cur_hop"

    local new_cfg
    new_cfg=$(NEW_PORT="$new_port" NEW_HOP="$new_hop" CFG_JSON="$cfg" python3 - <<'PYEOF'
import json, os
cfg = json.loads(os.environ["CFG_JSON"])
cfg["port"]      = os.environ["NEW_PORT"] or cfg.get("port","")
cfg["hop_range"] = os.environ["NEW_HOP"]  or cfg.get("hop_range","")
print(json.dumps(cfg))
PYEOF
)
    inbound_db_update "$tag" "port"        "$new_port"
    inbound_db_update "$tag" "config_json" "$new_cfg"

    # Rewrite hysteria2 yaml
    local domain; domain=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('domain',''))" 2>/dev/null)
    local selfcert; selfcert=$(echo "$cfg" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('selfcert','True'))" 2>/dev/null)
    probe_server &>/dev/null || true
    local bw rtt quic up down
    bw=$(estimate_bandwidth); rtt=$(measure_rtt "8.8.8.8")
    quic=$(hy2_compute_quic_params "$bw" "$rtt")
    IFS='|' read -r is ms ic mc <<< "$quic"
    up=$(( bw * 85 / 100 )); down=$(( bw * 85 / 100 ))
    hy2_write_config "${new_port:-$cur_port}" "$domain" "$up" "$down" "$is" "$ms" "$ic" "$mc" "60s" "20s" "${new_hop:-$cur_hop}"
    systemctl restart hysteria-server 2>/dev/null || true

    print_success "Hysteria2 inbound '${tag}' updated."
    press_enter
}

# ── List inbounds ──────────────────────────────────────────────

inbound_list_table() {
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os

CYAN="\033[0;36m"; GREEN="\033[0;32m"; RED="\033[0;31m"
DIM="\033[2m"; BOLD="\033[1m"; NC="\033[0m"

conn = sqlite3.connect(os.environ["DB_PATH"])
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT * FROM inbounds ORDER BY created_at").fetchall()
conn.close()

header = f"  {'Tag':<25} {'Protocol':<15} {'Domain/IP':<22} {'Port':<7} {'Status'}"
print(f"\n{BOLD}{header}{NC}")
print("  " + "─" * 76)

for r in rows:
    status = f"{GREEN}ON{NC}" if r['enabled'] else f"{RED}OFF{NC}"
    print(f"  {CYAN}{r['tag']:<25}{NC} {DIM}{r['protocol']:<15}{NC} "
          f"{r['domain']:<22} {r['port']:<7} {status}")
print("")
PYEOF
}

# ── Toggle enable/disable ──────────────────────────────────────

inbound_toggle() {
    inbound_list_table
    echo -ne "  ${YELLOW}Tag to toggle: ${NC}"
    local tag; read -r tag
    [[ -z "$tag" ]] && return

    local json; json=$(inbound_db_get "$tag")
    [[ -z "$json" ]] && { print_error "Not found."; press_enter; return; }

    local cur; cur=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['enabled'])")
    local new_val; [[ "$cur" == "1" ]] && new_val=0 || new_val=1
    inbound_db_update "$tag" "enabled" "$new_val"

    local proto; proto=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['protocol'])")
    if [[ "$proto" == "hysteria2" ]]; then
        systemctl restart hysteria-server 2>/dev/null || true
    else
        rebuild_singbox_config
    fi
    [[ "$new_val" -eq 1 ]] && print_success "Enabled." || print_success "Disabled."
    press_enter
}

# ── Delete inbound ─────────────────────────────────────────────

inbound_delete() {
    inbound_list_table
    echo -ne "  ${YELLOW}Tag to delete: ${NC}"
    local tag; read -r tag
    [[ -z "$tag" ]] && return

    confirm "Delete inbound '${tag}'?" "n" || return

    local json; json=$(inbound_db_get "$tag")
    local proto; proto=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['protocol'])" 2>/dev/null)

    inbound_db_delete "$tag"

    if [[ "$proto" == "hysteria2" ]]; then
        systemctl restart hysteria-server 2>/dev/null || true
    else
        rebuild_singbox_config
    fi
    print_success "Inbound '${tag}' deleted."
    press_enter
}

# ── Main menu ──────────────────────────────────────────────────

inbounds_menu() {
    while true; do
        print_banner
        print_header "Inbound Management"
        inbound_list_table

        echo -e "  ${CYAN}1)${NC}  Add inbound"
        echo -e "  ${CYAN}2)${NC}  Edit inbound       ${DIM}(change port, SNI, path...)${NC}"
        echo -e "  ${CYAN}3)${NC}  Enable / Disable"
        echo -e "  ${CYAN}4)${NC}  Delete inbound"
        echo -e "  ${CYAN}5)${NC}  Rebuild & reload   ${DIM}(force config regeneration)${NC}"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt

        case "$MENU_CHOICE" in
            1) _inbound_add_menu ;;
            2) inbound_edit ;;
            3) inbound_toggle ;;
            4) inbound_delete ;;
            5) rebuild_singbox_config; press_enter ;;
            0) return ;;
            *) print_warn "Invalid."; sleep 1 ;;
        esac
    done
}

_inbound_add_menu() {
    print_banner
    print_header "Add Inbound — Choose Protocol"
    echo ""
    echo -e "  ${CYAN}1)${NC}  VLESS + Reality      ${DIM}(direct, no CDN)${NC}"
    echo -e "  ${CYAN}2)${NC}  VLESS + WS + TLS     ${DIM}(CDN proxy ON)${NC}"
    echo -e "  ${CYAN}3)${NC}  VLESS + gRPC + TLS   ${DIM}(CDN proxy ON)${NC}"
    echo -e "  ${CYAN}4)${NC}  Hysteria2            ${DIM}(QUIC/UDP, direct)${NC}"
    echo -e "  ${CYAN}0)${NC}  Back"
    menu_prompt
    case "$MENU_CHOICE" in
        1) _inbound_add_vless_reality ;;
        2) _inbound_add_vless_ws ;;
        3) _inbound_add_vless_grpc ;;
        4) _inbound_add_hysteria2 ;;
        0) return ;;
    esac
}
