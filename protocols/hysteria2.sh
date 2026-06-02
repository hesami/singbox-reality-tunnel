#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  protocols/hysteria2.sh — Hysteria2 (QUIC/UDP)
#
#  Depends on: core/common.sh  core/system.sh  core/db.sh
#  Global vars consumed: SRV_*, HY2_VERSION
#  Global vars exported: HY2_BIN, HY2_CONFIG, HY2_INFO
# ═══════════════════════════════════════════════════════════════

# ── Paths ──────────────────────────────────────────────────────
HY2_BIN="/usr/local/bin/hysteria"
HY2_CONFIG="/etc/hysteria/config.yaml"
HY2_INFO="/etc/hysteria/server.json"
HY2_AUTH_API="/etc/hysteria/auth_api.py"
HY2_SYNC_SCRIPT="/etc/hysteria/sync_traffic.py"
HY2_AUTH_PORT="18989"    # Flask auth+subscription server
HY2_STATS_PORT="18990"   # Hysteria2 built-in traffic stats API

# ── Dependency check ───────────────────────────────────────────

hy2_install_deps() {
    print_info "Checking Python dependencies (Flask)..."
    python3 -c "import flask" &>/dev/null && { print_success "Flask already installed."; return 0; }

    print_info "Installing Flask..."
    apt-get update -qq &>/dev/null
    apt-get install -y python3-flask &>/dev/null && \
        python3 -c "import flask" &>/dev/null && { print_success "Flask installed via apt."; return 0; }

    pip3 install flask --break-system-packages -q &>/dev/null && \
        python3 -c "import flask" &>/dev/null && { print_success "Flask installed via pip3."; return 0; }

    python3 -m pip install flask --break-system-packages -q &>/dev/null && \
        python3 -c "import flask" &>/dev/null && { print_success "Flask installed via python3 -m pip."; return 0; }

    print_error "Could not install Flask. Run manually: apt-get install python3-flask"
    return 1
}

# ── Binary install ─────────────────────────────────────────────

hy2_install_binary() {
    local version="$1"
    local arch tmp_dir
    arch=$(get_arch)
    tmp_dir=$(mktemp -d)

    print_info "Downloading Hysteria2 v${version} (${arch})..."
    local url="https://github.com/apernet/hysteria/releases/download/app%2Fv${version}/hysteria-linux-${arch}"

    if ! curl -L --progress-bar -o "${tmp_dir}/hysteria" "$url"; then
        print_error "Download failed. Check internet or version."
        rm -rf "$tmp_dir"; return 1
    fi

    install -m 755 "${tmp_dir}/hysteria" "$HY2_BIN"
    rm -rf "$tmp_dir"
    mkdir -p /etc/hysteria
    print_success "Hysteria2 v${version} installed."
}

# ── systemd service ────────────────────────────────────────────

hy2_create_server_service() {
    cat > /etc/systemd/system/hysteria-server.service << 'EOF'
[Unit]
Description=Hysteria2 Server
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-server &>/dev/null
    print_success "hysteria-server service created."
}

hy2_create_auth_service() {
    cat > /etc/systemd/system/hysteria-auth.service << EOF
[Unit]
Description=Hysteria2 Auth + Subscription API
After=network.target network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${HY2_AUTH_API}
Restart=on-failure
RestartSec=3
StandardOutput=null
StandardError=journal
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria-auth &>/dev/null
    print_success "hysteria-auth service created."
}

# ── Config helpers ─────────────────────────────────────────────

# hy2_save_server_info <ip> <port> <domain> <selfcert:true|false>
hy2_save_server_info() {
    local ip="$1" port="$2" domain="${3:-}" selfcert="${4:-true}"
    mkdir -p /etc/hysteria
    python3 - <<PYEOF
import json
data = {
    "ip":       "${ip}",
    "port":     "${port}",
    "domain":   "${domain}",
    "selfcert": ${selfcert}
}
with open("${HY2_INFO}", "w") as f:
    json.dump(data, f, indent=2)
PYEOF
    print_success "Server info saved → ${HY2_INFO}"
}

# hy2_read_server_info → exports HINFO_* variables
hy2_read_server_info() {
    [[ ! -f "$HY2_INFO" ]] && return 1
    eval "$(python3 - <<'PYEOF'
import json
d = json.load(open("/etc/hysteria/server.json"))
print(f"HINFO_IP=\"{d.get('ip','')}\"")
print(f"HINFO_PORT=\"{d.get('port','443')}\"")
print(f"HINFO_DOMAIN=\"{d.get('domain','')}\"")
print(f"HINFO_SELFCERT=\"{d.get('selfcert',True)}\"")
PYEOF
)"
}

# Patch YAML to add http auth + trafficStats sections
hy2_patch_config() {
    python3 - <<PYEOF
import re, sys

path = "${HY2_CONFIG}"
try:
    with open(path) as f:
        content = f.read()
except Exception as e:
    print(f"ERROR:{e}"); sys.exit(1)

auth_block = """auth:
  type: http
  http:
    url: http://127.0.0.1:${HY2_AUTH_PORT}/auth"""

# Replace existing auth block or append
content = re.sub(
    r'^auth:.*?(?=^\S|\Z)',
    auth_block + '\n\n',
    content, flags=re.MULTILINE | re.DOTALL
)

# Add trafficStats if missing
if 'trafficStats' not in content:
    content = content.rstrip('\n') + '\n\ntrafficStats:\n  listen: 127.0.0.1:${HY2_STATS_PORT}\n'

tmp = path + ".tmp"
with open(tmp, "w") as f:
    f.write(content)
import os; os.replace(tmp, path)
print("OK")
PYEOF
}

# ── Build connection link ──────────────────────────────────────

# hy2_build_link <username> <password> [label]
hy2_build_link() {
    local uname="$1" pass="$2" label="${3:-$1}"
    hy2_read_server_info || { print_error "Server info not found."; return 1; }

    local host insecure sni
    host="${HINFO_DOMAIN:-$HINFO_IP}"

    if [[ "$HINFO_SELFCERT" == "True" || -z "$HINFO_DOMAIN" ]]; then
        insecure="&insecure=1"
        sni="sni=hysteria"
    else
        insecure=""
        sni="sni=${HINFO_DOMAIN}"
    fi

    echo "hysteria2://${uname}:${pass}@${host}:${HINFO_PORT}?${sni}${insecure}#${label}"
}

# ── Auth API (Flask) ───────────────────────────────────────────
# Serves:  POST /auth         → Hysteria2 per-connection auth
#          GET  /sub/<token>  → unified subscription (all engines)
#          GET  /health       → liveness probe

hy2_write_auth_api() {
    cat > "$HY2_AUTH_API" << 'PYEOF'
#!/usr/bin/env python3
"""
Hysteria2 Auth API + Unified Subscription Server
  POST /auth           — Hysteria2 per-connection auth
  GET  /sub/<token>    — Unified multi-protocol subscription (VLESS + Hysteria2)
  GET  /health         — Health check
"""
import sqlite3, logging, base64, json, os
from datetime import datetime, timezone
from flask import Flask, request, jsonify, Response

app     = Flask(__name__)
DB_PATH = "/etc/singbox-manager/data/users.db"
HY2_INFO_PATH  = "/etc/hysteria/server.json"
VLESS_INFO_PATH = "/etc/sing-box/server.json"
VWS_INFO_PATH  = "/etc/sing-box/server_ws.json"
GRPC_INFO_PATH = "/etc/sing-box/server_grpc.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("/var/log/singbox-manager/auth_api.log"),
        logging.StreamHandler()
    ]
)

# ── DB helpers ─────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_sub_token(token):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE sub_token=? AND enabled=1", (token,)
        ).fetchone()

def get_user_by_uuid_pass(uuid, password):
    """
    Hysteria2 uses username:password auth.
    We store uuid as the identifier and sub_token as password.
    """
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE uuid=? AND sub_token=? AND enabled=1",
            (uuid, password)
        ).fetchone()

def is_expired(row):
    if not row["expires_at"]:
        return False
    try:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False

def is_over_quota(row):
    q = int(row["quota_gb"] or 0)
    if q == 0:
        return False
    return int(row["used_bytes"] or 0) >= int(q * 1024**3)

def load_json_file(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}

# ── Auth endpoint ──────────────────────────────────────────────

@app.route("/auth", methods=["POST"])
def auth():
    try:
        data     = request.get_json(force=True, silent=True) or {}
        auth_str = (data.get("auth") or data.get("payload") or "").strip().strip('"')

        if ":" not in auth_str:
            return jsonify({"ok": False, "id": ""}), 200

        uuid, token = auth_str.split(":", 1)
        uuid  = uuid.strip()
        token = token.strip()

        row = get_user_by_uuid_pass(uuid, token)
        if not row:
            app.logger.warning(f"Auth FAIL: '{uuid}' from {data.get('addr','?')}")
            return jsonify({"ok": False, "id": ""}), 200

        if is_expired(row):
            app.logger.warning(f"Auth DENY expired: '{uuid}'")
            return jsonify({"ok": False, "id": ""}), 200

        if is_over_quota(row):
            app.logger.warning(f"Auth DENY quota: '{uuid}'")
            return jsonify({"ok": False, "id": ""}), 200

        app.logger.info(f"Auth OK: '{row['label']}' ({uuid[:8]}...) from {data.get('addr','?')}")
        return jsonify({"ok": True, "id": uuid}), 200

    except Exception as e:
        app.logger.error(f"Auth error: {e}")
        return jsonify({"ok": False, "id": ""}), 200

# ── Unified subscription endpoint ─────────────────────────────

@app.route("/sub/<token>", methods=["GET"])
def subscription(token):
    """
    Returns a base64-encoded list of ALL active configs for this user.
    - If VLESS is enabled for the user  → include VLESS link
    - If Hysteria2 is enabled           → include Hysteria2 link
    Clients (Hiddify, v2rayN) parse the list and try each config.
    Traffic is counted from the shared quota.
    """
    row = get_user_by_sub_token(token)
    if not row:
        return Response("Unauthorized", status=401)

    if is_expired(row):
        return Response("Subscription expired", status=403)

    if is_over_quota(row):
        return Response("Quota exceeded", status=403)

    try:
        engines = json.loads(row["engines"] or "{}")
    except Exception:
        engines = {}

    links = []

    # ── VLESS + Reality link ───────────────────────────────────
    if engines.get("vless"):
        vi = load_json_file(VLESS_INFO_PATH)
        if vi:
            host  = vi.get("domain") or vi.get("ip", "")
            port  = vi.get("port", 443)
            pub   = vi.get("public_key", "")
            sid   = vi.get("short_id", "")
            sni   = vi.get("sni", "")
            uuid  = row["uuid"]
            label = f"{row['label']}-VLESS"
            import urllib.parse
            enc_label = urllib.parse.quote(label)
            vless_link = (
                f"vless://{uuid}@{host}:{port}"
                f"?encryption=none&flow=xtls-rprx-vision"
                f"&security=reality&sni={sni}&fp=chrome"
                f"&pbk={pub}&sid={sid}&type=tcp&headerType=none"
                f"#{enc_label}"
            )
            links.append(vless_link)

    # ── Hysteria2 link ─────────────────────────────────────────
    if engines.get("hysteria2"):
        hi = load_json_file(HY2_INFO_PATH)
        if hi:
            h_host  = hi.get("domain") or hi.get("ip", "")
            h_port  = hi.get("port", 443)
            selfcert = hi.get("selfcert", True)
            uuid     = row["uuid"]
            sub_tok  = row["sub_token"]
            label    = f"{row['label']}-HY2"

            insecure = "&insecure=1" if selfcert else ""
            sni      = "sni=hysteria" if selfcert else f"sni={hi.get('domain','')}"
            hy2_link = f"hysteria2://{uuid}:{sub_tok}@{h_host}:{h_port}?{sni}{insecure}#{label}"
            links.append(hy2_link)

    # ── VLESS + WebSocket + TLS link ──────────────────────────
    if engines.get("vless_ws"):
        wi = load_json_file(VWS_INFO_PATH)
        if wi:
            import urllib.parse
            w_host  = wi.get("domain", "")
            w_port  = wi.get("port", 443)
            w_path  = urllib.parse.quote(wi.get("path", "/ws"))
            uuid    = row["uuid"]
            label   = urllib.parse.quote(f"{row['label']}-WS")
            ws_link = (
                f"vless://{uuid}@{w_host}:{w_port}"
                f"?encryption=none&security=tls&sni={w_host}&fp=chrome"
                f"&type=ws&path={w_path}&host={w_host}"
                f"#{label}"
            )
            links.append(ws_link)

    # ── VLESS + gRPC + TLS link ────────────────────────────────
    if engines.get("vless_grpc"):
        gi = load_json_file(GRPC_INFO_PATH)
        if gi:
            import urllib.parse
            g_host  = gi.get("domain", "")
            g_port  = gi.get("port", 443)
            g_service = urllib.parse.quote(gi.get("service_name", "singbox-grpc"))
            uuid    = row["uuid"]
            label   = urllib.parse.quote(f"{row['label']}-gRPC")
            grpc_link = (
                f"vless://{uuid}@{g_host}:{g_port}"
                f"?encryption=none&security=tls&sni={g_host}&fp=chrome&alpn=h2"
                f"&type=grpc&serviceName={g_service}"
                f"#{label}"
            )
            links.append(grpc_link)

    if not links:
        return Response("No active configs for this user", status=404)

    # Build Hiddify/v2rayN compatible subscription body
    body = base64.b64encode("\n".join(links).encode()).decode()

    # Subscription metadata headers
    used_bytes  = int(row["used_bytes"] or 0)
    quota_bytes = int(float(row["quota_gb"] or 0) * 1024**3)

    expire_ts = ""
    if row["expires_at"]:
        try:
            exp = datetime.fromisoformat(row["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            expire_ts = str(int(exp.timestamp()))
        except Exception:
            pass

    sub_info = f"upload={used_bytes}; download=0; total={quota_bytes}"
    if expire_ts:
        sub_info += f"; expire={expire_ts}"

    label_b64 = base64.b64encode(row["label"].encode()).decode()

    headers = {
        "Content-Type":              "text/plain; charset=utf-8",
        "profile-title":             f"base64:{label_b64}",
        "subscription-userinfo":     sub_info,
        "profile-update-interval":   "12",
    }

    return Response(body, status=200, headers=headers)

# ── Health ─────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    try:
        with get_db() as conn:
            n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        return jsonify({"status": "ok", "users": n}), 200
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

if __name__ == "__main__":
    os.makedirs("/var/log/singbox-manager", exist_ok=True)
    app.run(host="0.0.0.0", port=18989, threaded=True)
PYEOF
    chmod +x "$HY2_AUTH_API"
    print_success "Auth + Subscription API written → ${HY2_AUTH_API}"
}

# ── Traffic sync (cron) ────────────────────────────────────────

hy2_write_sync_script() {
    cat > "$HY2_SYNC_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""
Hysteria2 traffic sync — polls the Hysteria2 Stats API and writes
cumulative delta into the central unified DB.
Runs via cron every 2 minutes.
"""
import sqlite3, urllib.request, json, logging, os
from datetime import datetime, timezone

CENTRAL_DB = "/etc/singbox-manager/data/users.db"
LOG_FILE   = "/var/log/singbox-manager/hy2_sync.log"

STATS_URLS = [
    "http://127.0.0.1:18990/traffic",
    "http://127.0.0.1:18990/v1/traffic",
]

RESET_ATTEMPTS = [
    ("DELETE", "http://127.0.0.1:18990/traffic"),       # v2.6+
    ("POST",   "http://127.0.0.1:18990/traffic/reset"), # v2.5-
    ("POST",   "http://127.0.0.1:18990/reset"),
]

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def fetch_stats():
    for url in STATS_URLS:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read())
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return None

def reset_stats():
    for method, url in RESET_ATTEMPTS:
        try:
            req = urllib.request.Request(
                url, method=method, data=b"",
                headers={"Content-Length": "0"}
            )
            urllib.request.urlopen(req, timeout=5)
            return
        except Exception:
            continue

def main():
    if not os.path.exists(CENTRAL_DB):
        return

    stats = fetch_stats()
    if stats is None:
        logging.warning("Could not reach Hysteria2 Stats API.")
        return

    conn = sqlite3.connect(CENTRAL_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    now  = datetime.now(timezone.utc).isoformat()

    updated = 0
    for uuid, traffic in stats.items():
        if not isinstance(traffic, dict):
            continue
        delta = int(traffic.get("tx", 0)) + int(traffic.get("rx", 0))
        if delta == 0:
            continue

        row = conn.execute(
            "SELECT id FROM users WHERE uuid=?", (uuid,)
        ).fetchone()
        if not row:
            continue

        conn.execute(
            "UPDATE users SET used_bytes=used_bytes+?, last_seen=? WHERE uuid=?",
            (delta, now, uuid)
        )
        conn.execute(
            "INSERT INTO traffic_log (uuid, engine, delta_bytes, recorded_at) VALUES (?,?,?,?)",
            (uuid, "hysteria2", delta, now)
        )
        updated += 1

    conn.commit()
    conn.close()

    if updated:
        logging.info(f"Synced traffic for {updated} user(s).")

    reset_stats()

if __name__ == "__main__":
    main()
PYEOF
    chmod +x "$HY2_SYNC_SCRIPT"
    print_success "Traffic sync script written → ${HY2_SYNC_SCRIPT}"
}

hy2_install_sync_cron() {
    local cron_line="*/2 * * * * /usr/bin/python3 ${HY2_SYNC_SCRIPT} >/dev/null 2>&1"
    { crontab -l 2>/dev/null || true; } \
        | { grep -v "sync_traffic\|hy2_sync" || true; } > /tmp/hy2_cron.tmp
    echo "$cron_line" >> /tmp/hy2_cron.tmp
    crontab /tmp/hy2_cron.tmp && rm -f /tmp/hy2_cron.tmp
    print_success "Traffic sync cron installed (every 2 min)."
}

# ── Generate server config YAML ────────────────────────────────

# hy2_write_config <port> <domain_or_empty> <up_mbps> <down_mbps>
#                  <init_stream> <max_stream> <init_conn> <max_conn>
#                  <idle_timeout> <keepalive> [hop_range e.g. "8000-9000"]
hy2_write_config() {
    local port="$1" domain="$2" up="$3" down="$4"
    local is="$5" ms="$6" ic="$7" mc="$8"
    local idle="${9:-60s}" ka="${10:-20s}" hop_range="${11:-}"
    local masq_url="https://www.speedtest.net"

    # Build listen line: port hopping if range provided
    local listen_line=":${port}"
    if [[ -n "$hop_range" ]]; then
        listen_line=":${port},${hop_range}"
        print_info "Port hopping enabled: ${port} + ${hop_range}"
    fi

    mkdir -p /etc/hysteria

    if [[ -n "$domain" ]]; then
        # ACME auto-cert
        cat > "$HY2_CONFIG" << YAMLEOF
listen: ${listen_line}

acme:
  domains:
    - ${domain}
  email: admin@${domain}

auth:
  type: http
  http:
    url: http://127.0.0.1:${HY2_AUTH_PORT}/auth

masquerade:
  type: proxy
  proxy:
    url: ${masq_url}
    rewriteHost: true

bandwidth:
  up: ${up} mbps
  down: ${down} mbps

quic:
  initStreamReceiveWindow: ${is}
  maxStreamReceiveWindow:  ${ms}
  initConnReceiveWindow:   ${ic}
  maxConnReceiveWindow:    ${mc}
  maxIdleTimeout:          ${idle}
  keepAlivePeriod:         ${ka}

trafficStats:
  listen: 127.0.0.1:${HY2_STATS_PORT}
YAMLEOF
    else
        # Self-signed cert
        mkdir -p /etc/hysteria/certs
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -keyout /etc/hysteria/certs/key.pem \
            -out    /etc/hysteria/certs/cert.pem \
            -days 3650 -subj "/CN=hysteria" &>/dev/null \
            && print_success "Self-signed certificate generated." \
            || { print_error "openssl not found: apt install openssl"; return 1; }

        cat > "$HY2_CONFIG" << YAMLEOF
listen: ${listen_line}

tls:
  cert: /etc/hysteria/certs/cert.pem
  key:  /etc/hysteria/certs/key.pem

auth:
  type: http
  http:
    url: http://127.0.0.1:${HY2_AUTH_PORT}/auth

masquerade:
  type: proxy
  proxy:
    url: ${masq_url}
    rewriteHost: true

bandwidth:
  up: ${up} mbps
  down: ${down} mbps

quic:
  initStreamReceiveWindow: ${is}
  maxStreamReceiveWindow:  ${ms}
  initConnReceiveWindow:   ${ic}
  maxConnReceiveWindow:    ${mc}
  maxIdleTimeout:          ${idle}
  keepAlivePeriod:         ${ka}

trafficStats:
  listen: 127.0.0.1:${HY2_STATS_PORT}
YAMLEOF
    fi

    print_success "Config written → ${HY2_CONFIG}"
}

# ── Compute sensible QUIC defaults from server profile ─────────

hy2_compute_quic_params() {
    # Returns: init_stream|max_stream|init_conn|max_conn
    local bw_mbps="${1:-$(estimate_bandwidth)}"
    local rtt_ms="${2:-150}"

    python3 - <<PYEOF
bw    = ${bw_mbps} * 1_000_000 / 8   # bytes/sec
rtt   = ${rtt_ms}  / 1000             # seconds
bdp   = bw * rtt                      # bandwidth-delay product

def clamp(v, lo, hi): return max(lo, min(hi, int(v)))

init_stream = clamp(bdp * 4,  2*1024*1024,  32*1024*1024)
max_stream  = clamp(bdp * 8,  4*1024*1024,  64*1024*1024)
init_conn   = clamp(bdp * 8,  4*1024*1024,  64*1024*1024)
max_conn    = clamp(bdp * 16, 8*1024*1024, 128*1024*1024)

print(f"{init_stream}|{max_stream}|{init_conn}|{max_conn}")
PYEOF
}

# ── Server install wizard ──────────────────────────────────────

hy2_install_server() {
    print_banner
    print_header "Install Hysteria2 — Outbound Server"
    echo -e "  ${DIM}Hysteria2 uses QUIC (UDP) — difficult to detect and block.${NC}"
    echo -e "  ${DIM}Install this on your foreign VPS (e.g. Germany, Netherlands).${NC}\n"

    # Step 1: binary
    print_step 1 5 "Installing Hysteria2 binary"
    check_internet
    fetch_hysteria2_version
    hy2_install_binary "$HY2_VERSION" || { press_enter; return 1; }

    # Step 2: deps
    print_step 2 5 "Installing Python dependencies"
    ensure_packages python3 python3-pip openssl
    hy2_install_deps || { press_enter; return 1; }

    # Step 3: parameters
    print_step 3 5 "Configure server parameters"
    echo ""

    local port domain
    ask port   "  UDP listen port"                          "443"

    local hop_range=""
    echo ""
    echo -e "  ${BOLD}Port hopping${NC} ${DIM}— Hysteria2 rotates through a port range every few seconds.${NC}"
    echo -e "  ${DIM}Makes it much harder for DPI to block. Requires client support (Hiddify/NekoBox).${NC}"
    if confirm "Enable port hopping?" "y"; then
        local hop_start hop_end
        ask hop_start "  Hop range start" "20000"
        ask hop_end   "  Hop range end"   "30000"
        hop_range="${hop_start}-${hop_end}"
        print_info "Open UDP ${hop_start}-${hop_end} in your VPS provider firewall too."
    fi

    echo ""
    echo -e "  ${BOLD}SSL Certificate Options:${NC}"
    echo -e "  ${CYAN}1.${NC} Use domain with ACME auto-cert (recommended)"
    echo -e "  ${CYAN}2.${NC} Self-signed certificate (requires client 'insecure=true')"
    echo -e "  ${CYAN}3.${NC} Use existing Let's Encrypt certificate"
    echo ""
    
    local ssl_choice
    echo -ne "  ${YELLOW}Choose option [1]: ${NC}"
    read -r ssl_choice
    ssl_choice="${ssl_choice:-1}"
    
    case "$ssl_choice" in
        1)
            # Check for existing SSL configuration
            ssl_load_domain 2>/dev/null || true
            local existing_domain="${DOMAIN:-}"
            
            if [[ -n "$existing_domain" ]] && confirm "Use existing domain '${existing_domain}'?" "y"; then
                domain="$existing_domain"
                print_success "Using domain: ${domain}"
            else
                ask domain "  Domain for ACME auto-cert" ""
                [[ -z "$domain" ]] && { print_warn "No domain specified. Using self-signed."; }
            fi
            ;;
        2)
            print_info "Using self-signed certificate"
            domain=""
            ;;
        3)
            # Check for existing SSL certs
            ssl_load_domain 2>/dev/null || true
            local existing_domain="${DOMAIN:-}"
            
            if [[ -n "$existing_domain" ]]; then
                echo ""
                print_info "Found existing domain: ${existing_domain}"
                if ssl_has_valid_cert "$existing_domain"; then
                    print_success "Valid SSL certificate found for ${existing_domain}"
                    domain="$existing_domain"
                    print_info "Will use existing certificate"
                else
                    print_warn "No valid certificate found for ${existing_domain}"
                    ask domain "  Enter domain with valid certificate" ""
                fi
            else
                print_info "No existing domain configured"
                ask domain "  Enter domain with existing certificate" ""
            fi
            
            # If domain is provided but cert not found, warn user
            if [[ -n "$domain" ]] && ! ssl_has_valid_cert "$domain"; then
                print_warn "No valid certificate found for ${domain}"
                print_warn "You need to get a certificate first from SSL menu"
                confirm "Continue with self-signed for now?" "y" || return 1
                domain=""
            fi
            ;;
        *)
            print_warn "Invalid choice. Using self-signed."
            domain=""
            ;;
    esac
    
    if [[ -z "$domain" ]]; then
        echo ""
        print_warn "Using self-signed certificate"
        print_info "Clients must enable 'insecure=true' or 'Skip TLS verification'"
    else
        echo ""
        print_success "Will use domain: ${domain}"
    fi

    # Probe server and compute QUIC params
    print_info "Profiling server for optimal QUIC settings..."
    probe_server
    local bw_mbps rtt_ms quic_params
    bw_mbps=$(estimate_bandwidth)
    # Measure RTT to a neutral target
    rtt_ms=$(measure_rtt "8.8.8.8")
    quic_params=$(hy2_compute_quic_params "$bw_mbps" "$rtt_ms")
    IFS='|' read -r init_stream max_stream init_conn max_conn <<< "$quic_params"

    local up_mbps down_mbps
    up_mbps=$(( bw_mbps * 85 / 100 ))    # 85% of estimated bandwidth
    down_mbps=$(( bw_mbps * 85 / 100 ))

    echo ""
    echo -e "  ${DIM}Detected bandwidth: ~${bw_mbps} Mbps | RTT: ${rtt_ms}ms | Profile: ${SRV_RAM_PROFILE}${NC}"
    echo -e "  ${DIM}Using: up=${up_mbps}mbps down=${down_mbps}mbps${NC}"
    echo -e "  ${DIM}QUIC windows computed from bandwidth-delay product.${NC}"
    echo ""
    confirm "Use auto-computed settings? (choose No to customize each value)" "y" \
        || hy2_customize_quic_params \
               up_mbps down_mbps init_stream max_stream init_conn max_conn

    # Step 4: write config + save info
    print_step 4 5 "Writing configuration"
    hy2_write_config "$port" "$domain" "$up_mbps" "$down_mbps" \
                     "$init_stream" "$max_stream" "$init_conn" "$max_conn" \
                     "60s" "20s" "$hop_range"

    local server_ip
    server_ip=$(get_public_ip)
    local selfcert_py="True"
    [[ -n "$domain" ]] && selfcert_py="False"
    hy2_save_server_info "$server_ip" "$port" "$domain" "$selfcert_py"

    # Step 5: services + cron + firewall
    print_step 5 5 "Starting services"
    mkdir -p "$LOG_DIR"
    hy2_write_auth_api
    hy2_write_sync_script
    hy2_create_server_service
    hy2_create_auth_service
    hy2_install_sync_cron
    open_port "$port" both
    open_port "$HY2_AUTH_PORT" tcp

    service_start hysteria-server || { press_enter; return 1; }
    service_start hysteria-auth   || { press_enter; return 1; }

    # Ensure central DB is ready
    db_init

    # ── Success ──────────────────────────────────────────────
    local host="${domain:-$server_ip}"
    echo ""
    echo -e "  ${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "  ${GREEN}${BOLD}║    Hysteria2 Server — Ready!                     ║${NC}"
    echo -e "  ${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Host      : ${CYAN}${host}${NC}"
    echo -e "  Port      : ${CYAN}${port}/UDP${NC}"
    if [[ -n "$domain" ]]; then
        echo -e "  TLS       : ${GREEN}ACME auto-cert (${domain})${NC}"
    else
        echo -e "  TLS       : ${YELLOW}Self-signed — clients need 'insecure=true'${NC}"
    fi
    echo -e "  Bandwidth : ${CYAN}↑${up_mbps} / ↓${down_mbps} Mbps${NC}"
    echo ""
    echo -e "  ${YELLOW}IMPORTANT: also allow UDP ${port} in your VPS provider's firewall panel!${NC}"
    echo ""
    if confirm "Add first user now?" "y"; then
        hy2_add_user
    fi
    press_enter
}

# Interactive parameter customization helper
hy2_customize_quic_params() {
    local -n _up="$1" _down="$2" _is="$3" _ms="$4" _ic="$5" _mc="$6"
    echo ""
    local inp
    echo -ne "  ${YELLOW}Upload Mbps   [${_up}]: ${NC}";  read -r inp; [[ -n "$inp" ]] && _up="${inp//[^0-9]/}"
    echo -ne "  ${YELLOW}Download Mbps [${_down}]: ${NC}"; read -r inp; [[ -n "$inp" ]] && _down="${inp//[^0-9]/}"

    local is_mb ms_mb ic_mb mc_mb
    is_mb=$(( _is / 1048576 )); ms_mb=$(( _ms / 1048576 ))
    ic_mb=$(( _ic / 1048576 )); mc_mb=$(( _mc / 1048576 ))

    echo -ne "  ${YELLOW}initStreamWindow MB [${is_mb}]: ${NC}"; read -r inp
    [[ -n "$inp" ]] && _is=$(( ${inp//[^0-9]/} * 1048576 ))
    echo -ne "  ${YELLOW}maxStreamWindow  MB [${ms_mb}]: ${NC}"; read -r inp
    [[ -n "$inp" ]] && _ms=$(( ${inp//[^0-9]/} * 1048576 ))
    echo -ne "  ${YELLOW}initConnWindow   MB [${ic_mb}]: ${NC}"; read -r inp
    [[ -n "$inp" ]] && _ic=$(( ${inp//[^0-9]/} * 1048576 ))
    echo -ne "  ${YELLOW}maxConnWindow    MB [${mc_mb}]: ${NC}"; read -r inp
    [[ -n "$inp" ]] && _mc=$(( ${inp//[^0-9]/} * 1048576 ))
}

# ── User management ────────────────────────────────────────────

hy2_add_user() {
    print_banner
    print_header "Hysteria2 — Add User"

    if [[ ! -f "$HY2_CONFIG" ]]; then
        print_error "Hysteria2 not installed. Run Install first."
        press_enter; return 1
    fi

    local label quota_gb expiry_days
    ask label       "  Label"                              "New-User"
    ask quota_gb    "  Traffic quota GB (0 = unlimited)"   "0"
    ask expiry_days "  Validity days    (0 = never)"       "30"

    local uuid sub_token expiry_iso=""
    uuid=$(generate_uuid)
    sub_token=$(generate_token)

    if [[ "$expiry_days" != "0" && -n "$expiry_days" ]]; then
        expiry_iso=$(python3 -c "
from datetime import datetime, timedelta, timezone
exp = datetime.now(timezone.utc) + timedelta(days=int('${expiry_days}'))
print(exp.isoformat())
" 2>/dev/null)
    fi

    # Add to central DB
    local add_result
    add_result=$(DB_PATH="$DB_PATH" \
        db_add_user "$uuid" "$label" "$quota_gb" "$sub_token" '{"hysteria2":true}' "$expiry_iso" 2>&1)

    if [[ "$?" -ne 0 ]]; then
        print_error "DB error: ${add_result}"
        press_enter; return 1
    fi

    db_enable_engine "$uuid" "hysteria2"

    # Build and show link
    local hy2_link sub_url host
    hy2_link=$(hy2_build_link "$uuid" "$sub_token" "$label")
    hy2_read_server_info
    host="${HINFO_DOMAIN:-$HINFO_IP}"
    sub_url="http://${host}:${HY2_AUTH_PORT}/sub/${sub_token}"

    echo ""
    echo -e "  ${BOLD}User created:${NC}"
    echo -e "  Label       : ${CYAN}${label}${NC}"
    echo -e "  UUID        : ${DIM}${uuid}${NC}"
    echo -e "  Sub token   : ${DIM}${sub_token}${NC}"
    echo -e "  Quota       : ${CYAN}$([ "$quota_gb" = "0" ] && echo "Unlimited" || echo "${quota_gb} GB")${NC}"
    [[ -n "$expiry_iso" ]] && echo -e "  Expires     : ${CYAN}${expiry_iso:0:10}${NC}"
    echo ""
    echo -e "  ${BOLD}Connection link (Hiddify / v2rayN):${NC}"
    echo -e "  ${MAGENTA}${hy2_link}${NC}"
    echo ""
    echo -e "  ${BOLD}Subscription URL ${DIM}(includes ALL active protocols for this user)${NC}:"
    echo -e "  ${CYAN}${sub_url}${NC}"
    print_qr "$hy2_link" "$label"
    press_enter
}

# hy2_delete_user <uuid>
hy2_delete_user() {
    local uuid="$1"
    db_delete_user "$uuid"
    print_success "User removed."
}

# ── Status ─────────────────────────────────────────────────────

hy2_show_status() {
    print_banner
    print_header "Hysteria2 — Status"

    service_status_line hysteria-server "hysteria-server"
    service_status_line hysteria-auth   "auth + sub API"
    echo ""

    if [[ -f "$HY2_BIN" ]]; then
        local ver
        ver=$("$HY2_BIN" version 2>/dev/null | grep -oP 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo -e "  Binary version : ${CYAN}${ver}${NC}"
    fi

    if hy2_read_server_info 2>/dev/null; then
        echo ""
        local host="${HINFO_DOMAIN:-$HINFO_IP}"
        echo -e "  Host : ${CYAN}${host}${NC}"
        echo -e "  Port : ${CYAN}${HINFO_PORT}/UDP${NC}"
        if [[ "$HINFO_SELFCERT" == "True" ]]; then
            echo -e "  TLS  : ${YELLOW}self-signed${NC}"
        else
            echo -e "  TLS  : ${GREEN}ACME (${HINFO_DOMAIN})${NC}"
        fi
    fi

    # Stats API check
    echo ""
    local stats_resp auth_resp
    stats_resp=$(curl -s --connect-timeout 3 "http://127.0.0.1:${HY2_STATS_PORT}/traffic" 2>/dev/null || echo "")
    auth_resp=$(curl -s  --connect-timeout 3 "http://127.0.0.1:${HY2_AUTH_PORT}/health"   2>/dev/null || echo "")

    [[ -n "$stats_resp" ]] \
        && echo -e "  Stats API (${HY2_STATS_PORT}) : ${GREEN}responding${NC}" \
        || echo -e "  Stats API (${HY2_STATS_PORT}) : ${RED}not responding${NC}"
    [[ "$auth_resp" =~ "ok" ]] \
        && echo -e "  Auth  API (${HY2_AUTH_PORT}) : ${GREEN}responding${NC}" \
        || echo -e "  Auth  API (${HY2_AUTH_PORT}) : ${RED}not responding${NC}"

    echo ""
    echo -e "  ${BOLD}Recent log:${NC}"
    journalctl -u hysteria-server --no-pager -n 15 2>/dev/null | sed 's/^/  /' \
        || echo "  (no log available)"
    echo ""
    press_enter
}

# ── Update ─────────────────────────────────────────────────────

hy2_update() {
    print_banner
    print_header "Update Hysteria2"

    [[ ! -f "$HY2_BIN" ]] && { print_error "Hysteria2 not installed."; press_enter; return; }

    check_internet
    fetch_hysteria2_version

    local current
    current=$("$HY2_BIN" version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
    echo -e "  Current: ${YELLOW}${current}${NC}  →  Available: ${GREEN}${HY2_VERSION}${NC}"

    if [[ "$current" == "$HY2_VERSION" ]]; then
        print_info "Already on latest version."
        press_enter; return
    fi

    confirm "Proceed with update?" "y" || return
    systemctl stop hysteria-server 2>/dev/null || true
    hy2_install_binary "$HY2_VERSION"
    systemctl start hysteria-server 2>/dev/null || true
    print_success "Updated to v${HY2_VERSION}."
    press_enter
}

# ── Service control menu ───────────────────────────────────────

hy2_service_menu() {
    while true; do
        print_banner
        print_header "Hysteria2 — Service Control"
        service_status_line hysteria-server "hysteria-server"
        service_status_line hysteria-auth   "hysteria-auth"
        echo ""
        echo -e "  ${CYAN}1)${NC}  Start   hysteria-server"
        echo -e "  ${CYAN}2)${NC}  Stop    hysteria-server"
        echo -e "  ${CYAN}3)${NC}  Restart hysteria-server"
        echo -e "  ${CYAN}4)${NC}  Live log — hysteria-server  ${DIM}(Ctrl+C to exit)${NC}"
        echo -e "  ${CYAN}5)${NC}  Restart hysteria-auth"
        echo -e "  ${CYAN}6)${NC}  Live log — hysteria-auth    ${DIM}(Ctrl+C to exit)${NC}"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) systemctl start   hysteria-server && print_success "Started.";   press_enter ;;
            2) systemctl stop    hysteria-server && print_success "Stopped.";   press_enter ;;
            3) systemctl restart hysteria-server && print_success "Restarted."; press_enter ;;
            4) journalctl -u hysteria-server -f ;;
            5) systemctl restart hysteria-auth   && print_success "Restarted."; press_enter ;;
            6) journalctl -u hysteria-auth -f ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}

# ── Uninstall ──────────────────────────────────────────────────

hy2_uninstall() {
    print_banner
    echo -e "  ${RED}${BOLD}Uninstall Hysteria2${NC}\n"
    echo -e "  ${YELLOW}Removes binary, config, auth API, crons, and service files.${NC}"
    echo -e "  ${DIM}The central user database will NOT be deleted.${NC}\n"
    confirm "Proceed?" "n" || return

    systemctl stop    hysteria-server 2>/dev/null || true
    systemctl stop    hysteria-auth   2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true
    systemctl disable hysteria-auth   2>/dev/null || true
    rm -f /etc/systemd/system/hysteria-server.service
    rm -f /etc/systemd/system/hysteria-auth.service
    systemctl daemon-reload
    rm -f "$HY2_BIN"
    rm -rf /etc/hysteria
    { crontab -l 2>/dev/null || true; } \
        | { grep -v "sync_traffic\|hy2_sync" || true; } \
        | crontab - 2>/dev/null || true

    # Disable hysteria2 engine in DB
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os
db = os.environ["DB_PATH"]
if not os.path.exists(db): exit()
conn = sqlite3.connect(db)
for r in conn.execute("SELECT uuid, engines FROM users").fetchall():
    try: e = json.loads(r[1] or "{}")
    except: e = {}
    e["hysteria2"] = False
    conn.execute("UPDATE users SET engines=? WHERE uuid=?", (json.dumps(e), r[0]))
conn.commit(); conn.close()
PYEOF

    print_success "Hysteria2 completely removed."
    press_enter
}
