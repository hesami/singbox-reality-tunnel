#!/usr/bin/env bash
# Xray-core helpers dedicated to the two-server tunnel.
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/etc/xray-tunnel"
XRAY_SERVER_CONFIG="${XRAY_DIR}/server.json"
XRAY_CLIENT_CONFIG="${XRAY_DIR}/client.json"
XRAY_VERSION=""

fetch_xray_version() {
    local ver=""
    ver=$(curl -fsSL -H "User-Agent: singbox-reality-tunnel" \
        https://api.github.com/repos/XTLS/Xray-core/releases 2>/dev/null \
        | grep '"tag_name"' | head -1 | grep -oP '"v\K[0-9][^"]+' | head -1 || true)
    if [[ -z "$ver" ]]; then
        local location
        location=$(curl -fsSIL https://github.com/XTLS/Xray-core/releases/latest 2>/dev/null \
            | grep -i '^location:' | tail -1 | tr -d '\r' | awk '{print $2}' || true)
        ver=$(echo "$location" | grep -oP 'tag/v\K[0-9][^/[:space:]]+' | head -1 || true)
    fi
    XRAY_VERSION="${ver:-26.7.28}"
    print_info "Xray-core version: ${XRAY_VERSION}"
}

_xray_asset_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "64" ;;
        aarch64|arm64) echo "arm64-v8a" ;;
        armv7l) echo "arm32-v7a" ;;
        *) return 1 ;;
    esac
}

xray_install_binary() {
    local version="${1:-$XRAY_VERSION}" arch tmp url
    [[ -n "$version" ]] || { print_error "Xray version is empty."; return 1; }
    arch=$(_xray_asset_arch) || { print_error "Unsupported architecture for Xray-core: $(uname -m)"; return 1; }
    ensure_packages curl unzip ca-certificates >/dev/null || return 1
    tmp=$(mktemp -d)
    url="https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
    print_info "Downloading Xray-core v${version} (${arch})..."
    if ! curl -fL --retry 3 --connect-timeout 15 -o "${tmp}/xray.zip" "$url"; then
        rm -rf "$tmp"; print_error "Failed to download Xray-core v${version}."; return 1
    fi
    unzip -q -o "${tmp}/xray.zip" -d "$tmp" || { rm -rf "$tmp"; print_error "Invalid Xray archive."; return 1; }
    [[ -x "${tmp}/xray" ]] || { rm -rf "$tmp"; print_error "Xray binary missing from archive."; return 1; }
    install -m 755 "${tmp}/xray" "$XRAY_BIN"
    mkdir -p /usr/local/share/xray "$XRAY_DIR"
    [[ -f "${tmp}/geoip.dat" ]] && install -m 644 "${tmp}/geoip.dat" /usr/local/share/xray/geoip.dat
    [[ -f "${tmp}/geosite.dat" ]] && install -m 644 "${tmp}/geosite.dat" /usr/local/share/xray/geosite.dat
    rm -rf "$tmp"
    print_success "Xray-core $($XRAY_BIN version 2>/dev/null | head -1 | awk '{print $2}') installed."
}

xray_generate_reality_keypair() {
    local out priv pub
    out=$($XRAY_BIN x25519 2>/dev/null) || return 1
    priv=$(printf '%s\n' "$out" | sed -nE 's/^Private[[:space:]]*[Kk]ey:[[:space:]]*//p; s/^PrivateKey:[[:space:]]*//p' | head -1)
    pub=$(printf '%s\n' "$out" | sed -nE 's/^Password( \(PublicKey\))?:[[:space:]]*//p; s/^Public[[:space:]]*[Kk]ey:[[:space:]]*//p' | head -1)
    [[ -n "$priv" && -n "$pub" ]] || return 1
    printf '%s|%s\n' "$priv" "$pub"
}

xray_check_config() {
    local f="$1"
    "$XRAY_BIN" run -test -config "$f"
}

xray_write_server_config() {
    local port="$1" uuid="$2" sni="$3" priv="$4" sid="$5"
    mkdir -p "$XRAY_DIR" /var/log/xray-tunnel
    PORT="$port" UUID="$uuid" SNI="$sni" PRIV="$priv" SID="$sid" OUT="$XRAY_SERVER_CONFIG" python3 - <<'PY'
import json, os
c={
  "log":{"loglevel":"warning","access":"/var/log/xray-tunnel/access.log","error":"/var/log/xray-tunnel/error.log"},
  "inbounds":[{
    "listen":"0.0.0.0","port":int(os.environ["PORT"]),"protocol":"vless","tag":"reality-in",
    "settings":{"users":[{"id":os.environ["UUID"],"flow":"xtls-rprx-vision","level":0,"email":"tunnel@local"}],"decryption":"none"},
    "streamSettings":{"method":"raw","security":"reality","realitySettings":{
      "show":False,"target":os.environ["SNI"]+":443","xver":0,
      "serverNames":[os.environ["SNI"]],"privateKey":os.environ["PRIV"],"shortIds":[os.environ["SID"]],
      "limitFallbackUpload":{"afterBytes":0,"bytesPerSec":0,"burstBytesPerSec":0},
      "limitFallbackDownload":{"afterBytes":0,"bytesPerSec":0,"burstBytesPerSec":0}
    }}
  }],
  "outbounds":[{"protocol":"freedom","tag":"direct"}]
}
with open(os.environ["OUT"],"w") as f: json.dump(c,f,indent=2)
PY
    chmod 600 "$XRAY_SERVER_CONFIG"
}

xray_write_client_config() {
    local ip="$1" port="$2" uuid="$3" sni="$4" password="$5" sid="$6" socks_host="$7" socks_port="$8"
    mkdir -p "$XRAY_DIR" /var/log/xray-tunnel
    IP="$ip" PORT="$port" UUID="$uuid" SNI="$sni" PASS="$password" SID="$sid" \
    SOCKS_HOST="$socks_host" SOCKS_PORT="$socks_port" OUT="$XRAY_CLIENT_CONFIG" python3 - <<'PY'
import json, os
c={
  "log":{"loglevel":"warning","access":"/var/log/xray-tunnel/client-access.log","error":"/var/log/xray-tunnel/client-error.log"},
  "inbounds":[{
    "listen":os.environ["SOCKS_HOST"],"port":int(os.environ["SOCKS_PORT"]),"protocol":"socks","tag":"socks-in",
    "settings":{"auth":"noauth","udp":True}
  }],
  "outbounds":[{
    "protocol":"vless","tag":"reality-out",
    "settings":{"address":os.environ["IP"],"port":int(os.environ["PORT"]),"id":os.environ["UUID"],"encryption":"none","flow":"xtls-rprx-vision"},
    "streamSettings":{"method":"raw","security":"reality","realitySettings":{
      "serverName":os.environ["SNI"],"fingerprint":"chrome","password":os.environ["PASS"],
      "shortId":os.environ["SID"],"spiderX":"/"
    }}
  },{"protocol":"freedom","tag":"direct"}],
  "routing":{"domainStrategy":"AsIs","rules":[]}
}
with open(os.environ["OUT"],"w") as f: json.dump(c,f,indent=2)
PY
    chmod 600 "$XRAY_CLIENT_CONFIG"
}

xray_create_service() {
    local role="$1" name cfg desc
    if [[ "$role" == "server" ]]; then
        name="xray-tunnel-server"; cfg="$XRAY_SERVER_CONFIG"; desc="Xray Reality Tunnel Server"
    else
        name="xray-tunnel-client"; cfg="$XRAY_CLIENT_CONFIG"; desc="Xray Reality Tunnel Client"
    fi
    cat > "/etc/systemd/system/${name}.service" <<EOF2
[Unit]
Description=${desc}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${XRAY_BIN} run -config ${cfg}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF2
    systemctl daemon-reload
    systemctl enable "$name" >/dev/null 2>&1 || true
}
