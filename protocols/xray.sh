#!/usr/bin/env bash
# Xray-core runtime used only by the customer gateway.
XRAY_BIN="/usr/local/bin/xray"
XRAY_VERSION=""

fetch_xray_version(){
    local ver
    ver=$(curl -fsSL -H 'User-Agent: gateway-manager' https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | grep '"tag_name"' | grep -oP '"v\K[0-9][^"]+' | head -1 || true)
    XRAY_VERSION="${ver:-26.7.28}"
}
_xray_arch(){ case "$(uname -m)" in x86_64|amd64) echo 64;; aarch64|arm64) echo arm64-v8a;; armv7l) echo arm32-v7a;; *) return 1;; esac; }
xray_install_binary(){
    local version="${1:-$XRAY_VERSION}" arch tmp url
    arch=$(_xray_arch) || { print_error "Unsupported CPU: $(uname -m)"; return 1; }
    ensure_packages curl unzip ca-certificates >/dev/null || return 1
    tmp=$(mktemp -d); url="https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-${arch}.zip"
    print_info "Downloading Xray-core v${version}..."
    curl -fL --retry 3 --connect-timeout 15 -o "$tmp/xray.zip" "$url" >/dev/null 2>&1 || { rm -rf "$tmp"; print_error "Xray download failed."; return 1; }
    unzip -q -o "$tmp/xray.zip" -d "$tmp" || { rm -rf "$tmp"; return 1; }
    install -m755 "$tmp/xray" "$XRAY_BIN"; rm -rf "$tmp"
    print_success "Xray-core installed: $($XRAY_BIN version 2>/dev/null | head -1 | awk '{print $2}')"
}
xray_ensure(){
    [[ -x "$XRAY_BIN" ]] && return 0
    fetch_xray_version; xray_install_binary "$XRAY_VERSION"
}
xray_generate_reality_keypair(){
    local out priv pub
    out=$($XRAY_BIN x25519 2>/dev/null) || return 1
    priv=$(printf '%s\n' "$out" | sed -nE 's/^Private[[:space:]]*[Kk]ey:[[:space:]]*//p;s/^PrivateKey:[[:space:]]*//p' | head -1)
    pub=$(printf '%s\n' "$out" | sed -nE 's/^Password( \(PublicKey\))?:[[:space:]]*//p;s/^Public[[:space:]]*[Kk]ey:[[:space:]]*//p' | head -1)
    [[ -n "$priv" && -n "$pub" ]] || return 1; printf '%s|%s\n' "$priv" "$pub"
}
