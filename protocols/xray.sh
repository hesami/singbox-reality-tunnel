#!/usr/bin/env bash
# Xray-core runtime used only by the customer gateway.
# The customer data-plane is intentionally pinned to the exact Xray build that
# was verified working for this project. Do not silently drift to "latest".
XRAY_BIN="/usr/local/bin/xray"
XRAY_PINNED_VERSION="26.7.28"
XRAY_VERSION="$XRAY_PINNED_VERSION"

_xray_arch(){
    case "$(uname -m)" in
      x86_64|amd64) echo 64 ;;
      aarch64|arm64) echo arm64-v8a ;;
      armv7l) echo arm32-v7a ;;
      *) return 1 ;;
    esac
}

xray_current_version(){
    [[ -x "$XRAY_BIN" ]] || return 1
    "$XRAY_BIN" version 2>/dev/null | awk 'NR==1{print $2}'
}

xray_install_binary(){
    local version="${1:-$XRAY_PINNED_VERSION}" arch tmp url staged got asset expected actual
    arch=$(_xray_arch) || { print_error "Unsupported CPU: $(uname -m)"; return 1; }
    ensure_packages curl unzip ca-certificates >/dev/null || return 1
    tmp=$(mktemp -d)
    asset="Xray-linux-${arch}.zip"
    url="https://github.com/XTLS/Xray-core/releases/download/v${version}/${asset}"
    print_info "Installing pinned Xray-core v${version}..."
    curl -fL --retry 4 --retry-delay 2 --connect-timeout 15 --max-time 180 -o "$tmp/xray.zip" "$url" >/dev/null 2>&1 || {
        rm -rf "$tmp"; print_error "Xray v${version} download failed."; return 1;
    }
    # NOTE: Xray-core releases no longer ship a combined "sha256sum.txt".
    # Each asset instead has its own "<asset>.dgst" sidecar file with
    # MD5/SHA1/SHA2-256/SHA2-512 lines (verified against the real v26.7.28
    # release on 2026-08-23). Parse the SHA2-256 line out of that file.
    curl -fL --retry 3 --connect-timeout 15 --max-time 60 -o "$tmp/${asset}.dgst" "https://github.com/XTLS/Xray-core/releases/download/v${version}/${asset}.dgst" >/dev/null 2>&1 || {
        rm -rf "$tmp"; print_error "Xray checksum (.dgst) download failed."; return 1;
    }
    expected=$(awk -F'= *' '/^SHA2-256=/{print tolower($2)}' "$tmp/${asset}.dgst" | tr -d '[:space:]')
    actual=$(sha256sum "$tmp/xray.zip" | awk '{print $1}')
    [[ -n "$expected" && "$actual" == "$expected" ]] || {
        rm -rf "$tmp"; print_error "Xray checksum verification failed."; return 1;
    }
    unzip -q -o "$tmp/xray.zip" -d "$tmp" || { rm -rf "$tmp"; print_error "Xray archive extraction failed."; return 1; }
    [[ -x "$tmp/xray" ]] || { rm -rf "$tmp"; print_error "Xray binary missing from release archive."; return 1; }
    got=$("$tmp/xray" version 2>/dev/null | awk 'NR==1{print $2}')
    [[ "$got" == "$version" ]] || {
        rm -rf "$tmp"; print_error "Downloaded Xray version mismatch: expected ${version}, got ${got:-unknown}."; return 1;
    }
    staged="${XRAY_BIN}.new.$$"
    install -m755 "$tmp/xray" "$staged" || { rm -rf "$tmp" "$staged"; return 1; }
    mv -f "$staged" "$XRAY_BIN" || { rm -rf "$tmp" "$staged"; return 1; }
    rm -rf "$tmp"
    got=$(xray_current_version 2>/dev/null || true)
    [[ "$got" == "$version" ]] || { print_error "Installed Xray verification failed."; return 1; }
    print_success "Xray-core normalized to v${got}."
}

xray_ensure(){
    local current
    current=$(xray_current_version 2>/dev/null || true)
    if [[ "$current" == "$XRAY_PINNED_VERSION" ]]; then
        return 0
    fi
    if [[ -n "$current" ]]; then
        print_warn "Xray runtime drift detected: v${current}; required v${XRAY_PINNED_VERSION}."
    else
        print_info "Xray runtime is not installed."
    fi
    xray_install_binary "$XRAY_PINNED_VERSION"
}

xray_generate_reality_keypair(){
    local out priv pub
    out=$($XRAY_BIN x25519 2>/dev/null) || return 1
    priv=$(printf '%s\n' "$out" | sed -nE 's/^Private[[:space:]]*[Kk]ey:[[:space:]]*//p;s/^PrivateKey:[[:space:]]*//p' | head -1)
    pub=$(printf '%s\n' "$out" | sed -nE 's/^Password( \(PublicKey\))?:[[:space:]]*//p;s/^Public[[:space:]]*[Kk]ey:[[:space:]]*//p' | head -1)
    [[ -n "$priv" && -n "$pub" ]] || return 1
    printf '%s|%s\n' "$priv" "$pub"
}
