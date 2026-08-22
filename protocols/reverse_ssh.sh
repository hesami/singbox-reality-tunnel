#!/usr/bin/env bash
# Reverse SSH tunnel helpers.
# Foreign/Turkey initiates SSH to Iran and creates a remote dynamic SOCKS5
# listener on Iran. This does not modify nginx, websites, TLS, or ports 80/443.

RSSH_DIR="/etc/reverse-ssh-tunnel"
RSSH_KEY="${RSSH_DIR}/id_ed25519"
RSSH_ENV="${RSSH_DIR}/tunnel.env"
RSSH_KNOWN_HOSTS="${RSSH_DIR}/known_hosts"
RSSH_SERVICE="reverse-ssh-tunnel.service"
RSSH_MARKER="singbox-manager-reverse-tunnel"

rssh_ensure_client() {
    command -v ssh >/dev/null 2>&1 && command -v ssh-keygen >/dev/null 2>&1 && return 0
    ensure_packages openssh-client
}

rssh_generate_key() {
    rssh_ensure_client || return 1
    mkdir -p "$RSSH_DIR"
    chmod 700 "$RSSH_DIR"
    if [[ ! -s "$RSSH_KEY" || ! -s "${RSSH_KEY}.pub" ]]; then
        rm -f "$RSSH_KEY" "${RSSH_KEY}.pub"
        ssh-keygen -q -t ed25519 -f "$RSSH_KEY" -N '' -C "$RSSH_MARKER" || return 1
    fi
    chmod 600 "$RSSH_KEY"
    chmod 644 "${RSSH_KEY}.pub"
}

rssh_public_key() {
    [[ -s "${RSSH_KEY}.pub" ]] || return 1
    cat "${RSSH_KEY}.pub"
}

rssh_write_foreign_service() {
    local iran_host="$1" ssh_port="$2" socks_port="$3"
    mkdir -p "$RSSH_DIR"
    chmod 700 "$RSSH_DIR"
    cat > "$RSSH_ENV" <<EOF2
IRAN_HOST=${iran_host}
IRAN_SSH_PORT=${ssh_port}
IRAN_SOCKS_PORT=${socks_port}
EOF2
    chmod 600 "$RSSH_ENV"

    cat > "/etc/systemd/system/${RSSH_SERVICE}" <<EOF2
[Unit]
Description=Persistent reverse SSH tunnel to Iran
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/usr/bin/ssh -NT \\
  -i ${RSSH_KEY} \\
  -p ${ssh_port} \\
  -R 127.0.0.1:${socks_port} \\
  -o BatchMode=yes \\
  -o ExitOnForwardFailure=yes \\
  -o ServerAliveInterval=20 \\
  -o ServerAliveCountMax=3 \\
  -o TCPKeepAlive=yes \\
  -o ConnectTimeout=10 \\
  -o StrictHostKeyChecking=accept-new \\
  -o UserKnownHostsFile=${RSSH_KNOWN_HOSTS} \\
  root@${iran_host}
Restart=always
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF2
    systemctl daemon-reload
    systemctl enable "$RSSH_SERVICE" >/dev/null 2>&1 || return 1
    systemctl restart "$RSSH_SERVICE" >/dev/null 2>&1 || true
}

rssh_validate_public_key() {
    local key="$1"
    [[ "$key" =~ ^ssh-ed25519[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]
}

rssh_authorize_on_iran() {
    local pubkey="$1" socks_port="$2"
    rssh_validate_public_key "$pubkey" || return 2
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh
    touch /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys

    # Remove only manager-owned previous reverse-tunnel keys.
    local tmp
    tmp=$(mktemp)
    grep -v "$RSSH_MARKER" /root/.ssh/authorized_keys > "$tmp" 2>/dev/null || true
    cat "$tmp" > /root/.ssh/authorized_keys
    rm -f "$tmp"

    # Restrict this root key to TCP forwarding only, and only to the requested
    # loopback listener. It cannot open a shell, PTY, agent or X11 session.
    printf 'restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s %s\n' \
        "$socks_port" "$pubkey" "$RSSH_MARKER" >> /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
}

rssh_sshd_forwarding_ok() {
    command -v sshd >/dev/null 2>&1 || return 1
    local out
    out=$(sshd -T 2>/dev/null) || return 1
    grep -Eq '^allowtcpforwarding (yes|all|remote)$' <<<"$out"
}

rssh_wait_listener() {
    local port="$1" timeout="${2:-30}" i
    for ((i=0; i<timeout; i++)); do
        if ss -H -ltn 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {found=1} END{exit !found}'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

rssh_test_socks() {
    local port="$1" timeout="${2:-20}" out
    out=$(curl -fsS --max-time "$timeout" --connect-timeout 10 \
        --socks5-hostname "127.0.0.1:${port}" https://api.ipify.org 2>/tmp/reverse-ssh-curl.err \
        | tr -d '[:space:]' || true)
    [[ "$out" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$out" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    printf '%s\n' "$out"
}

rssh_remove_iran_authorization() {
    [[ -f /root/.ssh/authorized_keys ]] || return 0
    local tmp
    tmp=$(mktemp)
    grep -v "$RSSH_MARKER" /root/.ssh/authorized_keys > "$tmp" 2>/dev/null || true
    cat "$tmp" > /root/.ssh/authorized_keys
    rm -f "$tmp"
}
