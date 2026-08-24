#!/usr/bin/env bash
# Production transport: persistent reverse SSH from Turkey -> Iran.
RSSH_DIR="/etc/reverse-ssh-tunnel"
RSSH_KEY="${RSSH_DIR}/id_ed25519"
RSSH_ENV="${RSSH_DIR}/tunnel.env"
RSSH_KNOWN_HOSTS="${RSSH_DIR}/known_hosts"
RSSH_SERVICE="reverse-ssh-tunnel.service"
RSSH_MARKER="gateway-manager-reverse-tunnel"
RSSH_USER="tunnelrelay"
RSSH_HOME="/var/lib/tunnelrelay"
RSSH_SSHD_PORT_DEFAULT="22022"
RSSH_SSHD_CONFIG="/etc/ssh/sshd_config_reverse_tunnel"
RSSH_SSHD_SERVICE="sshd-reverse-tunnel.service"
RSSH_SYSCTL="/etc/sysctl.d/99-reverse-ssh-tunnel.conf"

rssh_ensure_client(){ command -v ssh >/dev/null 2>&1 && command -v ssh-keygen >/dev/null 2>&1 || ensure_packages openssh-client; }
rssh_ensure_server(){ command -v sshd >/dev/null 2>&1 || ensure_packages openssh-server; }
rssh_generate_key(){
    rssh_ensure_client || return 1; mkdir -p "$RSSH_DIR"; chmod 700 "$RSSH_DIR"
    if [[ ! -s "$RSSH_KEY" || ! -s "${RSSH_KEY}.pub" ]]; then
        rm -f "$RSSH_KEY" "${RSSH_KEY}.pub"; ssh-keygen -q -t ed25519 -a 64 -f "$RSSH_KEY" -N '' -C "$RSSH_MARKER" || return 1
    fi
    chmod 600 "$RSSH_KEY"; chmod 644 "${RSSH_KEY}.pub"
}
rssh_public_key(){ [[ -s "${RSSH_KEY}.pub" ]] && cat "${RSSH_KEY}.pub"; }
rssh_validate_public_key(){ [[ "$1" =~ ^ssh-ed25519[[:space:]]+[A-Za-z0-9+/=]+([[:space:]].*)?$ ]]; }
rssh_public_ip(){ get_public_ip; }

rssh_socks_port(){
    local p=""
    if [[ -r "$RSSH_ENV" ]]; then p=$(awk -F= '$1=="IRAN_SOCKS_PORT"{print $2;exit}' "$RSSH_ENV" 2>/dev/null || true); fi
    if ! valid_port "$p" && [[ -r "$RSSH_SSHD_CONFIG" ]]; then p=$(sed -nE 's/^PermitListen[[:space:]]+127\.0\.0\.1:([0-9]+).*/\1/p' "$RSSH_SSHD_CONFIG" | head -1); fi
    valid_port "$p" && echo "$p" || echo 10808
}
rssh_pair_code(){
    local turkey_ip="$1" ssh_port="$2" socks_port="$3" pubkey="$4"
    valid_ipv4 "$turkey_ip" && valid_port "$ssh_port" && valid_port "$socks_port" && rssh_validate_public_key "$pubkey" || return 2
    TURKEY_IP="$turkey_ip" SSH_PORT="$ssh_port" SOCKS_PORT="$socks_port" PUBKEY="$pubkey" python3 - <<'PY'
import os,json,base64
obj={'v':1,'turkey_ip':os.environ['TURKEY_IP'],'ssh_port':int(os.environ['SSH_PORT']),'socks_port':int(os.environ['SOCKS_PORT']),'public_key':os.environ['PUBKEY']}
raw=json.dumps(obj,separators=(',',':')).encode(); print(base64.urlsafe_b64encode(raw).decode().rstrip('='))
PY
}
rssh_parse_pair_code(){
    PAIR_CODE="$1" python3 - <<'PY'
import os,json,base64,sys
try:
 s=os.environ['PAIR_CODE'].strip(); s += '='*((4-len(s)%4)%4); d=json.loads(base64.urlsafe_b64decode(s.encode()))
 vals=[str(d['turkey_ip']),str(int(d['ssh_port'])),str(int(d['socks_port'])),str(d['public_key'])]
 for v in vals: print(v)
except Exception: sys.exit(1)
PY
}

rssh_apply_performance(){
    local cc=cubic qdisc=fq_codel
    modprobe tcp_bbr 2>/dev/null || true
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then cc=bbr; modprobe sch_fq 2>/dev/null && qdisc=fq || true; fi
    cat >"$RSSH_SYSCTL" <<EOF2
# Conservative production tuning for the Iran-Turkey TCP path.
net.ipv4.tcp_congestion_control=${cc}
net.core.default_qdisc=${qdisc}
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_keepalive_time=60
net.ipv4.tcp_keepalive_intvl=10
net.ipv4.tcp_keepalive_probes=5
net.core.somaxconn=16384
net.ipv4.tcp_max_syn_backlog=8192
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 262144 16777216
net.ipv4.tcp_wmem=4096 262144 16777216
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=15
net.ipv4.ip_local_port_range=1024 65535
net.core.netdev_max_backlog=16384
net.ipv4.tcp_no_metrics_save=1
EOF2
    sysctl --system >/dev/null 2>&1 || true; echo "${cc}/${qdisc}"
}

# Picks the SSH symmetric cipher with the least CPU overhead for this CPU:
# hardware AES (AES-NI) makes aes128-gcm the fastest option; without it,
# chacha20-poly1305 is consistently faster on typical budget VPS cores.
# The proxied payload is already REALITY/TLS-encrypted, so this only
# affects the SSH transport's own (mandatory, unavoidable) encryption
# layer — picking the cheaper cipher here reduces CPU load on both ends
# under sustained throughput, which is what keeps the tunnel smooth
# instead of stalling when a cheap vCPU core saturates.
rssh_pick_cipher(){
    if grep -qm1 '\baes\b' /proc/cpuinfo 2>/dev/null; then
        echo "aes128-gcm@openssh.com,chacha20-poly1305@openssh.com"
    else
        echo "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com"
    fi
}

rssh_create_restricted_user(){
    rssh_ensure_server || return 1
    if ! id "$RSSH_USER" >/dev/null 2>&1; then useradd --system --create-home --home-dir "$RSSH_HOME" --shell /usr/sbin/nologin "$RSSH_USER" || return 1; fi
    usermod -L "$RSSH_USER" >/dev/null 2>&1 || true
    mkdir -p "$RSSH_HOME/.ssh"; touch "$RSSH_HOME/.ssh/authorized_keys"; chown -R "$RSSH_USER:$RSSH_USER" "$RSSH_HOME"; chmod 700 "$RSSH_HOME/.ssh"; chmod 600 "$RSSH_HOME/.ssh/authorized_keys"
}
rssh_authorize_on_iran(){
    local pubkey="$1" socks_port="$2" ak tmp
    rssh_validate_public_key "$pubkey" || return 2; valid_port "$socks_port" || return 2; rssh_create_restricted_user || return 1
    ak="$RSSH_HOME/.ssh/authorized_keys"; tmp=$(mktemp); grep -v "$RSSH_MARKER" "$ak" >"$tmp" 2>/dev/null || true; cat "$tmp" >"$ak"; rm -f "$tmp"
    printf 'restrict,port-forwarding,permitlisten="127.0.0.1:%s" %s %s\n' "$socks_port" "$pubkey" "$RSSH_MARKER" >>"$ak"
    chown "$RSSH_USER:$RSSH_USER" "$ak"; chmod 600 "$ak"
}
rssh_install_dedicated_sshd(){
    local turkey_ip="$1" sshd_port="$2" socks_port="$3"
    valid_ipv4 "$turkey_ip" || return 2; valid_port "$sshd_port" || return 2; valid_port "$socks_port" || return 2; rssh_create_restricted_user || return 1
    cat >"$RSSH_SSHD_CONFIG" <<EOF2
Port ${sshd_port}
ListenAddress 0.0.0.0
AddressFamily inet
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
PidFile /run/sshd-reverse-tunnel.pid
AuthorizedKeysFile .ssh/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
AllowUsers ${RSSH_USER}@${turkey_ip}
AllowTcpForwarding remote
PermitListen 127.0.0.1:${socks_port}
GatewayPorts no
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
Ciphers aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 30
ClientAliveCountMax 3
TCPKeepAlive yes
LogLevel VERBOSE
UsePAM yes
EOF2
    /usr/sbin/sshd -t -f "$RSSH_SSHD_CONFIG" || return 1
    cat >"/etc/systemd/system/${RSSH_SSHD_SERVICE}" <<EOF2
[Unit]
Description=Dedicated SSH receiver for Turkey reverse tunnel
After=network.target
[Service]
Type=simple
ExecStartPre=/bin/sh -c '/usr/sbin/iptables -C INPUT -p tcp -s ${turkey_ip} --dport ${sshd_port} -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -p tcp -s ${turkey_ip} --dport ${sshd_port} -j ACCEPT'
ExecStartPre=/bin/sh -c '/usr/sbin/iptables -C INPUT -p tcp --dport ${sshd_port} -j DROP 2>/dev/null || /usr/sbin/iptables -A INPUT -p tcp --dport ${sshd_port} -j DROP'
ExecStart=/usr/sbin/sshd -D -e -f ${RSSH_SSHD_CONFIG}
ExecStopPost=/bin/sh -c '/usr/sbin/iptables -D INPUT -p tcp -s ${turkey_ip} --dport ${sshd_port} -j ACCEPT 2>/dev/null || true; /usr/sbin/iptables -D INPUT -p tcp --dport ${sshd_port} -j DROP 2>/dev/null || true'
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
[Install]
WantedBy=multi-user.target
EOF2
    systemctl daemon-reload; systemctl enable "$RSSH_SSHD_SERVICE" >/dev/null 2>&1 || return 1; systemctl restart "$RSSH_SSHD_SERVICE" >/dev/null 2>&1 || return 1
    # Dedicated tunnel SSH port is reachable only from the configured Turkey IP.
    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -p tcp -s "$turkey_ip" --dport "$sshd_port" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp -s "$turkey_ip" --dport "$sshd_port" -j ACCEPT
        iptables -C INPUT -p tcp --dport "$sshd_port" -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport "$sshd_port" -j DROP
        command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    fi
}
rssh_write_foreign_service(){
    local iran_host="$1" ssh_port="$2" socks_port="$3"
    valid_host "$iran_host" || return 2; valid_port "$ssh_port" || return 2; valid_port "$socks_port" || return 2; mkdir -p "$RSSH_DIR"; chmod 700 "$RSSH_DIR"; touch "$RSSH_KNOWN_HOSTS"; chmod 600 "$RSSH_KNOWN_HOSTS"
    cat >"$RSSH_ENV" <<EOF2
IRAN_HOST=${iran_host}
IRAN_SSH_PORT=${ssh_port}
IRAN_SOCKS_PORT=${socks_port}
IRAN_SSH_USER=${RSSH_USER}
EOF2
    chmod 600 "$RSSH_ENV"
    cat >"/etc/systemd/system/${RSSH_SERVICE}" <<EOF2
[Unit]
Description=Persistent reverse SSH tunnel from Turkey to Iran
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
ExecStart=/usr/bin/ssh -NT -i ${RSSH_KEY} -p ${ssh_port} -R 127.0.0.1:${socks_port} -o BatchMode=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes -o Compression=no -o IPQoS=throughput -o ConnectTimeout=8 -o ConnectionAttempts=3 -o Ciphers=$(rssh_pick_cipher) -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${RSSH_KNOWN_HOSTS} ${RSSH_USER}@${iran_host}
Restart=always
RestartSec=3
TimeoutStopSec=10
LimitNOFILE=131072
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${RSSH_DIR}
ProtectHome=true
[Install]
WantedBy=multi-user.target
EOF2
    systemctl daemon-reload; systemctl enable "$RSSH_SERVICE" >/dev/null 2>&1 || return 1; systemctl restart "$RSSH_SERVICE" >/dev/null 2>&1 || true
}
rssh_wait_listener(){ local port="$1" timeout="${2:-45}" i; for((i=0;i<timeout;i++)); do ss -H -ltn 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$"{f=1}END{exit !f}' && return 0; sleep 1; done; return 1; }
rssh_test_socks(){
    # Do not use a single public-IP service as a tunnel health oracle. Some
    # providers intermittently throttle VPS traffic and can trigger false
    # kill-switch failures. Probe a fixed Cloudflare endpoint first and retry.
    local port="${1:-$(rssh_socks_port)}" timeout="${2:-15}" body ip i per_try
    valid_port "$port" || return 2
    per_try=$(( timeout / 3 )); (( per_try < 3 )) && per_try=3; (( per_try > 8 )) && per_try=8
    : > /tmp/reverse-ssh-curl.err 2>/dev/null || true
    for i in 1 2 3; do
        body=$(curl -4kfsS --max-time "$per_try" --connect-timeout 3           --socks5 "127.0.0.1:${port}" https://1.1.1.1/cdn-cgi/trace           2>>/tmp/reverse-ssh-curl.err || true)
        ip=$(printf '%s\n' "$body" | awk -F= '$1=="ip"{print $2; exit}' | tr -d '[:space:]')
        if [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
            echo "$ip"; return 0
        fi
        sleep 0.4
    done
    return 1
}
rssh_rotate_key(){
    rssh_ensure_client || return 1; mkdir -p "$RSSH_DIR"; local stamp; stamp=$(date +%Y%m%d-%H%M%S)
    [[ -f "$RSSH_KEY" ]] && mv "$RSSH_KEY" "${RSSH_KEY}.old-${stamp}"; [[ -f "${RSSH_KEY}.pub" ]] && mv "${RSSH_KEY}.pub" "${RSSH_KEY}.pub.old-${stamp}"
    ssh-keygen -q -t ed25519 -a 64 -f "$RSSH_KEY" -N '' -C "$RSSH_MARKER" || return 1; chmod 600 "$RSSH_KEY"; chmod 644 "${RSSH_KEY}.pub"
    systemctl restart "$RSSH_SERVICE" >/dev/null 2>&1 || true
}
rssh_remove_iran_authorization(){
    local ak="$RSSH_HOME/.ssh/authorized_keys" tmp; [[ -f "$ak" ]] || return 0; tmp=$(mktemp); grep -v "$RSSH_MARKER" "$ak" >"$tmp" 2>/dev/null || true; cat "$tmp" >"$ak"; rm -f "$tmp"; chown "$RSSH_USER:$RSSH_USER" "$ak" 2>/dev/null || true
}
rssh_security_audit(){
    local p="${1:-$(rssh_socks_port)}" ip
    echo "Restricted user       : $(id "$RSSH_USER" >/dev/null 2>&1 && echo OK || echo MISSING)"
    echo "Dedicated Iran sshd   : $(systemctl is-active --quiet "$RSSH_SSHD_SERVICE" 2>/dev/null && echo RUNNING || echo NOT-RUNNING)"
    echo "Turkey connector      : $(systemctl is-active --quiet "$RSSH_SERVICE" 2>/dev/null && echo RUNNING || echo NOT-RUNNING)"
    [[ -f "$RSSH_SSHD_CONFIG" ]] && grep -E '^(Port|AllowUsers|AllowTcpForwarding|PermitListen|GatewayPorts|PasswordAuthentication|PermitRootLogin) ' "$RSSH_SSHD_CONFIG" | sed 's/^/  /'
    ip=$(rssh_test_socks "$p" 10 || true); echo "Turkey egress         : ${ip:-FAILED}"
    echo "TCP tuning            : $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?') / $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
}
