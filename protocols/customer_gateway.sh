#!/usr/bin/env bash
# Customer Gateway v3.0.16 hardened: VLESS+Reality on Iran -> local reverse-SSH SOCKS -> Turkey.
# Does not modify nginx, websites, or ports 80/443.

CGW_DIR="/etc/customer-gateway"
CGW_STATE="${CGW_DIR}/gateway.json"
CGW_XRAY_CONFIG="${CGW_DIR}/xray.json"
CGW_REBUILD="${CGW_DIR}/rebuild.py"
CGW_SYNC="${CGW_DIR}/sync_traffic.py"
CGW_SUB_SERVER="${CGW_DIR}/subscription_server.py"
CGW_SERVICE="customer-gateway.service"
CGW_SUB_SERVICE="customer-gateway-sub.service"
CGW_DEFAULT_PORT="24443"
CGW_DEFAULT_SUB_PORT="18080"

cgw_installed() { [[ -s "$CGW_STATE" && -f "/etc/systemd/system/${CGW_SERVICE}" ]]; }

cgw_state_get() {
    local key="$1"
    [[ -s "$CGW_STATE" ]] || return 1
    KEY="$key" STATE="$CGW_STATE" python3 - <<'PY'
import json, os
try:
    d=json.load(open(os.environ['STATE']))
    v=d.get(os.environ['KEY'], '')
    print(v if v is not None else '')
except Exception:
    pass
PY
}

cgw_rebuild_if_installed() {
    cgw_installed || return 0
    [[ -x "$CGW_REBUILD" ]] || return 0
    "$CGW_REBUILD" >/dev/null 2>&1 || true
}

cgw_enable_user() {
    local uuid="$1"
    cgw_installed || return 0
    db_enable_engine "$uuid" "gateway" >/dev/null 2>&1 || true
    cgw_rebuild_if_installed
}

cgw_build_link() {
    local uuid="$1" label="${2:-User}"
    [[ -s "$CGW_STATE" ]] || return 1
    UUID="$uuid" LABEL="$label" STATE="$CGW_STATE" python3 - <<'PY'
import json, os, urllib.parse
s=json.load(open(os.environ['STATE']))
label=urllib.parse.quote(os.environ['LABEL'], safe='')
q={'encryption':'none','security':'reality','sni':s['sni'],'fp':'chrome','pbk':s['public_key'],'sid':s['short_id'],'type':'tcp','headerType':'none','spx':'/'}
print(f"vless://{os.environ['UUID']}@{s['host']}:{s['port']}?{urllib.parse.urlencode(q)}#{label}")
PY
}

cgw_write_rebuild_script() {
    mkdir -p "$CGW_DIR"
    cat > "$CGW_REBUILD" <<'PY'
#!/usr/bin/env python3
import json, os, sqlite3, subprocess, sys
from datetime import datetime, timezone
DB='/etc/singbox-manager/data/users.db'
STATE='/etc/customer-gateway/gateway.json'
CFG='/etc/customer-gateway/xray.json'
XRAY='/usr/local/bin/xray'
SERVICE='customer-gateway.service'
if not os.path.exists(DB) or not os.path.exists(STATE): sys.exit(0)
state=json.load(open(STATE))
conn=sqlite3.connect(DB); conn.row_factory=sqlite3.Row
rows=conn.execute('SELECT * FROM users ORDER BY id').fetchall(); conn.close()
def active(r):
    if int(r['enabled'] or 0)!=1: return False
    try:e=json.loads(r['engines'] or '{}')
    except:e={}
    if not e.get('gateway'): return False
    exp=r['expires_at']
    if exp:
        try:
            d=datetime.fromisoformat(exp); d=d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc)>=d: return False
        except: pass
    q=float(r['quota_gb'] or 0)
    if q>0 and int(r['used_bytes'] or 0)>=int(q*1024**3): return False
    return True
users=[{'id':r['uuid'],'level':0,'email':r['uuid']} for r in rows if active(r)]
config={
 'log':{'loglevel':'warning','access':'/var/log/customer-gateway-access.log','error':'/var/log/customer-gateway-error.log'},
 'stats':{},
 'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
 'api':{'tag':'api','listen':'127.0.0.1:10085','services':['StatsService']},
 'inbounds':[
  {'listen':'0.0.0.0','port':int(state['port']),'protocol':'vless','tag':'customer-in','settings':{'users':users,'decryption':'none'},
   'streamSettings':{'method':'raw','security':'reality','realitySettings':{'show':False,'target':state['sni']+':443','xver':0,'serverNames':[state['sni']],'privateKey':state['private_key'],'minClientVer':'26.3.27','shortIds':[state['short_id']]}}}
 ],
 'outbounds':[
  {'protocol':'socks','tag':'turkey-exit','settings':{'address':'127.0.0.1','port':int(state['exit_socks_port'])}},
  {'protocol':'freedom','tag':'direct'}
 ],
 'routing':{'domainStrategy':'AsIs','rules':[
  {'type':'field','inboundTag':['customer-in'],'outboundTag':'turkey-exit'}
 ]}
}
new=json.dumps(config,indent=2,sort_keys=True)+'\n'
try: old=open(CFG).read()
except: old=''
if old==new and '--force' not in sys.argv: sys.exit(0)
tmp=CFG+'.new.json'
with open(tmp,'w') as f:
    f.write(new)
os.chmod(tmp,0o600)
r=subprocess.run([XRAY,'run','-test','-config',tmp],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
if r.returncode!=0:
    print(r.stdout,file=sys.stderr)
    try: os.unlink(tmp)
    except FileNotFoundError: pass
    sys.exit(1)
# Keep the previous validated config so a failed restart can be rolled back.
had_old=os.path.exists(CFG)
backup=old if had_old else None
os.replace(tmp,CFG)
r=subprocess.run(['systemctl','restart',SERVICE],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
active=subprocess.run(['systemctl','is-active','--quiet',SERVICE]).returncode==0
if r.returncode!=0 or not active:
    msg=(r.stdout or '').strip()
    if msg: print(msg,file=sys.stderr)
    if backup is not None:
        with open(CFG,'w') as f: f.write(backup)
        os.chmod(CFG,0o600)
        subprocess.run(['systemctl','restart',SERVICE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    else:
        try: os.unlink(CFG)
        except FileNotFoundError: pass
    sys.exit(1)
PY
    chmod 755 "$CGW_REBUILD"
}

cgw_write_sync_script() {
    cat > "$CGW_SYNC" <<'PY'
#!/usr/bin/env python3
import json,re,sqlite3,subprocess
from datetime import datetime, timezone
DB='/etc/singbox-manager/data/users.db'; XRAY='/usr/local/bin/xray'; REBUILD='/etc/customer-gateway/rebuild.py'
try:
    p=subprocess.run([XRAY,'api','statsquery','--server=127.0.0.1:10085','-reset=true'],capture_output=True,text=True,timeout=15)
    text=(p.stdout or '')
except: raise SystemExit(0)
acc={}
try:
    data=json.loads(text)
    for st in data.get('stat',[]):
        name=st.get('name',''); val=int(st.get('value',0) or 0)
        m=re.match(r'user>>>(.+?)>>>traffic>>>(?:uplink|downlink)$',name)
        if m: acc[m.group(1)]=acc.get(m.group(1),0)+val
except Exception:
    pat=re.compile(r'(?:"name"|name):\s*"user>>>([^">]+)>>>traffic>>>(?:uplink|downlink)".*?(?:"value"|value):\s*"?(\d+)"?',re.S)
    for uuid,val in pat.findall(text): acc[uuid]=acc.get(uuid,0)+int(val)
if acc:
    c=sqlite3.connect(DB); now=datetime.now(timezone.utc).isoformat()
    for uuid,delta in acc.items():
        if delta<=0: continue
        c.execute('UPDATE users SET used_bytes=used_bytes+?,last_seen=? WHERE uuid=?',(delta,now,uuid))
        c.execute("INSERT INTO traffic_log(uuid,engine,delta_bytes,recorded_at) VALUES (?,?,?,datetime('now'))",(uuid,'gateway',delta))
    c.commit(); c.close()
subprocess.run([REBUILD],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
PY
    chmod 755 "$CGW_SYNC"
}

cgw_write_subscription_server(){
cat >"$CGW_SUB_SERVER" <<'SUBPY'
#!/usr/bin/env python3
import base64,json,sqlite3,urllib.parse,ssl,time,threading,traceback
from collections import defaultdict,deque
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
DB='/etc/singbox-manager/data/users.db';STATE='/etc/customer-gateway/gateway.json';LOG='/var/log/customer-gateway-sub.log';lock=threading.Lock();allq=defaultdict(deque);badq=defaultdict(deque)
def throttle(ip,bad=False):
 now=time.time();q=badq[ip] if bad else allq[ip];cap=10 if bad else 90
 with lock:
  while q and q[0]<now-60:q.popleft()
  if len(q)>=cap:return False
  q.append(now);return True
def logbad(ip,tok):
 try:
  with open(LOG,'a') as f:f.write(f'AUTHFAIL {ip} token={tok[:8]}\n')
 except:pass
def active(r):
 if int(r['enabled'] or 0)!=1:return False,'disabled'
 try:e=json.loads(r['engines'] or '{}')
 except:e={}
 if not e.get('gateway'):return False,'gateway disabled'
 if r['expires_at']:
  try:
   d=datetime.fromisoformat(r['expires_at']);d=d if d.tzinfo else d.replace(tzinfo=timezone.utc)
   if datetime.now(timezone.utc)>=d:return False,'expired'
  except:pass
 q=float(r['quota_gb'] or 0)
 if q>0 and int(r['used_bytes'] or 0)>=int(q*1024**3):return False,'quota exceeded'
 return True,''
def link(r,st):
 q={'encryption':'none','security':'reality','sni':st['sni'],'fp':'chrome','pbk':st['public_key'],'sid':st['short_id'],'type':'tcp','headerType':'none','spx':'/'}
 return f"vless://{r['uuid']}@{st['host']}:{st['port']}?{urllib.parse.urlencode(q)}#{urllib.parse.quote(r['label'] or 'User',safe='')}"
class H(BaseHTTPRequestHandler):
 server_version='Subscription/1.1'
 def log_message(self,*a):pass
 def out(self,c,b=b''):
  self.send_response(c);self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
 def do_GET(self):
  ip=self.client_address[0]
  try:
   if not throttle(ip):return self.out(429,b'Too Many Requests')
   if not self.path.startswith('/sub/'):return self.out(404,b'Not Found')
   tok=self.path.split('/sub/',1)[1].split('?',1)[0].strip('/')
   c=sqlite3.connect(DB);c.row_factory=sqlite3.Row
   try:r=c.execute('SELECT * FROM users WHERE sub_token=?',(tok,)).fetchone()
   finally:c.close()
   if not r: throttle(ip,True);logbad(ip,tok);return self.out(401,b'Unauthorized')
   ok,why=active(r)
   if not ok:return self.out(403,why.encode())
   st=json.load(open(STATE));body=base64.b64encode((link(r,st)+'\n').encode());used=int(r['used_bytes'] or 0);total=int(float(r['quota_gb'] or 0)*1024**3);info=f'upload={used}; download=0; total={total}'
   if r['expires_at']:
    try:
     d=datetime.fromisoformat(r['expires_at']);d=d if d.tzinfo else d.replace(tzinfo=timezone.utc);info+=f'; expire={int(d.timestamp())}'
    except:pass
   self.send_response(200);self.send_header('Content-Type','text/plain; charset=utf-8');self.send_header('Cache-Control','no-store');self.send_header('subscription-userinfo',info);self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  except Exception as e:
   try:
    with open(LOG,'a') as f:f.write(f'ERROR {ip} {type(e).__name__}: {e}\n{traceback.format_exc()}\n')
   except:pass
   try:self.out(500,b'Internal Server Error')
   except:pass
st=json.load(open(STATE));srv=ThreadingHTTPServer(('0.0.0.0',int(st['sub_port'])),H)
if st.get('sub_scheme')=='https':
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(st['tls_cert'],st['tls_key']);srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
srv.serve_forever()
SUBPY
chmod 755 "$CGW_SUB_SERVER"
}

cgw_create_services(){
cat >"/etc/systemd/system/${CGW_SERVICE}" <<'UNIT'
[Unit]
Description=Customer VLESS Reality Gateway via Turkey reverse SOCKS
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /etc/customer-gateway/xray.json
Restart=on-failure
RestartSec=3
LimitNOFILE=262144
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
[Install]
WantedBy=multi-user.target
UNIT
cat >"/etc/systemd/system/${CGW_SUB_SERVICE}" <<'UNIT'
[Unit]
Description=Customer Gateway Subscription Server
After=network-online.target customer-gateway.service
[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/customer-gateway/subscription_server.py
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/log /etc/singbox-manager/data
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/customer-gateway/watchdog.sh <<'SH'
#!/usr/bin/env bash
f=/run/customer-gateway-watchdog.fail;n=0;[[ -f "$f" ]]&&n=$(cat "$f" 2>/dev/null||echo 0)
if curl -fsS --connect-timeout 4 --max-time 10 --socks5-hostname 127.0.0.1:10808 https://api.ipify.org >/dev/null 2>&1;then echo 0>"$f";systemctl is-active --quiet customer-gateway.service||systemctl start customer-gateway.service >/dev/null 2>&1||true;else n=$((n+1));echo "$n">"$f";((n>=3))&&systemctl stop customer-gateway.service >/dev/null 2>&1||true;fi
SH
chmod 755 /etc/customer-gateway/watchdog.sh
cat >/etc/systemd/system/customer-gateway-watchdog.service <<'UNIT'
[Unit]
Description=Customer Gateway kill-switch watchdog
[Service]
Type=oneshot
ExecStart=/etc/customer-gateway/watchdog.sh
UNIT
cat >/etc/systemd/system/customer-gateway-watchdog.timer <<'UNIT'
[Unit]
Description=Customer Gateway watchdog timer
[Timer]
OnBootSec=20s
OnUnitActiveSec=20s
AccuracySec=5s
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload;systemctl enable "$CGW_SERVICE" "$CGW_SUB_SERVICE" customer-gateway-watchdog.timer >/dev/null 2>&1||true;systemctl restart customer-gateway-watchdog.timer >/dev/null 2>&1||true
}

cgw_install_cron() {
    (crontab -l 2>/dev/null | grep -v 'customer-gateway/sync_traffic.py' || true; echo '* * * * * /usr/bin/python3 /etc/customer-gateway/sync_traffic.py >/dev/null 2>&1') | crontab -
}


cgw_configure_subscription_tls(){
    local default_host="$1" current_scheme="${2:-}" current_host="${3:-}" current_cert="${4:-}" current_key="${5:-}"
    local c h cert key email default_choice=1
    [[ "$current_scheme" == https && -r "$current_cert" && -r "$current_key" ]] && default_choice=2
    echo -e "\n  ${BOLD}Subscription security${NC}"
    echo -e "  ${CYAN}1)${NC} HTTP quick setup ${DIM}(works immediately; upgrade later)${NC}"
    echo -e "  ${CYAN}2)${NC} HTTPS with existing certificate ${DIM}(recommended)${NC}"
    echo -e "  ${CYAN}3)${NC} HTTPS via Certbot DNS-01 ${DIM}(does not use ports 80/443)${NC}"
    ask c "  Select" "$default_choice"
    case "$c" in
      1) CGW_TLS_SCHEME=http; CGW_TLS_HOST="${current_host:-$default_host}"; CGW_TLS_CERT=""; CGW_TLS_KEY="" ;;
      2)
        ask h "  Subscription domain" "${current_host:-$default_host}"
        ask cert "  Fullchain path" "${current_cert:-/etc/letsencrypt/live/${h}/fullchain.pem}"
        ask key "  Private key path" "${current_key:-/etc/letsencrypt/live/${h}/privkey.pem}"
        [[ -r "$cert" && -r "$key" ]] || { print_error "Certificate/key not readable."; return 1; }
        CGW_TLS_SCHEME=https; CGW_TLS_HOST="$h"; CGW_TLS_CERT="$cert"; CGW_TLS_KEY="$key" ;;
      3)
        ensure_packages certbot || return 1
        ask h "  Subscription domain" "${current_host:-$default_host}"
        ask email "  ACME email" "admin@${h#*.}"
        echo -e "\n  ${YELLOW}Certbot will show a DNS TXT record. Add that TXT record at your DNS provider, then continue.${NC}\n"
        certbot certonly --manual --preferred-challenges dns --agree-tos -m "$email" -d "$h" || return 1
        CGW_TLS_SCHEME=https; CGW_TLS_HOST="$h"; CGW_TLS_CERT="/etc/letsencrypt/live/${h}/fullchain.pem"; CGW_TLS_KEY="/etc/letsencrypt/live/${h}/privkey.pem" ;;
      *) return 1 ;;
    esac
}

cgw_install_sub_fail2ban(){
    command -v fail2ban-client >/dev/null 2>&1 || ensure_packages fail2ban || return 0
    mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d
    cat >/etc/fail2ban/filter.d/customer-gateway-sub.conf <<'F2B'
[Definition]
failregex = ^AUTHFAIL <HOST> .*$
ignoreregex =
F2B
    cat >/etc/fail2ban/jail.d/customer-gateway-sub.local <<'F2B'
[customer-gateway-sub]
enabled=true
filter=customer-gateway-sub
logpath=/var/log/customer-gateway-sub.log
backend=polling
maxretry=8
findtime=300
bantime=3600
action=iptables-allports[name=cgw-sub, protocol=all]
F2B
    touch /var/log/customer-gateway-sub.log
    systemctl enable fail2ban >/dev/null 2>&1 || true; systemctl restart fail2ban >/dev/null 2>&1 || true
}

cgw_backup(){
    local d="${BASE_DIR}/backups" f; mkdir -p "$d"; f="$d/gateway-$(date +%Y%m%d-%H%M%S).tar.gz"
    local items=(); [[ -f "$DB_PATH" ]] && items+=("$DB_PATH"); [[ -d "$CGW_DIR" ]] && items+=("$CGW_DIR"); [[ -d "$RSSH_DIR" ]] && items+=("$RSSH_DIR")
    ((${#items[@]})) || { print_error "Nothing to back up."; return 1; }
    tar -czf "$f" "${items[@]}" 2>/dev/null || return 1; chmod 600 "$f"; print_success "Backup created: $f"
}
cgw_restore_latest(){
    local f; f=$(ls -1t "${BASE_DIR}/backups"/gateway-*.tar.gz 2>/dev/null | head -1 || true)
    [[ -n "$f" ]] || { print_error "No backup found."; return 1; }; confirm "Restore $f?" n || return 0
    systemctl stop "$CGW_SERVICE" "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true
    tar -xzf "$f" -C / || return 1
    [[ -x "$CGW_REBUILD" ]] && "$CGW_REBUILD" --force >/dev/null 2>&1 || true
    systemctl restart "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true; print_success "Restored: $f"
}
cgw_pick_test_user(){
    [[ -f "$DB_PATH" ]] || return 1
    DB_PATH="$DB_PATH" python3 - <<'PY'
import json,sqlite3,os
from datetime import datetime,timezone
c=sqlite3.connect(os.environ['DB_PATH']); c.row_factory=sqlite3.Row
for r in c.execute('SELECT * FROM users ORDER BY created_at DESC'):
    if int(r['enabled'] or 0)!=1: continue
    try: e=json.loads(r['engines'] or '{}')
    except: e={}
    if not e.get('gateway'): continue
    if r['expires_at']:
        try:
            d=datetime.fromisoformat(r['expires_at']); d=d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc)>=d: continue
        except: pass
    q=float(r['quota_gb'] or 0)
    if q>0 and int(r['used_bytes'] or 0)>=int(q*1024**3): continue
    print(r['uuid']); break
c.close()
PY
}

cgw_local_client_test(){
    cgw_installed || { echo "GATEWAY_NOT_CONFIGURED"; return 2; }
    systemctl is-active --quiet "$CGW_SERVICE" 2>/dev/null || { echo "GATEWAY_NOT_RUNNING"; return 3; }
    local uuid state_port sni pub sid test_port tmp log pid out expected i
    uuid=$(cgw_pick_test_user 2>/dev/null || true)
    [[ -n "$uuid" ]] || { echo "NO_ACTIVE_USER"; return 4; }
    state_port=$(cgw_state_get port); sni=$(cgw_state_get sni); pub=$(cgw_state_get public_key); sid=$(cgw_state_get short_id)
    expected=$(rssh_test_socks 10808 12 || true)
    [[ -n "$expected" ]] || { echo "TURKEY_SOCKS_FAILED"; return 5; }
    test_port=19081
    for i in $(seq 19081 19120); do
        if ! ss -H -ltn 2>/dev/null | awk -v p=":$i" '$4 ~ p"$"{f=1}END{exit !f}'; then test_port=$i; break; fi
    done
    tmp=$(mktemp --suffix=.json); log=$(mktemp)
    UUID="$uuid" PORT="$state_port" SNI="$sni" PUB="$pub" SID="$sid" LPORT="$test_port" python3 - "$tmp" <<'PY'
import json,os,sys
cfg={
 'log':{'loglevel':'warning'},
 'inbounds':[{'listen':'127.0.0.1','port':int(os.environ['LPORT']),'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
 'outbounds':[{
   'tag':'proxy','protocol':'vless',
   'settings':{'address':'127.0.0.1','port':int(os.environ['PORT']),'id':os.environ['UUID'],'encryption':'none'},
   'streamSettings':{'method':'raw','security':'reality','realitySettings':{
      'serverName':os.environ['SNI'],'fingerprint':'chrome','password':os.environ['PUB'],'shortId':os.environ['SID']
   }}
 }]
}
with open(sys.argv[1],'w') as f: json.dump(cfg,f)
PY
    "$XRAY_BIN" run -test -config "$tmp" >"$log" 2>&1 || { cat "$log"; rm -f "$tmp" "$log"; return 6; }
    "$XRAY_BIN" run -config "$tmp" >"$log" 2>&1 & pid=$!
    for i in 1 2 3 4 5; do
        sleep 0.4
        ss -H -ltn 2>/dev/null | awk -v p=":$test_port" '$4 ~ p"$"{f=1}END{exit !f}' && break
    done
    out=$(curl -fsS --connect-timeout 5 --max-time 15 --socks5-hostname "127.0.0.1:${test_port}" https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)
    kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true
    if [[ -n "$out" && "$out" == "$expected" ]]; then rm -f "$tmp" "$log"; echo "$out"; return 0; fi
    echo "LOCAL_REALITY_FAILED expected=${expected:-?} got=${out:-none}"
    sed -n '1,80p' "$log" | sed 's/^/XRAY_CLIENT: /'
    rm -f "$tmp" "$log"; return 7
}

cgw_reality_target_test(){
    local sni out
    sni=$(cgw_state_get sni 2>/dev/null || true); [[ -n "$sni" ]] || return 1
    out=$(timeout 10 "$XRAY_BIN" tls ping "$sni" 2>&1 || true)
    if printf '%s' "$out" | grep -qiE 'TLS|certificate|handshake|X25519|MLKEM'; then return 0; fi
    timeout 8 openssl s_client -connect "${sni}:443" -servername "$sni" </dev/null >/dev/null 2>&1
}

cgw_security_audit(){
    local scheme host port exit
    scheme=$(cgw_state_get sub_scheme 2>/dev/null || echo http); host=$(cgw_state_get sub_host 2>/dev/null || true); port=$(cgw_state_get sub_port 2>/dev/null || true)
    echo "Subscription           : ${scheme}://${host}:${port}"
    [[ "$scheme" == https ]] && print_success "HTTPS subscription enabled." || print_warn "Subscription uses HTTP."
    ss -H -ltn 2>/dev/null | grep -q '127.0.0.1:10808' && print_success "Turkey SOCKS is loopback-only." || print_warn "Reverse SOCKS listener is missing."
    systemctl is-active --quiet customer-gateway-watchdog.timer 2>/dev/null && print_success "Kill-switch watchdog active." || print_warn "Kill-switch watchdog inactive."
    systemctl is-active --quiet fail2ban 2>/dev/null && print_success "Fail2ban active." || print_warn "Fail2ban inactive."
    exit=$(rssh_test_socks 10808 10 || true); [[ -n "$exit" ]] && print_success "Turkey egress healthy: $exit" || print_error "Turkey egress failed."
    if cgw_reality_target_test; then print_success "REALITY camouflage target is reachable from Iran."; else print_warn "REALITY camouflage target may be unreachable from Iran."; fi
    local rt; rt=$(cgw_local_client_test 2>&1); case $? in
      0) print_success "Local VLESS/REALITY → Turkey path works: $rt" ;;
      4) print_info "Local VLESS/REALITY test skipped: create an active customer first." ;;
      *) print_warn "Local VLESS/REALITY path test failed: $rt" ;;
    esac
}

cgw_setup(){
    print_banner; print_header "Customer Gateway — Iran Access for v2rayN"
    echo -e "  ${DIM}Clients connect to Iran with VLESS+Reality; all Internet egress uses the verified Turkey reverse-SSH tunnel.${NC}\n"
    local exit_ip; exit_ip=$(rssh_test_socks 10808 15 || true)
    [[ -n "$exit_ip" ]] || { print_error "Turkey tunnel is not healthy on 127.0.0.1:10808. Configure Tunnel first."; press_enter; return 1; }
    print_success "Turkey exit verified: $exit_ip"
    xray_ensure || { press_enter; return 1; }; ensure_packages python3 openssl cron iptables ca-certificates || { press_enter; return 1; }; db_init || { press_enter; return 1; }

    local old=0 host port sub_port sni sid priv pub kp cur_scheme cur_subhost cur_cert cur_key keep_keys
    if [[ -s "$CGW_STATE" ]]; then
        old=1; host=$(cgw_state_get host); port=$(cgw_state_get port); sub_port=$(cgw_state_get sub_port); sni=$(cgw_state_get sni)
        sid=$(cgw_state_get short_id); priv=$(cgw_state_get private_key); pub=$(cgw_state_get public_key)
        cur_scheme=$(cgw_state_get sub_scheme); cur_subhost=$(cgw_state_get sub_host); cur_cert=$(cgw_state_get tls_cert); cur_key=$(cgw_state_get tls_key)
        print_info "Existing gateway detected. Current keys are preserved by default."
    else
        host=$(get_public_ip 2>/dev/null || echo unknown); port="$CGW_DEFAULT_PORT"; sub_port="$CGW_DEFAULT_SUB_PORT"; sni="www.speedtest.net"
        cur_scheme=""; cur_subhost=""; cur_cert=""; cur_key=""
    fi
    ask host "  Iran public IP/domain for client links" "$host"
    ask port "  VLESS Reality TCP port" "$port"; valid_port "$port" || { print_error "Invalid port."; press_enter; return 1; }
    ask sub_port "  Subscription port" "$sub_port"; valid_port "$sub_port" || { print_error "Invalid subscription port."; press_enter; return 1; }
    ask sni "  Reality camouflage SNI" "$sni"
    cgw_configure_subscription_tls "$host" "$cur_scheme" "$cur_subhost" "$cur_cert" "$cur_key" || { print_error "Subscription security setup failed."; press_enter; return 1; }

    if ((old)) && [[ -n "$priv" && -n "$pub" && -n "$sid" ]]; then
        keep_keys=y; confirm "Keep existing Reality key pair (recommended)?" y || keep_keys=n
    else keep_keys=n; fi
    if [[ "$keep_keys" != y ]]; then
        sid=$(openssl rand -hex 4) || return 1; kp=$(xray_generate_reality_keypair) || { print_error "Reality key generation failed."; press_enter; return 1; }; priv=${kp%%|*}; pub=${kp#*|}
    fi

    mkdir -p "$CGW_DIR"
    HOST="$host" PORT="$port" SUB="$sub_port" SNI="$sni" SID="$sid" PRIV="$priv" PUB="$pub" SUBSCHEME="$CGW_TLS_SCHEME" SUBHOST="$CGW_TLS_HOST" TLSCERT="$CGW_TLS_CERT" TLSKEY="$CGW_TLS_KEY" python3 - <<'PY'
import json,os
s={'host':os.environ['HOST'],'port':int(os.environ['PORT']),'sub_port':int(os.environ['SUB']),'sni':os.environ['SNI'],'short_id':os.environ['SID'],'private_key':os.environ['PRIV'],'public_key':os.environ['PUB'],'exit_socks_port':10808,'stats_port':10085,'sub_scheme':os.environ.get('SUBSCHEME','http'),'sub_host':os.environ.get('SUBHOST') or os.environ['HOST'],'tls_cert':os.environ.get('TLSCERT',''),'tls_key':os.environ.get('TLSKEY','')}
with open('/etc/customer-gateway/gateway.json','w') as f:json.dump(s,f,indent=2)
os.chmod('/etc/customer-gateway/gateway.json',0o600)
PY
    # All existing users belong to the single retained gateway engine.
    DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,json,os
c=sqlite3.connect(os.environ['DB_PATH'])
for uid in [r[0] for r in c.execute('SELECT uuid FROM users')]: c.execute('UPDATE users SET engines=? WHERE uuid=?',(json.dumps({'gateway':True}),uid))
c.commit();c.close()
PY
    cgw_write_rebuild_script; cgw_write_sync_script; cgw_write_subscription_server; cgw_create_services
    if [[ "$CGW_TLS_SCHEME" == https ]]; then
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        cat >/etc/letsencrypt/renewal-hooks/deploy/customer-gateway-sub.sh <<'HOOK'
#!/usr/bin/env bash
systemctl restart customer-gateway-sub.service >/dev/null 2>&1 || true
HOOK
        chmod 755 /etc/letsencrypt/renewal-hooks/deploy/customer-gateway-sub.sh
    fi
    "$CGW_REBUILD" --force || { print_error "Gateway config validation failed; previous working config was preserved when possible."; press_enter; return 1; }
    systemctl restart "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true
    cgw_install_cron; open_port "$port" tcp; open_port "$sub_port" tcp; cgw_install_sub_fail2ban; sleep 1
    systemctl is-active --quiet "$CGW_SERVICE" || { print_error "Customer gateway failed to start."; journalctl -u "$CGW_SERVICE" -n 30 --no-pager | sed 's/^/  /'; press_enter; return 1; }
    systemctl is-active --quiet "$CGW_SUB_SERVICE" || { print_error "Subscription service failed to start."; journalctl -u "$CGW_SUB_SERVICE" -n 20 --no-pager | sed 's/^/  /'; press_enter; return 1; }
    local sub_probe_code
    sub_probe_code=$(curl -ksS --connect-timeout 3 --max-time 6 -o /dev/null -w '%{http_code}' "${CGW_TLS_SCHEME}://127.0.0.1:${sub_port}/sub/__gateway_health_probe__" 2>/dev/null || true)
    if [[ "$sub_probe_code" != "401" ]]; then
        print_error "Subscription self-test failed (HTTP ${sub_probe_code:-no-response})."
        journalctl -u "$CGW_SUB_SERVICE" -n 30 --no-pager | sed 's/^/  /'
        press_enter; return 1
    fi
    print_success "Subscription endpoint self-test passed."
    print_success "Customer gateway is ready."
    echo -e "  Client endpoint : ${CYAN}${host}:${port}${NC}"
    echo -e "  Subscription    : ${CYAN}${CGW_TLS_SCHEME}://${CGW_TLS_HOST}:${sub_port}/sub/<user-token>${NC}"
    echo -e "  Turkey exit IP  : ${CYAN}${exit_ip}${NC}\n"
    print_info "Create users from User Management. Each user gets an individual quota, expiry and subscription URL."
    print_info "Client requirement: v2rayN should use Xray-core 26.3.27 or newer for this REALITY profile."
    press_enter
}

cgw_upgrade_runtime(){
    print_banner; print_header "Upgrade / Repair Customer Gateway"
    cgw_installed || { print_error "Customer Gateway is not configured yet."; press_enter; return 1; }
    local port sub_port scheme rc rt
    port=$(cgw_state_get port); sub_port=$(cgw_state_get sub_port); scheme=$(cgw_state_get sub_scheme); [[ -n "$scheme" ]] || scheme=http
    xray_ensure || { press_enter; return 1; }
    ensure_packages python3 openssl cron iptables ca-certificates || { press_enter; return 1; }
    db_init || { press_enter; return 1; }
    print_info "Refreshing generated runtime files while preserving users, Reality keys, certificate and endpoints..."
    cgw_write_rebuild_script
    cgw_write_sync_script
    cgw_write_subscription_server
    cgw_create_services
    "$CGW_REBUILD" --force || { print_error "Gateway rebuild failed."; press_enter; return 1; }
    systemctl restart "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true
    cgw_install_cron
    open_port "$port" tcp; open_port "$sub_port" tcp
    cgw_install_sub_fail2ban
    sleep 1
    systemctl is-active --quiet "$CGW_SERVICE" || { print_error "Customer gateway is not running."; press_enter; return 1; }
    systemctl is-active --quiet "$CGW_SUB_SERVICE" || { print_error "Subscription service is not running."; press_enter; return 1; }
    local code
    code=$(curl -ksS --connect-timeout 3 --max-time 6 -o /dev/null -w '%{http_code}' "${scheme}://127.0.0.1:${sub_port}/sub/__gateway_health_probe__" 2>/dev/null || true)
    [[ "$code" == 401 ]] && print_success "Subscription runtime self-test passed." || print_warn "Subscription runtime returned HTTP ${code:-no-response}."
    rt=$(cgw_local_client_test 2>&1); rc=$?
    if ((rc==0)); then print_success "VLESS/REALITY → Turkey self-test passed: $rt"; elif ((rc==4)); then print_info "Client-path self-test skipped: no active customer."; else print_warn "Client-path self-test failed: $rt"; fi
    print_success "Runtime upgrade/repair completed without changing customer credentials or TLS certificate."
    press_enter
}

cgw_status(){
    print_banner; print_header "Customer Gateway Status"
    service_status_line "$CGW_SERVICE" "Customer VLESS gateway"; service_status_line "$CGW_SUB_SERVICE" "Subscription service"; service_status_line customer-gateway-watchdog.timer "Kill-switch watchdog"
    local exit; exit=$(rssh_test_socks 10808 10 || true); echo -e "  Turkey exit             : ${CYAN}${exit:-FAILED}${NC}"
    if [[ -s "$CGW_STATE" ]]; then
        echo -e "  Client endpoint         : ${CYAN}$(cgw_state_get host):$(cgw_state_get port)${NC}"
        echo -e "  Subscription endpoint   : ${CYAN}$(cgw_state_get sub_scheme)://$(cgw_state_get sub_host):$(cgw_state_get sub_port)${NC}"
    fi
    press_enter
}
cgw_remove(){
    confirm "Remove Customer Gateway services/config? User database is kept." n || return 0
    systemctl disable --now "$CGW_SERVICE" "$CGW_SUB_SERVICE" customer-gateway-watchdog.timer >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${CGW_SERVICE}" "/etc/systemd/system/${CGW_SUB_SERVICE}" /etc/systemd/system/customer-gateway-watchdog.{service,timer}
    (crontab -l 2>/dev/null | grep -v 'customer-gateway/sync_traffic.py' || true) | crontab - 2>/dev/null || true
    rm -rf "$CGW_DIR"; systemctl daemon-reload; print_success "Customer Gateway removed; users preserved."; press_enter
}
cgw_menu(){
    while true; do
        print_banner; print_header "Customer Gateway"
        echo -e "  ${CYAN}1)${NC} Setup / reconfigure ${DIM}(preserves Reality keys by default)${NC}"
        echo -e "  ${CYAN}2)${NC} Upgrade / repair runtime ${DIM}(no key/certificate changes)${NC}"
        echo -e "  ${CYAN}3)${NC} Status / health check"
        echo -e "  ${CYAN}4)${NC} Security audit"
        echo -e "  ${CYAN}5)${NC} Remove gateway"
        echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
        case "$MENU_CHOICE" in 1)cgw_setup;;2)cgw_upgrade_runtime;;3)cgw_status;;4)print_banner;print_header "Gateway Security Audit";cgw_security_audit;press_enter;;5)cgw_remove;;0)return;;*)print_warn "Invalid choice.";sleep 1;;esac
    done
}
