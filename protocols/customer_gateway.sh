#!/usr/bin/env bash
# Customer Gateway v4.3.0: domain-first endpoint + external-path VLESS/Reality validation via the foreign exit.
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

cgw_exit_port(){
    local p
    p=$(cgw_state_get exit_socks_port 2>/dev/null || true)
    valid_port "$p" && echo "$p" || rssh_socks_port
}

cgw_client_host() {
    local h
    h=$(cgw_state_get client_host 2>/dev/null || true)
    [[ -n "$h" ]] || h=$(cgw_state_get host 2>/dev/null || true)
    printf '%s\n' "$h"
}

cgw_is_domain() {
    local h="$1"
    [[ -n "$h" && ! "$h" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && "$h" == *.* ]]
}

cgw_resolve_v4() {
    local h="$1"
    python3 - "$h" <<'PYDNS'
import socket,sys
h=sys.argv[1]
try:
    seen=[]
    for x in socket.getaddrinfo(h,None,socket.AF_INET,socket.SOCK_STREAM):
        ip=x[4][0]
        if ip not in seen: seen.append(ip)
    print(' '.join(seen))
except Exception:
    pass
PYDNS
}

cgw_domain_points_to_self() {
    local h="$1" self_ip ips
    cgw_is_domain "$h" || return 1
    self_ip=$(get_public_ip 2>/dev/null || true)
    [[ -n "$self_ip" && "$self_ip" != unknown ]] || return 2
    ips=$(cgw_resolve_v4 "$h")
    [[ " $ips " == *" $self_ip "* ]]
}

cgw_state_set() {
    local key="$1" value="$2"
    [[ -s "$CGW_STATE" ]] || return 1
    KEY="$key" VALUE="$value" STATE="$CGW_STATE" python3 - <<'PY2'
import json,os,tempfile
p=os.environ['STATE']; d=json.load(open(p)); d[os.environ['KEY']]=os.environ['VALUE']
fd,tmp=tempfile.mkstemp(prefix='.gateway.',suffix='.json',dir=os.path.dirname(p)); os.close(fd)
with open(tmp,'w') as f: json.dump(d,f,indent=2)
os.chmod(tmp,0o600); os.replace(tmp,p)
PY2
}

cgw_rebuild_if_installed() {
    cgw_installed || return 0
    [[ -x "$CGW_REBUILD" ]] || return 0
    "$CGW_REBUILD" >/dev/null 2>&1
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
host=s.get('client_host') or s.get('host')
endpoint=f'[{host}]' if ':' in host and not host.startswith('[') else host
print(f"vless://{os.environ['UUID']}@{endpoint}:{s['port']}?{urllib.parse.urlencode(q)}#{label}")
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
   'streamSettings':{'method':'raw','security':'reality','realitySettings':{'show':False,'target':state['sni']+':443','xver':0,'serverNames':[state['sni']],'privateKey':state['private_key'],'shortIds':[state['short_id']]}}}
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

class SafeHTTPServer(ThreadingHTTPServer):
 daemon_threads=True
 allow_reuse_address=True
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
 host=st.get('client_host') or st.get('host')
 endpoint=f'[{host}]' if ':' in host and not host.startswith('[') else host
 return f"vless://{r['uuid']}@{endpoint}:{st['port']}?{urllib.parse.urlencode(q)}#{urllib.parse.quote(r['label'] or 'User',safe='')}"
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
   tok=urllib.parse.unquote(self.path.split('/sub/',1)[1].split('?',1)[0].strip('/'))
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
st=json.load(open(STATE));srv=SafeHTTPServer(('0.0.0.0',int(st['sub_port'])),H)
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
UMask=0077
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
UMask=0077
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
# Conservative kill-switch: use a fixed, highly available endpoint and require
# repeated consecutive failures before stopping the customer gateway.
f=/run/customer-gateway-watchdog.fail
port=$(python3 - <<'PY'
import json
try: print(int(json.load(open('/etc/customer-gateway/gateway.json')).get('exit_socks_port',10808)))
except Exception: print(10808)
PY
)
n=0
[[ -f "$f" ]] && n=$(cat "$f" 2>/dev/null || echo 0)
probe(){
  local body ip i
  for i in 1 2; do
    body=$(curl -4kfsS --connect-timeout 3 --max-time 6 --socks5 "127.0.0.1:${port}" https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
    ip=$(printf '%s\n' "$body" | awk -F= '$1=="ip"{print $2;exit}' | tr -d '[:space:]')
    [[ -n "$ip" ]] && return 0
    sleep 1
  done
  return 1
}
if probe; then
  echo 0 >"$f"
  systemctl is-active --quiet customer-gateway.service || systemctl start customer-gateway.service >/dev/null 2>&1 || true
else
  n=$((n+1)); echo "$n" >"$f"
  (( n >= 5 )) && systemctl stop customer-gateway.service >/dev/null 2>&1 || true
fi
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
    local d="${BASE_DIR}/backups" f; mkdir -p "$d"; db_checkpoint || return 1; f="$d/gateway-$(date +%Y%m%d-%H%M%S).tar.gz"
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

cgw_probe_tcp_via_socks(){
    local host="$1" port="$2" socks_port="$3" result rc
    result=$(HOST="$host" PORT="$port" SOCKS_PORT="$socks_port" python3 - <<'PYTCP'
import os, socket, struct, sys
host=os.environ['HOST'].strip().strip('[]')
port=int(os.environ['PORT'])
socks=int(os.environ['SOCKS_PORT'])
def readn(s,n):
    b=b''
    while len(b)<n:
        x=s.recv(n-len(b))
        if not x: raise OSError('proxy closed connection')
        b+=x
    return b
try:
    with socket.create_connection(('127.0.0.1',socks),timeout=8) as s:
        s.settimeout(8)
        s.sendall(b'\x05\x01\x00')
        if readn(s,2) != b'\x05\x00': raise OSError('SOCKS5 no-auth negotiation failed')
        try:
            ip=socket.inet_pton(socket.AF_INET,host); req=b'\x05\x01\x00\x01'+ip+struct.pack('!H',port)
        except OSError:
            try:
                ip=socket.inet_pton(socket.AF_INET6,host); req=b'\x05\x01\x00\x04'+ip+struct.pack('!H',port)
            except OSError:
                name=host.encode('idna')
                if not name or len(name)>255: raise OSError('invalid endpoint hostname')
                req=b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H',port)
        s.sendall(req)
        h=readn(s,4)
        if h[0] != 5: raise OSError('invalid SOCKS5 response')
        if h[1] != 0: raise OSError('SOCKS5 CONNECT reply='+str(h[1]))
        atyp=h[3]
        if atyp==1: readn(s,4)
        elif atyp==3: readn(s,readn(s,1)[0])
        elif atyp==4: readn(s,16)
        else: raise OSError('invalid SOCKS5 address type')
        readn(s,2)
    print('TCP_REACHABLE')
except Exception as e:
    print(type(e).__name__+': '+str(e))
    sys.exit(1)
PYTCP
); rc=$?
    if ((rc==0)); then echo "$result"; return 0; fi
    echo "TCP_UNREACHABLE ${result:-unknown}"; return 1
}

cgw_local_client_test(){
    cgw_installed || { echo "GATEWAY_NOT_CONFIGURED"; return 2; }
    systemctl is-active --quiet "$CGW_SERVICE" 2>/dev/null || { echo "GATEWAY_NOT_RUNNING"; return 3; }
    local uuid state_port client_host sni pub sid test_port tmp log pid out expected i err_start access_start exit_port tcp_probe
    exit_port=$(cgw_exit_port)
    uuid=$(cgw_pick_test_user 2>/dev/null || true)
    [[ -n "$uuid" ]] || { echo "NO_ACTIVE_USER"; return 4; }
    state_port=$(cgw_state_get port)
    client_host=$(cgw_client_host)
    sni=$(cgw_state_get sni); pub=$(cgw_state_get public_key); sid=$(cgw_state_get short_id)

    # Prove the reverse SOCKS first. Then dial the public customer endpoint THROUGH
    # that SOCKS so the probe exits from the foreign server and re-enters Iran like
    # a real remote client. This avoids false negatives from same-host loopback.
    expected=$(rssh_test_socks "$exit_port" 12 || true)
    [[ -n "$expected" ]] || { echo "FOREIGN_SOCKS_FAILED"; return 5; }
    [[ -n "$client_host" ]] || { echo "CLIENT_ENDPOINT_MISSING"; return 6; }
    tcp_probe=$(cgw_probe_tcp_via_socks "$client_host" "$state_port" "$exit_port") || {
        echo "EXTERNAL_ENDPOINT_UNREACHABLE endpoint=${client_host}:${state_port} via_foreign_exit=${expected} ${tcp_probe}"
        return 7
    }
    echo "EXTERNAL_ENDPOINT_REACHABLE endpoint=${client_host}:${state_port} via_foreign_exit=${expected}"

    test_port=19081
    for i in $(seq 19081 19120); do
        if ! ss -H -ltn 2>/dev/null | awk -v p=":$i" '$4 ~ p"$"{f=1}END{exit !f}'; then test_port=$i; break; fi
    done
    ss -H -ltn 2>/dev/null | awk -v p=":$test_port" '$4 ~ p"$"{f=1}END{exit f}' || { echo "NO_FREE_TEST_PORT"; return 6; }
    tmp=$(mktemp --suffix=.json); log=$(mktemp)
    err_start=$(wc -l </var/log/customer-gateway-error.log 2>/dev/null || echo 0)
    access_start=$(wc -l </var/log/customer-gateway-access.log 2>/dev/null || echo 0)

    UUID="$uuid" HOST="$client_host" PORT="$state_port" SNI="$sni" PUB="$pub" SID="$sid" LPORT="$test_port" EXITPORT="$exit_port" python3 - "$tmp" <<'PYTEST'
import json,os,sys
cfg={
 'log':{'loglevel':'debug'},
 'inbounds':[{'listen':'127.0.0.1','port':int(os.environ['LPORT']),'protocol':'socks','settings':{'auth':'noauth','udp':False}}],
 'outbounds':[
  {
   'tag':'proxy','protocol':'vless',
   'settings':{'address':os.environ['HOST'],'port':int(os.environ['PORT']),'id':os.environ['UUID'],'encryption':'none'},
   'streamSettings':{'method':'raw','security':'reality','realitySettings':{
      'serverName':os.environ['SNI'],'fingerprint':'chrome','password':os.environ['PUB'],'shortId':os.environ['SID'],'spiderX':'/'
   }},
   'proxySettings':{'tag':'foreign-hop','transportLayer':False},
   'targetStrategy':'UseIPv4'
  },
  {'tag':'foreign-hop','protocol':'socks','settings':{'address':'127.0.0.1','port':int(os.environ['EXITPORT'])}}
 ]
}
with open(sys.argv[1],'w') as f: json.dump(cfg,f)
PYTEST
    "$XRAY_BIN" run -test -config "$tmp" >"$log" 2>&1 || { cat "$log"; rm -f "$tmp" "$log"; return 7; }
    "$XRAY_BIN" run -config "$tmp" >"$log" 2>&1 & pid=$!
    for i in 1 2 3 4 5; do
        sleep 0.4
        ss -H -ltn 2>/dev/null | awk -v p=":$test_port" '$4 ~ p"$"{f=1}END{exit !f}' && break
    done
    local trace
    trace=$(curl -4kfsS --connect-timeout 6 --max-time 20 --socks5 "127.0.0.1:${test_port}" https://1.1.1.1/cdn-cgi/trace 2>/dev/null || true)
    out=$(printf '%s\n' "$trace" | awk -F= '$1=="ip"{print $2;exit}' | tr -d '[:space:]')
    kill "$pid" >/dev/null 2>&1 || true; wait "$pid" 2>/dev/null || true
    if [[ -n "$out" && "$out" == "$expected" ]]; then rm -f "$tmp" "$log"; echo "$out"; return 0; fi

    echo "EXTERNAL_REALITY_FAILED endpoint=${client_host}:${state_port} expected_exit=${expected:-?} got=${out:-none}"
    sed -n '1,180p' "$log" | sed 's/^/XRAY_CLIENT: /'
    if [[ -s /var/log/customer-gateway-error.log ]]; then
        echo "SERVER_ERROR_LOG_NEW:"
        sed -n "$((err_start+1)),\$p" /var/log/customer-gateway-error.log | tail -n 80 | sed 's/^/XRAY_SERVER: /'
    fi
    if [[ -s /var/log/customer-gateway-access.log ]]; then
        echo "SERVER_ACCESS_LOG_NEW:"
        sed -n "$((access_start+1)),\$p" /var/log/customer-gateway-access.log | tail -n 60 | sed 's/^/XRAY_SERVER_ACCESS: /'
    fi
    rm -f "$tmp" "$log"; return 8
}

cgw_probe_reality_sni(){
    local sni="$1"
    [[ -n "$sni" ]] || return 1
    timeout 10 openssl s_client -connect "${sni}:443" -servername "$sni" </dev/null 2>/dev/null | grep -q 'BEGIN CERTIFICATE'
}

cgw_reality_target_test(){
    local sni
    sni=$(cgw_state_get sni 2>/dev/null || true); [[ -n "$sni" ]] || return 1
    cgw_probe_reality_sni "$sni"
}

cgw_security_audit(){
    local scheme host port exit exit_port
    exit_port=$(cgw_exit_port)
    valid_port "$exit_port" || exit_port=10808
    scheme=$(cgw_state_get sub_scheme 2>/dev/null || echo http); host=$(cgw_state_get sub_host 2>/dev/null || true); port=$(cgw_state_get sub_port 2>/dev/null || true)
    echo "Subscription           : ${scheme}://${host}:${port}"
    [[ "$scheme" == https ]] && print_success "HTTPS subscription enabled." || print_warn "Subscription uses HTTP."
    ss -H -ltn 2>/dev/null | grep -q "127.0.0.1:${exit_port}" && print_success "Turkey SOCKS is loopback-only." || print_warn "Reverse SOCKS listener is missing."
    systemctl is-active --quiet customer-gateway-watchdog.timer 2>/dev/null && print_success "Kill-switch watchdog active." || print_warn "Kill-switch watchdog inactive."
    systemctl is-active --quiet fail2ban 2>/dev/null && print_success "Fail2ban active." || print_warn "Fail2ban inactive."
    exit=$(rssh_test_socks "$(cgw_exit_port)" 10 || true); [[ -n "$exit" ]] && print_success "Turkey egress healthy: $exit" || print_error "Turkey egress failed."
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
    local exit_port exit_ip; exit_port=$(rssh_socks_port); exit_ip=$(rssh_test_socks "$exit_port" 15 || true)
    [[ -n "$exit_ip" ]] || { print_error "Turkey tunnel is not healthy on 127.0.0.1:${exit_port}. Configure Tunnel first."; press_enter; return 1; }
    print_success "Turkey exit verified: $exit_ip"
    xray_ensure || { press_enter; return 1; }; ensure_packages python3 openssl cron iptables ca-certificates || { press_enter; return 1; }; db_init || { press_enter; return 1; }

    local old=0 host port sub_port sni sid priv pub kp cur_scheme cur_subhost cur_cert cur_key keep_keys detected_ip legacy_host
    detected_ip=$(get_public_ip 2>/dev/null || true)
    exit_port=$(rssh_socks_port)
    if [[ -s "$CGW_STATE" ]]; then
        old=1; legacy_host=$(cgw_state_get host); host=$(cgw_client_host); port=$(cgw_state_get port); sub_port=$(cgw_state_get sub_port); sni=$(cgw_state_get sni)
        sid=$(cgw_state_get short_id); priv=$(cgw_state_get private_key); pub=$(cgw_state_get public_key)
        cur_scheme=$(cgw_state_get sub_scheme); cur_subhost=$(cgw_state_get sub_host); cur_cert=$(cgw_state_get tls_cert); cur_key=$(cgw_state_get tls_key)
        # Prefer a configured customer domain. Subscription and VLESS may share one domain.
        if [[ -z "$(cgw_state_get client_host 2>/dev/null || true)" ]]; then
            if cgw_is_domain "$cur_subhost"; then host="$cur_subhost"; elif [[ -n "$detected_ip" && "$detected_ip" != unknown ]]; then host="$detected_ip"; fi
        fi
        print_info "Existing gateway detected. Current keys/certificate are preserved by default."
    else
        host="${detected_ip:-unknown}"; port="$CGW_DEFAULT_PORT"; sub_port="$CGW_DEFAULT_SUB_PORT"; sni="www.speedtest.net"
        cur_scheme=""; cur_subhost=""; cur_cert=""; cur_key=""
    fi
    ask host "  VLESS client endpoint (domain recommended)" "$host"
    if cgw_is_domain "$host"; then
        local resolved_v4; resolved_v4=$(cgw_resolve_v4 "$host")
        if [[ -n "$detected_ip" && "$detected_ip" != unknown && " $resolved_v4 " == *" $detected_ip "* ]]; then
            print_success "Client domain resolves directly to this Iran server: $host → $detected_ip"
        else
            print_warn "Client domain does not currently resolve directly to this Iran public IP (${detected_ip:-unknown})."
            print_info "Resolved IPv4: ${resolved_v4:-none}. Non-standard ports require a direct/DNS-only record unless your DNS proxy explicitly supports them."
            confirm "Continue with this client domain anyway?" n || { press_enter; return 1; }
        fi
    fi
    ask port "  VLESS Reality TCP port" "$port"; valid_port "$port" || { print_error "Invalid port."; press_enter; return 1; }
    valid_host "$host" && [[ "$host" != unknown ]] || { print_error "Invalid VLESS endpoint host."; press_enter; return 1; }
    ask sub_port "  Subscription port" "$sub_port"; valid_port "$sub_port" || { print_error "Invalid subscription port."; press_enter; return 1; }
    ask sni "  Reality camouflage SNI" "$sni"
    cgw_is_domain "$sni" || { print_error "Reality SNI must be a DNS hostname."; press_enter; return 1; }
    if cgw_probe_reality_sni "$sni"; then
        print_success "REALITY target responds to TLS from this Iran server: ${sni}:443"
    else
        print_warn "REALITY target ${sni}:443 did not complete a TLS certificate handshake from this server."
        confirm "Continue with this SNI anyway?" n || { print_info "Re-run Setup and choose a reachable TLS target."; press_enter; return 1; }
    fi
    cgw_configure_subscription_tls "${cur_subhost:-$host}" "$cur_scheme" "$cur_subhost" "$cur_cert" "$cur_key" || { print_error "Subscription security setup failed."; press_enter; return 1; }
    valid_host "$CGW_TLS_HOST" || { print_error "Invalid subscription host."; press_enter; return 1; }
    if [[ "$CGW_TLS_SCHEME" == https ]] && ! cgw_is_domain "$CGW_TLS_HOST"; then print_error "HTTPS subscription requires a DNS hostname with a valid certificate."; press_enter; return 1; fi

    # If the operator kept the auto-detected IP at the first prompt but then configured
    # a valid HTTPS subscription domain that points directly to this VPS, use that same
    # domain for VLESS links too. This keeps customer configs domain-based by default.
    if cgw_is_domain "$CGW_TLS_HOST" && [[ "$host" == "$detected_ip" || -z "$host" ]]; then
        local tls_ips; tls_ips=$(cgw_resolve_v4 "$CGW_TLS_HOST")
        if [[ -n "$detected_ip" && "$detected_ip" != unknown && " $tls_ips " == *" $detected_ip "* ]]; then
            host="$CGW_TLS_HOST"
            print_success "Using the HTTPS domain for customer VLESS links too: $host"
        fi
    fi

    if ((old)) && [[ -n "$priv" && -n "$pub" && -n "$sid" ]]; then
        keep_keys=y; confirm "Keep existing Reality key pair (recommended)?" y || keep_keys=n
    else keep_keys=n; fi
    if [[ "$keep_keys" != y ]]; then
        sid=$(openssl rand -hex 4) || return 1; kp=$(xray_generate_reality_keypair) || { print_error "Reality key generation failed."; press_enter; return 1; }; priv=${kp%%|*}; pub=${kp#*|}
    fi

    mkdir -p "$CGW_DIR"
    HOST="$host" PORT="$port" SUB="$sub_port" EXITPORT="$exit_port" SNI="$sni" SID="$sid" PRIV="$priv" PUB="$pub" SUBSCHEME="$CGW_TLS_SCHEME" SUBHOST="$CGW_TLS_HOST" TLSCERT="$CGW_TLS_CERT" TLSKEY="$CGW_TLS_KEY" python3 - <<'PY'
import json,os
s={'client_host':os.environ['HOST'],'host':os.environ['HOST'],'port':int(os.environ['PORT']),'sub_port':int(os.environ['SUB']),'sni':os.environ['SNI'],'short_id':os.environ['SID'],'private_key':os.environ['PRIV'],'public_key':os.environ['PUB'],'exit_socks_port':int(os.environ['EXITPORT']),'stats_port':10085,'sub_scheme':os.environ.get('SUBSCHEME','http'),'sub_host':os.environ.get('SUBHOST') or os.environ['HOST'],'tls_cert':os.environ.get('TLSCERT',''),'tls_key':os.environ.get('TLSKEY','')}
tmp='/etc/customer-gateway/.gateway.json.new'
with open(tmp,'w') as f: json.dump(s,f,indent=2); f.write('\n')
os.chmod(tmp,0o600); os.replace(tmp,'/etc/customer-gateway/gateway.json')
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
    echo -e "  Client endpoint : ${CYAN}${host}:${port}${NC} ${DIM}(subscription domain may be different)${NC}"
    echo -e "  Subscription    : ${CYAN}${CGW_TLS_SCHEME}://${CGW_TLS_HOST}:${sub_port}/sub/<user-token>${NC}"
    echo -e "  Turkey exit IP  : ${CYAN}${exit_ip}${NC}\n"
    print_info "Create users from User Management. Each user gets an individual quota, expiry and subscription URL."
    print_info "Server runtime is pinned to Xray-core 26.7.28. Customer links use the configured domain when it resolves directly to this VPS."
    press_enter
}

cgw_upgrade_runtime(){
    print_banner; print_header "Upgrade / Repair Customer Gateway"
    cgw_installed || { print_error "Customer Gateway is not configured yet."; press_enter; return 1; }
    local port sub_port scheme rc rt detected_ip existing_client
    port=$(cgw_state_get port); sub_port=$(cgw_state_get sub_port); scheme=$(cgw_state_get sub_scheme); [[ -n "$scheme" ]] || scheme=http
    existing_client=$(cgw_state_get client_host 2>/dev/null || true)
    detected_ip=$(get_public_ip 2>/dev/null || true)
    local sub_host resolved_v4
    sub_host=$(cgw_state_get sub_host 2>/dev/null || true)
    # Earlier versions could migrate VLESS links to an IP. Prefer the configured
    # domain again, but only if it resolves directly to this VPS.
    if cgw_is_domain "$sub_host"; then
        resolved_v4=$(cgw_resolve_v4 "$sub_host")
        if [[ -n "$detected_ip" && "$detected_ip" != unknown && " $resolved_v4 " == *" $detected_ip "* ]]; then
            if [[ "$existing_client" != "$sub_host" ]]; then
                cgw_state_set client_host "$sub_host" || true
                cgw_state_set host "$sub_host" || true
                print_success "Customer VLESS endpoint normalized to domain: $sub_host → $detected_ip"
            fi
        elif [[ -z "$existing_client" && -n "$detected_ip" && "$detected_ip" != unknown ]]; then
            cgw_state_set client_host "$detected_ip" || true
            print_warn "Configured domain does not resolve directly to this VPS; kept IP as the endpoint."
        fi
    elif [[ -z "$existing_client" && -n "$detected_ip" && "$detected_ip" != unknown ]]; then
        cgw_state_set client_host "$detected_ip" || true
    fi
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
    if ((rc==0)); then
        print_success "VLESS/REALITY → Turkey self-test passed: $rt"
    elif ((rc==4)); then
        print_info "Client-path self-test skipped: no active customer."
    else
        print_error "Client-path self-test FAILED. Runtime is not being reported healthy."
        printf '%s\n' "$rt" | sed 's/^/  /'
        press_enter
        return 1
    fi
    print_success "Runtime upgrade/repair completed and validated end-to-end."
    press_enter
}

cgw_status(){
    print_banner; print_header "Customer Gateway Status"
    service_status_line "$CGW_SERVICE" "Customer VLESS gateway"; service_status_line "$CGW_SUB_SERVICE" "Subscription service"; service_status_line customer-gateway-watchdog.timer "Kill-switch watchdog"
    local exit xv; exit=$(rssh_test_socks "$(cgw_exit_port)" 10 || true); xv=$(xray_current_version 2>/dev/null || true)
    echo -e "  Foreign exit            : ${CYAN}${exit:-FAILED}${NC}"
    if [[ "$xv" == "$XRAY_PINNED_VERSION" ]]; then
        echo -e "  Xray data-plane         : ${CYAN}v${xv} (pinned)${NC}"
    else
        echo -e "  Xray data-plane         : ${YELLOW}v${xv:-missing} (expected v${XRAY_PINNED_VERSION})${NC}"
    fi
    if [[ -s "$CGW_STATE" ]]; then
        echo -e "  Client endpoint         : ${CYAN}$(cgw_client_host):$(cgw_state_get port)${NC}"
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
