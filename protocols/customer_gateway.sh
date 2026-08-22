#!/usr/bin/env bash
# Customer Gateway: VLESS+Reality on Iran -> local reverse-SSH SOCKS -> Turkey.
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
q={'encryption':'none','security':'reality','sni':s['sni'],'fp':'chrome','pbk':s['public_key'],'sid':s['short_id'],'type':'tcp'}
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
tmp=CFG+'.tmp'; open(tmp,'w').write(new); os.chmod(tmp,0o600)
r=subprocess.run([XRAY,'run','-test','-config',tmp],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
if r.returncode!=0:
    print(r.stdout,file=sys.stderr); os.unlink(tmp); sys.exit(1)
os.replace(tmp,CFG)
subprocess.run(['systemctl','restart',SERVICE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
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

cgw_write_subscription_server() {
    cat > "$CGW_SUB_SERVER" <<'PY'
#!/usr/bin/env python3
import base64,json,sqlite3,urllib.parse
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
DB='/etc/singbox-manager/data/users.db'; STATE='/etc/customer-gateway/gateway.json'
def active(r):
    if int(r['enabled'] or 0)!=1:return False,'disabled'
    try:e=json.loads(r['engines'] or '{}')
    except:e={}
    if not e.get('gateway'):return False,'gateway disabled'
    if r['expires_at']:
        try:
            d=datetime.fromisoformat(r['expires_at']); d=d if d.tzinfo else d.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc)>=d:return False,'expired'
        except:pass
    q=float(r['quota_gb'] or 0)
    if q>0 and int(r['used_bytes'] or 0)>=int(q*1024**3):return False,'quota exceeded'
    return True,''
def link(r,s):
    q={'encryption':'none','security':'reality','sni':s['sni'],'fp':'chrome','pbk':s['public_key'],'sid':s['short_id'],'type':'tcp'}
    return f"vless://{r['uuid']}@{s['host']}:{s['port']}?{urllib.parse.urlencode(q)}#{urllib.parse.quote(r['label'] or 'User',safe='')}"
class H(BaseHTTPRequestHandler):
    server_version='Subscription/1.0'
    def log_message(self,*a):pass
    def do_GET(self):
        if not self.path.startswith('/sub/'):self.send_error(404);return
        token=self.path.split('/sub/',1)[1].split('?',1)[0].strip('/')
        c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; r=c.execute('SELECT * FROM users WHERE sub_token=?',(token,)).fetchone(); c.close()
        if not r:self.send_response(401);self.end_headers();self.wfile.write(b'Unauthorized');return
        ok,why=active(r)
        if not ok:self.send_response(403);self.end_headers();self.wfile.write(why.encode());return
        s=json.load(open(STATE)); body=base64.b64encode((link(r,s)+'\n').encode())
        used=int(r['used_bytes'] or 0); total=int(float(r['quota_gb'] or 0)*1024**3); info=f'upload={used}; download=0; total={total}'
        if r['expires_at']:
            try:
                d=datetime.fromisoformat(r['expires_at']); d=d if d.tzinfo else d.replace(tzinfo=timezone.utc); info+=f'; expire={int(d.timestamp())}'
            except:pass
        self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('subscription-userinfo',info); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
s=json.load(open(STATE)); ThreadingHTTPServer(('0.0.0.0',int(s['sub_port'])),H).serve_forever()
PY
    chmod 755 "$CGW_SUB_SERVER"
}

cgw_create_services() {
    cat > "/etc/systemd/system/${CGW_SERVICE}" <<'UNIT'
[Unit]
Description=Customer VLESS Reality Gateway via Turkey reverse SOCKS
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /etc/customer-gateway/xray.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
    cat > "/etc/systemd/system/${CGW_SUB_SERVICE}" <<'UNIT'
[Unit]
Description=Customer Gateway Subscription Server
After=network-online.target customer-gateway.service
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/customer-gateway/subscription_server.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable "$CGW_SERVICE" "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true
}

cgw_install_cron() {
    (crontab -l 2>/dev/null | grep -v 'customer-gateway/sync_traffic.py' || true; echo '* * * * * /usr/bin/python3 /etc/customer-gateway/sync_traffic.py >/dev/null 2>&1') | crontab -
}

cgw_setup() {
    print_banner; print_header "Customer Gateway — Iran → Turkey Exit"
    echo -e "  ${DIM}VLESS+Reality for v2rayN users; all egress uses reverse SSH SOCKS.${NC}\n"
    if ! curl -fsS --max-time 15 --socks5-hostname 127.0.0.1:10808 https://api.ipify.org >/tmp/cgw-exit-ip 2>/dev/null; then
        print_error "Reverse SSH SOCKS 127.0.0.1:10808 is not healthy. Fix Tunnel Setup first."; press_enter; return 1
    fi
    local exit_ip; exit_ip=$(tr -d '[:space:]' </tmp/cgw-exit-ip); print_success "Turkey exit is healthy: ${exit_ip}"
    fetch_xray_version >/dev/null 2>&1 || true
    [[ -x "$XRAY_BIN" ]] || xray_install_binary "$XRAY_VERSION" || { press_enter; return 1; }
    db_init >/dev/null || { print_error "Database initialization failed."; press_enter; return 1; }
    local host port sub_port sni sid kp priv pub
    host=$(get_public_ip 2>/dev/null || true)
    ask host "  Iran public IP/domain for client links" "$host"
    ask port "  VLESS Reality TCP port" "$CGW_DEFAULT_PORT"
    ask sub_port "  Subscription HTTP port" "$CGW_DEFAULT_SUB_PORT"
    ask sni "  Reality camouflage SNI" "www.speedtest.net"
    sid=$(openssl rand -hex 4 2>/dev/null || echo a1b2c3d4)
    kp=$(xray_generate_reality_keypair) || { print_error "Failed to generate Reality keypair."; press_enter; return 1; }
    priv=${kp%%|*}; pub=${kp#*|}; mkdir -p "$CGW_DIR"
    HOST="$host" PORT="$port" SUB="$sub_port" SNI="$sni" SID="$sid" PRIV="$priv" PUB="$pub" python3 - <<'PY'
import json,os
s={'host':os.environ['HOST'],'port':int(os.environ['PORT']),'sub_port':int(os.environ['SUB']),'sni':os.environ['SNI'],'short_id':os.environ['SID'],'private_key':os.environ['PRIV'],'public_key':os.environ['PUB'],'exit_socks_port':10808,'stats_port':10085}
json.dump(s,open('/etc/customer-gateway/gateway.json','w'),indent=2); os.chmod('/etc/customer-gateway/gateway.json',0o600)
PY
    DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,json,os
c=sqlite3.connect(os.environ['DB_PATH'])
for uuid,raw in c.execute('SELECT uuid,engines FROM users').fetchall():
    try:e=json.loads(raw or '{}')
    except:e={}
    e['gateway']=True; c.execute('UPDATE users SET engines=? WHERE uuid=?',(json.dumps(e),uuid))
c.commit();c.close()
PY
    cgw_write_rebuild_script; cgw_write_sync_script; cgw_write_subscription_server; cgw_create_services
    "$CGW_REBUILD" --force || { print_error "Gateway config validation failed."; press_enter; return 1; }
    systemctl restart "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true
    cgw_install_cron; open_port "$port" tcp; open_port "$sub_port" tcp; sleep 1
    systemctl is-active --quiet "$CGW_SERVICE" || { print_error "Customer gateway failed to start."; journalctl -u "$CGW_SERVICE" -n 30 --no-pager | sed 's/^/  /'; press_enter; return 1; }
    systemctl is-active --quiet "$CGW_SUB_SERVICE" || { print_error "Subscription service failed to start."; press_enter; return 1; }
    print_success "Customer gateway is running."
    echo -e "  Client endpoint : ${CYAN}${host}:${port}${NC}"
    echo -e "  Subscription    : ${CYAN}http://${host}:${sub_port}/sub/<token>${NC}"
    echo -e "  Turkey exit IP  : ${CYAN}${exit_ip}${NC}\n"
    echo -e "  ${BOLD}Now use User Management → Add user.${NC}"; press_enter
}

cgw_status() {
    print_banner; print_header "Customer Gateway Status"
    service_status_line "$CGW_SERVICE" "VLESS Reality gateway"
    service_status_line "$CGW_SUB_SERVICE" "Subscription server"
    local exit; exit=$(curl -fsS --max-time 12 --socks5-hostname 127.0.0.1:10808 https://api.ipify.org 2>/dev/null || echo FAIL)
    echo -e "  Reverse SOCKS exit: ${CYAN}${exit}${NC}"
    [[ -s "$CGW_STATE" ]] && echo -e "  Endpoint          : ${CYAN}$(cgw_state_get host):$(cgw_state_get port)${NC}"
    press_enter
}

cgw_remove() {
    confirm "Remove Customer Gateway services/config? User database will be kept." "n" || return
    systemctl disable --now "$CGW_SERVICE" "$CGW_SUB_SERVICE" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${CGW_SERVICE}" "/etc/systemd/system/${CGW_SUB_SERVICE}"
    (crontab -l 2>/dev/null | grep -v 'customer-gateway/sync_traffic.py' || true) | crontab -
    rm -rf "$CGW_DIR"; systemctl daemon-reload; print_success "Customer Gateway removed. Users/database preserved."; press_enter
}

cgw_menu() {
    while true; do
        print_banner; print_header "Customer Gateway — v2rayN Sales Access"
        echo -e "  ${CYAN}1)${NC} Setup / rebuild gateway on Iran server"
        echo -e "  ${CYAN}2)${NC} Status / health check"
        echo -e "  ${CYAN}3)${NC} Remove gateway"
        echo -e "  ${CYAN}0)${NC} Back"
        menu_prompt
        case "$MENU_CHOICE" in 1) cgw_setup ;; 2) cgw_status ;; 3) cgw_remove ;; 0) return ;; *) print_warn "Invalid choice."; sleep 1 ;; esac
    done
}
