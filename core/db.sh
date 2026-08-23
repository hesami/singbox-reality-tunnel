#!/usr/bin/env bash
# SQLite user database. Kept at the legacy path so upgrades preserve users.
DB_PATH="/etc/singbox-manager/data/users.db"
DB_DIR="/etc/singbox-manager/data"

db_init(){
    mkdir -p "$DB_DIR"
    DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
p=os.environ['DB_PATH']; c=sqlite3.connect(p, timeout=15)
c.execute('PRAGMA busy_timeout=15000')
c.executescript('''
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 uuid TEXT NOT NULL UNIQUE,
 label TEXT NOT NULL DEFAULT '',
 quota_gb REAL NOT NULL DEFAULT 0,
 used_bytes INTEGER NOT NULL DEFAULT 0,
 engines TEXT NOT NULL DEFAULT '{}',
 sub_token TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL DEFAULT 1,
 expires_at TEXT DEFAULT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 last_seen TEXT DEFAULT NULL,
 note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS traffic_log(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 uuid TEXT NOT NULL,
 engine TEXT NOT NULL DEFAULT 'gateway',
 delta_bytes INTEGER NOT NULL DEFAULT 0,
 recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_token ON users(sub_token);
CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_traffic_uuid ON traffic_log(uuid);
''')
# Normalize every legacy user into the only production engine retained.
import json
for uid,raw in c.execute('SELECT uuid,engines FROM users').fetchall():
    try:e=json.loads(raw or '{}')
    except:e={}
    e={'gateway': bool(e.get('gateway', True))}
    c.execute('UPDATE users SET engines=? WHERE uuid=?',(json.dumps(e),uid))
c.commit(); c.close()
PY
}

db_add_user(){
    local uuid="$1" label="$2" quota="$3" token="$4" expires="${5:-}"
    UUID="$uuid" LABEL="$label" QUOTA="$quota" TOKEN="$token" EXPIRES="$expires" DB_PATH="$DB_PATH" python3 - <<'PY'
import math,sqlite3,json,os,sys
c=sqlite3.connect(os.environ['DB_PATH'], timeout=15)
c.execute('PRAGMA busy_timeout=15000')
try:
 q=float(os.environ['QUOTA'] or 0)
 if not math.isfinite(q) or q < 0: raise ValueError('quota must be a finite non-negative number')
 c.execute('INSERT INTO users(uuid,label,quota_gb,engines,sub_token,expires_at) VALUES(?,?,?,?,?,?)',(
  os.environ['UUID'],os.environ['LABEL'],q,json.dumps({'gateway':True}),os.environ['TOKEN'],os.environ['EXPIRES'] or None))
 c.commit()
except (sqlite3.IntegrityError,ValueError) as e:
 print(e,file=sys.stderr);sys.exit(1)
finally:c.close()
PY
}
db_get_user(){ UUID="$1" DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,json,os
c=sqlite3.connect(os.environ['DB_PATH']);c.row_factory=sqlite3.Row
r=c.execute('SELECT * FROM users WHERE uuid=?',(os.environ['UUID'],)).fetchone();print(json.dumps(dict(r)) if r else '');c.close()
PY
}
db_get_user_by_token(){ TOKEN="$1" DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,json,os
c=sqlite3.connect(os.environ['DB_PATH']);c.row_factory=sqlite3.Row
r=c.execute('SELECT * FROM users WHERE sub_token=?',(os.environ['TOKEN'],)).fetchone();print(json.dumps(dict(r)) if r else '');c.close()
PY
}
db_update_field(){
    local uuid="$1" field="$2" value="$3"
    case "$field" in label|quota_gb|enabled|expires_at|note|last_seen|sub_token|engines) ;; *) return 1;; esac
    UUID="$uuid" FIELD="$field" VALUE="$value" DB_PATH="$DB_PATH" python3 - <<'PY'
import math,sqlite3,os
c=sqlite3.connect(os.environ['DB_PATH'], timeout=15); c.execute('PRAGMA busy_timeout=15000')
f=os.environ['FIELD']; v=os.environ['VALUE']
if f == 'quota_gb':
 v=float(v or 0)
 if not math.isfinite(v) or v < 0: raise SystemExit('invalid quota')
elif f == 'enabled':
 v=int(v)
 if v not in (0,1): raise SystemExit('invalid enabled value')
elif f == 'expires_at' and not v: v=None
c.execute(f'UPDATE users SET {f}=? WHERE uuid=?',(v,os.environ['UUID'])); c.commit(); c.close()
PY
}
db_delete_user(){ UUID="$1" DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
c=sqlite3.connect(os.environ['DB_PATH']);c.execute('DELETE FROM users WHERE uuid=?',(os.environ['UUID'],));c.execute('DELETE FROM traffic_log WHERE uuid=?',(os.environ['UUID'],));c.commit();c.close()
PY
}
db_reset_traffic(){ UUID="$1" DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
c=sqlite3.connect(os.environ['DB_PATH']);c.execute('UPDATE users SET used_bytes=0,last_seen=NULL WHERE uuid=?',(os.environ['UUID'],));c.execute('DELETE FROM traffic_log WHERE uuid=?',(os.environ['UUID'],));c.commit();c.close()
PY
}
db_checkpoint(){
    DB_PATH="$DB_PATH" python3 - <<'PY'
import os,sqlite3
c=sqlite3.connect(os.environ['DB_PATH'], timeout=15); c.execute('PRAGMA busy_timeout=15000')
c.execute('PRAGMA wal_checkpoint(TRUNCATE)'); c.close()
PY
}
db_user_count(){ DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
c=sqlite3.connect(os.environ['DB_PATH']);print(c.execute('SELECT COUNT(*) FROM users').fetchone()[0]);c.close()
PY
}
db_enabled_count(){ DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
c=sqlite3.connect(os.environ['DB_PATH']);print(c.execute('SELECT COUNT(*) FROM users WHERE enabled=1').fetchone()[0]);c.close()
PY
}
db_expired_users(){ DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os,json
from datetime import datetime,timezone
c=sqlite3.connect(os.environ['DB_PATH']); out=[]; now=datetime.now(timezone.utc)
for u,e in c.execute('SELECT uuid,expires_at FROM users WHERE enabled=1 AND expires_at IS NOT NULL'):
 try:
  d=datetime.fromisoformat(e);d=d if d.tzinfo else d.replace(tzinfo=timezone.utc)
  if now>=d:out.append(u)
 except:pass
print(json.dumps(out));c.close()
PY
}
db_print_users_table(){ DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
from datetime import datetime,timezone
c=sqlite3.connect(os.environ['DB_PATH']);c.row_factory=sqlite3.Row
rows=c.execute('SELECT uuid,label,quota_gb,used_bytes,enabled,expires_at FROM users ORDER BY created_at DESC').fetchall()
print(f"  {'#':<3} {'Label':<20} {'Used':>10} {'Quota':>10} {'Status':<9} {'Expires':<12}")
print('  '+'─'*72)
def h(n):
 n=float(n or 0)
 for u in ['B','KB','MB','GB','TB']:
  if n<1024 or u=='TB':return f'{n:.1f}{u}'
  n/=1024
for i,r in enumerate(rows,1):
 q=float(r['quota_gb'] or 0);quota='∞' if q==0 else f'{q:g}GB';status='ON' if r['enabled'] else 'OFF';exp='—'
 if r['expires_at']:
  try:
   d=datetime.fromisoformat(r['expires_at']); d=d if d.tzinfo else d.replace(tzinfo=timezone.utc); exp=d.strftime('%Y-%m-%d')
   if d<=datetime.now(timezone.utc):status='EXPIRED'
  except: exp='invalid'
 print(f"  {i:<3} {r['label'][:20]:<20} {h(r['used_bytes']):>10} {quota:>10} {status:<9} {exp:<12}")
c.close()
PY
}
