#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  core/db.sh — unified SQLite user database
#
#  Schema design:
#    • One row per user
#    • quota_gb / used_bytes cover ALL protocols combined
#    • engines JSON column: {"vless":true,"hysteria2":true}
#    • sub_token  → unique subscription URL token
#    • Each protocol's traffic is synced here by its own cron job
# ═══════════════════════════════════════════════════════════════

DB_PATH="/etc/singbox-manager/data/users.db"
DB_DIR="/etc/singbox-manager/data"

# ── Bootstrap ─────────────────────────────────────────────────

db_init() {
    mkdir -p "$DB_DIR"
    python3 - <<'PYEOF'
import sqlite3, sys, os

db_path = os.environ.get("DB_PATH", "/etc/singbox-manager/data/users.db")

conn = sqlite3.connect(db_path)
conn.executescript("""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid          TEXT    NOT NULL UNIQUE,
    label         TEXT    NOT NULL DEFAULT '',
    -- Traffic
    quota_gb      REAL    NOT NULL DEFAULT 0,   -- 0 = unlimited
    used_bytes    INTEGER NOT NULL DEFAULT 0,
    -- Protocol flags (JSON: {"vless":true,"hysteria2":false})
    engines       TEXT    NOT NULL DEFAULT '{}',
    -- Subscription
    sub_token     TEXT    NOT NULL UNIQUE,
    -- Access control
    enabled       INTEGER NOT NULL DEFAULT 1,
    expires_at    TEXT    DEFAULT NULL,          -- ISO-8601 or NULL
    -- Metadata
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT    DEFAULT NULL,
    note          TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS traffic_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid          TEXT    NOT NULL,
    engine        TEXT    NOT NULL,             -- 'vless' | 'hysteria2'
    delta_bytes   INTEGER NOT NULL DEFAULT 0,
    recorded_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_users_token  ON users(sub_token);
CREATE INDEX IF NOT EXISTS idx_users_uuid   ON users(uuid);
CREATE INDEX IF NOT EXISTS idx_traffic_uuid ON traffic_log(uuid);
""")
conn.commit()
conn.close()
print("OK")
PYEOF
}

# ── Helpers called from shell (export DB_PATH before running) ──

_db_exec() {
    # _db_exec <python_snippet>
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os, sys

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

${1}

conn.commit()
conn.close()
PYEOF
}

# ── User CRUD ─────────────────────────────────────────────────

# db_add_user <uuid> <label> <quota_gb> <sub_token> [engines_json] [expires_at]
db_add_user() {
    local uuid="$1" label="$2" quota_gb="$3" sub_token="$4"
    local engines="${5:-'{}'}" expires="${6:-}"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os, sys

db_path   = os.environ["DB_PATH"]
uuid      = """${uuid}"""
label     = """${label}"""
quota_gb  = float("${quota_gb}" or "0")
sub_token = """${sub_token}"""
engines   = """${engines}"""
expires   = """${expires}""" or None

try:
    json.loads(engines)
except:
    engines = "{}"

conn = sqlite3.connect(db_path)
try:
    conn.execute(
        "INSERT INTO users (uuid, label, quota_gb, sub_token, engines, expires_at) "
        "VALUES (?,?,?,?,?,?)",
        (uuid, label, quota_gb, sub_token, engines, expires)
    )
    conn.commit()
    print("OK")
except sqlite3.IntegrityError as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
finally:
    conn.close()
PYEOF
}

# db_get_user <uuid>  → JSON or empty
db_get_user() {
    local uuid="$1"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT * FROM users WHERE uuid=?", ("${uuid}",)).fetchone()
if row:
    print(json.dumps(dict(row)))
conn.close()
PYEOF
}

# db_get_user_by_token <token>  → JSON or empty
db_get_user_by_token() {
    local token="$1"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT * FROM users WHERE sub_token=?", ("${token}",)).fetchone()
if row:
    print(json.dumps(dict(row)))
conn.close()
PYEOF
}

# db_list_users  → JSON array
db_list_users() {
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
rows = conn.execute(
    "SELECT * FROM users ORDER BY created_at DESC"
).fetchall()
print(json.dumps([dict(r) for r in rows]))
conn.close()
PYEOF
}

# db_update_field <uuid> <field> <value>
db_update_field() {
    local uuid="$1" field="$2" value="$3"
    # Whitelist allowed fields to prevent SQL injection
    case "$field" in
        label|quota_gb|enabled|expires_at|note|engines|last_seen) ;;
        *) print_error "db_update_field: disallowed field '${field}'"; return 1 ;;
    esac
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.execute("UPDATE users SET ${field}=? WHERE uuid=?", ("${value}", "${uuid}"))
conn.commit()
conn.close()
print("OK")
PYEOF
}

# db_delete_user <uuid>
db_delete_user() {
    local uuid="$1"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.execute("DELETE FROM users WHERE uuid=?", ("${uuid}",))
conn.execute("DELETE FROM traffic_log WHERE uuid=?", ("${uuid}",))
conn.commit()
conn.close()
print("OK")
PYEOF
}

# ── Engine management ─────────────────────────────────────────

# db_enable_engine <uuid> <engine>   e.g. db_enable_engine $uuid vless
db_enable_engine() {
    local uuid="$1" engine="$2"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
row = conn.execute("SELECT engines FROM users WHERE uuid=?", ("${uuid}",)).fetchone()
if row:
    try:
        engines = json.loads(row[0] or "{}")
    except:
        engines = {}
    engines["${engine}"] = True
    conn.execute("UPDATE users SET engines=? WHERE uuid=?",
                 (json.dumps(engines), "${uuid}"))
    conn.commit()
conn.close()
PYEOF
}

# db_disable_engine <uuid> <engine>
db_disable_engine() {
    local uuid="$1" engine="$2"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
row = conn.execute("SELECT engines FROM users WHERE uuid=?", ("${uuid}",)).fetchone()
if row:
    try:
        engines = json.loads(row[0] or "{}")
    except:
        engines = {}
    engines["${engine}"] = False
    conn.execute("UPDATE users SET engines=? WHERE uuid=?",
                 (json.dumps(engines), "${uuid}"))
    conn.commit()
conn.close()
PYEOF
}

# db_has_engine <uuid> <engine>  → exits 0 if enabled, 1 otherwise
db_has_engine() {
    local uuid="$1" engine="$2"
    local result
    result=$(DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, json, os
db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
row = conn.execute("SELECT engines FROM users WHERE uuid=?", ("${uuid}",)).fetchone()
if row:
    try:
        engines = json.loads(row[0] or "{}")
    except:
        engines = {}
    print("yes" if engines.get("${engine}") else "no")
else:
    print("no")
conn.close()
PYEOF
)
    [[ "$result" == "yes" ]]
}

# ── Traffic accounting ────────────────────────────────────────

# db_add_traffic <uuid> <engine> <delta_bytes>
db_add_traffic() {
    local uuid="$1" engine="$2" delta="$3"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, os, datetime

db_path = os.environ["DB_PATH"]
conn    = sqlite3.connect(db_path)
now     = datetime.datetime.utcnow().isoformat()

# Add to cumulative used_bytes
conn.execute("UPDATE users SET used_bytes = used_bytes + ? WHERE uuid=?",
             (int("${delta}"), "${uuid}"))

# Log individual entry
conn.execute("INSERT INTO traffic_log (uuid, engine, delta_bytes, recorded_at) VALUES (?,?,?,?)",
             ("${uuid}", "${engine}", int("${delta}"), now))

# Update last_seen
conn.execute("UPDATE users SET last_seen=? WHERE uuid=?", (now, "${uuid}"))

conn.commit()
conn.close()
PYEOF
}

# db_reset_traffic <uuid>
db_reset_traffic() {
    local uuid="$1"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
conn.execute("UPDATE users SET used_bytes=0 WHERE uuid=?", ("${uuid}",))
conn.execute("DELETE FROM traffic_log WHERE uuid=?", ("${uuid}",))
conn.commit()
conn.close()
print("OK")
PYEOF
}

# ── Quota enforcement ─────────────────────────────────────────

# db_check_quota <uuid>  → echoes "over" or "ok"
db_check_quota() {
    local uuid="$1"
    DB_PATH="$DB_PATH" python3 - <<PYEOF
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
row = conn.execute(
    "SELECT quota_gb, used_bytes FROM users WHERE uuid=?", ("${uuid}",)
).fetchone()
if row:
    quota_gb, used_bytes = row
    quota_bytes = int(float(quota_gb) * 1024**3)
    if quota_bytes > 0 and used_bytes >= quota_bytes:
        print("over")
    else:
        print("ok")
conn.close()
PYEOF
}

# db_expired_users  → JSON array of UUIDs whose expiry has passed
db_expired_users() {
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os, json, datetime

db_path = os.environ["DB_PATH"]
conn    = sqlite3.connect(db_path)
now     = datetime.datetime.utcnow().isoformat()
rows    = conn.execute(
    "SELECT uuid FROM users WHERE expires_at IS NOT NULL AND expires_at <= ? AND enabled=1",
    (now,)
).fetchall()
print(json.dumps([r[0] for r in rows]))
conn.close()
PYEOF
}

# ── Display helpers ───────────────────────────────────────────

# db_print_users_table  — pretty table to stdout
db_print_users_table() {
    DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, json, os, datetime

db_path = os.environ["DB_PATH"]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

rows = conn.execute(
    "SELECT uuid, label, quota_gb, used_bytes, engines, enabled, expires_at, sub_token "
    "FROM users ORDER BY created_at DESC"
).fetchall()

CYAN  = "\033[0;36m"
GREEN = "\033[0;32m"
RED   = "\033[0;31m"
DIM   = "\033[2m"
BOLD  = "\033[1m"
NC    = "\033[0m"

header = f"  {'#':<4} {'Label':<20} {'Engines':<18} {'Used':<12} {'Quota':<10} {'Status':<8} {'Expires':<12}"
print(f"\n{BOLD}{header}{NC}")
print("  " + "─" * 86)

for i, row in enumerate(rows, 1):
    try:
        engines = json.loads(row["engines"] or "{}")
    except:
        engines = {}
    eng_str = "+".join(k for k, v in engines.items() if v) or "none"

    used = row["used_bytes"] or 0
    if   used >= 1_073_741_824: used_str = f"{used/1_073_741_824:.1f}GB"
    elif used >= 1_048_576:     used_str = f"{used/1_048_576:.1f}MB"
    else:                       used_str = f"{used/1024:.1f}KB"

    q = float(row["quota_gb"] or 0)
    quota_str = "Unlimited" if q == 0 else f"{q:.0f} GB"

    status = f"{GREEN}ON{NC}" if row["enabled"] else f"{RED}OFF{NC}"

    exp = row["expires_at"] or "—"
    if exp != "—":
        try:
            dt = datetime.datetime.fromisoformat(exp)
            exp = dt.strftime("%Y-%m-%d")
            if dt < datetime.datetime.utcnow():
                exp = f"{RED}{exp}{NC}"
        except:
            pass

    print(f"  {i:<4} {CYAN}{row['label']:<20}{NC} {DIM}{eng_str:<18}{NC} "
          f"{used_str:<12} {quota_str:<10} {status:<8} {exp}")

print("")
conn.close()
PYEOF
}

# db_user_count  → integer
db_user_count() {
    DB_PATH="$DB_PATH" python3 -c "
import sqlite3, os
conn = sqlite3.connect(os.environ['DB_PATH'])
print(conn.execute('SELECT COUNT(*) FROM users').fetchone()[0])
conn.close()
" 2>/dev/null || echo "0"
}

# ── Self-update / migration stubs ─────────────────────────────
# (no migration needed — fresh install only)

db_exists() {
    [[ -f "$DB_PATH" ]]
}
