#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  features/users.sh — Unified user management (all protocols)
#
#  Depends on: core/common.sh  core/db.sh
#              protocols/vless.sh  protocols/hysteria2.sh
# ═══════════════════════════════════════════════════════════════

# ── Detect which engines are installed on this server ──────────

users_vless_installed()    { [[ -f "$SINGBOX_BIN"  && -f "$SINGBOX_CONFIG"  ]]; }
users_hy2_installed()      { [[ -f "$HY2_BIN"      && -f "$HY2_CONFIG"      ]]; }
users_vws_installed()      { [[ -f "/etc/sing-box/server_ws.json" ]]; }
users_vgrpc_installed()    { [[ -f "/etc/sing-box/server_grpc.json" ]]; }

users_active_engines() {
    local engines=()
    users_vless_installed  && engines+=("vless")
    users_hy2_installed    && engines+=("hysteria2")
    users_vws_installed    && engines+=("vless_ws")
    users_vgrpc_installed  && engines+=("vless_grpc")
    echo "${engines[@]}"
}

# ── Subscription URL builder ───────────────────────────────────

users_sub_url() {
    local sub_token="$1"
    local host
    ssl_load_domain 2>/dev/null || true
    if [[ -n "${DOMAIN:-}" ]]; then
        host="$DOMAIN"
    else
        hy2_read_server_info 2>/dev/null && host="${HINFO_IP:-$(get_public_ip)}" \
            || host="$(get_public_ip)"
    fi
    echo "http://${host}:${HY2_AUTH_PORT}/sub/${sub_token}"
}

# ── Add user (interactive — protocol-aware) ────────────────────

users_add() {
    print_banner
    print_header "Add New User"
    echo -e "  ${DIM}The user will automatically receive links for ALL active inbounds.${NC}\n"

    local label quota_gb expiry_days
    ask label       "  Label"                             "User-$(date +%H%M)"
    ask quota_gb    "  Traffic quota GB  (0 = unlimited)" "50"
    ask expiry_days "  Validity days     (0 = never)"     "30"

    local uuid sub_token expiry_iso=""
    uuid=$(generate_uuid)
    sub_token=$(generate_token)

    if [[ "$expiry_days" != "0" && -n "$expiry_days" ]]; then
        expiry_iso=$(python3 -c "
from datetime import datetime, timedelta, timezone
exp = datetime.now(timezone.utc) + timedelta(days=int('${expiry_days}'))
print(exp.isoformat())
" 2>/dev/null)
    fi

    if ! db_add_user "$uuid" "$label" "$quota_gb" "$sub_token" '{}' "$expiry_iso"; then
        print_error "Failed to add user to database."
        press_enter; return 1
    fi

    # Add UUID to all sing-box inbounds that exist in config
    if [[ -f "/etc/sing-box/config.json" ]]; then
        TARGET_UUID="$uuid" SINGBOX_CONFIG="/etc/sing-box/config.json" python3 - <<'PYEOF2'
import json, os
cf = os.environ["SINGBOX_CONFIG"]
uuid = os.environ["TARGET_UUID"]
with open(cf) as f: c = json.load(f)
changed = False
for ib in c.get("inbounds", []):
    if ib.get("type") == "vless":
        users = ib.get("users", [])
        if not any(u.get("uuid") == uuid for u in users):
            users.append({"uuid": uuid, "flow": "xtls-rprx-vision"})
            ib["users"] = users
            changed = True
if changed:
    import tempfile
    tmp = cf + ".tmp"
    with open(tmp, "w") as f: json.dump(c, f, indent=2)
    os.replace(tmp, cf)
PYEOF2
        systemctl is-active --quiet sing-box &&             systemctl reload-or-restart sing-box 2>/dev/null || true
    fi

    local sub_url
    sub_url=$(users_sub_url "$sub_token")

    echo ""
    echo -e "  ${GREEN}${BOLD}User created!${NC}"
    echo -e "  ──────────────────────────────────────────────────"
    echo -e "  Label   : ${CYAN}${BOLD}${label}${NC}"
    echo -e "  UUID    : ${DIM}${uuid}${NC}"
    echo -e "  Quota   : ${CYAN}$([ "$quota_gb" = "0" ] && echo "Unlimited" || echo "${quota_gb} GB")${NC}"
    [[ -n "$expiry_iso" ]] && echo -e "  Expires : ${CYAN}${expiry_iso:0:10}${NC}"
    echo ""
    echo -e "  ${BOLD}Subscription URL ${DIM}(all active inbounds included):${NC}"
    echo -e "  ${GREEN}${BOLD}${sub_url}${NC}"
    print_qr "$sub_url" "${label}"
    press_enter
}


# ── List users ─────────────────────────────────────────────────

users_list() {
    print_banner
    print_header "All Users"

    local count
    count=$(db_user_count)
    echo -e "  Total: ${CYAN}${count}${NC} user(s)\n"

    if [[ "$count" -eq 0 ]]; then
        print_info "No users yet. Use 'Add User' to create one."
        echo ""
        press_enter; return
    fi

    db_print_users_table
    press_enter
}

# ── Show user details ──────────────────────────────────────────

users_show() {
    local uuid="$1"
    local json
    json=$(db_get_user "$uuid")
    [[ -z "$json" ]] && { print_error "User not found."; return 1; }

    echo ""
    USER_JSON="$json" python3 - <<'PYEOF'
import json, os, sys

d = json.loads(os.environ["USER_JSON"])

CYAN  = "\033[0;36m"
GREEN = "\033[0;32m"
RED   = "\033[0;31m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
NC    = "\033[0m"

def human(b):
    b = int(b or 0)
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.2f} GB"
    if b >= 1_048_576:     return f"{b/1_048_576:.2f} MB"
    return f"{b/1024:.2f} KB"

used    = d.get("used_bytes", 0)
quota   = float(d.get("quota_gb", 0))
quota_b = int(quota * 1024**3)
pct     = f"{used/quota_b*100:.1f}%" if quota_b > 0 else "—"

try:
    engines_raw = d.get("engines") or "{}"
    if isinstance(engines_raw, str):
        engines = json.loads(engines_raw)
    else:
        engines = engines_raw
except Exception:
    engines = {}

eng_str = ", ".join(k for k, v in engines.items() if v) or "none"

print(f"  {BOLD}{'Label':<14}{NC} {CYAN}{d['label']}{NC}")
print(f"  {'UUID':<14} {DIM}{d['uuid']}{NC}")
print(f"  {'Sub Token':<14} {DIM}{d.get('sub_token','')}{NC}")
print(f"  {'Engines':<14} {eng_str}")
print(f"  {'Used':<14} {human(used)}" + (f"  ({pct} of {quota:.0f}GB)" if quota > 0 else "  (Unlimited)"))
print(f"  {'Status':<14} " + (f"{GREEN}Enabled{NC}" if d.get("enabled") else f"{RED}Disabled{NC}"))
print(f"  {'Expires':<14} {d.get('expires_at','—') or '—'}")
print(f"  {'Created':<14} {d.get('created_at','—')}")
print(f"  {'Last seen':<14} {d.get('last_seen','never') or 'never'}")
if d.get("note"):
    print(f"  {'Note':<14} {d['note']}")
PYEOF
    echo ""
}

# ── Interactive user picker ────────────────────────────────────
# Returns selected UUID in global USER_PICK_UUID

users_pick() {
    local prompt="${1:-Select user}"
    print_banner
    print_header "Select User"

    db_print_users_table

    local count
    count=$(db_user_count)
    [[ "$count" -eq 0 ]] && { print_warn "No users."; USER_PICK_UUID=""; return 1; }

    local user_uuids
    mapfile -t user_uuids < <(
        DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import sqlite3, os
conn = sqlite3.connect(os.environ["DB_PATH"])
rows = conn.execute("SELECT uuid FROM users ORDER BY created_at DESC").fetchall()
for r in rows: print(r[0])
conn.close()
PYEOF
    )

    echo -ne "  ${YELLOW}${prompt} [1-${count}]: ${NC}"
    local idx
    read -r idx
    idx=$(( idx - 1 ))

    if [[ $idx -ge 0 && $idx -lt ${#user_uuids[@]} ]]; then
        USER_PICK_UUID="${user_uuids[$idx]}"
        return 0
    else
        print_warn "Invalid selection."
        USER_PICK_UUID=""
        return 1
    fi
}

# ── Edit user ──────────────────────────────────────────────────

users_edit() {
    users_pick "Select user to edit" || { press_enter; return; }
    local uuid="$USER_PICK_UUID"

    local json
    json=$(db_get_user "$uuid")
    [[ -z "$json" ]] && { print_error "User not found."; press_enter; return; }

    local cur_label cur_quota cur_note
    cur_label=$(USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('label',''))")
    cur_quota=$(USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('quota_gb',0))")
    cur_note=$( USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('note',''))")

    print_banner
    print_header "Edit User"
    echo -e "  ${DIM}Leave blank to keep current value.${NC}\n"

    local new_label new_quota new_note
    ask new_label "  Label"    "$cur_label"
    ask new_quota "  Quota GB" "$cur_quota"
    ask new_note  "  Note"     "$cur_note"

    [[ -n "$new_label" ]] && db_update_field "$uuid" "label"    "$new_label"
    [[ -n "$new_quota" ]] && db_update_field "$uuid" "quota_gb" "$new_quota"
    [[ -n "$new_note"  ]] && db_update_field "$uuid" "note"     "$new_note"

    print_success "User updated."
    press_enter
}

# ── Toggle enable/disable ──────────────────────────────────────

users_toggle() {
    users_pick "Select user to enable/disable" || { press_enter; return; }
    local uuid="$USER_PICK_UUID"

    local json cur_state new_state
    json=$(db_get_user "$uuid")
    cur_state=$(USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('enabled',1))")

    if [[ "$cur_state" == "1" ]]; then
        new_state=0
        db_update_field "$uuid" "enabled" "0"
        print_success "User disabled."
    else
        new_state=1
        db_update_field "$uuid" "enabled" "1"
        print_success "User enabled."
    fi

    if users_vless_installed; then
        TARGET_UUID="$uuid" NEW_STATE="$new_state" SINGBOX_CONFIG="$SINGBOX_CONFIG" \
        python3 - <<'PYEOF'
import json, os

config_file = os.environ["SINGBOX_CONFIG"]
target_uuid = os.environ["TARGET_UUID"]
new_state   = int(os.environ["NEW_STATE"])

if not os.path.exists(config_file):
    exit()
with open(config_file) as f:
    config = json.load(f)

for ib in config.get("inbounds", []):
    for client in ib.get("users", []):
        if client.get("uuid") == target_uuid:
            client["disabled"] = (new_state == 0)

tmp = config_file + ".tmp"
with open(tmp, "w") as f:
    json.dump(config, f, indent=2)
os.replace(tmp, config_file)
PYEOF
        systemctl is-active --quiet sing-box && \
            systemctl reload-or-restart sing-box 2>/dev/null || true
    fi
    press_enter
}

# ── Delete user ────────────────────────────────────────────────

users_delete() {
    users_pick "Select user to delete" || { press_enter; return; }
    local uuid="$USER_PICK_UUID"

    local json label
    json=$(db_get_user "$uuid")
    label=$(USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('label','?'))")

    echo -e "\n  ${RED}Delete user '${label}'?${NC}"
    confirm "This cannot be undone." "n" || { press_enter; return; }

    users_vless_installed && vless_config_remove_user "$uuid" && \
        systemctl is-active --quiet sing-box && \
        systemctl reload-or-restart sing-box 2>/dev/null || true
    users_vws_installed   && vws_config_remove_user   "$uuid" &>/dev/null && systemctl reload-or-restart sing-box-ws   2>/dev/null || true
    users_vgrpc_installed && vgrpc_config_remove_user "$uuid" &>/dev/null && systemctl reload-or-restart sing-box-grpc 2>/dev/null || true

    db_delete_user "$uuid"
    print_success "User '${label}' deleted."
    press_enter
}

# ── Reset traffic ──────────────────────────────────────────────

users_reset_traffic() {
    users_pick "Select user to reset traffic" || { press_enter; return; }
    local uuid="$USER_PICK_UUID"

    local json label
    json=$(db_get_user "$uuid")
    label=$(USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('label','?'))")

    confirm "Reset traffic for '${label}'?" "y" || { press_enter; return; }
    db_reset_traffic "$uuid"

    db_update_field "$uuid" "enabled" "1"

    if users_vless_installed; then
        TARGET_UUID="$uuid" SINGBOX_CONFIG="$SINGBOX_CONFIG" python3 - <<'PYEOF'
import json, os

config_file = os.environ["SINGBOX_CONFIG"]
target_uuid = os.environ["TARGET_UUID"]

if not os.path.exists(config_file):
    exit()
with open(config_file) as f:
    c = json.load(f)

for ib in c.get("inbounds", []):
    for u in ib.get("users", []):
        if u.get("uuid") == target_uuid:
            u.pop("disabled", None)

tmp = config_file + ".tmp"
with open(tmp, "w") as f:
    json.dump(c, f, indent=2)
os.replace(tmp, config_file)
PYEOF
        systemctl is-active --quiet sing-box && \
            systemctl reload-or-restart sing-box 2>/dev/null || true
    fi

    print_success "Traffic reset for '${label}'."
    press_enter
}

# ── Show subscription URL ──────────────────────────────────────

users_show_subscription() {
    users_pick "Select user to show subscription" || { press_enter; return; }
    local uuid="$USER_PICK_UUID"

    local json label sub_token
    json=$(db_get_user "$uuid")
    [[ -z "$json" ]] && { print_error "Failed to load user data."; press_enter; return; }

    label=$(    USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('label','?'))")
    sub_token=$(USER_JSON="$json" python3 -c "import json,os; d=json.loads(os.environ['USER_JSON']); print(d.get('sub_token',''))")

    [[ -z "$sub_token" ]] && { print_error "Sub token missing for this user."; press_enter; return; }

    local sub_url
    sub_url=$(users_sub_url "$sub_token")

    print_banner
    print_header "Subscription — ${label}"
    users_show "$uuid"
    echo -e "  ${BOLD}Subscription URL:${NC}"
    echo -e "  ${GREEN}${BOLD}${sub_url}${NC}"
    echo ""
    print_qr "$sub_url" "${label}"

    # Individual protocol links
    local has_vless has_hy2 has_ws
    has_vless=$(USER_JSON="$json" python3 -c "
import json, os
d = json.loads(os.environ['USER_JSON'])
engines_raw = d.get('engines') or '{}'
e = json.loads(engines_raw) if isinstance(engines_raw, str) else engines_raw
print('1' if e.get('vless') else '')
")
    has_hy2=$(USER_JSON="$json" python3 -c "
import json, os
d = json.loads(os.environ['USER_JSON'])
engines_raw = d.get('engines') or '{}'
e = json.loads(engines_raw) if isinstance(engines_raw, str) else engines_raw
print('1' if e.get('hysteria2') else '')
")
    has_ws=$(USER_JSON="$json" python3 -c "
import json, os
d = json.loads(os.environ['USER_JSON'])
engines_raw = d.get('engines') or '{}'
e = json.loads(engines_raw) if isinstance(engines_raw, str) else engines_raw
print('1' if e.get('vless_ws') else '')
")

    if [[ -n "$has_vless" ]] && users_vless_installed; then
        local vlink
        vlink=$(vless_build_link "$uuid" "${label}-VLESS" 2>/dev/null || echo "")
        [[ -n "$vlink" ]] && echo -e "  ${DIM}VLESS:    ${MAGENTA}${vlink}${NC}\n"
    fi

    if [[ -n "$has_hy2" ]] && users_hy2_installed; then
        local hlink
        hlink=$(hy2_build_link "$uuid" "$sub_token" "${label}-HY2" 2>/dev/null || echo "")
        [[ -n "$hlink" ]] && echo -e "  ${DIM}HY2:      ${MAGENTA}${hlink}${NC}\n"
    fi

    if [[ -n "$has_ws" ]] && users_vws_installed; then
        local wlink
        wlink=$(vws_build_link "$uuid" "${label}-WS" 2>/dev/null || echo "")
        [[ -n "$wlink" ]] && echo -e "  ${DIM}WS+TLS:   ${MAGENTA}${wlink}${NC}\n"
    fi

    local has_grpc
    has_grpc=$(USER_JSON="$json" python3 -c "
import json, os
d = json.loads(os.environ['USER_JSON'])
engines_raw = d.get('engines') or '{}'
e = json.loads(engines_raw) if isinstance(engines_raw, str) else engines_raw
print('1' if e.get('vless_grpc') else '')
")
    if [[ -n "$has_grpc" ]] && users_vgrpc_installed; then
        local glink
        glink=$(vgrpc_build_link "$uuid" "${label}-gRPC" 2>/dev/null || echo "")
        [[ -n "$glink" ]] && echo -e "  ${DIM}gRPC+TLS: ${MAGENTA}${glink}${NC}\n"
    fi

    press_enter
}

# ── Bulk operations ────────────────────────────────────────────

users_expire_check() {
    local expired_json
    expired_json=$(db_expired_users)

    local count
    count=$(echo "$expired_json" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

    if [[ "$count" -eq 0 ]]; then
        print_info "No expired users."; return
    fi

    print_warn "${count} expired user(s) found. Disabling..."

    echo "$expired_json" | DB_PATH="$DB_PATH" python3 - <<'PYEOF'
import json, sqlite3, os, sys

db_path = os.environ["DB_PATH"]
uuids   = json.load(sys.stdin)
conn    = sqlite3.connect(db_path)
for uuid in uuids:
    conn.execute("UPDATE users SET enabled=0 WHERE uuid=?", (uuid,))
conn.commit()
conn.close()
PYEOF

    if users_vless_installed && [[ -f "$SINGBOX_CONFIG" ]]; then
        DB_PATH="$DB_PATH" SINGBOX_CONFIG="$SINGBOX_CONFIG" python3 - <<'PYEOF'
import json, os, sqlite3

db_path     = os.environ["DB_PATH"]
config_file = os.environ["SINGBOX_CONFIG"]

if not os.path.exists(config_file):
    exit()

conn = sqlite3.connect(db_path)
disabled_uuids = set(
    r[0] for r in conn.execute("SELECT uuid FROM users WHERE enabled=0").fetchall()
)
conn.close()

with open(config_file) as f:
    config = json.load(f)

changed = False
for ib in config.get("inbounds", []):
    for client in ib.get("users", []):
        if client.get("uuid") in disabled_uuids and not client.get("disabled"):
            client["disabled"] = True
            changed = True

if changed:
    tmp = config_file + ".tmp"
    with open(tmp, "w") as f:
        json.dump(config, f, indent=2)
    os.replace(tmp, config_file)
PYEOF
        systemctl is-active --quiet sing-box && \
            systemctl reload-or-restart sing-box 2>/dev/null || true
    fi

    print_success "${count} user(s) disabled."
}

# ── Main user management menu ──────────────────────────────────

users_menu() {
    while true; do
        print_banner
        print_header "User Management"

        local count
        count=$(db_user_count 2>/dev/null || echo "0")

        local eng_line=""
        users_vless_installed && eng_line+="VLESS+Reality "
        users_hy2_installed   && eng_line+="Hysteria2 "
        [[ -z "$eng_line" ]]  && eng_line="${RED}none installed${NC}"
        echo -e "  Active protocols : ${CYAN}${eng_line}${NC}"
        echo -e "  Total users      : ${CYAN}${count}${NC}\n"

        echo -e "  ${CYAN}1)${NC}  Add user              ${DIM}(all enabled protocols)${NC}"
        echo -e "  ${CYAN}2)${NC}  List users"
        echo -e "  ${CYAN}3)${NC}  Show subscription URL"
        echo -e "  ${CYAN}4)${NC}  Edit user             ${DIM}(quota, label, note)${NC}"
        echo -e "  ${CYAN}5)${NC}  Enable / Disable user"
        echo -e "  ${CYAN}6)${NC}  Reset traffic"
        echo -e "  ${CYAN}7)${NC}  Delete user"
        echo -e "  ${CYAN}8)${NC}  Check & disable expired users"
        echo -e "  ${CYAN}0)${NC}  Back"
        menu_prompt
        case "$MENU_CHOICE" in
            1) users_add ;;
            2) users_list ;;
            3) users_show_subscription ;;
            4) users_edit ;;
            5) users_toggle ;;
            6) users_reset_traffic ;;
            7) users_delete ;;
            8) users_expire_check; press_enter ;;
            0) return ;;
            *) print_warn "Invalid choice."; sleep 1 ;;
        esac
    done
}
