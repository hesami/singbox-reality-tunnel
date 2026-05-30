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

users_active_engines() {
    local engines=()
    users_vless_installed && engines+=("vless")
    users_hy2_installed   && engines+=("hysteria2")
    echo "${engines[@]}"
}

# ── Subscription URL builder ───────────────────────────────────

users_sub_url() {
    local sub_token="$1"
    # Prefer domain, fall back to IP
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

    local active_engines
    read -ra active_engines <<< "$(users_active_engines)"

    if (( ${#active_engines[@]} == 0 )); then
        print_error "No protocols installed yet. Install VLESS or Hysteria2 first."
        press_enter; return 1
    fi

    # ── Basic info ─────────────────────────────────────────
    local label quota_gb expiry_days
    ask label       "  Label"                             "User-$(date +%H%M)"
    ask quota_gb    "  Traffic quota GB  (0 = unlimited)" "50"
    ask expiry_days "  Validity days     (0 = never)"     "30"

    # ── Protocol selection ─────────────────────────────────
    echo ""
    echo -e "  ${BOLD}Enable for which protocols?${NC}"
    local enable_vless=false enable_hy2=false

    if users_vless_installed && users_hy2_installed; then
        echo -e "  ${CYAN}1)${NC}  Both VLESS + Hysteria2  ${DIM}(recommended — client picks best)${NC}"
        echo -e "  ${CYAN}2)${NC}  VLESS + Reality only"
        echo -e "  ${CYAN}3)${NC}  Hysteria2 only"
        menu_prompt
        case "$MENU_CHOICE" in
            1|"") enable_vless=true; enable_hy2=true ;;
            2)    enable_vless=true ;;
            3)    enable_hy2=true ;;
            *)    print_warn "Invalid — using both."; enable_vless=true; enable_hy2=true ;;
        esac
    elif users_vless_installed; then
        enable_vless=true
    elif users_hy2_installed; then
        enable_hy2=true
    fi

    # ── Generate identifiers ───────────────────────────────
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

    local engines_json
    engines_json=$(python3 -c "
import json
e = {'vless': '${enable_vless}' == 'true', 'hysteria2': '${enable_hy2}' == 'true'}
print(json.dumps(e))
")

    # ── Write to central DB ────────────────────────────────
    if ! db_add_user "$uuid" "$label" "$quota_gb" "$sub_token" \
                     "$engines_json" "$expiry_iso"; then
        print_error "Failed to add user to database."
        press_enter; return 1
    fi

    # ── Propagate to each protocol ─────────────────────────
    if $enable_vless && users_vless_installed; then
        local vless_result
        vless_result=$(vless_config_add_user "$uuid")
        [[ "$vless_result" == "OK" ]] \
            && print_success "Added to VLESS config." \
            || print_warn "VLESS config update: ${vless_result}"
        systemctl is-active --quiet sing-box && \
            systemctl reload-or-restart sing-box 2>/dev/null || true
    fi

    # Hysteria2 is handled by auth API (reads UUID from central DB) — no config edit needed

    # ── Show results ───────────────────────────────────────
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

    # Individual protocol links
    if $enable_vless && users_vless_installed; then
        local vlink
        vlink=$(vless_build_link "$uuid" "${label}-VLESS" 2>/dev/null || echo "")
        [[ -n "$vlink" ]] && echo -e "  ${BOLD}VLESS link:${NC}\n  ${MAGENTA}${vlink}${NC}\n"
    fi

    if $enable_hy2 && users_hy2_installed; then
        local hlink
        hlink=$(hy2_build_link "$uuid" "$sub_token" "${label}-HY2" 2>/dev/null || echo "")
        [[ -n "$hlink" ]] && echo -e "  ${BOLD}Hysteria2 link:${NC}\n  ${MAGENTA}${hlink}${NC}\n"
    fi

    # Unified subscription URL
    echo -e "  ${BOLD}Subscription URL ${DIM}(all protocols — paste into Hiddify / v2rayN):${NC}"
    echo -e "  ${GREEN}${BOLD}${sub_url}${NC}"
    print_qr "$sub_url" "${label} — Subscription"
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
    python3 - <<PYEOF
import json, sys

d   = json.loads("""${json}""")
CYAN  = "\033[0;36m"
GREEN = "\033[0;32m"
RED   = "\033[0;31m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
NC    = "\033[0m"

def human(b):
    b=int(b or 0)
    if b>=1_073_741_824: return f"{b/1_073_741_824:.2f} GB"
    if b>=1_048_576:     return f"{b/1_048_576:.2f} MB"
    return f"{b/1024:.2f} KB"

used  = d.get("used_bytes",0)
quota = float(d.get("quota_gb",0))
quota_b = int(quota * 1024**3)
pct   = f"{used/quota_b*100:.1f}%" if quota_b > 0 else "—"

try:
    engines = json.loads(d.get("engines") or "{}")
except:
    engines = {}
eng_str = ", ".join(k for k,v in engines.items() if v) or "none"

print(f"  {BOLD}{'Label':<14}{NC} {CYAN}{d['label']}{NC}")
print(f"  {'UUID':<14} {DIM}{d['uuid']}{NC}")
print(f"  {'Sub Token':<14} {DIM}{d.get('sub_token','')}{NC}")
print(f"  {'Engines':<14} {eng_str}")
print(f"  {'Used':<14} {human(used)}" + (f"  ({pct} of {quota:.0f}GB)" if quota>0 else "  (Unlimited)"))
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
    cur_label=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('label',''))")
    cur_quota=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('quota_gb',0))")
    cur_note=$(echo  "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('note',''))")

    print_banner
    print_header "Edit User"
    echo -e "  ${DIM}Leave blank to keep current value.${NC}\n"

    local new_label new_quota new_note
    ask new_label "  Label"        "$cur_label"
    ask new_quota "  Quota GB"     "$cur_quota"
    ask new_note  "  Note"         "$cur_note"

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
    cur_state=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('enabled',1))")

    if [[ "$cur_state" == "1" ]]; then
        new_state=0
        db_update_field "$uuid" "enabled" "0"
        print_success "User disabled."
    else
        new_state=1
        db_update_field "$uuid" "enabled" "1"
        print_success "User enabled."
    fi

    # For VLESS: update config disabled flag
    if users_vless_installed; then
        python3 - <<PYEOF
import json, os

config_file = "${SINGBOX_CONFIG}"
if not os.path.exists(config_file): exit()
with open(config_file) as f:
    config = json.load(f)

for ib in config.get("inbounds", []):
    for client in ib.get("users", []):
        if client.get("uuid") == "${uuid}":
            client["disabled"] = (${new_state} == 0)

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
    label=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('label','?'))")

    echo -e "\n  ${RED}Delete user '${label}'?${NC}"
    confirm "This cannot be undone." "n" || { press_enter; return; }

    # Remove from VLESS config
    users_vless_installed && vless_config_remove_user "$uuid" && \
        systemctl is-active --quiet sing-box && \
        systemctl reload-or-restart sing-box 2>/dev/null || true

    # Remove from DB (Hysteria2 auth reads DB directly, no extra step)
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
    label=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('label','?'))")

    confirm "Reset traffic for '${label}'?" "y" || { press_enter; return; }
    db_reset_traffic "$uuid"

    # Re-enable if it was disabled due to quota
    db_update_field "$uuid" "enabled" "1"

    # Re-enable in VLESS config too
    if users_vless_installed; then
        python3 - <<PYEOF
import json, os
cf = "${SINGBOX_CONFIG}"
if not os.path.exists(cf): exit()
with open(cf) as f: c = json.load(f)
for ib in c.get("inbounds",[]):
    for u in ib.get("users",[]):
        if u.get("uuid")=="${uuid}": u.pop("disabled", None)
tmp = cf+".tmp"
with open(tmp,"w") as f: json.dump(c,f,indent=2)
os.replace(tmp,cf)
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
    label=$(echo     "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('label','?'))")
    sub_token=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('sub_token',''))")

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

    # Also show individual protocol links
    local engines_json
    engines_json=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('engines','{}'))")

    local has_vless has_hy2
    has_vless=$(echo "$engines_json" | python3 -c "import json,sys; e=json.loads(sys.stdin.read()); print('1' if e.get('vless') else '')")
    has_hy2=$(echo   "$engines_json" | python3 -c "import json,sys; e=json.loads(sys.stdin.read()); print('1' if e.get('hysteria2') else '')")

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

    press_enter
}

# ── Bulk operations ────────────────────────────────────────────

users_expire_check() {
    # Disable expired users across all protocols
    local expired_json
    expired_json=$(db_expired_users)

    local count
    count=$(echo "$expired_json" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))")

    if [[ "$count" -eq 0 ]]; then
        print_info "No expired users."; return
    fi

    print_warn "${count} expired user(s) found. Disabling..."

    echo "$expired_json" | python3 - <<'PYEOF'
import json, sqlite3, os

db_path = os.environ["DB_PATH"]
uuids = json.loads(open("/dev/stdin").read())
conn  = sqlite3.connect(db_path)
for uuid in uuids:
    conn.execute("UPDATE users SET enabled=0 WHERE uuid=?", (uuid,))
conn.commit(); conn.close()
PYEOF

    # Disable in VLESS config
    if users_vless_installed && [[ -f "$SINGBOX_CONFIG" ]]; then
        python3 - <<PYEOF
import json, os

db_path   = os.environ.get("DB_PATH","")
config_file = "${SINGBOX_CONFIG}"
if not os.path.exists(config_file): exit()

import sqlite3
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
    with open(tmp,"w") as f: json.dump(config, f, indent=2)
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

        # Show installed engines
        local eng_line=""
        users_vless_installed    && eng_line+="VLESS+Reality "
        users_hy2_installed      && eng_line+="Hysteria2 "
        [[ -z "$eng_line" ]]     && eng_line="${RED}none installed${NC}"
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
