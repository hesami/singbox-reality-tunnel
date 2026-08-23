#!/usr/bin/env bash
# Customer user management for the single production gateway.

users_gateway_installed(){ [[ -s "$CGW_STATE" && -f "/etc/systemd/system/${CGW_SERVICE}" ]]; }
users_sub_url(){
    local token="$1" host port scheme
    users_gateway_installed || return 1
    host=$(cgw_state_get sub_host); port=$(cgw_state_get sub_port); scheme=$(cgw_state_get sub_scheme); [[ -n "$scheme" ]] || scheme=http
    echo "${scheme}://$(host_port "$host" "$port")/sub/${token}"
}
_users_expiry_from_days(){ DAYS="$1" python3 - <<'PY'
from datetime import datetime,timedelta,timezone
import os
n=int(os.environ['DAYS'] or 0)
print('' if n<=0 else (datetime.now(timezone.utc)+timedelta(days=n)).isoformat())
PY
}
_users_json_field(){ USER_JSON="$1" FIELD="$2" python3 - <<'PY'
import json,os
try:v=json.loads(os.environ['USER_JSON']).get(os.environ['FIELD'],'')
except:v=''
print('' if v is None else v)
PY
}

# Keep technical client-path diagnostics out of the customer-facing UI.
# Full details are still written to the manager log for administrators.
_users_log_client_test_failure(){
    local rc="$1" output="$2"
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    {
        printf '%s [WARN] Customer client-path verification failed (rc=%s)\n' "$(date '+%F %T')" "$rc"
        printf '%s\n' "$output" | sed 's/^/    /'
    } >>"$MANAGER_LOG" 2>/dev/null || true
}

_users_client_test_message(){
    case "$1" in
      2) echo "Customer Gateway is not configured correctly." ;;
      3) echo "The customer gateway service is not running." ;;
      4) echo "No active customer was available for the connection check." ;;
      5) echo "The Turkey exit connection is temporarily unavailable." ;;
      6) echo "The public customer endpoint is incomplete or the local test could not start." ;;
      7) echo "The public customer endpoint could not be reached from the Turkey side." ;;
      8) echo "The endpoint is reachable, but the automated VLESS/REALITY verification could not complete." ;;
      *) echo "The customer was created, but the connection could not be verified." ;;
    esac
}

# Safe, non-interactive repair used by Add Customer. It preserves users,
# REALITY keys, certificates and endpoint settings, and never prints raw logs.
_users_quiet_gateway_repair(){
    cgw_installed || return 1
    local port sub_port
    port=$(cgw_state_get port 2>/dev/null || true)
    sub_port=$(cgw_state_get sub_port 2>/dev/null || true)

    cgw_write_rebuild_script >/dev/null 2>&1 || return 1
    cgw_write_sync_script >/dev/null 2>&1 || return 1
    cgw_write_subscription_server >/dev/null 2>&1 || return 1
    cgw_create_services >/dev/null 2>&1 || return 1
    "$CGW_REBUILD" --force >/dev/null 2>&1 || return 1

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl restart "$CGW_SERVICE" >/dev/null 2>&1 || return 1
    systemctl restart "$CGW_SUB_SERVICE" >/dev/null 2>&1 || return 1

    # If the dedicated reverse-tunnel receiver exists on this host, refresh it too.
    if systemctl cat "$RSSH_SSHD_SERVICE" >/dev/null 2>&1; then
        systemctl restart "$RSSH_SSHD_SERVICE" >/dev/null 2>&1 || true
    fi

    valid_port "$port" && open_port "$port" tcp >/dev/null 2>&1 || true
    valid_port "$sub_port" && open_port "$sub_port" tcp >/dev/null 2>&1 || true
    sleep 1
    systemctl is-active --quiet "$CGW_SERVICE" 2>/dev/null &&
        systemctl is-active --quiet "$CGW_SUB_SERVICE" 2>/dev/null
}

_users_verify_customer_path(){
    local rt rc choice repair_attempted=0
    while true; do
        if rt=$(cgw_local_client_test 2>&1); then
            print_success "Connection verified successfully through the Turkey route."
            return 0
        else
            rc=$?
        fi

        _users_log_client_test_failure "$rc" "$rt"
        echo
        print_warn "$(_users_client_test_message "$rc")"
        print_info "Your customer is saved and no technical error details are shown here."
        print_info "Diagnostic details were saved to ${MANAGER_LOG}."

        # A REALITY verification failure is not repaired by endlessly restarting
        # the same runtime. Allow one conservative rebuild, then stop offering it.
        if (( repair_attempted == 0 )); then
            echo
            echo -e "  ${CYAN}1)${NC} Rebuild the gateway runtime once"
            echo -e "  ${CYAN}2)${NC} Test the connection again"
            echo -e "  ${CYAN}3)${NC} Continue without verification"
            echo -ne "  ${YELLOW}Select option [3]: ${NC}"
            read -r choice; choice="${choice:-3}"
            case "$choice" in
              1)
                repair_attempted=1
                print_info "Rebuilding the gateway runtime without changing customers or Reality keys..."
                if _users_quiet_gateway_repair; then
                    print_info "Runtime rebuilt. Running one fresh connection check..."
                else
                    print_warn "The runtime rebuild could not be completed. Customer data was not changed."
                fi
                ;;
              2) print_info "Checking the connection again..." ;;
              3)
                print_info "Continuing without connection verification. The customer remains active."
                return 1
                ;;
              *) print_warn "Invalid option. Please choose 1, 2 or 3." ;;
            esac
        else
            echo
            print_warn "The runtime rebuild did not change the test result. Repeating the same repair will not help, so it will not be offered again."
            print_info "This verification result does not by itself prove that the customer's real v2rayN connection is broken."
            echo
            echo -e "  ${CYAN}1)${NC} Test the connection again"
            echo -e "  ${CYAN}2)${NC} Continue without verification"
            echo -ne "  ${YELLOW}Select option [2]: ${NC}"
            read -r choice; choice="${choice:-2}"
            case "$choice" in
              1) print_info "Checking the connection again..." ;;
              2)
                print_info "Continuing without connection verification. The customer remains active."
                return 1
                ;;
              *) print_warn "Invalid option. Please choose 1 or 2." ;;
            esac
        fi
    done
}

users_add(){
    print_banner; print_header "Add Customer"
    users_gateway_installed || { print_error "Customer Gateway is not configured. Run Customer Gateway → Setup first."; press_enter; return 1; }
    local label quota days uuid token exp sub
    ask label "  Customer label" "User-$(date +%H%M)"
    ask quota "  Traffic quota in GB (0 = unlimited)" "50"
    [[ "$quota" =~ ^[0-9]+([.][0-9]+)?$ ]] || { print_error "Quota must be a number."; press_enter; return 1; }
    ask days "  Validity in days (0 = no expiry)" "30"
    [[ "$days" =~ ^[0-9]+$ ]] || { print_error "Validity must be a whole number."; press_enter; return 1; }
    uuid=$(generate_uuid); token=$(generate_token); exp=$(_users_expiry_from_days "$days")
    db_add_user "$uuid" "$label" "$quota" "$token" "$exp" || { print_error "Database insert failed."; press_enter; return 1; }
    if ! cgw_rebuild_if_installed; then db_delete_user "$uuid"; print_error "Gateway rebuild failed; customer was not kept."; press_enter; return 1; fi
    sub=$(users_sub_url "$token")
    echo; print_success "Customer created."
    echo -e "  Label        : ${CYAN}${label}${NC}"
    echo -e "  Quota        : ${CYAN}$([[ "$quota" == 0 ]] && echo Unlimited || echo "${quota} GB")${NC}"
    echo -e "  Validity     : ${CYAN}$([[ "$days" == 0 ]] && echo No-expiry || echo "${days} days")${NC}"
    echo -e "  Subscription : ${GREEN}${BOLD}${sub}${NC}"
    _users_verify_customer_path || true
    print_info "For v2rayN, use a current Xray-core; server runtime is pinned to v26.7.28."
    print_qr "$sub" "$label"; press_enter
}

users_pick(){
    local prompt="${1:-Select customer}" count idx; print_banner; print_header "Select Customer"; db_print_users_table
    count=$(db_user_count); ((count>0)) || { print_warn "No customers."; return 1; }
    mapfile -t USER_UUIDS < <(DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,os
c=sqlite3.connect(os.environ['DB_PATH'])
for r in c.execute('SELECT uuid FROM users ORDER BY created_at DESC'):print(r[0])
c.close()
PY
)
    echo -ne "  ${YELLOW}${prompt} [1-${count}]: ${NC}"; read -r idx
    [[ "$idx" =~ ^[0-9]+$ ]] || return 1; idx=$((idx-1)); ((idx>=0 && idx<${#USER_UUIDS[@]})) || return 1
    USER_PICK_UUID="${USER_UUIDS[$idx]}"
}

users_list(){ print_banner; print_header "Customers"; echo -e "  Total: ${CYAN}$(db_user_count)${NC}   Enabled: ${CYAN}$(db_enabled_count)${NC}\n"; db_print_users_table; press_enter; }
users_show_subscription(){
    users_pick "Select customer" || { press_enter; return; }; local j label token sub link
    j=$(db_get_user "$USER_PICK_UUID"); label=$(_users_json_field "$j" label); token=$(_users_json_field "$j" sub_token); sub=$(users_sub_url "$token")
    link=$(cgw_build_link "$USER_PICK_UUID" "${label}-Turkey" 2>/dev/null || true)
    print_banner; print_header "Subscription — ${label}"
    echo -e "  Subscription URL:\n  ${GREEN}${BOLD}${sub}${NC}\n"
    [[ -n "$link" ]] && echo -e "  ${DIM}Direct VLESS link (optional):${NC}\n  ${MAGENTA}${link}${NC}\n"
    print_qr "$sub" "$label"; press_enter
}

users_edit(){
    users_pick "Select customer to edit" || { press_enter; return; }; local u="$USER_PICK_UUID" j label quota note days exp
    j=$(db_get_user "$u"); label=$(_users_json_field "$j" label); quota=$(_users_json_field "$j" quota_gb); note=$(_users_json_field "$j" note)
    print_banner; print_header "Edit Customer"
    ask label "  Label" "$label"; ask quota "  Quota GB (0 = unlimited)" "$quota"
    [[ "$quota" =~ ^[0-9]+([.][0-9]+)?$ ]] || { print_error "Invalid quota."; press_enter; return 1; }
    ask note "  Note" "$note"
    echo -e "\n  ${DIM}Validity: enter 0 to keep current expiry; positive number sets a new expiry from today; -1 removes expiry.${NC}"
    ask days "  Validity change" "0"
    db_update_field "$u" label "$label"; db_update_field "$u" quota_gb "$quota"; db_update_field "$u" note "$note"
    if [[ "$days" == -1 ]]; then db_update_field "$u" expires_at ""; elif [[ "$days" =~ ^[1-9][0-9]*$ ]]; then exp=$(_users_expiry_from_days "$days"); db_update_field "$u" expires_at "$exp"; fi
    cgw_rebuild_if_installed || { print_error "Customer saved, but gateway rebuild failed. Run Gateway → Upgrade/repair."; press_enter; return 1; }; print_success "Customer updated."; press_enter
}
users_toggle(){
    users_pick "Select customer to enable/disable" || { press_enter; return; }; local j cur
    j=$(db_get_user "$USER_PICK_UUID"); cur=$(_users_json_field "$j" enabled)
    if [[ "$cur" == 1 ]]; then db_update_field "$USER_PICK_UUID" enabled 0; print_success "Customer disabled."; else db_update_field "$USER_PICK_UUID" enabled 1; print_success "Customer enabled."; fi
    cgw_rebuild_if_installed || print_warn "State changed, but gateway rebuild failed."; press_enter
}
users_reset_traffic(){
    users_pick "Select customer to reset traffic" || { press_enter; return; }; confirm "Reset consumed traffic and re-enable this customer?" n || return
    db_reset_traffic "$USER_PICK_UUID"; db_update_field "$USER_PICK_UUID" enabled 1; cgw_rebuild_if_installed || print_warn "Traffic reset, but gateway rebuild failed."; print_success "Traffic reset."; press_enter
}
users_delete(){
    users_pick "Select customer to delete" || { press_enter; return; }; local j label; j=$(db_get_user "$USER_PICK_UUID"); label=$(_users_json_field "$j" label)
    confirm "Permanently delete '${label}'?" n || return; db_delete_user "$USER_PICK_UUID"; cgw_rebuild_if_installed || print_warn "Customer deleted, but gateway rebuild failed."; print_success "Customer deleted."; press_enter
}
users_rotate_sub_token(){
    users_pick "Select customer" || { press_enter; return; }; local t sub; t=$(generate_token); db_update_field "$USER_PICK_UUID" sub_token "$t"; sub=$(users_sub_url "$t")
    print_success "Subscription token rotated. Old URL is now invalid."; echo -e "  ${GREEN}${BOLD}${sub}${NC}"; print_qr "$sub" "New subscription"; press_enter
}
users_disable_expired(){
    local j count; j=$(db_expired_users); count=$(J="$j" python3 -c 'import json,os;print(len(json.loads(os.environ["J"])))')
    ((count>0)) || { print_info "No expired customers."; return 0; }
    EXPIRED="$j" DB_PATH="$DB_PATH" python3 - <<'PY'
import sqlite3,json,os
c=sqlite3.connect(os.environ['DB_PATH'])
for u in json.loads(os.environ['EXPIRED']):c.execute('UPDATE users SET enabled=0 WHERE uuid=?',(u,))
c.commit();c.close()
PY
    cgw_rebuild_if_installed || print_warn "Expired customers disabled, but gateway rebuild failed."; print_success "$count expired customer(s) disabled."
}

users_menu(){
    db_init >/dev/null 2>&1 || true
    while true; do
        print_banner; print_header "Customer Management"
        echo -e "  Customers: ${CYAN}$(db_user_count)${NC}   Gateway: $(systemctl is-active --quiet "$CGW_SERVICE" 2>/dev/null && echo -e "${GREEN}running${NC}" || echo -e "${DIM}not ready${NC}")\n"
        echo -e "  ${CYAN}1)${NC} Add customer ${DIM}(quota + expiry + subscription)${NC}"
        echo -e "  ${CYAN}2)${NC} List customers"
        echo -e "  ${CYAN}3)${NC} Show subscription / QR"
        echo -e "  ${CYAN}4)${NC} Edit quota / expiry / label"
        echo -e "  ${CYAN}5)${NC} Enable / disable customer"
        echo -e "  ${CYAN}6)${NC} Reset traffic"
        echo -e "  ${CYAN}7)${NC} Rotate subscription token"
        echo -e "  ${CYAN}8)${NC} Delete customer"
        echo -e "  ${CYAN}9)${NC} Disable expired customers now"
        echo -e "  ${CYAN}0)${NC} Back"; menu_prompt
        case "$MENU_CHOICE" in 1)users_add;;2)users_list;;3)users_show_subscription;;4)users_edit;;5)users_toggle;;6)users_reset_traffic;;7)users_rotate_sub_token;;8)users_delete;;9)users_disable_expired;press_enter;;0)return;;*)print_warn "Invalid choice.";sleep 1;;esac
    done
}
