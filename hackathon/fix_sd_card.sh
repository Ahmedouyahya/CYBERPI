#!/bin/bash
# ============================================================================
#  Fix Pi SD Card — Wi-Fi + USB networking
#  Run: sudo bash hackathon/fix_sd_card.sh
# ============================================================================
set -euo pipefail

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
ok()   { echo -e "${G}[✓]${N} $*"; }
info() { echo -e "${B}[·]${N} $*"; }
fail() { echo -e "${R}[✗]${N} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash $0"

# ─── Find and mount the SD card ─────────────────────────
BOOT_DEV="/dev/sdb1"
ROOT_DEV="/dev/sdb2"
BOOT_MNT="/mnt/piboot"
ROOT_MNT="/mnt/piroot"

[[ -b "$BOOT_DEV" ]] || fail "$BOOT_DEV not found — is the SD card plugged in?"
[[ -b "$ROOT_DEV" ]] || fail "$ROOT_DEV not found"

mkdir -p "$BOOT_MNT" "$ROOT_MNT"
mountpoint -q "$BOOT_MNT" || mount "$BOOT_DEV" "$BOOT_MNT"
mountpoint -q "$ROOT_MNT" || mount "$ROOT_DEV" "$ROOT_MNT"
ok "SD card mounted: boot=$BOOT_MNT  root=$ROOT_MNT"

# ─── Detect boot config path ────────────────────────────
# Newer Pi OS uses /boot/firmware/, older uses /boot/
if [[ -f "$BOOT_MNT/config.txt" ]]; then
    BOOT="$BOOT_MNT"
elif [[ -f "$BOOT_MNT/firmware/config.txt" ]]; then
    BOOT="$BOOT_MNT/firmware"
else
    BOOT="$BOOT_MNT"
fi
info "Boot config directory: $BOOT"

# ═══════════════════════════════════════════════════════════
#  FIX 1: Wi-Fi — Set country=TN and configure network
# ═══════════════════════════════════════════════════════════
info "FIX 1: Configuring Wi-Fi for Tunisia (TN)..."

# Method A: wpa_supplicant.conf on boot partition (works on most Pi OS versions)
cat > "$BOOT/wpa_supplicant.conf" << 'WPA'
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=TN

network={
    ssid="REPLACE_WITH_YOUR_WIFI_NAME"
    psk="REPLACE_WITH_YOUR_WIFI_PASSWORD"
    key_mgmt=WPA-PSK
}
WPA
ok "Created $BOOT/wpa_supplicant.conf (country=TN)"

# Method B: Also set it in the rootfs wpa_supplicant (belt and suspenders)
WPA_ROOT="$ROOT_MNT/etc/wpa_supplicant/wpa_supplicant.conf"
if [[ -f "$WPA_ROOT" ]]; then
    # Update existing file — set country=TN
    if grep -q "^country=" "$WPA_ROOT"; then
        sed -i 's/^country=.*/country=TN/' "$WPA_ROOT"
    else
        sed -i '1a country=TN' "$WPA_ROOT"
    fi
    ok "Updated $WPA_ROOT with country=TN"
else
    mkdir -p "$(dirname "$WPA_ROOT")"
    cp "$BOOT/wpa_supplicant.conf" "$WPA_ROOT"
    ok "Created $WPA_ROOT"
fi

# Method C: Unblock rfkill via config  
# Create a file that runs on first boot to unblock wifi
cat > "$ROOT_MNT/etc/rc.local" << 'RCLOCAL'
#!/bin/bash
# Unblock Wi-Fi and set regulatory domain
rfkill unblock wifi 2>/dev/null || true
iw reg set TN 2>/dev/null || true
# Disable LEDs for stealth
echo none > /sys/class/leds/ACT/trigger 2>/dev/null || true
echo 0    > /sys/class/leds/ACT/brightness 2>/dev/null || true
echo none > /sys/class/leds/PWR/trigger 2>/dev/null || true
echo 0    > /sys/class/leds/PWR/brightness 2>/dev/null || true
exit 0
RCLOCAL
chmod +x "$ROOT_MNT/etc/rc.local"
ok "Created rc.local to unblock rfkill + set TN regulatory domain"

# Method D: Set regulatory domain in cfg80211
mkdir -p "$ROOT_MNT/etc/default"
echo 'REGDOMAIN=TN' > "$ROOT_MNT/etc/default/crda"
ok "Set CRDA regulatory domain to TN"

# ═══════════════════════════════════════════════════════════
#  FIX 2: USB networking — static IP on USB gadget
# ═══════════════════════════════════════════════════════════
info "FIX 2: Configuring USB networking with static IP..."

# Add modules-load=dwc2 and g_ether to cmdline.txt if not there
CMDLINE="$BOOT/cmdline.txt"
if [[ -f "$CMDLINE" ]]; then
    CONTENT=$(cat "$CMDLINE")
    
    # Add modules-load=dwc2 after rootwait
    if ! echo "$CONTENT" | grep -q "modules-load=dwc2"; then
        CONTENT=$(echo "$CONTENT" | sed 's/rootwait/rootwait modules-load=dwc2/')
    fi
    
    # Add g_ether for USB Ethernet gadget (fallback networking)
    if ! echo "$CONTENT" | grep -q "g_ether"; then
        CONTENT="$CONTENT modules-load=g_ether"
    fi
    
    echo "$CONTENT" > "$CMDLINE"
    ok "Updated cmdline.txt with dwc2 + g_ether"
else
    warn "cmdline.txt not found at $CMDLINE"
fi

# config.txt — enable dwc2 overlay
CONFIG="$BOOT/config.txt"
if [[ -f "$CONFIG" ]]; then
    if ! grep -q "dtoverlay=dwc2" "$CONFIG"; then
        echo "" >> "$CONFIG"
        echo "# USB gadget mode" >> "$CONFIG"
        echo "dtoverlay=dwc2" >> "$CONFIG"
    fi
    ok "config.txt has dtoverlay=dwc2"
else
    warn "config.txt not found at $CONFIG"
fi

# Set static IP on usb0 interface via dhcpcd.conf
DHCPCD="$ROOT_MNT/etc/dhcpcd.conf"
if [[ -f "$DHCPCD" ]]; then
    if ! grep -q "interface usb0" "$DHCPCD"; then
        cat >> "$DHCPCD" << 'DHCP'

# USB gadget static IP
interface usb0
static ip_address=10.0.0.2/24
static routers=10.0.0.1
DHCP
        ok "Added usb0 static IP (10.0.0.2) to dhcpcd.conf"
    else
        ok "dhcpcd.conf already has usb0 config"
    fi
fi

# Also configure via NetworkManager (newer Pi OS uses this instead of dhcpcd)
NM_DIR="$ROOT_MNT/etc/NetworkManager/system-connections"
if [[ -d "$ROOT_MNT/etc/NetworkManager" ]]; then
    mkdir -p "$NM_DIR"
    cat > "$NM_DIR/usb0.nmconnection" << 'NM'
[connection]
id=USB Gadget
type=ethernet
interface-name=usb0
autoconnect=true

[ipv4]
method=manual
addresses=10.0.0.2/24
gateway=10.0.0.1

[ipv6]
method=disabled
NM
    chmod 600 "$NM_DIR/usb0.nmconnection"
    ok "Created NetworkManager USB connection (10.0.0.2)"
fi

# ═══════════════════════════════════════════════════════════
#  FIX 3: Enable SSH
# ═══════════════════════════════════════════════════════════
info "FIX 3: Ensuring SSH is enabled..."

# Touch the ssh file on boot partition (enables SSH on first boot)
touch "$BOOT/ssh"
ok "Created $BOOT/ssh (enables SSH server)"

# Also enable via systemd symlink
SSH_LINK="$ROOT_MNT/etc/systemd/system/multi-user.target.wants/ssh.service"
SSH_SRC="/lib/systemd/system/ssh.service"
if [[ ! -L "$SSH_LINK" ]]; then
    mkdir -p "$(dirname "$SSH_LINK")"
    ln -sf "$SSH_SRC" "$SSH_LINK" 2>/dev/null || true
fi
ok "SSH service enabled"

# ═══════════════════════════════════════════════════════════
#  Summary
# ═══════════════════════════════════════════════════════════

# Unmount
sync
umount "$BOOT_MNT" 2>/dev/null || true
umount "$ROOT_MNT" 2>/dev/null || true
ok "SD card unmounted — safe to remove"

echo ""
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo -e "${G}       SD CARD FIXED${N}"
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${Y}⚠  IMPORTANT: Edit your Wi-Fi credentials first!${N}"
echo ""
echo -e "  Before removing the SD card, re-mount and edit:"
echo -e "    sudo mount /dev/sdb1 /mnt/piboot"
echo -e "    sudo nano /mnt/piboot/wpa_supplicant.conf"
echo -e "      → Change REPLACE_WITH_YOUR_WIFI_NAME"
echo -e "      → Change REPLACE_WITH_YOUR_WIFI_PASSWORD"
echo -e "    sudo umount /mnt/piboot"
echo ""
echo -e "  ${G}What was fixed:${N}"
echo -e "    1. Wi-Fi: country=TN, rfkill unblock, CRDA=TN"
echo -e "    2. USB:   usb0 static IP 10.0.0.2/24"
echo -e "    3. SSH:   enabled on boot"
echo ""
echo -e "  ${B}After booting the Pi:${N}"
echo ""
echo -e "  ${G}Option A — Wi-Fi:${N}"
echo -e "    ssh pi@<pi-ip-address>"
echo -e "    # Find IP: check your router, or nmap -sn 192.168.x.0/24"
echo ""
echo -e "  ${G}Option B — USB:${N}"
echo -e "    # On your computer, after plugging Pi USB data port:"
echo -e "    sudo ip addr add 10.0.0.1/24 dev \$(ip -br link | grep enx | awk '{print \$1}')"
echo -e "    ssh pi@10.0.0.2"
echo ""
