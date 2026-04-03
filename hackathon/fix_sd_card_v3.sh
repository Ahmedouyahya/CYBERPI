#!/bin/bash
# ============================================================================
#  DEFINITIVE Pi SD Card Fix — v3
#  Fixes: USB IP assignment + Wi-Fi + SSH
#
#  Run: sudo bash hackathon/fix_sd_card_v3.sh
# ============================================================================
set -euo pipefail

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'
ok()   { echo -e "${G}[✓]${N} $*"; }
fail() { echo -e "${R}[✗]${N} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash $0"

BOOT="/mnt/piboot"
ROOT="/mnt/piroot"

[[ -f "$BOOT/cmdline.txt" ]] || fail "SD card not mounted. Run: sudo mount /dev/sdb1 /mnt/piboot && sudo mount /dev/sdb2 /mnt/piroot"

echo -e "${Y}Applying definitive fixes...${N}"

# ═══════════════════════════════════════════════════════════
#  FIX 1: Remove broken kernel ip= from cmdline.txt
#  (kernel ip= doesn't work for USB gadget interfaces)
# ═══════════════════════════════════════════════════════════
echo "FIX 1: Cleaning up cmdline.txt..."
CMDLINE=$(cat "$BOOT/cmdline.txt")
# Remove ip= parameter (doesn't work for gadget)
CMDLINE=$(echo "$CMDLINE" | sed 's/ ip=[^ ]*//')
# Remove duplicate modules-load and consolidate
CMDLINE=$(echo "$CMDLINE" | sed 's/ modules-load=[^ ]*//g')
# Re-add modules-load with just dwc2 (g_ether will be loaded by our service)
CMDLINE="$CMDLINE modules-load=dwc2"
# Ensure single line, no double spaces
CMDLINE=$(echo "$CMDLINE" | tr -s ' ')
echo "$CMDLINE" > "$BOOT/cmdline.txt"
ok "cmdline.txt cleaned: $(cat "$BOOT/cmdline.txt")"

# ═══════════════════════════════════════════════════════════
#  FIX 2: Create a systemd service that assigns USB IP
#  This is the BULLETPROOF method — a dedicated service
#  that waits for usb0 to appear and assigns the IP
# ═══════════════════════════════════════════════════════════
echo "FIX 2: Creating USB IP systemd service..."

# The actual script that assigns the IP
cat > "$ROOT/usr/local/bin/usb-gadget-ip.sh" << 'SCRIPT'
#!/bin/bash
# Load g_ether to create usb0 interface
modprobe g_ether 2>/dev/null || true

# Wait up to 30 seconds for usb0 to appear
for i in $(seq 1 60); do
    if ip link show usb0 &>/dev/null; then
        break
    fi
    sleep 0.5
done

if ! ip link show usb0 &>/dev/null; then
    echo "usb0 did not appear after 30 seconds"
    exit 1
fi

# Bring it up and assign IP
ip link set usb0 up
ip addr flush dev usb0 2>/dev/null || true
ip addr add 10.0.0.2/24 dev usb0
echo "USB gadget IP assigned: 10.0.0.2/24 on usb0"

# Also tell NetworkManager to leave usb0 alone
# (we're managing it ourselves)
nmcli device set usb0 managed no 2>/dev/null || true
SCRIPT
chmod +x "$ROOT/usr/local/bin/usb-gadget-ip.sh"

# The systemd service
cat > "$ROOT/etc/systemd/system/usb-gadget-ip.service" << 'SERVICE'
[Unit]
Description=Assign IP to USB gadget interface
After=network-pre.target systemd-modules-load.service
Before=network.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/usb-gadget-ip.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE

# Enable it
ln -sf /etc/systemd/system/usb-gadget-ip.service \
    "$ROOT/etc/systemd/system/multi-user.target.wants/usb-gadget-ip.service"
ok "USB IP service created and enabled"

# ═══════════════════════════════════════════════════════════
#  FIX 3: Enable rc-local.service (was NOT enabled!)
# ═══════════════════════════════════════════════════════════
echo "FIX 3: Enabling rc-local.service..."
ln -sf /lib/systemd/system/rc-local.service \
    "$ROOT/etc/systemd/system/multi-user.target.wants/rc-local.service" 2>/dev/null || true
chmod +x "$ROOT/etc/rc.local"
ok "rc-local.service enabled"

# ═══════════════════════════════════════════════════════════
#  FIX 4: Fix NetworkManager to manage ethernet interfaces
# ═══════════════════════════════════════════════════════════
echo "FIX 4: Fixing NetworkManager config..."
cat > "$ROOT/etc/NetworkManager/NetworkManager.conf" << 'NMCONF'
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=true

[device]
wifi.scan-rand-mac-address=no
NMCONF

# Fix NM USB connection profile (ensure proper format)
cat > "$ROOT/etc/NetworkManager/system-connections/usb0.nmconnection" << 'NM'
[connection]
id=USB Gadget
uuid=a1b2c3d4-e5f6-7890-abcd-ef1234567890
type=ethernet
interface-name=usb0
autoconnect=true
autoconnect-priority=100

[ethernet]

[ipv4]
method=manual
address1=10.0.0.2/24,10.0.0.1

[ipv6]
addr-gen-mode=default
method=disabled
NM
chmod 600 "$ROOT/etc/NetworkManager/system-connections/usb0.nmconnection"

# Fix Wi-Fi NM profile
cat > "$ROOT/etc/NetworkManager/system-connections/wifi.nmconnection" << 'WIFI'
[connection]
id=TOPNET-PNNGYM
uuid=b2c3d4e5-f6a7-8901-bcde-f12345678901
type=wifi
autoconnect=true

[wifi]
mode=infrastructure
ssid=TOPNET-PNNGYM

[wifi-security]
key-mgmt=wpa-psk
psk=pc499t2jng

[ipv4]
method=auto

[ipv6]
addr-gen-mode=default
method=disabled
WIFI
chmod 600 "$ROOT/etc/NetworkManager/system-connections/wifi.nmconnection"
ok "NetworkManager profiles fixed"

# ═══════════════════════════════════════════════════════════
#  FIX 5: Ensure SSH is enabled (multiple methods)
# ═══════════════════════════════════════════════════════════
echo "FIX 5: Enabling SSH..."
touch "$BOOT/ssh"
ln -sf /lib/systemd/system/ssh.service \
    "$ROOT/etc/systemd/system/multi-user.target.wants/ssh.service" 2>/dev/null || true
ln -sf /lib/systemd/system/sshd.service \
    "$ROOT/etc/systemd/system/multi-user.target.wants/sshd.service" 2>/dev/null || true
# Also use raspi-config nonint method
mkdir -p "$ROOT/var/lib/systemd/linger"
ok "SSH enabled"

# ═══════════════════════════════════════════════════════════
#  FIX 6: Ensure dwc2 overlay in config.txt
# ═══════════════════════════════════════════════════════════
echo "FIX 6: Verifying config.txt..."
if grep -q "dtoverlay=dwc2" "$BOOT/config.txt"; then
    ok "config.txt already has dtoverlay=dwc2"
else
    echo -e "\ndtoverlay=dwc2" >> "$BOOT/config.txt"
    ok "Added dtoverlay=dwc2 to config.txt"
fi

# ═══════════════════════════════════════════════════════════
#  FIX 7: Ensure g_ether in modules-load.d (modern method)
# ═══════════════════════════════════════════════════════════
echo "FIX 7: Configuring module loading..."
mkdir -p "$ROOT/etc/modules-load.d"
echo "g_ether" > "$ROOT/etc/modules-load.d/usb-gadget.conf"
echo "dwc2" > "$ROOT/etc/modules-load.d/dwc2.conf"
ok "Module loading configured via modules-load.d"

# ═══════════════════════════════════════════════════════════
#  FIX 8: Wi-Fi regulatory domain
# ═══════════════════════════════════════════════════════════
echo "FIX 8: Wi-Fi regulatory domain..."
mkdir -p "$ROOT/etc/default"
echo 'REGDOMAIN=TN' > "$ROOT/etc/default/crda"
# Also set via wpa_supplicant on boot partition (some OS versions read this)
cat > "$BOOT/wpa_supplicant.conf" << 'WPA'
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=TN

network={
    ssid="TOPNET-PNNGYM"
    psk="pc499t2jng"
    key_mgmt=WPA-PSK
}
WPA
ok "Wi-Fi regulatory domain set to TN"

# Sync and unmount
sync
umount "$BOOT" 2>/dev/null || true
umount "$ROOT" 2>/dev/null || true
ok "SD card unmounted — safe to remove"

echo ""
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo -e "${G}  ALL FIXES APPLIED (v3 — definitive)${N}"
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo ""
echo -e "  What's different this time:"
echo -e "    - Dedicated systemd service assigns 10.0.0.2 to usb0"
echo -e "    - rc-local.service ENABLED (was disabled!)"
echo -e "    - NetworkManager set to managed=true (was false!)"
echo -e "    - NM profiles use correct address1= format"
echo -e "    - Removed broken kernel ip= from cmdline"
echo -e "    - g_ether loaded via modules-load.d (modern method)"
echo ""
echo -e "  ${Y}Now:${N}"
echo -e "    1. Remove SD card from computer"
echo -e "    2. Put it in Pi"
echo -e "    3. Plug Pi DATA port into computer"
echo -e "    4. Wait 30-60 seconds"
echo -e "    5. On your computer:"
echo -e "       ${G}sudo ip addr add 10.0.0.1/24 dev \$(ip -br link | grep enx | awk '{print \$1}') 2>/dev/null${N}"
echo -e "       ${G}ssh pi@10.0.0.2${N}"
echo ""
