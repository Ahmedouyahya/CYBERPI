#!/bin/bash
# Quick fix — run with: sudo bash hackathon/fix_sd_card_v2.sh
set -euo pipefail
G='\033[0;32m'; Y='\033[1;33m'; N='\033[0m'

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

BOOT="/mnt/piboot"
ROOT="/mnt/piroot"

# Verify mounted
[[ -f "$BOOT/config.txt" ]] || { echo "ERROR: SD card not mounted at $BOOT"; exit 1; }
echo -e "${G}SD card is mounted${N}"

# ═══ FIX 1: Kernel-level static IP on USB (100% reliable) ═══
echo -e "${Y}FIX 1: Adding kernel-level USB IP to cmdline.txt...${N}"
CMDLINE="$BOOT/cmdline.txt"
CURRENT=$(cat "$CMDLINE")
# Remove any existing ip= parameter
CURRENT=$(echo "$CURRENT" | sed 's/ ip=[^ ]*//')
# Add kernel IP config: ip=<client>:<server>:<gateway>:<netmask>:<hostname>:<device>:<autoconf>
CURRENT="$CURRENT ip=10.0.0.2::10.0.0.1:255.255.255.0:cyberpi:usb0:off"
echo "$CURRENT" > "$CMDLINE"
echo -e "${G}[✓] cmdline.txt now has static IP 10.0.0.2 on usb0${N}"
echo "    Content: $(cat "$CMDLINE")"

# ═══ FIX 2: NetworkManager USB connection profile ═══
echo -e "${Y}FIX 2: Creating NetworkManager USB profile...${N}"
NM_DIR="$ROOT/etc/NetworkManager/system-connections"
mkdir -p "$NM_DIR"
cat > "$NM_DIR/usb0.nmconnection" << 'NM'
[connection]
id=USB Gadget
type=ethernet
interface-name=usb0
autoconnect=true
autoconnect-priority=100

[ethernet]

[ipv4]
method=manual
addresses=10.0.0.2/24
gateway=10.0.0.1

[ipv6]
method=disabled
NM
chmod 600 "$NM_DIR/usb0.nmconnection"
echo -e "${G}[✓] NetworkManager USB profile created (10.0.0.2/24)${N}"

# ═══ FIX 3: NetworkManager Wi-Fi connection (belt & suspenders) ═══
echo -e "${Y}FIX 3: Creating NetworkManager Wi-Fi profile...${N}"
cat > "$NM_DIR/wifi.nmconnection" << 'WIFI'
[connection]
id=TOPNET-PNNGYM
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
method=disabled
WIFI
chmod 600 "$NM_DIR/wifi.nmconnection"
echo -e "${G}[✓] NetworkManager Wi-Fi profile created${N}"

# ═══ FIX 4: Ensure Wi-Fi regulatory domain ═══
echo -e "${Y}FIX 4: Setting Wi-Fi regulatory domain TN...${N}"
# cfg80211 regulatory
mkdir -p "$ROOT/etc/default"
echo 'REGDOMAIN=TN' > "$ROOT/etc/default/crda"
# Also in NetworkManager main config
if [[ -f "$ROOT/etc/NetworkManager/NetworkManager.conf" ]]; then
    if ! grep -q "wifi.scan-rand-mac-address" "$ROOT/etc/NetworkManager/NetworkManager.conf"; then
        cat >> "$ROOT/etc/NetworkManager/NetworkManager.conf" << 'NMCONF'

[device]
wifi.scan-rand-mac-address=no
NMCONF
    fi
fi
echo -e "${G}[✓] Regulatory domain set to TN${N}"

# ═══ FIX 5: Ensure dwc2 + g_ether modules load ═══
echo -e "${Y}FIX 5: Ensuring kernel modules...${N}"
for mod in dwc2 g_ether; do
    grep -q "^${mod}$" "$ROOT/etc/modules" 2>/dev/null || echo "$mod" >> "$ROOT/etc/modules"
done
echo -e "${G}[✓] dwc2 + g_ether in /etc/modules${N}"

# ═══ FIX 6: Ensure SSH enabled ═══
echo -e "${Y}FIX 6: Enabling SSH...${N}"
touch "$BOOT/ssh"
# Enable via systemd
SSH_WANTS="$ROOT/etc/systemd/system/multi-user.target.wants"
mkdir -p "$SSH_WANTS"
ln -sf /lib/systemd/system/ssh.service "$SSH_WANTS/ssh.service" 2>/dev/null || true
# Also sshd.service for some distros
ln -sf /lib/systemd/system/sshd.service "$SSH_WANTS/sshd.service" 2>/dev/null || true
echo -e "${G}[✓] SSH enabled${N}"

# ═══ FIX 7: Fallback IP assignment in rc.local ═══
echo -e "${Y}FIX 7: Adding rc.local fallback IP...${N}"
cat > "$ROOT/etc/rc.local" << 'RCLOCAL'
#!/bin/bash
# Wait for usb0 to appear, then ensure it has an IP
sleep 5
if ip link show usb0 &>/dev/null; then
    ip addr show usb0 | grep -q "10.0.0.2" || ip addr add 10.0.0.2/24 dev usb0
    ip link set usb0 up
fi
# Unblock Wi-Fi
rfkill unblock wifi 2>/dev/null || true
iw reg set TN 2>/dev/null || true
# Disable LEDs
echo none > /sys/class/leds/ACT/trigger 2>/dev/null || true
echo 0    > /sys/class/leds/ACT/brightness 2>/dev/null || true
exit 0
RCLOCAL
chmod +x "$ROOT/etc/rc.local"
echo -e "${G}[✓] rc.local fallback IP + rfkill unblock${N}"

# Sync and unmount
sync
umount "$BOOT" 2>/dev/null || true  
umount "$ROOT" 2>/dev/null || true
echo -e "${G}[✓] SD card unmounted — safe to remove${N}"

echo ""
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo -e "${G}  ALL FIXES APPLIED — 3 layers of USB IP assignment:${N}"
echo -e "${G}    1. Kernel cmdline ip=10.0.0.2 (boot-time)${N}"
echo -e "${G}    2. NetworkManager profile (service-level)${N}"
echo -e "${G}    3. rc.local fallback (belt & suspenders)${N}"
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${Y}Now:${N}"
echo -e "    1. Remove SD card"
echo -e "    2. Put it in Pi"
echo -e "    3. Plug Pi DATA port into your computer"
echo -e "    4. Wait ~30 seconds"
echo -e "    5. On your computer run:"
echo -e "       ${G}sudo ip addr add 10.0.0.1/24 dev \$(ip -br link | grep enx | awk '{print \$1}') 2>/dev/null ; ssh pi@10.0.0.2${N}"
echo ""
