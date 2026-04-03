#!/bin/bash
# ============================================================================
#  USB Composite Gadget Setup — Raspberry Pi Zero (W/WH)
#
#  Creates a composite USB device with TWO functions:
#    1. HID keyboard  → sends keystrokes to the host (the "attack" vector)
#    2. Mass storage   → presents a virtual FAT32 drive (exfiltration/payload)
#
#  Requirements:
#    - Pi Zero must be connected via the *USB* (data) port, NOT the power port
#    - /boot/config.txt must contain  dtoverlay=dwc2
#    - dwc2 kernel module must be loaded (setup.sh handles this)
#
#  Usage:
#    sudo bash scripts/usb_gadget.sh          # create the gadget
#    sudo bash scripts/usb_gadget.sh teardown  # remove the gadget
#
#  Educational Purpose Only — authorized testing on systems you own.
# ============================================================================

set -euo pipefail

# ───────────────────── Configuration ─────────────────────
GADGET_NAME="cybersec_gadget"
GADGET_DIR="/sys/kernel/config/usb_gadget/${GADGET_NAME}"

USB_IMAGE="/piusb.bin"           # created by setup.sh (2 GB FAT32 / exFAT image)
MOUNT_POINT="/mnt/usb_share"

# USB device descriptors (benign-looking flash-drive identity)
ID_VENDOR="0x1d6b"              # Linux Foundation
ID_PRODUCT="0x0104"             # Multifunction Composite Gadget
SERIAL_NUM="CYBERSEC0001"
MANUFACTURER="Generic"
PRODUCT="USB Flash Drive"

# HID keyboard report descriptor (standard 8-byte boot keyboard)
# Byte layout sent to host: [modifier, reserved, key1..key6]
HID_REPORT_DESC="\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x05\x75\x01\x05\x08\x19\x01\x29\x05\x91\x02\x95\x01\x75\x03\x91\x03\x95\x06\x75\x08\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0"

# ───────────────────── Helpers ─────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

need_root() {
    [[ $EUID -eq 0 ]] || die "Must run as root (sudo)"
}

# ───────────────────── Teardown ─────────────────────
gadget_teardown() {
    log "Tearing down USB gadget..."

    # Unbind from UDC
    if [[ -f "${GADGET_DIR}/UDC" ]]; then
        echo "" > "${GADGET_DIR}/UDC" 2>/dev/null || true
    fi

    # Remove config symlinks
    for link in "${GADGET_DIR}"/configs/*/hid.usb0 "${GADGET_DIR}"/configs/*/mass_storage.usb0; do
        [[ -L "$link" ]] && rm -f "$link"
    done

    # Remove strings directories
    for d in "${GADGET_DIR}"/configs/*/strings/0x0409 "${GADGET_DIR}"/strings/0x0409; do
        [[ -d "$d" ]] && rmdir "$d" 2>/dev/null || true
    done

    # Remove configs & functions
    for d in "${GADGET_DIR}"/configs/*; do
        [[ -d "$d" ]] && rmdir "$d" 2>/dev/null || true
    done
    for d in "${GADGET_DIR}"/functions/*; do
        [[ -d "$d" ]] && rmdir "$d" 2>/dev/null || true
    done

    # Remove gadget root
    [[ -d "${GADGET_DIR}" ]] && rmdir "${GADGET_DIR}" 2>/dev/null || true

    log "Gadget removed."
}

# ───────────────────── Setup ─────────────────────
gadget_setup() {
    log "Creating composite USB gadget (HID keyboard + mass storage)..."

    # Load required modules
    modprobe libcomposite 2>/dev/null || true
    modprobe dwc2          2>/dev/null || true

    # If already exists, tear down first
    [[ -d "${GADGET_DIR}" ]] && gadget_teardown

    # Ensure virtual storage image exists
    if [[ ! -f "${USB_IMAGE}" ]]; then
        warn "USB image ${USB_IMAGE} not found — creating 64 MB placeholder..."
        dd if=/dev/zero of="${USB_IMAGE}" bs=1M count=64 status=progress
        mkfs.vfat -F 32 -n "CYBERSEC" "${USB_IMAGE}"
    fi

    # Mount the image so our scripts can read/write payloads
    mkdir -p "${MOUNT_POINT}"
    if ! mountpoint -q "${MOUNT_POINT}"; then
        mount -o loop "${USB_IMAGE}" "${MOUNT_POINT}" || warn "Could not mount image"
    fi

    # ---- Create gadget ----
    mkdir -p "${GADGET_DIR}"
    echo "${ID_VENDOR}"  > "${GADGET_DIR}/idVendor"
    echo "${ID_PRODUCT}" > "${GADGET_DIR}/idProduct"
    echo "0x0100"        > "${GADGET_DIR}/bcdDevice"
    echo "0x0200"        > "${GADGET_DIR}/bcdUSB"

    # Device strings
    mkdir -p "${GADGET_DIR}/strings/0x0409"
    echo "${SERIAL_NUM}"   > "${GADGET_DIR}/strings/0x0409/serialnumber"
    echo "${MANUFACTURER}" > "${GADGET_DIR}/strings/0x0409/manufacturer"
    echo "${PRODUCT}"      > "${GADGET_DIR}/strings/0x0409/product"

    # ---- Function 1: HID keyboard ----
    mkdir -p "${GADGET_DIR}/functions/hid.usb0"
    echo 1   > "${GADGET_DIR}/functions/hid.usb0/protocol"   # keyboard
    echo 1   > "${GADGET_DIR}/functions/hid.usb0/subclass"   # boot interface
    echo 8   > "${GADGET_DIR}/functions/hid.usb0/report_length"
    echo -ne "${HID_REPORT_DESC}" > "${GADGET_DIR}/functions/hid.usb0/report_desc"

    # ---- Function 2: Mass storage ----
    mkdir -p "${GADGET_DIR}/functions/mass_storage.usb0"
    echo 1              > "${GADGET_DIR}/functions/mass_storage.usb0/stall"
    mkdir -p "${GADGET_DIR}/functions/mass_storage.usb0/lun.0"
    echo 0              > "${GADGET_DIR}/functions/mass_storage.usb0/lun.0/cdrom"
    echo 0              > "${GADGET_DIR}/functions/mass_storage.usb0/lun.0/ro"
    echo 0              > "${GADGET_DIR}/functions/mass_storage.usb0/lun.0/nofua"
    echo "${USB_IMAGE}" > "${GADGET_DIR}/functions/mass_storage.usb0/lun.0/file"

    # ---- Configuration ----
    mkdir -p "${GADGET_DIR}/configs/c.1/strings/0x0409"
    echo "Composite Device" > "${GADGET_DIR}/configs/c.1/strings/0x0409/configuration"
    echo 250                > "${GADGET_DIR}/configs/c.1/MaxPower"

    # Bind functions to config
    ln -sf "${GADGET_DIR}/functions/hid.usb0"          "${GADGET_DIR}/configs/c.1/"
    ln -sf "${GADGET_DIR}/functions/mass_storage.usb0"  "${GADGET_DIR}/configs/c.1/"

    # ---- Enable gadget ----
    local udc
    udc=$(ls /sys/class/udc/ 2>/dev/null | head -1)
    if [[ -z "$udc" ]]; then
        die "No UDC (USB Device Controller) found — is dwc2 loaded and Pi connected via USB data port?"
    fi
    echo "${udc}" > "${GADGET_DIR}/UDC"

    log "USB gadget enabled on UDC: ${udc}"
    log "  HID keyboard device:  /dev/hidg0"
    log "  Mass storage image:   ${USB_IMAGE}"
    log "  Mount point:          ${MOUNT_POINT}"
}

# ───────────────────── Main ─────────────────────
main() {
    need_root

    case "${1:-setup}" in
        setup)    gadget_setup   ;;
        teardown) gadget_teardown ;;
        *)        echo "Usage: $0 [setup|teardown]"; exit 1 ;;
    esac
}

main "$@"
