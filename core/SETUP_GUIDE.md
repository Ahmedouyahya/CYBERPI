# CyberPI — Step-by-Step Setup Guide

> **From a blank SD card to a weaponised USB device in ~15 minutes.**

---

## What You Need

| Item | Notes |
|------|-------|
| Raspberry Pi Zero W (or Zero 2 W) | Must be the one with the **micro-USB data port** (not just power) |
| Micro SD card (8 GB+) | Class 10 or faster |
| Another computer (any OS) | For flashing the SD card + SSH access |
| Micro-USB **data** cable | The one you'll plug into the target |
| SD card reader / adapter | To flash the card |
| Wi-Fi network | For the initial SSH setup (only needed once) |

---

## Step 1 — Flash Raspberry Pi OS Lite

1. Download **Raspberry Pi Imager** → https://www.raspberrypi.com/software/
2. Open it and choose:
   - **OS** → Raspberry Pi OS (other) → **Raspberry Pi OS Lite (64-bit)** *(or 32-bit if Pi Zero v1)*
   - **Storage** → your SD card
3. Click the **gear icon ⚙️** (or Ctrl+Shift+X) to open **Advanced Settings**:
   - ✅ **Set hostname**: `cyberpi`
   - ✅ **Enable SSH** → Use password authentication
   - **Username**: `pi`  |  **Password**: pick one you'll remember
   - ✅ **Configure wireless LAN**:
     - SSID: *your Wi-Fi network name*
     - Password: *your Wi-Fi password*
     - Country: *your country code*
4. Click **Write** and wait for it to finish.
5. Put the SD card in the Pi. **Do NOT plug USB into a target yet.**

---

## Step 2 — Boot & SSH In

1. Power the Pi using a phone charger (into the **PWR** micro-USB port, not the data port).
2. Wait ~90 seconds for it to boot.
3. Find the Pi on your network:
   ```bash
   # From your computer:
   ping cyberpi.local
   # or scan your network:
   nmap -sn 192.168.1.0/24 | grep -i pi
   ```
4. SSH in:
   ```bash
   ssh pi@cyberpi.local
   # Password: whatever you set in Step 1
   ```

---

## Step 3 — Copy the Project

From **your computer** (not the Pi), copy the entire project to the Pi:

```bash
# Option A — scp (from the project root on your computer)
scp -r /home/ahmedouyahye/Desktop/me/projects/raspberry_pi pi@cyberpi.local:~/cyberpi

# Option B — git (if you have a repo)
ssh pi@cyberpi.local
git clone https://your-repo-url.git ~/cyberpi
```

---

## Step 4 — Run the Installer (One Command)

SSH into the Pi and run:

```bash
ssh pi@cyberpi.local
cd ~/cyberpi
sudo bash hackathon/install.sh
```

This single command will:
- Install all system packages (Python 3, venv, dosfstools, etc.)
- Create a Python virtual environment with pycryptodomex
- Configure `/boot/config.txt` for USB gadget mode (dwc2)
- Create a 512 MB virtual USB drive (FAT32)
- Deploy v2 payloads (PowerShell + Bash) onto the USB drive
- Install the USB composite gadget script (HID keyboard + mass storage)
- Install and enable the auto-attack systemd service
- Apply stealth hardening (disable LEDs, Bluetooth, reduce boot noise)

**Takes about 3–5 minutes depending on your internet speed.**

---

## Step 5 — Reboot

```bash
sudo reboot
```

The Pi is now ready. **Unplug the power cable.**

---

## Step 6 — Use It

### Attack Flow

1. **Plug the Pi** into the target computer's USB port (**use the DATA port** on the Pi, the one closest to the HDMI port).
2. The target sees a "Kingston DataTraveler" flash drive being connected.
3. Within 6-10 seconds, the Pi:
   - Detects the target OS (Windows/macOS/Linux)
   - Opens a terminal via HID keyboard injection
   - Executes the appropriate payload
   - Collects credentials, Wi-Fi passwords, system info
   - Encrypts everything with AES-256-GCM
   - Blinks the LED when done
4. **Wait ~30-60 seconds** for the LED blink (or just wait a full minute).
5. **Unplug.**

### View Results

SSH into the Pi (power it normally or plug into your own computer) and run:

```bash
sudo mount -o loop /piusb.bin /mnt/usb_share
/opt/cyberpi/venv/bin/python3 /opt/cyberpi/hackathon/viewer.py /mnt/usb_share
```

This shows a formatted display of:
- Decrypted browser credentials
- Wi-Fi passwords
- System information
- SSH keys found
- Collection statistics

---

## Configuration

### Change Keyboard Layout

The default is US QWERTY. If the target uses a different layout:

```bash
sudo mount -o loop /piusb.bin /mnt/usb_share
echo "fr" | sudo tee /mnt/usb_share/.kb_layout   # fr = French AZERTY
sudo umount /mnt/usb_share
```

Supported: `us`, `fr`, `de`

### Disable Stealth Mode (for demos)

Edit the runner if you want visible windows during demos:

```bash
sudo nano /usr/local/bin/cyberpi-run
# Change: --layout auto
# To:     --layout auto --no-stealth
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Pi not showing up as USB device | Make sure you're using the **DATA** port (closest to HDMI), not the PWR port |
| Nothing happens when plugged in | SSH in and check: `journalctl -u cyberpi.service` |
| HID device not found | Check: `ls -la /dev/hidg0` — if missing, run `sudo /usr/local/bin/cyberpi-gadget setup` |
| Payload doesn't find the drive | The volume label must match `TRUSTED` or `CYBERSEC` — check with `sudo blkid /piusb.bin` |
| Screen was locked error | The Pi detected the screen was locked. It won't inject into a locked screen. |
| Need to re-run | Just reboot: `sudo reboot` — the attack resets on every boot |

### Check Logs

```bash
# Service status
sudo systemctl status cyberpi.service

# Full log
cat /var/log/cyberpi.log

# systemd journal
journalctl -u cyberpi.service --no-pager
```

---

## Hardware Diagram

```
                    ┌─────────────────────┐
                    │  Raspberry Pi Zero W │
   ┌────────────────┤                     │
   │  DATA port     │  SD Card with       │
   │  (to target)   │  Raspberry Pi OS    │
   │                │  + CyberPI          │
   │  ┌──────┐      │                     │
   │  │ LED  │ GPIO │  PWR port           ├────── (for initial setup only)
   │  └──────┘  17  │  (power/charge)     │
   └────────────────┤                     │
                    └─────────────────────┘

   DATA port pinout:
   ┌──────────────┐
   │  micro-USB   │ ← Closest to HDMI connector
   │  DATA port   │ ← This is the one you plug into the target
   └──────────────┘
```

---

## For the Hackathon Demo

### Live Demo Script

1. **Show the Pi** — "This is a $10 Raspberry Pi Zero"
2. **Show the code** — open `viewer.py` and `auto_attack_v2.py` on your laptop
3. **Plug it into a demo laptop** (your own, pre-configured)
4. **Wait ~45 seconds**
5. **SSH into the Pi from your phone** (or another laptop)
6. **Run the viewer** — show extracted credentials on the big screen
7. **Explain the defense** — "Here's how to protect against this..."

### Timing

| Phase | Duration |
|-------|----------|
| USB enumeration | 4-6 seconds |
| OS detection | 2-5 seconds |
| Terminal open + payload launch | 3-5 seconds |
| Data collection | 15-45 seconds |
| Encryption | 2-3 seconds |
| **Total** | **~30-60 seconds** |

---

## Important Reminders

- ⚠️ **ONLY use on computers you own or have written authorization to test**
- ⚠️ This tool is for **educational/authorized penetration testing** purposes
- ⚠️ Unauthorized use is illegal under CFAA, CMA, and equivalent laws worldwide
- ⚠️ Always get **written permission** before any penetration test
- ⚠️ Delete extracted data after your demo

---

*CyberPI — Hackathon Edition by Mr.D137*
