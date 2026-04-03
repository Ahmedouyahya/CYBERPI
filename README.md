# CyberPI — $10 USB Penetration Testing Device

> **Plug it in. Walk away. Get credentials.**
>
> A Raspberry Pi Zero W transforms into a fully automated penetration testing device
> that extracts browser passwords, Wi-Fi keys, SSH keys, and system intelligence in under 36 seconds.

> ⚠️ **For authorized penetration testing and security education only.**

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [What Gets Extracted](#what-gets-extracted)
3. [Phone Support](#phone-support)
4. [Hardware Requirements](#hardware-requirements)
5. [Setup — Step by Step](#setup--step-by-step)
6. [Running an Attack](#running-an-attack)
7. [Extracting the Data](#extracting-the-data)
   - [Method 1 — viewer.py (SSH)](#method-1--viewerpy-recommended)
   - [Method 2 — sd_reader.py (SD card)](#method-2--sd_readerpy-pull-the-sd-card)
   - [Method 3 — Manual (mount + browse)](#method-3--manual-mount--browse)
8. [Multi-Target / Continuous Mode](#multi-target--continuous-mode)
9. [Advanced Options](#advanced-options)
10. [Project Structure](#project-structure)
11. [Defense Recommendations](#defense-recommendations)
12. [Troubleshooting](#troubleshooting)
13. [Legal Notice](#legal-notice)

---

## How It Works

```
╔══════════════════════════════════════════════════════════════════════╗
║                        CYBERPI — FULL FLOW                          ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ┌─────────────────┐   USB cable   ┌──────────────────────────┐     ║
║  │  Pi Zero W      │ ────────────► │  Target Computer         │     ║
║  │                 │               │  (Windows / macOS /      │     ║
║  │  appears as:    │               │   Linux / Android)       │     ║
║  │  • USB keyboard │               └──────────────────────────┘     ║
║  │  • Flash drive  │                           │                     ║
║  └────────┬────────┘                           │                     ║
║           │                                    ▼                     ║
║           │   ┌─────────────────────────────────────────────────┐   ║
║           │   │              ATTACK SEQUENCE                    │   ║
║           │   │                                                 │   ║
║           │   │  [0s]  Pi boots → USB gadget created            │   ║
║           │   │  [6s]  Host enumerates: sees "Kingston Drive"   │   ║
║           │   │  [8s]  OS detected via filesystem artefacts     │   ║
║           │   │  [9s]  Screen-lock check (canary file)          │   ║
║           │   │  [10s] Hidden terminal opened via HID injection │   ║
║           │   │  [12s] Payload launches from the flash drive    │   ║
║           │   │  [30s] Browser DBs + Wi-Fi + SSH keys collected │   ║
║           │   │  [32s] DPAPI / Keychain decryption runs         │   ║
║           │   │  [35s] AES-256-GCM encrypts all data on drive   │   ║
║           │   │  [36s] LED blinks 5× → unplug                  │   ║
║           │   └─────────────────────────────────────────────────┘   ║
║           │                                                          ║
║           ▼                                                          ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │               DATA EXTRACTION (3 methods)                   │    ║
║  │                                                             │    ║
║  │  A) SSH into Pi → run viewer.py  (easiest)                  │    ║
║  │  B) Pull SD card → run sd_reader.py  (offline)              │    ║
║  │  C) Mount /piusb.bin manually → browse files  (raw)         │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Physical Device Diagram

```
  ┌──────────────────────────────────────┐
  │        Raspberry Pi Zero W           │
  │                                      │
  │  [SD Card]  ←── CyberPI firmware     │
  │                                      │
  │  [PWR port] ←── power only           │  ← use for setup / SSH
  │                                      │
  │  [DATA port]←── USB to target        │  ← this is the attack cable
  │  (next to HDMI)                      │
  │                                      │
  │  [GPIO 17]  ←── LED (optional)       │  ← blinks when done
  └──────────────────────────────────────┘
```

### Attack Timeline

| Time | Action |
|------|--------|
| 0s   | Pi boots, USB gadget initialised |
| 6s   | Target host enumerates "Kingston DataTraveler" |
| 8s   | OS detected (Windows / macOS / Linux) |
| 9s   | Screen-lock checked — aborts if screen is locked |
| 10s  | Hidden terminal launched via HID keyboard injection |
| 12s  | Payload begins execution from the flash drive |
| 30s  | Browser databases, Wi-Fi keys, SSH keys collected |
| 32s  | DPAPI / Keychain decryption — cleartext passwords |
| 35s  | All data encrypted with AES-256-GCM on drive |
| 36s  | LED blinks 5× → safe to unplug |

---

## What Gets Extracted

### Windows
| Data | How |
|------|-----|
| Chrome / Edge passwords | DPAPI decryption → **cleartext** |
| Firefox logins | `key4.db` + `login.json` (offline crackable) |
| Wi-Fi passwords | `netsh wlan` — all saved networks in plaintext |
| Windows Credential Manager | Saved RDP, web, app credentials |
| System recon | Hostname, users, processes, AV, network config |

### macOS
| Data | How |
|------|-----|
| Chrome / Edge passwords | Keychain Safe Storage key extraction |
| Safari history & bookmarks | TCC-aware (works when accessible) |
| SSH private keys | Full `~/.ssh/` directory |
| Keychain dump | All user-accessible Keychain items |
| Wi-Fi passwords | System Keychain (when authorised) |
| Security posture | FileVault, SIP, Gatekeeper, Firewall status |

### Linux
| Data | How |
|------|-----|
| Browser credentials | Chrome / Firefox profile directories |
| SSH private keys | `~/.ssh/` |
| System info | Users, network, running services |

### Android *(limited — see [Phone Support](#phone-support))*
| Data | Requirement |
|------|-------------|
| Device info, model, Android version | No root needed |
| Installed apps list | No root needed |
| Contacts, SMS, call log | Termux with permissions |
| Wi-Fi passwords | **Root required** |
| Browser data (Chrome) | **Root required** |
| Network info | No root needed |

---

## Phone Support

### Android — Partial

CyberPI has an Android attack mode but it works very differently from PC attacks and comes with real limitations.

```
┌─────────────────────────────────────────────────────────────────┐
│                   ANDROID ATTACK FLOW                           │
│                                                                 │
│  Pi plugged into phone via USB                                  │
│         │                                                       │
│         ▼                                                       │
│  Phone shows "Allow access to USB storage?" popup               │
│         │                                                       │
│         ├── User taps ALLOW ──► USB drive mounted               │
│         │                            │                          │
│         │                            ▼                          │
│         │             Pi injects HID → searches for Termux      │
│         │                            │                          │
│         │              ┌─────────────┴──────────────┐           │
│         │              │                            │           │
│         │         Termux found               Termux NOT found   │
│         │              │                            │           │
│         │              ▼                            ▼           │
│         │     android_payload.sh          Chrome fingerprint    │
│         │     runs → collects data        (basic device info)   │
│         │                                                       │
│         └── User taps DENY ──► attack aborted                   │
└─────────────────────────────────────────────────────────────────┘
```

| Condition | What happens |
|-----------|-------------|
| Screen unlocked | ✅ Attack proceeds |
| Screen locked | ❌ Aborted — same as PC |
| Termux installed | ✅ Full payload runs (device info, contacts, SMS, apps) |
| No Termux | ⚠️ Falls back to Chrome device fingerprinting only |
| User taps "Allow" on USB popup | ✅ Drive mounts, payload can save data |
| User taps "Deny" on USB popup | ❌ No data saved to drive |
| Root access | ✅ Also gets Wi-Fi passwords + browser logins |
| No root (stock phone) | ❌ Wi-Fi passwords and browser data are blocked by Android |

**Key difference from PC:** On Android 6+, the phone shows a permission popup when a USB drive is connected. The user must tap "Allow" for the drive to mount. This means the attack is **not fully silent** on Android.

To force Android mode (skip OS auto-detection):
```bash
python3 core/auto_attack.py --force-os android
```

---

### iOS (iPhone / iPad) — Not Supported

CyberPI does **not** work on iPhones or iPads. Apple's security model blocks every part of the attack:

| Blocker | Why |
|---------|-----|
| No USB mass storage | iOS never exposes the filesystem over USB |
| HID accessories require pairing | The phone shows "Trust this computer?" — requires a manual tap and PIN |
| No accessible terminal | No command execution possible without jailbreak |
| Strict app sandboxing | No cross-app data access |

There is no iOS payload in this project. It is not planned.

---

## Hardware Requirements

| Component | Cost | Notes |
|-----------|------|-------|
| Raspberry Pi Zero W | $5–10 | Must have the **micro-USB data port** |
| Micro-USB **data** cable | $1 | Not a charge-only cable |
| MicroSD card (8 GB+) | $3 | Class 10 or faster |
| LED + 330Ω resistor | $0.50 | Optional — status indicator on GPIO 17 |
| **Total** | **~$10** | |

> The Pi Zero W has **two** micro-USB ports. The DATA port is the one closest to the HDMI connector. **Always use that one when plugging into a target.**

---

## Setup — Step by Step

### Step 1 — Flash Raspberry Pi OS Lite

1. Download [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
2. Choose:
   - **OS** → Raspberry Pi OS (other) → **Raspberry Pi OS Lite 64-bit** *(32-bit if Pi Zero v1)*
   - **Storage** → your SD card
3. Click the **gear icon ⚙** → Advanced Settings:
   - ✅ Hostname: `cyberpi`
   - ✅ Enable SSH → password authentication
   - Username: `pi` / Password: something you'll remember
   - ✅ Configure Wi-Fi (SSID + password + country)
4. Click **Write** and wait.
5. Insert SD card into Pi. **Do not plug into a target yet.**

---

### Step 2 — Boot and SSH In

Power the Pi using a charger on the **PWR port**. Wait ~90 seconds, then:

```bash
# Find the Pi
ping cyberpi.local

# SSH in
ssh pi@cyberpi.local
```

---

### Step 3 — Clone the Project

```bash
# On the Pi (via SSH):
git clone https://github.com/Ahmedouyahya/CYBERPI.git ~/cyberpi

# Or copy from your machine:
# scp -r /path/to/CYBERPI pi@cyberpi.local:~/cyberpi
```

---

### Step 4 — Run the Installer

```bash
cd ~/cyberpi
sudo bash core/install.sh
```

This one command does everything:
- Installs Python 3, pip, venv, dosfstools
- Creates a Python venv with `pycryptodomex`
- Configures `/boot/config.txt` for USB gadget mode (`dwc2`)
- Creates a 512 MB FAT32 virtual USB drive (`/piusb.bin`)
- Deploys all OS payloads onto the virtual drive
- Installs the USB composite gadget script (HID keyboard + mass storage)
- Enables the auto-attack systemd service (runs on every boot)
- Applies stealth hardening (disables LEDs, Bluetooth, reduces boot noise)

**Takes ~3–5 minutes.**

---

### Step 5 — Reboot

```bash
sudo reboot
```

The Pi is now ready. **Unplug the power cable.** The device will run automatically the next time it is plugged into a USB port.

---

## Running an Attack

```
┌─────────────────────────────────────────────────────────────┐
│                ATTACK FLOW — PC (Windows/macOS/Linux)       │
│                                                             │
│  1. Target must be ON and screen UNLOCKED                   │
│                                                             │
│  2. Plug the Pi DATA port into the target USB port          │
│        Pi DATA port = the one closest to HDMI               │
│                                                             │
│  3. Target sees a "Kingston DataTraveler" flash drive       │
│        (nothing suspicious, no driver install needed)       │
│                                                             │
│  4. Wait for the LED to blink 5 times (~30–60 seconds)     │
│        No LED? Wait a full 60 seconds to be safe            │
│                                                             │
│  5. Unplug                                                  │
└─────────────────────────────────────────────────────────────┘
```

> If the screen is locked, the Pi detects it via a canary file check and **does nothing** — no keystrokes are injected.

For Android phones, see [Phone Support](#phone-support) — the flow is different and requires user interaction.

---

## Extracting the Data

The Pi stores all collected data inside `/piusb.bin` — a FAT32 disk image on the SD card. Each attack creates its own profile folder: `targets/HOSTNAME_TIMESTAMP/`.

```
/piusb.bin
└── targets/
    ├── DESKTOP-A1B2C3_20240315_143022/   ← attack on device 1
    │   ├── DECRYPTED_CREDENTIALS.json
    │   ├── WIFI_PASSWORDS.json
    │   ├── system/
    │   ├── ssh/
    │   └── attack_meta.json
    ├── MacBook-Pro_20240315_151045/       ← attack on device 2
    │   └── ...
    └── ubuntu-laptop_20240315_160312/    ← attack on device 3
        └── ...
```

---

### Method 1 — viewer.py (Recommended)

Plug the Pi into **your own computer** or power it normally and SSH in:

```bash
ssh pi@cyberpi.local

# Mount the virtual USB drive
sudo mount -o loop /piusb.bin /mnt/usb_share

# Run the viewer — shows everything in a formatted report
/opt/cyberpi/venv/bin/python3 /opt/cyberpi/core/viewer.py /mnt/usb_share
```

The viewer displays:
- **Decrypted browser credentials** (URL, username, password)
- **Wi-Fi passwords** (SSID + key)
- **System information** (hostname, users, AV status)
- **SSH keys** found
- **Collection statistics** (files count, total size)

To decrypt an encrypted blob directly:
```bash
/opt/cyberpi/venv/bin/python3 /opt/cyberpi/core/viewer.py \
    /mnt/usb_share/targets/<profile>/collected_data.enc \
    --password <pi-serial-number>
```

Unmount when done:
```bash
sudo umount /mnt/usb_share
```

---

### Method 2 — sd_reader.py (Pull the SD Card)

Remove the SD card from the Pi and insert it into your own computer. Then:

```bash
# Auto-detect and mount the Pi rootfs + USB image
sudo python3 core/sd_reader.py

# Or specify the rootfs manually
sudo python3 core/sd_reader.py --rootfs /mnt/piroot

# Export everything as an HTML report
sudo python3 core/sd_reader.py --export report
# → saves report.html — open in any browser
```

What `sd_reader.py` does automatically:
1. Finds the Pi rootfs partition (ext4, label `rootfs`)
2. Reads the Pi serial / machine-id for decryption
3. Mounts `/piusb.bin` from the rootfs
4. Shows the attack log, multi-target profiles, collected files
5. Decrypts all `.enc` files automatically

```
┌─────────────────────────────────────────────────────────────┐
│                  sd_reader.py FLOW                          │
│                                                             │
│  SD card inserted into your computer                        │
│         │                                                   │
│         ▼                                                   │
│  auto-detect rootfs partition  ──►  /mnt/piroot             │
│         │                                                   │
│         ▼                                                   │
│  read machine-id / serial  ──►  decryption key              │
│         │                                                   │
│         ▼                                                   │
│  mount /piusb.bin  ──►  /tmp/cyberpi_usb_XXXXX/             │
│         │                                                   │
│         ▼                                                   │
│  display: attack log → profiles → files → decrypt .enc      │
└─────────────────────────────────────────────────────────────┘
```

---

### Method 3 — Manual (Mount + Browse)

If you prefer raw access without the viewer:

```bash
# SSH into Pi
ssh pi@cyberpi.local

# Mount the USB image
sudo mount -o loop /piusb.bin /mnt/usb_share

# Browse the files directly
ls /mnt/usb_share/targets/

# Read credentials JSON
cat /mnt/usb_share/targets/<profile>/DECRYPTED_CREDENTIALS.json | python3 -m json.tool

# Read Wi-Fi passwords
cat /mnt/usb_share/targets/<profile>/WIFI_PASSWORDS.json | python3 -m json.tool

# Check the attack log
cat /var/log/cyberpi.log

# Unmount when done
sudo umount /mnt/usb_share
```

---

## Multi-Target / Continuous Mode

CyberPI supports attacking multiple devices **without resetting** — each attack is saved in its own profile. Just plug, wait for the LED, unplug, plug into the next target.

```
┌─────────────────────────────────────────────────────────────────┐
│                   CONTINUOUS ATTACK MODE                        │
│                                                                 │
│   Target 1                Target 2                Target 3      │
│   ┌────────┐              ┌────────┐              ┌────────┐    │
│   │Windows │              │ macOS  │              │ Linux  │    │
│   └───┬────┘              └───┬────┘              └───┬────┘    │
│       │plug in                │plug in                │plug in  │
│       ▼                       ▼                       ▼         │
│  [36s → unplug]          [36s → unplug]          [36s → unplug] │
│       │                       │                       │         │
│       ▼                       ▼                       ▼         │
│  targets/                targets/                targets/        │
│  DESKTOP-A1_...          MacBook_...             ubuntu_...      │
└─────────────────────────────────────────────────────────────────┘
```

**The Pi resets automatically on every reboot.** To attack a new device:
1. Unplug from target
2. Briefly power-cycle the Pi (unplug/replug the power), OR it resets on its own if running as a service
3. Plug into next target

To list all collected attack profiles:
```bash
/opt/cyberpi/venv/bin/python3 /opt/cyberpi/core/auto_attack.py --list-targets
```

To view results across all targets at once:
```bash
sudo mount -o loop /piusb.bin /mnt/usb_share
/opt/cyberpi/venv/bin/python3 /opt/cyberpi/core/viewer.py /mnt/usb_share
```
The viewer automatically loops through every profile found in `targets/`.

---

## Advanced Options

### Keyboard Layout

Default is US QWERTY. Change it before plugging into a target with a different layout:

```bash
sudo mount -o loop /piusb.bin /mnt/usb_share
echo "fr" | sudo tee /mnt/usb_share/.kb_layout   # French AZERTY
# echo "de" for German QWERTZ
sudo umount /mnt/usb_share
```

Supported: `us`, `fr`, `de`

### CLI Flags (auto_attack.py)

| Flag | Default | Description |
|------|---------|-------------|
| `--layout` | `auto` | Keyboard layout: `us`, `fr`, `de`, `auto` |
| `--os-timeout` | `10s` | How long to wait for OS detection |
| `--payload-timeout` | `90s` | Max time to wait for payload completion |
| `--force-os` | — | Skip detection: `windows`, `macos`, `linux`, `android` |
| `--no-encrypt` | — | Disable AES encryption (raw files) |
| `--no-stealth` | — | Leave terminal visible (useful for demos) |
| `--no-lock-check` | — | Skip screen-lock detection |
| `--dry-run` | — | Test without hardware (no HID injection) |
| `--list-targets` | — | Show all past attack profiles |

### Dry Run (No Hardware)

Test the full setup without a target computer:

```bash
python3 core/auto_attack.py --dry-run --mount /tmp/fake_mount
```

### Check Logs

```bash
# Full attack log
cat /var/log/cyberpi.log

# Service status
sudo systemctl status cyberpi.service

# Live log stream
journalctl -u cyberpi.service -f
```

---

## Project Structure

```
CYBERPI/
├── README.md                        ← this file
├── .gitignore
│
├── core/                            ← runs on the Pi
│   ├── auto_attack.py               ← attack orchestrator (boot → inject → collect → encrypt)
│   ├── viewer.py                    ← post-exploitation data viewer
│   ├── sd_reader.py                 ← offline SD card reader + HTML export
│   ├── install.sh                   ← one-command Pi installer
│   ├── fix_sd_card.sh               ← SD card Wi-Fi + USB networking fix
│   ├── SETUP_GUIDE.md               ← detailed hardware setup guide
│   ├── payloads/
│   │   ├── windows_payload.ps1      ← DPAPI decryption + full Windows extraction
│   │   ├── macos_payload.sh         ← Keychain + TCC-aware macOS extraction
│   │   ├── linux_payload.sh         ← Linux credential + SSH extraction
│   │   └── android_payload.sh       ← Android extraction (Termux-based)
│   └── deploy/
│       ├── cyberpi.service          ← systemd service (auto-run on boot)
│       ├── cyberpi-run              ← boot runner script
│       ├── cyberpi-gadget           ← USB composite gadget setup
│       └── rc.local                 ← LED stealth config
│
├── scripts/
│   ├── setup.sh                     ← manual Pi setup (alternative to install.sh)
│   └── usb_gadget.sh                ← USB gadget creation script
│
└── src/tools/                       ← shared Python utilities
    ├── encrypt_data.py              ← AES-256-GCM encryption (used by payloads + viewer)
    ├── decrypt_data.py              ← decryption utility
    └── detect_os.py                 ← OS detection logic
```

---

## Security Architecture

```
Collected Data
      │
      ▼
AES-256-GCM Encryption
      │
      ├── Key derivation: PBKDF2-SHA256 (100,000 iterations)
      ├── Password: Pi hardware serial / machine-id
      ├── Salt: random 128-bit, unique per encryption
      ├── Nonce: random 128-bit
      ├── Auth tag: 128-bit (tamper detection)
      │
      └── Result: .enc file — only decryptable on the original Pi
```

Data is **hardware-bound**: even if someone takes the SD card, they need the Pi's serial number to decrypt. The serial is read from `/proc/cpuinfo` or `/etc/machine-id`.

---

## Defense Recommendations

| Threat | Mitigation |
|--------|-----------|
| This attack | **Lock your screen.** The Pi aborts if it detects a locked screen. |
| USB attacks in general | Disable USB ports via Group Policy / MDM / BIOS |
| HID injection | Deploy EDR that detects rogue HID devices |
| Browser-stored credentials | Use a dedicated password manager |
| Wi-Fi password exposure | Use enterprise Wi-Fi (802.1X) — no password stored locally |
| Full compromise | Enable BitLocker / FileVault (full-disk encryption) |

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Pi not showing as USB device | Use the **DATA port** (closest to HDMI), not the PWR port |
| Nothing happens | SSH in → `journalctl -u cyberpi.service` |
| HID device missing | Run `sudo /usr/local/bin/cyberpi-gadget setup` then `ls /dev/hidg0` |
| Payload can't find drive | Volume must be labelled `TRUSTED` — check with `sudo blkid /piusb.bin` |
| Screen locked — attack aborted | Correct behaviour. Wait for the screen to be unlocked. |
| Need to re-run | `sudo reboot` — the attack resets on every boot |
| viewer.py decryption fails | Run on the same Pi the data was collected with (hardware-bound key) |

---

## Legal Notice

This tool is for **authorized penetration testing and security education only**.

- Only use on systems you **own** or have **explicit written permission** to test
- Comply with all applicable laws (CFAA, GDPR, CMA, and local equivalents)
- All collected data must be handled and destroyed responsibly after testing
- This is a proof-of-concept to demonstrate why USB port security matters

**Unauthorized use is illegal. With great power comes great responsibility.**

---

## Author

**Ahmed Ouyahya (Mr.D137)**

## License

MIT — Educational and authorized testing use only.
