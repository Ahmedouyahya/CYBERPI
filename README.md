# CyberPI — $5 USB Penetration Testing Device

> **Plug it in. Walk away. Get credentials.**
>
> A Raspberry Pi Zero transforms into a fully automated penetration testing device
> that extracts browser passwords, Wi-Fi keys, SSH keys, and system intelligence
> in under 30 seconds.

---

## The Problem

Organizations spend millions on perimeter security but ignore the USB port.
**Any unlocked workstation can be fully compromised in seconds** with nothing
more than a $5 microcomputer.

We built CyberPI to prove it.

---

## How It Works

```
┌──────────────┐     USB cable      ┌────────────────┐
│  Pi Zero W   │ ──────────────────→│  Target PC     │
│              │   appears as:      │  (Win/Mac/Lin) │
│  CyberPI     │   • USB keyboard   │                │
│  firmware    │   • USB flash drive │                │
└──────┬───────┘                    └────────────────┘
       │
       │  1. Detects target OS (filesystem artefacts)
       │  2. Checks if screen is unlocked (canary file)
       │  3. Types keystrokes to open hidden terminal
       │  4. Executes OS-specific payload from flash drive
       │  5. Extracts: browser creds, Wi-Fi, SSH keys, system info
       │  6. Decrypts Chrome/Edge passwords via DPAPI (Windows)
       │  7. AES-256-GCM encrypts everything on the drive
       │  8. LED blinks → done → unplug
       │
       ▼
  Post-exploitation viewer shows all collected data
```

### Attack Timeline (Real-World)

| Time | Action |
|------|--------|
| 0s | Plug in Pi Zero |
| 6s | Host enumerates USB device |
| 8s | OS detected (Windows/macOS/Linux) |
| 9s | Screen lock check (canary file) |
| 10s | Hidden PowerShell/Terminal launched |
| 12s | Payload begins extraction |
| 30s | Browser DBs + Wi-Fi + system info collected |
| 32s | DPAPI master key extracted, passwords decrypted |
| 35s | All data AES-256 encrypted on drive |
| 36s | LED blinks 5x → unplug |

**Total: ~36 seconds from plug to unplug.**

---

## What We Actually Extract

### Windows
- **Chrome/Edge passwords** — decrypted in cleartext via DPAPI
- **Firefox databases** — login DB + key4.db for offline cracking
- **Wi-Fi passwords** — all saved networks in plaintext
- **Windows Credential Manager** — saved RDP, web, app credentials
- **System recon** — hostname, users, processes, AV status, network config

### macOS
- **Chrome/Edge passwords** — via Keychain Safe Storage key extraction
- **Safari history & bookmarks** — TCC-aware (works when accessible)
- **SSH private keys** — `~/.ssh/*`
- **Keychain dump** — user-accessible keychain items
- **Wi-Fi passwords** — from system Keychain (when authorised)
- **Security posture** — FileVault, SIP, Gatekeeper, Firewall status

---

## Key Technical Features

### v2 Improvements (Hackathon Edition)

| Feature | v1 (Original) | v2 (Hackathon) |
|---------|---------------|----------------|
| OS Detection | Single filesystem check | Polling-based, multi-signal, 15s timeout |
| Keyboard Layout | US-only | Auto-detect or configurable (US/FR/DE) |
| Screen Lock | No detection | Canary file verification |
| Windows Passwords | Raw encrypted DBs | **DPAPI decryption → cleartext** |
| macOS Chrome | Raw DBs | Keychain Safe Storage key extraction |
| Payload Wait | Fixed 25s sleep | Adaptive polling for completion marker |
| Window Visibility | Visible terminal | Hidden/minimised (`-W Hidden`) |
| Wi-Fi (Windows) | `netsh export` XML | Parsed JSON with passwords |
| Data Output | Raw files | Structured JSON + encrypted blob |
| Post-exploitation | Manual file browsing | **Interactive data viewer with formatting** |
| Firefox | Raw copy only | key4.db + cert9.db for offline decrypt |
| SSH Keys | Not collected | Full `~/.ssh/` harvesting |

### Security Architecture

```
Collected Data → AES-256-GCM Encryption
                    │
                    ├── PBKDF2-SHA256 key derivation (100k iterations)
                    ├── Hardware-bound key (Pi serial number)
                    ├── Random 128-bit salt per encryption
                    ├── Authentication tag (tamper detection)
                    └── Only decryptable on original Pi device
```

---

## Hardware Requirements

| Component | Cost | Purpose |
|-----------|------|---------|
| Raspberry Pi Zero W | $5-10 | The attack device |
| Micro USB cable | $1 | Connection to target |
| MicroSD card (8GB+) | $3 | OS + payloads |
| LED + resistor (optional) | $0.50 | Status indicator |
| **Total** | **~$10** | |

---

## Live Demo Flow

```bash
# 1. SETUP (before demo)
sudo bash scripts/setup.sh          # Install deps, create USB image
sudo bash scripts/usb_gadget.sh     # Create composite USB gadget

# 2. DEPLOY (plug Pi into target laptop)
#    → Pi auto-detects OS, injects keystrokes, runs payload
#    → LED blinks when done (~30 seconds)

# 3. VIEW RESULTS (plug Pi into your laptop or SSH in)
python3 hackathon/viewer.py /mnt/usb_share
#    → Shows all extracted credentials, Wi-Fi passwords, system info

# 4. DECRYPT (if data was encrypted)
python3 hackathon/viewer.py /mnt/usb_share/collected_data.enc -p <pi-serial>
```

### Dry Run (No Hardware)
```bash
python3 hackathon/auto_attack_v2.py --dry-run --mount /tmp/fake_mount
```

---

## Project Structure

```
hackathon/
├── auto_attack_v2.py          # Attack orchestrator (all fixes)
├── viewer.py                  # Post-exploitation data viewer
├── payloads/
│   ├── windows_payload_v2.ps1 # DPAPI decryption + full extraction
│   └── macos_payload_v2.sh    # TCC-aware + Keychain extraction
└── README.md                  # This file (hackathon pitch)

src/                           # Original codebase
├── auto_attack.py             # v1 orchestrator
├── main.py                    # CLI entry point
├── tools/
│   ├── encrypt_data.py        # AES-256-GCM encryption (shared)
│   ├── detect_os.py           # OS detection module
│   └── ...
├── payloads/
│   ├── windows_payload.ps1    # v1 Windows payload
│   └── macos_payload.sh       # v1 macOS payload
└── ...

scripts/
├── setup.sh                   # Pi setup automation
└── usb_gadget.sh              # USB composite gadget creation
```

---

## Why This Matters

- **$10 in hardware** defeats enterprise security on any unlocked workstation
- **No software installation** on the target — pure hardware attack
- **30 seconds** — faster than getting coffee
- **Undetectable** by most consumer AV (no malware signature, just keystrokes)
- **Demonstrates** why USB port security, screen locking, and EDR matter

### Defense Recommendations

1. **Lock your screen.** This attack fails on locked machines.
2. **Disable USB ports** or use USB device whitelisting (Group Policy / MDM)
3. **Deploy EDR** that detects rogue HID devices
4. **Enable full-disk encryption** (BitLocker/FileVault)
5. **Use a password manager** instead of browser-stored credentials
6. **Enterprise Wi-Fi** (802.1X) — passwords aren't stored locally

---

## Legal & Ethical Notice

This tool is for **authorized penetration testing and security education only**.

- Only use on systems you **own** or have **explicit written permission** to test
- Comply with all applicable laws (CFAA, GDPR, local regulations)
- All collected data must be handled, stored, and destroyed responsibly
- This tool is a proof-of-concept to demonstrate USB attack vectors

**With great power comes great responsibility.**

---

## Team

- **Ahmed Ouyahya (Mr.D137)** — Creator & Lead Developer

## License

MIT License — Educational and authorized testing use only.
