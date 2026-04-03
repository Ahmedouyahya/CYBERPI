#!/usr/bin/env python3
"""
CyberPI SD Card Reader — Extract & View Attack Results

When you pull the SD card from the Pi and insert it into your laptop,
this app automatically finds the rootfs, mounts the USB image, decrypts
collected data, and displays everything in a clean readable format.

Usage:
    sudo python3 sd_reader.py                  # auto-detect SD card
    sudo python3 sd_reader.py --rootfs /mnt/piroot
    sudo python3 sd_reader.py --export report  # save HTML report

Requirements:
    sudo apt install python3-pip
    pip3 install pycryptodomex    (only needed if data is encrypted)

Author: Mr.D137
License: MIT (Authorized Penetration Testing Only)
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ─── ANSI Colors ──────────────────────────────────────────────────

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"


def banner():
    print(f"""
{C.RED}{C.BOLD}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝ ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║     ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
{C.RESET}
{C.CYAN}          SD Card Reader — Attack Results{C.RESET}
{C.DIM}        Authorized Penetration Testing Only{C.RESET}
""")


def section(title: str, icon: str = "─"):
    width = 64
    print(f"\n{C.CYAN}{C.BOLD}{icon * 2} {title} {'─' * (width - len(title) - 4)}{C.RESET}")


def label_value(label: str, value: str, indent: int = 2):
    print(f"{' ' * indent}{C.DIM}{label}:{C.RESET} {value}")


def status_badge(text: str, ok: bool) -> str:
    if ok:
        return f"{C.BG_GREEN}{C.BOLD} {text} {C.RESET}"
    return f"{C.BG_RED}{C.BOLD} {text} {C.RESET}"


def warn(msg: str):
    print(f"  {C.YELLOW}⚠ {msg}{C.RESET}")


def error(msg: str):
    print(f"  {C.RED}✗ {msg}{C.RESET}")


def success(msg: str):
    print(f"  {C.GREEN}✓ {msg}{C.RESET}")


def info(msg: str):
    print(f"  {C.BLUE}• {msg}{C.RESET}")


# ─── SD Card Discovery ───────────────────────────────────────────

def find_sd_rootfs() -> Optional[str]:
    """Auto-detect the Pi SD card rootfs partition."""
    # Check if already mounted at common locations
    for candidate in ["/mnt/piroot", "/media/*/rootfs"]:
        for path in glob.glob(candidate):
            if os.path.isdir(os.path.join(path, "etc")) and \
               os.path.isdir(os.path.join(path, "usr")):
                return path

    # Try to find unmounted ext4 partitions labeled 'rootfs'
    try:
        result = subprocess.run(
            ["lsblk", "-o", "NAME,FSTYPE,LABEL,MOUNTPOINT", "-J"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            for dev in data.get("blockdevices", []):
                for child in dev.get("children", []):
                    if child.get("label") == "rootfs" and child.get("fstype") == "ext4":
                        mp = child.get("mountpoint")
                        if mp:
                            return mp
                        # Need to mount it
                        dev_path = f"/dev/{child['name']}"
                        mount_point = "/mnt/piroot"
                        os.makedirs(mount_point, exist_ok=True)
                        subprocess.run(
                            ["mount", dev_path, mount_point],
                            capture_output=True, timeout=10
                        )
                        if os.path.isdir(os.path.join(mount_point, "etc")):
                            return mount_point
    except Exception:
        pass

    return None


def mount_usb_image(rootfs: str) -> Optional[str]:
    """Mount the /piusb.bin FAT32 image from the Pi rootfs."""
    usb_image = os.path.join(rootfs, "piusb.bin")
    if not os.path.isfile(usb_image):
        return None

    mount_point = tempfile.mkdtemp(prefix="cyberpi_usb_")
    try:
        result = subprocess.run(
            ["mount", "-o", "loop,ro", usb_image, mount_point],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return mount_point
    except Exception:
        pass

    # Cleanup on failure
    try:
        os.rmdir(mount_point)
    except Exception:
        pass
    return None


def get_device_id(rootfs: str) -> str:
    """Extract the Pi's device identifier (used as encryption password)."""
    # Try /proc/cpuinfo serial (Pi-specific)
    cpuinfo = os.path.join(rootfs, "proc", "cpuinfo")
    if os.path.isfile(cpuinfo):
        try:
            with open(cpuinfo) as f:
                for line in f:
                    if line.startswith("Serial"):
                        serial = line.split(":")[1].strip()
                        if serial and serial != "0000000000000000":
                            return serial
        except Exception:
            pass

    # machine-id (always available on systemd)
    machine_id_file = os.path.join(rootfs, "etc", "machine-id")
    if os.path.isfile(machine_id_file):
        try:
            with open(machine_id_file) as f:
                mid = f.read().strip()
                if mid:
                    return mid
        except Exception:
            pass

    return ""


# ─── Decryption ──────────────────────────────────────────────────

def decrypt_file(filepath: str, device_id: str) -> Optional[Dict[str, Any]]:
    """
    Decrypt a .enc file using AES-256-GCM + PBKDF2.
    Format: salt(16) + nonce(16) + tag(16) + ciphertext
    """
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Protocol.KDF import PBKDF2
        from Cryptodome.Hash import SHA256
    except ImportError:
        error("pycryptodomex not installed — cannot decrypt")
        info("Install it:  pip3 install pycryptodomex")
        return None

    SALT_LEN = 16
    NONCE_LEN = 16
    TAG_LEN = 16
    ITERATIONS = 100000

    try:
        with open(filepath, "rb") as f:
            blob = f.read()

        if len(blob) < SALT_LEN + NONCE_LEN + TAG_LEN + 1:
            error(f"File too small to be encrypted data: {len(blob)} bytes")
            return None

        salt = blob[:SALT_LEN]
        nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
        tag = blob[SALT_LEN + NONCE_LEN:SALT_LEN + NONCE_LEN + TAG_LEN]
        ciphertext = blob[SALT_LEN + NONCE_LEN + TAG_LEN:]

        key = PBKDF2(
            password=device_id,
            salt=salt,
            dkLen=32,
            count=ITERATIONS,
            hmac_hash_module=SHA256
        )

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return json.loads(plaintext.decode("utf-8"))

    except Exception as e:
        error(f"Decryption failed: {e}")
        return None


# ─── Data Display ────────────────────────────────────────────────

def display_attack_log(rootfs: str):
    """Show the attack execution log."""
    log_path = os.path.join(rootfs, "var", "log", "cyberpi.log")
    if not os.path.isfile(log_path):
        warn("No attack log found (var/log/cyberpi.log)")
        return

    section("ATTACK LOG", "📋")
    with open(log_path, errors="replace") as f:
        content = f.read().strip()

    if not content:
        warn("Attack log is empty — Pi hasn't run an attack yet")
        return

    lines = content.splitlines()
    for line in lines:
        # Colorize log lines
        if "ERROR" in line or "error" in line.lower():
            print(f"  {C.RED}{line}{C.RESET}")
        elif "WARNING" in line or "warning" in line.lower():
            print(f"  {C.YELLOW}{line}{C.RESET}")
        elif "STARTED" in line or "COMPLETED" in line:
            print(f"  {C.GREEN}{C.BOLD}{line}{C.RESET}")
        elif "Detected" in line or "Launched" in line:
            print(f"  {C.CYAN}{line}{C.RESET}")
        else:
            print(f"  {C.DIM}{line}{C.RESET}")


def display_attack_result(rootfs: str):
    """Extract and display the attack result JSON from journal/log."""
    log_path = os.path.join(rootfs, "var", "log", "cyberpi.log")
    if not os.path.isfile(log_path):
        return

    with open(log_path, errors="replace") as f:
        content = f.read()

    # Find the JSON result block (v2 or v3)
    result_data = None
    for version_tag in ["v3", "v2"]:
        json_match = re.search(
            rf'=== ATTACK RESULT \({version_tag}\) ===\s*(\{{.*?\}})',
            content, re.DOTALL
        )
        if json_match:
            try:
                result_data = json.loads(json_match.group(1))
                break
            except json.JSONDecodeError:
                pass

    if not result_data:
        return

    section("LATEST ATTACK SUMMARY", "🎯")

    os_name = result_data.get("host_os", "unknown")
    os_color = {
        "windows": C.BLUE, "macos": C.WHITE, "linux": C.GREEN,
        "android": C.YELLOW,
    }.get(os_name, C.YELLOW)

    if result_data.get("target_id"):
        label_value("Target ID", result_data["target_id"])
    if result_data.get("profile_dir"):
        label_value("Profile Dir", result_data["profile_dir"])

    label_value("Target OS", f"{os_color}{C.BOLD}{os_name.upper()}{C.RESET}")
    label_value("Keyboard Layout", result_data.get("keyboard_layout", "?"))
    label_value("Screen Locked", "Yes ⚠" if result_data.get("screen_was_locked") else "No")
    label_value("HID Injected", status_badge("YES", True) if result_data.get("hid_injected") else status_badge("NO", False))
    label_value("Payload Executed", status_badge("YES", True) if result_data.get("payload_executed") else status_badge("NO", False))
    label_value("Payload Completed", status_badge("YES", True) if result_data.get("payload_completed") else status_badge("NO", False))
    label_value("Data Encrypted", status_badge("YES", True) if result_data.get("encrypted") else status_badge("NO", False))
    label_value("Files Collected", str(result_data.get("files_collected", 0)))

    start = result_data.get("start", "")
    end = result_data.get("end", "")
    duration = result_data.get("duration_secs", 0)
    if start:
        label_value("Start Time", start)
    if end:
        label_value("End Time", end)
    if duration:
        label_value("Duration", f"{duration:.1f} seconds")

    errors = result_data.get("errors", [])
    if errors:
        print(f"\n  {C.RED}{C.BOLD}Errors:{C.RESET}")
        for err in errors:
            error(err)


def display_targets(usb_mount: str):
    """Show all multi-target profiles from targets/ directory."""
    targets_dir = os.path.join(usb_mount, "targets")
    if not os.path.isdir(targets_dir):
        return

    profiles = sorted([d for d in os.listdir(targets_dir)
                       if os.path.isdir(os.path.join(targets_dir, d))])
    if not profiles:
        return

    section(f"MULTI-TARGET PROFILES ({len(profiles)} targets)", "🎯")

    for i, profile in enumerate(profiles, 1):
        profile_path = os.path.join(targets_dir, profile)
        meta_file = os.path.join(profile_path, "attack_meta.json")

        # Count files in this profile
        file_count = sum(1 for _, _, files in os.walk(profile_path) for _ in files)
        total_size = sum(
            os.path.getsize(os.path.join(r, f))
            for r, _, files in os.walk(profile_path)
            for f in files
        )

        if os.path.isfile(meta_file):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                host_os = meta.get("host_os", "?")
                duration = meta.get("duration_secs", "?")
                completed = meta.get("payload_completed", False)
                files_enc = meta.get("files_collected", 0)
                start = meta.get("attack_start", "?")

                os_color = {
                    "windows": C.BLUE, "macos": C.WHITE,
                    "linux": C.GREEN, "android": C.YELLOW,
                }.get(host_os, C.DIM)

                status = status_badge("COMPLETE", True) if completed else status_badge("INCOMPLETE", False)
                print(f"\n  {C.BOLD}[{i}]{C.RESET} {C.CYAN}{profile}{C.RESET}")
                print(f"      OS: {os_color}{C.BOLD}{host_os.upper()}{C.RESET}  |  "
                      f"Status: {status}  |  Duration: {duration}s")
                print(f"      Files: {file_count} ({_human_size(total_size)})  |  "
                      f"Encrypted: {files_enc}  |  Started: {start}")

                errors = meta.get("errors", [])
                if errors:
                    for err in errors:
                        print(f"      {C.RED}ERROR: {err}{C.RESET}")
            except Exception:
                print(f"\n  {C.BOLD}[{i}]{C.RESET} {C.CYAN}{profile}{C.RESET}")
                print(f"      Files: {file_count} ({_human_size(total_size)}) — metadata corrupt")
        else:
            print(f"\n  {C.BOLD}[{i}]{C.RESET} {C.CYAN}{profile}{C.RESET}")
            print(f"      Files: {file_count} ({_human_size(total_size)}) — no metadata")

        # Show collection summary if present
        summary_file = os.path.join(profile_path, "collection_summary.txt")
        if os.path.isfile(summary_file):
            try:
                with open(summary_file, errors="replace") as f:
                    content = f.read(2000)
                # Show first few relevant lines
                for line in content.splitlines()[:8]:
                    line = line.strip()
                    if line and not line.startswith("==="):
                        if "WIFI" in line.upper() or "PSK" in line.upper() or "PASSWORD" in line.upper():
                            print(f"      {C.RED}{C.BOLD}{line}{C.RESET}")
                        elif "SSID" in line.upper():
                            print(f"      {C.YELLOW}{line}{C.RESET}")
                        else:
                            print(f"      {C.DIM}{line}{C.RESET}")
            except Exception:
                pass

    print()


def display_usb_contents(usb_mount: str):
    """List all files on the USB image."""
    section("USB DRIVE CONTENTS", "💾")

    if not os.path.isdir(usb_mount):
        warn("USB image not mounted")
        return

    total_files = 0
    for root, dirs, files in os.walk(usb_mount):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, usb_mount)
            size = os.path.getsize(fpath)
            mtime = datetime.fromtimestamp(os.path.getmtime(fpath))

            # Color by file type
            if fname.endswith(".enc"):
                color = C.RED
                icon = "🔒"
            elif fname.endswith((".ps1", ".sh", ".bat")):
                color = C.GREEN
                icon = "⚡"
            elif fname.endswith((".txt", ".json", ".xml", ".csv")):
                color = C.CYAN
                icon = "📄"
            elif fname.endswith((".db", ".sqlite")):
                color = C.MAGENTA
                icon = "🗃"
            else:
                color = C.DIM
                icon = "  "

            size_str = _human_size(size)
            print(f"  {icon} {color}{rel:<40}{C.RESET} {size_str:>8}  {C.DIM}{mtime:%Y-%m-%d %H:%M}{C.RESET}")
            total_files += 1

    if total_files == 0:
        warn("USB drive is empty — no payload results yet")
    else:
        print(f"\n  {C.BOLD}Total: {total_files} file(s){C.RESET}")


def display_raw_text_files(usb_mount: str):
    """Display any plaintext result files (unencrypted output)."""
    text_patterns = ["*.txt", "*.json", "*.csv", "*.xml"]
    found = False

    for pattern in text_patterns:
        for fpath in glob.glob(os.path.join(usb_mount, "**", pattern), recursive=True):
            fname = os.path.basename(fpath)
            rel = os.path.relpath(fpath, usb_mount)

            # Skip payload scripts
            if fname.endswith((".ps1", ".sh", ".bat")):
                continue

            if not found:
                section("RAW DATA FILES (Unencrypted)", "📄")
                found = True

            size = os.path.getsize(fpath)
            print(f"\n  {C.CYAN}{C.BOLD}── {rel} ({_human_size(size)}) ──{C.RESET}")

            try:
                with open(fpath, errors="replace") as f:
                    content = f.read(10000)  # Limit to 10KB per file

                if fname.endswith(".json"):
                    try:
                        data = json.loads(content)
                        content = json.dumps(data, indent=2)
                    except json.JSONDecodeError:
                        pass

                for line in content.splitlines()[:50]:
                    print(f"    {C.DIM}{line}{C.RESET}")

                if len(content) >= 10000:
                    warn(f"  ... truncated (file > 10KB)")
            except Exception as e:
                error(f"  Could not read: {e}")


def display_encrypted_data(usb_mount: str, device_id: str):
    """Find, decrypt, and display encrypted result files."""
    enc_files = glob.glob(os.path.join(usb_mount, "**", "*.enc"), recursive=True)

    if not enc_files:
        return

    section("DECRYPTED COLLECTED DATA", "🔓")

    for enc_path in enc_files:
        rel = os.path.relpath(enc_path, usb_mount)
        size = os.path.getsize(enc_path)
        print(f"\n  {C.RED}🔒 {rel}{C.RESET} ({_human_size(size)})")

        if not device_id:
            error("No device ID found — cannot decrypt")
            info("The Pi's /etc/machine-id is needed as the decryption key")
            continue

        info(f"Decrypting with device ID: {device_id[:8]}...")
        data = decrypt_file(enc_path, device_id)

        if data is None:
            continue

        success("Decryption successful!")

        # Display metadata
        if "encryption_info" in data:
            ei = data["encryption_info"]
            label_value("Algorithm", ei.get("algorithm", "?"), indent=4)

        if "timestamp" in data:
            label_value("Collected At", data["timestamp"], indent=4)

        if "device_id" in data:
            label_value("Device ID", data["device_id"][:12] + "...", indent=4)

        # Display the actual payload data
        payload = data.get("payload", {})
        if payload:
            print(f"\n  {C.GREEN}{C.BOLD}  Collected Data ({len(payload)} items):{C.RESET}")
            for filename, content in payload.items():
                print(f"\n    {C.CYAN}{C.BOLD}── {filename} ──{C.RESET}")
                # Truncate very long content
                if isinstance(content, str):
                    lines = content.splitlines()
                    for line in lines[:30]:
                        print(f"      {line}")
                    if len(lines) > 30:
                        warn(f"    ... {len(lines) - 30} more lines")
                elif isinstance(content, dict):
                    formatted = json.dumps(content, indent=2)
                    for line in formatted.splitlines()[:30]:
                        print(f"      {line}")
                else:
                    print(f"      {content}")
        else:
            warn("Payload section is empty")


def display_system_info(rootfs: str):
    """Show Pi system information."""
    section("PI SYSTEM INFO", "🔧")

    # Hostname
    hostname_file = os.path.join(rootfs, "etc", "hostname")
    if os.path.isfile(hostname_file):
        with open(hostname_file) as f:
            label_value("Hostname", f.read().strip())

    # OS version
    os_release = os.path.join(rootfs, "etc", "os-release")
    if os.path.isfile(os_release):
        with open(os_release) as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    name = line.split("=", 1)[1].strip().strip('"')
                    label_value("OS", name)
                    break

    # Machine ID
    mid_file = os.path.join(rootfs, "etc", "machine-id")
    if os.path.isfile(mid_file):
        with open(mid_file) as f:
            mid = f.read().strip()
            label_value("Machine ID", mid[:12] + "..." if len(mid) > 12 else mid)

    # Kernel (from boot)
    uname_file = os.path.join(rootfs, "proc", "version")
    if os.path.isfile(uname_file):
        with open(uname_file) as f:
            label_value("Kernel", f.read().strip()[:80])

    # USB image
    usb_img = os.path.join(rootfs, "piusb.bin")
    if os.path.isfile(usb_img):
        size = os.path.getsize(usb_img)
        label_value("USB Image", f"/piusb.bin ({_human_size(size)})")

    # Services status
    gadget_svc = os.path.join(rootfs, "etc/systemd/system/multi-user.target.wants/cyberpi-gadget.service")
    attack_svc = os.path.join(rootfs, "etc/systemd/system/multi-user.target.wants/cyberpi.service")
    label_value("Gadget Service", status_badge("ENABLED", True) if os.path.islink(gadget_svc) else status_badge("DISABLED", False))
    label_value("Attack Service", status_badge("ENABLED", True) if os.path.islink(attack_svc) else status_badge("DISABLED", False))


def display_service_logs(rootfs: str):
    """Show systemd journal entries for cyberpi services (if available)."""
    # Binary journal is harder to read from SD card; rely on cyberpi.log instead
    pass


# ─── Export ──────────────────────────────────────────────────────

def export_html(rootfs: str, usb_mount: Optional[str], device_id: str, outfile: str):
    """Export all collected data as an HTML report."""
    section("EXPORTING HTML REPORT", "📊")

    html_parts = []
    html_parts.append("""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>CyberPI Attack Report</title>
<style>
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #1a1a2e; color: #e0e0e0; padding: 2em; max-width: 900px; margin: auto; }
h1 { color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }
h2 { color: #0f3460; background: #16213e; padding: 8px 16px; border-left: 4px solid #e94560; }
pre { background: #0d1117; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 13px; line-height: 1.5; }
code { color: #c9d1d9; }
.ok { color: #3fb950; font-weight: bold; }
.err { color: #f85149; font-weight: bold; }
.meta { color: #8b949e; font-size: 0.9em; }
table { width: 100%; border-collapse: collapse; margin: 1em 0; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #30363d; }
th { background: #161b22; color: #58a6ff; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 0.85em; font-weight: bold; }
.badge-ok { background: #238636; color: #fff; }
.badge-err { background: #da3633; color: #fff; }
</style></head><body>
<h1>🔴 CyberPI Attack Report</h1>
<p class="meta">Generated: """ + datetime.now().isoformat() + "</p>\n")

    # System info
    html_parts.append("<h2>System Info</h2><table>")
    hostname_file = os.path.join(rootfs, "etc", "hostname")
    if os.path.isfile(hostname_file):
        with open(hostname_file) as f:
            html_parts.append(f"<tr><th>Hostname</th><td>{f.read().strip()}</td></tr>")
    mid_file = os.path.join(rootfs, "etc", "machine-id")
    if os.path.isfile(mid_file):
        with open(mid_file) as f:
            html_parts.append(f"<tr><th>Machine ID</th><td>{f.read().strip()[:16]}...</td></tr>")
    html_parts.append("</table>")

    # Attack log
    log_path = os.path.join(rootfs, "var", "log", "cyberpi.log")
    if os.path.isfile(log_path):
        with open(log_path, errors="replace") as f:
            log_content = f.read().strip()
        if log_content:
            escaped = log_content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html_parts.append(f"<h2>Attack Log</h2><pre><code>{escaped}</code></pre>")

    # USB contents
    if usb_mount and os.path.isdir(usb_mount):
        html_parts.append("<h2>USB Drive Files</h2><table><tr><th>File</th><th>Size</th><th>Modified</th></tr>")
        for root, dirs, files in os.walk(usb_mount):
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, usb_mount)
                size = _human_size(os.path.getsize(fpath))
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
                html_parts.append(f"<tr><td>{rel}</td><td>{size}</td><td>{mtime}</td></tr>")
        html_parts.append("</table>")

        # Raw text files
        for pattern in ("*.txt", "*.json", "*.csv", "*.xml"):
            for fpath in glob.glob(os.path.join(usb_mount, "**", pattern), recursive=True):
                rel = os.path.relpath(fpath, usb_mount)
                try:
                    with open(fpath, errors="replace") as f:
                        content = f.read(20000)
                    escaped = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    html_parts.append(f"<h2>📄 {rel}</h2><pre><code>{escaped}</code></pre>")
                except Exception:
                    pass

        # Encrypted data
        for enc_path in glob.glob(os.path.join(usb_mount, "**", "*.enc"), recursive=True):
            rel = os.path.relpath(enc_path, usb_mount)
            if device_id:
                data = decrypt_file(enc_path, device_id)
                if data and "payload" in data:
                    html_parts.append(f"<h2>🔓 {rel} (Decrypted)</h2>")
                    for fname, content in data["payload"].items():
                        escaped = str(content).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        html_parts.append(f"<h3>{fname}</h3><pre><code>{escaped[:10000]}</code></pre>")

    html_parts.append("</body></html>")
    html_content = "\n".join(html_parts)

    out_path = outfile if outfile.endswith(".html") else outfile + ".html"
    with open(out_path, "w") as f:
        f.write(html_content)

    success(f"Report saved to: {out_path}")
    info(f"Open in browser:  xdg-open {out_path}")


# ─── Helpers ─────────────────────────────────────────────────────

def _human_size(nbytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} TB"


# ─── Main ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CyberPI SD Card Reader — Extract & View Attack Results"
    )
    parser.add_argument(
        "--rootfs", default=None,
        help="Path to mounted Pi rootfs (auto-detected if omitted)"
    )
    parser.add_argument(
        "--export", default=None, metavar="FILENAME",
        help="Export results as HTML report"
    )
    parser.add_argument(
        "--no-decrypt", action="store_true",
        help="Skip decryption of .enc files"
    )
    parser.add_argument(
        "--password", default=None,
        help="Override decryption password (default: auto-detect from Pi machine-id)"
    )
    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print(f"{C.YELLOW}⚠  Running without root — mounting may fail.{C.RESET}")
        print(f"   Hint:  sudo python3 {sys.argv[0]}\n")

    banner()

    # ── Step 1: Find rootfs ──
    section("LOCATING SD CARD", "🔍")

    rootfs = args.rootfs
    if rootfs:
        if not os.path.isdir(rootfs):
            error(f"Rootfs path not found: {rootfs}")
            return 1
        success(f"Using rootfs: {rootfs}")
    else:
        info("Auto-detecting Pi SD card...")
        rootfs = find_sd_rootfs()
        if rootfs:
            success(f"Found rootfs at: {rootfs}")
        else:
            error("Could not find Pi SD card rootfs")
            info("Mount it manually:")
            info("  sudo mount /dev/sdX2 /mnt/piroot")
            info("Then run:  sudo python3 sd_reader.py --rootfs /mnt/piroot")
            return 1

    # ── Step 2: System info ──
    display_system_info(rootfs)

    # ── Step 3: Get device ID for decryption ──
    device_id = args.password or get_device_id(rootfs)
    if device_id:
        info(f"Device ID for decryption: {device_id[:12]}...")
    else:
        warn("Could not determine device ID — encrypted files won't be decryptable")

    # ── Step 4: Mount USB image ──
    section("MOUNTING USB IMAGE", "💾")
    usb_mount = mount_usb_image(rootfs)
    if usb_mount:
        success(f"USB image mounted at: {usb_mount}")
    else:
        warn("No USB image found or mount failed")
        info("The attack may not have written results to /piusb.bin")

    try:
        # ── Step 5: Show attack log ──
        display_attack_log(rootfs)

        # ── Step 6: Show attack result summary ──
        display_attack_result(rootfs)

        # ── Step 7: Multi-target profiles ──
        if usb_mount:
            display_targets(usb_mount)

        # ── Step 8: USB contents ──
        if usb_mount:
            display_usb_contents(usb_mount)

            # ── Step 9: Raw text files ──
            display_raw_text_files(usb_mount)

            # ── Step 10: Encrypted data ──
            if not args.no_decrypt:
                display_encrypted_data(usb_mount, device_id)

        # ── Step 11: Export ──
        if args.export:
            export_html(rootfs, usb_mount, device_id, args.export)

        # ── Done ──
        section("DONE", "✅")
        if usb_mount:
            info(f"USB image still mounted at: {usb_mount}")
            info(f"Unmount when done:  sudo umount {usb_mount}")

    finally:
        # Don't auto-unmount — user might want to browse
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
