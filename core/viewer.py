#!/usr/bin/env python3
"""
Post-Exploitation Data Viewer — Hackathon Edition

Decrypts and displays all collected data in a formatted report.
Designed for live hackathon demos: plug the Pi back in, run this
script, and show the judges what was collected.

Usage:
    python3 viewer.py /path/to/usb/mount
    python3 viewer.py /path/to/collected_data.enc --password <pi-serial>

Author: Mr.D137
License: MIT (Authorized Penetration Testing Only)
"""

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Path setup
_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_THIS_DIR), str(_PROJECT_ROOT), str(_PROJECT_ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ─── ANSI Colors ──────────────────────────────────────────

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"


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
{C.YELLOW}            Post-Exploitation Data Viewer{C.RESET}
{C.DIM}        Authorized Penetration Testing Only{C.RESET}
""")


def section(title: str):
    width = 60
    print(f"\n{C.CYAN}{C.BOLD}{'─' * width}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}{'─' * width}{C.RESET}")


def show_json_file(filepath: str, title: str, max_items: int = 20):
    """Display a JSON file in formatted output."""
    p = Path(filepath)
    if not p.exists():
        return
    section(title)
    try:
        data = json.loads(p.read_text(errors="replace"))
        if isinstance(data, list):
            for i, item in enumerate(data[:max_items]):
                if isinstance(item, dict):
                    for k, v in item.items():
                        label = k.replace("_", " ").title()
                        print(f"  {C.DIM}{label}:{C.RESET} {v}")
                    print()
                else:
                    print(f"  {item}")
            if len(data) > max_items:
                print(f"  {C.DIM}... and {len(data) - max_items} more{C.RESET}")
        elif isinstance(data, dict):
            for k, v in data.items():
                label = k.replace("_", " ").title()
                if isinstance(v, (dict, list)):
                    print(f"  {C.BOLD}{label}:{C.RESET}")
                    print(f"    {json.dumps(v, indent=4)[:500]}")
                else:
                    print(f"  {C.BOLD}{label}:{C.RESET} {v}")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"  {C.RED}Error parsing: {e}{C.RESET}")


def show_text_file(filepath: str, title: str, max_lines: int = 30):
    """Display a text file."""
    p = Path(filepath)
    if not p.exists():
        return
    section(title)
    lines = p.read_text(errors="replace").splitlines()
    for line in lines[:max_lines]:
        print(f"  {line}")
    if len(lines) > max_lines:
        print(f"  {C.DIM}... ({len(lines) - max_lines} more lines){C.RESET}")


def show_credentials(data_dir: Path):
    """Show decrypted credentials — the star of the demo."""
    cred_file = data_dir / "DECRYPTED_CREDENTIALS.json"
    if cred_file.exists():
        section("DECRYPTED BROWSER CREDENTIALS")
        creds = json.loads(cred_file.read_text(errors="replace"))
        print(f"\n  {C.RED}{C.BOLD}Found {len(creds)} credentials:{C.RESET}\n")
        for i, cred in enumerate(creds[:30], 1):
            browser = cred.get("Browser", "Unknown")
            url = cred.get("URL", "")
            user = cred.get("Username", "")
            pw = cred.get("Password", "")
            # Redact actual passwords in demo — show first 2 chars + asterisks
            if pw and len(pw) > 2:
                pw_display = pw[:2] + "*" * (len(pw) - 2)
            else:
                pw_display = pw or "[empty]"

            print(f"  {C.BOLD}{i:3d}.{C.RESET} [{C.BLUE}{browser}{C.RESET}]")
            print(f"       URL:  {url[:70]}")
            print(f"       User: {C.GREEN}{user}{C.RESET}")
            print(f"       Pass: {C.RED}{pw_display}{C.RESET}")
            print()

        if len(creds) > 30:
            print(f"  {C.DIM}... and {len(creds) - 30} more{C.RESET}")
    else:
        # Check for Chrome credential summary (macOS style)
        for browser in ["chrome", "edge"]:
            summary = data_dir / browser / "credentials_summary.json"
            if summary.exists():
                show_json_file(str(summary), f"{browser.upper()} Credentials (URLs + Usernames)")


def show_wifi(data_dir: Path):
    """Show Wi-Fi passwords."""
    wifi_file = data_dir / "WIFI_PASSWORDS.json"
    if wifi_file.exists():
        section("WI-FI PASSWORDS")
        try:
            networks = json.loads(wifi_file.read_text(errors="replace"))
            print(f"\n  {C.YELLOW}{C.BOLD}Found {len(networks)} networks:{C.RESET}\n")
            for net in networks:
                ssid = net.get("SSID") or net.get("ssid", "Unknown")
                pw = net.get("Password") or net.get("password", "[none]")
                print(f"  {C.BOLD}📶 {ssid}{C.RESET}")
                print(f"     Password: {C.RED}{pw}{C.RESET}")
                print()
        except json.JSONDecodeError:
            pass


def show_encrypted_data(enc_path: str, password: str):
    """Decrypt and show collected_data.enc content."""
    try:
        from tools.encrypt_data import SecureDataHandler
        handler = SecureDataHandler(storage_path=str(Path(enc_path).parent))

        with open(enc_path, "rb") as f:
            blob = f.read()

        data = handler.decrypt_data(blob, password=password)

        section("DECRYPTED COLLECTED DATA")
        payload = data.get("payload", data)
        if isinstance(payload, dict):
            for filename, content in payload.items():
                print(f"\n  {C.BOLD}{C.BLUE}{filename}{C.RESET}")
                if isinstance(content, str):
                    for line in content.splitlines()[:10]:
                        print(f"    {line}")
                    total = len(content.splitlines())
                    if total > 10:
                        print(f"    {C.DIM}... ({total - 10} more lines){C.RESET}")
                else:
                    print(f"    {content}")
    except Exception as e:
        print(f"\n  {C.RED}Decryption failed: {e}{C.RESET}")
        print(f"  {C.DIM}Make sure you're running on the same Pi (device-bound key){C.RESET}")


def view_collection(data_dir: str, password: str = None):
    """Main viewer — scans a directory for all collected data."""
    banner()

    dp = Path(data_dir)
    if not dp.exists():
        print(f"{C.RED}Error: {data_dir} does not exist{C.RESET}")
        return

    # Show summary first
    show_text_file(str(dp / "collection_summary.txt"), "COLLECTION SUMMARY")
    show_json_file(str(dp / "collection_results.json"), "COLLECTION RESULTS")

    # Star of the show: credentials
    show_credentials(dp)

    # Wi-Fi
    show_wifi(dp)

    # System info
    show_json_file(str(dp / "system" / "system_info.json"), "SYSTEM INFORMATION")
    show_text_file(str(dp / "system" / "network_info.txt"), "NETWORK INFORMATION")

    # Credential Manager
    show_text_file(str(dp / "credman" / "credential_manager.txt"), "CREDENTIAL MANAGER")

    # SSH keys
    ssh_dir = dp / "ssh"
    if ssh_dir.exists() and any(ssh_dir.iterdir()):
        section("SSH KEYS")
        for key_file in sorted(ssh_dir.iterdir()):
            print(f"  {C.GREEN}{key_file.name}{C.RESET} ({key_file.stat().st_size} bytes)")
            if key_file.name.endswith(".pub"):
                print(f"    {key_file.read_text(errors='replace').strip()[:100]}")
        print()

    # Encrypted blob
    enc_file = dp / "collected_data.enc"
    if enc_file.exists():
        if password:
            show_encrypted_data(str(enc_file), password)
        else:
            section("ENCRYPTED DATA BLOB")
            print(f"  File: {enc_file}")
            print(f"  Size: {enc_file.stat().st_size:,} bytes")
            print(f"  {C.DIM}Use --password <pi-serial> to decrypt{C.RESET}")

    # Final stats
    section("COLLECTION STATISTICS")
    total_files = sum(1 for _ in dp.rglob("*") if _.is_file())
    total_size = sum(f.stat().st_size for f in dp.rglob("*") if f.is_file())
    print(f"  Total files : {total_files}")
    print(f"  Total size  : {total_size:,} bytes ({total_size / 1024:.1f} KB)")
    print(f"  Location    : {dp}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Post-Exploitation Data Viewer — view collected data"
    )
    parser.add_argument("path", help="Path to USB mount or collected_data.enc file")
    parser.add_argument("--password", "-p", help="Decryption password (Pi serial)")
    parser.add_argument("--no-redact", action="store_true", help="Show full passwords (demo mode)")
    args = parser.parse_args()

    target = Path(args.path)

    if target.is_file() and target.suffix == ".enc":
        # Single encrypted file
        banner()
        pw = args.password or input("Decryption password (Pi serial): ")
        show_encrypted_data(str(target), pw)
    elif target.is_dir():
        view_collection(str(target), args.password)
    else:
        print(f"Error: {args.path} is not a valid directory or .enc file")
        sys.exit(1)


if __name__ == "__main__":
    main()
