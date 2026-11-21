#!/usr/bin/env python3
"""
pwnagotchi-zeroday Easy Board Flasher
Cross-platform tool to flash precompiled factory binaries to ESP32 / ESP32-S3 boards.
"""

import glob
import hashlib
import hmac
import os
import subprocess
import sys
import venv


def get_serial_ports():
    """Detect available serial / USB ports on Windows, macOS, and Linux."""
    ports = []
    if sys.platform.startswith("win"):
        try:
            import serial.tools.list_ports

            ports = [p.device for p in serial.tools.list_ports.comports()]
        except ImportError:
            try:
                import serial
            except ImportError:
                return []
            for i in range(1, 33):
                port = f"COM{i}"
                try:
                    s = serial.Serial(port)
                    s.close()
                    ports.append(port)
                except Exception:
                    pass
    elif sys.platform.startswith("darwin"):
        ports = (
            glob.glob("/dev/cu.usbserial*")
            + glob.glob("/dev/cu.usbmodem*")
            + glob.glob("/dev/cu.wchusbserial*")
        )
    else:
        # Linux
        ports = glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*")
    return sorted(list(set(ports)))


def is_safe_port_name(port):
    """Reject empty or flag-like port names (e.g. starting with '-')."""
    if not port or port.startswith("-"):
        return False
    return all(ord(c) >= 32 and ord(c) <= 126 for c in port)


def locate_factory_binary(search_dir="."):
    """Locate a merged *factory*.bin image suitable for flashing at offset 0x0."""
    pattern = os.path.join(search_dir, "*factory*.bin")
    matches = sorted(glob.glob(pattern))
    if not matches:
        return None
    for candidate in matches:
        base = os.path.basename(candidate)
        if not base.startswith("-"):
            return candidate
    return None


def flasher_venv_python():
    """Path to the isolated esptool venv interpreter (avoids PEP 668 system pip blocks)."""
    venv_dir = os.path.join(os.path.expanduser("~"), ".cache", "pwnagotchi-zd-flasher-venv")
    if sys.platform.startswith("win"):
        return os.path.join(venv_dir, "Scripts", "python.exe"), venv_dir
    return os.path.join(venv_dir, "bin", "python"), venv_dir


def verify_sha256(factory_bin):
    """Verify `factory_bin` against an adjacent `.sha256` or `SHA256SUMS*` manifest if present.

    Returns (ok: bool, message: str). If a checksum file is present and the digest mismatches
    or the file is missing from that manifest, returns False so callers abort before flashing.
    """
    search_dir = os.path.dirname(os.path.abspath(factory_bin)) or "."
    target_name = os.path.basename(factory_bin)
    candidates = [
        factory_bin + ".sha256",
        os.path.join(search_dir, target_name + ".sha256"),
        os.path.join(search_dir, "SHA256SUMS.txt"),
        os.path.join(search_dir, "SHA256SUMS"),
    ]
    manifest = next((p for p in candidates if os.path.isfile(p)), None)
    if manifest is None:
        return True, "no local SHA-256 manifest found; skipping offline checksum check"

    expected = None
    with open(manifest, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            parts = raw_line.strip().split()
            if not parts:
                continue
            digest = parts[0].lower()
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                continue
            if len(parts) == 1 and manifest.endswith(".sha256"):
                expected = digest
                break
            entry_name = parts[-1].lstrip("*")
            if os.path.basename(entry_name) == target_name:
                expected = digest
                break

    if expected is None:
        return False, f"{target_name} missing from checksum file {os.path.basename(manifest)}"

    h = hashlib.sha256()
    with open(factory_bin, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            h.update(chunk)
    actual = h.hexdigest().lower()
    if not hmac.compare_digest(actual, expected):
        return False, f"SHA-256 mismatch (expected {expected[:16]}..., got {actual[:16]}...)"
    return True, f"SHA-256 verified ({actual[:16]}... via {os.path.basename(manifest)})"


def ensure_esptool():
    """Ensure esptool is installed and accessible (prefer current Python or an isolated venv)."""
    venv_py, venv_dir = flasher_venv_python()
    candidates = [
        [sys.executable, "-m", "esptool"],
        ["esptool.py"],
        [venv_py, "-m", "esptool"],
    ]
    for base_cmd in candidates:
        if base_cmd[0] == venv_py and not os.path.isfile(venv_py):
            continue
        try:
            subprocess.run(
                base_cmd + ["version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            return base_cmd
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    print("[*] esptool not detected.")
    if not sys.stdin.isatty():
        print("[!] Please install esptool in a venv or via pipx: pipx install 'esptool==4.8.1'")
        sys.exit(1)
    ans = input(f"    Create isolated venv at {venv_dir} and install esptool==4.8.1? [y/N]: ").strip().lower()
    if ans != "y":
        print("[!] Aborted. Install esptool manually: pipx install 'esptool==4.8.1'")
        sys.exit(1)
    try:
        venv.create(venv_dir, with_pip=True)
        subprocess.check_call([venv_py, "-m", "pip", "install", "esptool==4.8.1"])
        return [venv_py, "-m", "esptool"]
    except Exception as err:
        print(f"[!] Failed to install esptool: {err}")
        print("    Please install esptool manually: pipx install 'esptool==4.8.1'")
        sys.exit(1)


def main():
    print("==================================================")
    print("      pwnagotchi-zeroday Easy Board Flasher       ")
    print("==================================================")

    # 1. Locate merged factory binary in current directory (never flash an unmerged .bin at 0x0)
    factory_bin = locate_factory_binary(".")
    if not factory_bin:
        print("[!] Error: No merged *factory*.bin image found in this folder.")
        print("    Refusing to flash unmerged bootloader/firmware images at offset 0x0.")
        print("    Download a release archive or run scripts/package_release.sh with esptool.")
        sys.exit(1)

    display_bin = os.path.basename(factory_bin)
    print(f"[*] Target Firmware: {display_bin}")

    sha_ok, sha_msg = verify_sha256(factory_bin)
    if not sha_ok:
        print(f"[!] Firmware integrity check FAILED: {sha_msg}")
        sys.exit(1)
    print(f"[*] Integrity check: {sha_msg}")

    # Determine chip family from filename
    chip_arg = []
    lower_bin = display_bin.lower()
    if "t-deck" in lower_bin or "s3" in lower_bin:
        chip_arg = ["--chip", "esp32s3"]
        print("[*] Detected Board: ESP32-S3 (LILYGO T-Deck / T-Deck Plus)")
    elif "cyd" in lower_bin or "2432" in lower_bin:
        chip_arg = ["--chip", "esp32"]
        print("[*] Detected Board: ESP32 (CYD ESP32-2432S028)")
    elif "m5" in lower_bin or "stick" in lower_bin or "core2" in lower_bin:
        chip_arg = ["--chip", "esp32"]
        print("[*] Detected Board: ESP32 (M5StickC / Plus2 / Core2)")

    # 2. Find serial ports
    ports = get_serial_ports()
    selected_port = None

    if not ports:
        print("[*] No serial port detected automatically.")
        print("    Please plug in your board via USB.")
        manual = input("    Enter serial port name (or press Enter to let esptool auto-probe): ").strip()
        if manual:
            if not is_safe_port_name(manual):
                print(f"[!] Error: invalid serial port name '{manual}'.")
                sys.exit(1)
            selected_port = manual
    elif len(ports) == 1:
        selected_port = ports[0]
        print(f"[*] Found 1 USB device: {selected_port}")
    else:
        print("[*] Multiple USB ports detected:")
        for idx, p in enumerate(ports, 1):
            print(f"    [{idx}] {p}")
        while True:
            choice = input(f"Select port [1-{len(ports)}] (or 'q' to abort): ").strip()
            if choice.lower() in ("q", "quit"):
                print("[*] Aborted by user.")
                sys.exit(0)
            if choice.isdigit() and 1 <= int(choice) <= len(ports):
                selected_port = ports[int(choice) - 1]
                break
            print(f"[!] Please enter a number from 1 to {len(ports)} (or 'q' to abort).")
        print(f"[*] Selected port: {selected_port}")

    # 3. Ensure esptool is ready
    esptool_cmd = ensure_esptool()

    # 4. Construct flashing command (unified factory image at offset 0x0)
    cmd = esptool_cmd + chip_arg
    if selected_port:
        cmd += ["--port", selected_port]
    cmd += ["--baud", "921600", "write_flash", "-z", "0x0", display_bin]

    print("\n[*] Starting flash process...")
    print(f"    Running: {' '.join(cmd)}\n")

    try:
        ret = subprocess.run(cmd)
        if ret.returncode != 0:
            print("\n[!] High-speed flash failed. Retrying at 115200 baud...")
            cmd[cmd.index("921600")] = "115200"
            ret = subprocess.run(cmd)

        if ret.returncode == 0:
            print("\n==================================================")
            print(" [OK] Flashing Complete!")
            print(" Press the RESET/PWR button on your board to boot")
            print(" pwnagotchi-zeroday!")
            print("==================================================")
        else:
            print("\n[!] Flashing failed. Please check your USB cable and board connection.")
            sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during flashing: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
