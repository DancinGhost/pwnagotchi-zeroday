#!/usr/bin/env python3
"""
pwnagotchi-zeroday Easy Board Flasher
Cross-platform tool to flash precompiled factory binaries to ESP32 / ESP32-S3 boards.
"""

import glob
import os
import subprocess
import sys


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


def ensure_esptool():
    """Ensure esptool is installed and accessible."""
    try:
        subprocess.run(
            ["esptool.py", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return ["esptool.py"]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    try:
        subprocess.run(
            [sys.executable, "-m", "esptool", "version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return [sys.executable, "-m", "esptool"]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    print("[*] esptool not detected.")
    if not sys.stdin.isatty():
        print("[!] Please install esptool manually: python3 -m pip install 'esptool==4.8.1'")
        sys.exit(1)
    ans = input("    Install esptool==4.8.1 via pip now? [y/N]: ").strip().lower()
    if ans != "y":
        print("[!] Aborted. Install esptool manually: python3 -m pip install 'esptool==4.8.1'")
        sys.exit(1)
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "esptool==4.8.1"])
        return [sys.executable, "-m", "esptool"]
    except Exception as err:
        print(f"[!] Failed to install esptool: {err}")
        print("    Please install esptool manually: python3 -m pip install 'esptool==4.8.1'")
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
        choice = input(f"Select port [1-{len(ports)}] (default 1): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(ports):
            selected_port = ports[int(choice) - 1]
        else:
            selected_port = ports[0]
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
