#!/usr/bin/env bash
# scripts/package_release.sh
# Packages locally built binaries for GitHub Releases.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist_release"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "=== Packaging pwnagotchi-zeroday Release Assets ==="

# 1. Package Linux Desktop Binaries (prefer CMake build_cmake/, fallback to Makefile build/)
LINUX_BUILD_DIR=""
if [ -f "$ROOT_DIR/build_cmake/zd-linux" ] || [ -f "$ROOT_DIR/build_cmake/zd_sim" ]; then
    LINUX_BUILD_DIR="$ROOT_DIR/build_cmake"
elif [ -f "$ROOT_DIR/build/zd-linux" ] || [ -f "$ROOT_DIR/build/zd_sim" ]; then
    LINUX_BUILD_DIR="$ROOT_DIR/build"
fi

if [ -n "$LINUX_BUILD_DIR" ]; then
    echo "[+] Packaging Linux x86_64 binaries from $LINUX_BUILD_DIR..."
    LINUX_DIR="$(mktemp -d)"
    mkdir -p "$LINUX_DIR/bin"
    [ -f "$LINUX_BUILD_DIR/zd-linux" ] && cp "$LINUX_BUILD_DIR/zd-linux" "$LINUX_DIR/bin/"
    [ -f "$LINUX_BUILD_DIR/zd-gui" ] && cp "$LINUX_BUILD_DIR/zd-gui" "$LINUX_DIR/bin/"
    [ -f "$LINUX_BUILD_DIR/zd_sim" ] && cp "$LINUX_BUILD_DIR/zd_sim" "$LINUX_DIR/bin/"
    cp "$ROOT_DIR/README.md" "$LINUX_DIR/"
    cp "$ROOT_DIR/LICENSE" "$LINUX_DIR/"
    cp "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$LINUX_DIR/"
    [ -f "$ROOT_DIR/docs/LINUX.md" ] && cp "$ROOT_DIR/docs/LINUX.md" "$LINUX_DIR/"
    tar -czf "$DIST_DIR/pwnagotchi-zd-linux-x86_64.tar.gz" -C "$LINUX_DIR" .
    rm -rf "$LINUX_DIR"
fi

# 2. Package Web Cyberdeck
if [ -d "$ROOT_DIR/platforms/web" ]; then
    echo "[+] Packaging Web Cyberdeck..."
    (cd "$ROOT_DIR/platforms/web" && zip -r "$DIST_DIR/pwnagotchi-zd-web.zip" index.html styles.css manifest.json sw.js icon.svg js/)
    zip -j "$DIST_DIR/pwnagotchi-zd-web.zip" "$ROOT_DIR/LICENSE" "$ROOT_DIR/THIRD_PARTY_NOTICES.md"
fi

# Resolve esptool command for merging factory images
ESPTOOL_CMD=()
if command -v esptool.py >/dev/null 2>&1; then
    ESPTOOL_CMD=(esptool.py)
elif python3 -m esptool version >/dev/null 2>&1; then
    ESPTOOL_CMD=(python3 -m esptool)
fi

# 3. Package Any Pre-Built ESP32 Firmwares in .pio/build
for env_dir in "$ROOT_DIR/.pio/build"/*; do
    if [ -d "$env_dir" ] && [ -f "$env_dir/firmware.bin" ]; then
        target="$(basename "$env_dir")"
        echo "[+] Packaging firmware for $target..."
        TEMP_FW="$(mktemp -d)"
        cp "$env_dir/firmware.bin" "$TEMP_FW/"
        [ -f "$env_dir/bootloader.bin" ] && cp "$env_dir/bootloader.bin" "$TEMP_FW/"
        [ -f "$env_dir/partitions.bin" ] && cp "$env_dir/partitions.bin" "$TEMP_FW/"

        # Merge unified factory image when bootloader + partitions + esptool are available
        if [ "${#ESPTOOL_CMD[@]}" -gt 0 ] && [ -f "$env_dir/bootloader.bin" ] && [ -f "$env_dir/partitions.bin" ]; then
            CHIP="esp32"
            BOOT_OFFSET="0x1000"
            if [[ "$target" == *t-deck* ]] || [[ "$target" == *s3* ]]; then
                CHIP="esp32s3"
                BOOT_OFFSET="0x0"
            fi
            MERGE_ARGS=(
                --chip "$CHIP" merge_bin
                -o "$TEMP_FW/pwnagotchi-zd-${target}-factory.bin"
                "$BOOT_OFFSET" "$env_dir/bootloader.bin"
                0x8000 "$env_dir/partitions.bin"
            )
            BOOT_APP0="${PLATFORMIO_CORE_DIR:-$HOME/.platformio}/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"
            if [ ! -f "$BOOT_APP0" ]; then
                echo "[!] Error: boot_app0.bin not found at $BOOT_APP0; refusing incomplete factory.bin merge for $target" >&2
                exit 1
            fi
            MERGE_ARGS+=(0xe000 "$BOOT_APP0" 0x10000 "$env_dir/firmware.bin")
            "${ESPTOOL_CMD[@]}" "${MERGE_ARGS[@]}"
            (cd "$TEMP_FW" && sha256sum "pwnagotchi-zd-${target}-factory.bin" > "pwnagotchi-zd-${target}-factory.bin.sha256")
        else
            echo "[!] Warning: esptool unavailable or bootloader/partitions missing; skipping factory.bin merge for $target" >&2
        fi

        # Copy only flasher scripts explicitly (never __pycache__ or stray files)
        for f in flash.py flash.sh flash.bat; do
            [ -f "$ROOT_DIR/scripts/flasher/$f" ] && cp "$ROOT_DIR/scripts/flasher/$f" "$TEMP_FW/"
        done
        [ -f "$ROOT_DIR/docs/FLASHING.md" ] && cp "$ROOT_DIR/docs/FLASHING.md" "$TEMP_FW/"
        cp "$ROOT_DIR/LICENSE" "$ROOT_DIR/THIRD_PARTY_NOTICES.md" "$TEMP_FW/"
        (cd "$TEMP_FW" && zip -r "$DIST_DIR/pwnagotchi-zd-${target}.zip" ./*)
        rm -rf "$TEMP_FW"
    fi
done

# 4. Generate SHA256 Checksums
if [ -n "$(ls -A "$DIST_DIR" 2>/dev/null)" ]; then
    echo "[+] Generating SHA256SUMS.txt..."
    (cd "$DIST_DIR" && sha256sum * > SHA256SUMS.txt)
    echo "=== Packaging complete. Artifacts in dist_release/: ==="
    ls -lh "$DIST_DIR"
else
    echo "[-] No artifacts found to package. Build targets first."
fi
