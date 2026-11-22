# Third-Party Notices

pwnagotchi-zeroday's own source code is released under the [MIT License](LICENSE).
No third-party source code is vendored into this repository; the components below are
fetched at build time (PlatformIO / system package manager) and are **linked into, or
required by, the distributed binaries**. Each remains under its own license.

## Embedded firmware (ESP32 / ESP32-S3 release zips)

| Component | License | Source |
|---|---|---|
| Arduino core for ESP32 (`framework-arduinoespressif32`, incl. `SPI`, `SD`, `WiFi`, `Preferences`, and `ESP32 BLE Arduino` `BLEDevice.h` under Apache-2.0) | LGPL-2.1-or-later / Apache-2.0 | https://github.com/espressif/arduino-esp32 |
| ESP-IDF (bootloader, partition table, libraries; incl. FreeRTOS, lwIP, mbedTLS, etc.) | Apache-2.0 (bundled components under their own permissive licenses) | https://github.com/espressif/esp-idf |
| M5Unified (M5Stack targets) | MIT, Copyright (c) 2021 M5Stack | https://github.com/m5stack/M5Unified |
| M5GFX (M5Stack targets) | MIT, Copyright (c) 2021 M5Stack | https://github.com/m5stack/M5GFX |
| LovyanGFX (T-Deck & CYD targets) | FreeBSD (BSD-2-Clause); incorporates Adafruit_GFX (BSD) and Adafruit_ILI9341 (MIT); bundled fonts under their own licenses | https://github.com/lovyan03/LovyanGFX |

**LGPL notice (Arduino-ESP32):** the firmware images statically link the Arduino core for
ESP32. The complete corresponding source of this project (MIT) and the upstream library
sources linked above are publicly available, so you may modify the LGPL-covered library and
rebuild/relink the firmware with `pio run -e <env>`.

## Linux desktop binaries (`pwnagotchi-zd-linux-x86_64.tar.gz`)

These are **dynamically** linked against system libraries that are not shipped in the archive:

| Component | License | Source |
|---|---|---|
| Qt 6 Widgets (`zd-gui` only) | LGPL-3.0 (dynamically linked) | https://www.qt.io/ |
| libpcap | BSD-3-Clause | https://www.tcpdump.org/ |
| ncurses | MIT-style (X11) | https://invisible-island.net/ncurses/ |

## Embedded 5×7 Bitmap Font (`surface_rgb565.hpp` & `canvas_gfx.js`)

The host/native rasterizer (`render/include/zd/render/surface_rgb565.hpp`) and browser canvas
rasterizer (`platforms/web/js/canvas_gfx.js`) include the standard 5×7 ASCII GLCD bitmap font
table (`kFont5x7` / `FONT_5X7`), originally distributed with **Adafruit_GFX** (`glcdfont.c`)
under the **BSD-2-Clause License**:

> Copyright (c) 2012 Adafruit Industries. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, are
> permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice, this list of
>    conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of
>    conditions and the following disclaimer in the documentation and/or other materials
>    provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
> OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
> MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
> COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
> EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
> HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
> TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
> EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Tooling (not redistributed)

- **Flasher scripts** invoke, but do not bundle or link, [esptool](https://github.com/espressif/esptool)
  (GPL-2.0-or-later), installed separately by the user via `pip`.
- **Linux CLI fallback adapters** (`platforms/linux/backend/cli_backend.hpp`) optionally invoke
  standard host utilities as separate OS subprocesses (`fork`/`execve`) when present on the
  system: `aircrack-ng` (`airmon-ng`, `airodump-ng`, `aireplay-ng`, GPL-2.0-or-later), `iw` (ISC),
  NetworkManager `nmcli` (GPL-2.0-or-later), `ip` (`iproute2`, GPL-2.0-only), `systemctl`
  (`systemd`, LGPL-2.1-or-later), BlueZ `bluetoothctl` (GPL-2.0-or-later), and `rtl_433`
  (GPL-2.0-or-later). None of these tools are bundled, linked into, or distributed with
  `pwnagotchi-zeroday`.
- **Optional Linux BLE / Sub-GHz line parsers** (`platforms/linux/backend/parsers.hpp`) accept
  line-based output formats produced by standard host utilities such as BlueZ (`bluetoothctl`,
  GPL-2.0-or-later) and `rtl_433` (GPL-2.0-or-later), which are never bundled, linked, or
  distributed with `pwnagotchi-zeroday`.

## Trademarks

"Pwnagotchi" refers to the original open-source project by evilsocket
(https://github.com/evilsocket/pwnagotchi, GPL-3.0); this project is an independent
clean-room C++17/JS implementation inspired by it and is not affiliated with or endorsed by it.
Tamagotchi is a registered trademark of Bandai; Wi-Fi is a registered trademark of Wi-Fi
Alliance; LoRa is a registered trademark of Semtech Corporation; Linux is a registered trademark
of Linus Torvalds; Windows and Microsoft Edge are trademarks of Microsoft Corporation; macOS,
Apple, AirTag, and Find My are trademarks or registered trademarks of Apple Inc.; Google and
Google Chrome are trademarks of Google LLC; Kali Linux is a registered trademark of OffSec;
Samsung and SmartTag are trademarks of Samsung Electronics Co., Ltd.; Linksys, NETGEAR, D-Link,
TP-Link, ASUS, Xfinity, AT&T, and Starbucks are trademarks of their respective owners; M5Stack,
M5StickC, LILYGO, T-Deck, Espressif, Adafruit, STMicroelectronics, Qt, Bluetooth, Tile, WiGLE,
Flipper Zero, and Texas Instruments (CC1101) are trademarks or registered trademarks of their
respective owners. Their use in hardware target names, passive signature matching, and
documentation is strictly nominative and descriptive to identify compatible hardware, radio
standards, file formats, and toolchains.
