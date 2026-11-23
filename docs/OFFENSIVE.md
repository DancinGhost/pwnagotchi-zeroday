# pwnagotchi-zeroday — ESP32 Active Offense (Deauthentication)

The ESP32 boards (M5StickC / Plus / Plus2, M5Stack Core2, LILYGO T-Deck / T-Deck Plus,
Sunton CYD) are passive scanners + pet that also carry an operator-gated **802.11
deauthentication injector** for authorized wireless assessment. The injector is compiled into
every build and gated entirely at **runtime** — the same capability, and the same portable,
unit-tested authorization gate, the Linux desktop target already uses.

> ⚠️ **Authorized use only.** Transmitting deauthentication frames at networks or clients you
> do not own and are not explicitly authorized in writing to test is illegal in most
> jurisdictions (e.g. US 47 U.S.C. §333, UK Computer Misuse Act, and equivalents). You are
> solely responsible for how you use this. The injector powers on **disarmed** and transmits
> nothing until you explicitly authorize a specific target at the console.

---

## Two independent runtime gates

The injector is present in every build. A frame reaches the air only when **both** runtime
gates are satisfied; neither alone transmits anything.

1. **Runtime authorization gate (`zd::sec`, shared with the Linux target).**
   The gate starts **disarmed** (`operatorConfirmed = false`) with an **empty allow-list**.
   `authorize()` permits a transmit only when the operator has *both* confirmed authorization
   *and* explicitly allow-listed the exact target BSSID. There is **no wildcard /
   "attack-all" command** on the ESP32 console.

2. **Operator-initiated only.**
   Nothing in `loop()` ever injects. A deauth happens solely in response to an explicit
   `sec deauth` serial command. Every attempt — allowed or blocked — is written to the audit
   log (Serial `[SEC-AUDIT]` + a durable NVS counter that survives reboots).

A fresh device therefore powers on silent and stays silent through boot, scanning, and the pet
loop. It transmits only after a human types the `sec allow` + `sec arm` + `sec deauth`
sequence below.

---

## Building

Nothing special — every board env builds the injector in:

```sh
pio run -e m5stick-c
```

The injector wraps ONLY the SDK's `ieee80211_raw_frame_sanity_check` symbol via
`-Wl,--wrap=ieee80211_raw_frame_sanity_check` (in `platformio.ini` `[common] build_flags`) so
crafted deauth frames reach the PHY while preserving full linker duplicate-symbol checks across
the rest of the firmware.

---

## Operator console (`sec` serial commands)

Over the USB serial monitor (115200 baud) — also the QWERTY keyboard on the T-Deck:

| Command | Effect |
| --- | --- |
| `sec status` | Arm state, allow-list, transmit/block counters (live + durable NVS) |
| `sec scan` | Blocking discovery scan; lists nearby BSSIDs + channels (needed before deauth) |
| `sec allow <bssid>` | Add a BSSID you are authorized to test to the allow-list |
| `sec deny <bssid>` | Remove a BSSID from the allow-list |
| `sec arm I-HAVE-AUTHORIZATION` | Confirm authorization (required; typed token prevents stray arming) |
| `sec disarm` | Revoke authorization |
| `sec deauth <bssid> [count] [client]` | Transmit deauth burst (gated: must be allow-listed **and** armed) |
| `sec pmkid <bssid> [count]` | Clientless PMKID probe sending open auth + RSN assoc (gated; WPA2 only — use `sec deauth` for WPA3-SAE/PMF) |

Typical authorized flow against a lab AP you own:

```
sec scan
sec allow aa:bb:cc:dd:ee:ff
sec arm I-HAVE-AUTHORIZATION
sec deauth aa:bb:cc:dd:ee:ff 16
```

A request that has not cleared the gate returns `BLOCKED: ...` and is recorded as a
`TxBlocked` alert + `DEAUTH BLOCKED` audit line; nothing is transmitted. The per-command burst
is capped (64) — repeat the command rather than flooding. After a burst the radio returns to passive STA scanning (and clears any interrupted async pet scan state) for the pet loop.

---

## Design / where the code lives

Functional Core / Imperative Shell, mirroring the Linux target:

- `core/include/zd/dot11.hpp` — **pure**, host-testable 802.11 deauth/disassoc frame builder
  and MAC parser (no SDK headers). Byte-exact output is covered by
  `tests/core/test_dot11_frames.cpp`.
- `core/include/zd/secops.hpp` + `secops_hal.hpp` — the portable authorization gate +
  `SecSession` chokepoint (`requestDeauth` → `authorize` → inject only if `Allowed`), with the
  gate invariants unit-tested in `tests/core/test_secops.cpp`.
- `platforms/common/esp32_offensive.hpp` — the ESP32 injector (`esp_wifi_80211_tx`) + the
  `OffensiveConsole` serial command handler, instantiated in each board's `main.cpp`.

The pure frame builder and the gate are validated on the desktop (`make test`) before any
byte reaches a radio.
