# Roadmap

Ideas for pwnagotchi-zeroday, organized by where the work lands. Nothing here is committed
to a timeline — it's a backlog to pull from. Items under **Done** were implemented in the
shared core (`core/include/zd/`) and are available to every platform; everything else is
not yet implemented.

---

## Done (shared core)

- **Station / probe-request tracking** (`secops.hpp`): a `Station` record (MAC, probed
  SSIDs, last-associated BSSID, activity counters) fed by a new `ProbeRequestObserved`
  event, plus the existing `ClientObserved` association event. Surfaces phones/laptops
  leaking their preferred-network list via probe requests, independent of whether they're
  associated to anything nearby. Capped (`kMaxStations`, `kMaxProbedSsidsPerStation`) like
  the existing alert ring buffer. Wired through `secops_hal.hpp::SecSession::ingest()`,
  which already had the probed SSID decoded in `CapturedFrame` but was discarding it.
- **WPS detection flag**: `WifiTarget.wps` / `ApObserved.wps` / `CapturedFrame.wps`, wired
  through `dot11.hpp::parseTaggedParams` (WPS vendor IE `00:50:F2:04`) and
  `SecSession::ingest()`, passive and informational only (no new transmit capability —
  consistent with the existing authorization gate).
- **`SecMood`**: a small pure signal (`Calm` / `Watchful` / `Alarmed`) derived from recent
  alert severity (`deriveSecMood`), decoupled from the cross-platform `Mood` enum so
  hardware that has never heard of `secops.hpp` is unaffected.
- **Session record/replay wire format**: `encodeSecEvent`/`decodeSecEvent` (and the
  `...Events` / `replaySecEvents` batch helpers) — a pure, escaped, line-based text
  encoding for the `SecEvent` log. Lets a session be replayed deterministically through
  `reduce()` to reproduce the exact `SecState` it produced live. Wired into `zd-linux`
  (`--record`, `--replay`, `replay <file>`, and TUI `w`/`r` hotkeys) and `zd-gui`
  ("Load Session…" / "Save Session…").
- **Bounded collections in `SecState`**: `kMaxTargets`, `kMaxStations`, `kMaxAlerts`,
  `kMaxDeauthTrackers`, `kMaxBssidSsids`, and `kMaxSsidsPerBssid` cap all in-memory
  tables with LRU/FIFO eviction so multi-hour monitoring sessions have strictly bounded
  memory usage.

## Core follow-ups (wiring the above into a shell)

- [x] **Linux CLI**: `--record <file>` / `--replay <file>` flags and `replay <file>`
  subcommand on `zd-linux` (plus interactive `w`/`r` save/load keys in the TUI).
- [x] **Linux GUI**: "Load Session…" and "Save Session…" actions in `zd-gui` that replay or
  export recorded sessions without touching hardware.
- [x] Surface the station/probe table in the `zd-linux` TUI (`[p]` / `Tab` view toggle) and
  `zd-gui` (`Stations / Probes` tab), including a `WEAK!` / `WEAK / DEFAULT` flag
  (`hasWeakOrDefaultProbe`) for stations probing default/open-bait SSIDs.
- [x] Surface `WifiTarget.wps` (`WPS*`) in both the `zd-linux` and `zd-gui` network tables.
- [x] Surface `SecMood`/alert severity in the Linux GUI pet widget (amber/red bezel shift +
  `SEC: CALM/WATCHFUL/ALARMED` status badge) and `zd-linux` TUI header / `watch` stream.
- [x] Detect WPS in active scan paths (`nmcli`/`iw` recon parsers) in addition to the
  monitor-mode 802.11 beacon/probe-response parser (`dot11.hpp`).

## Linux desktop (CLI/TUI + Qt6 GUI)

- [x] **Assessment report export** (Markdown/HTML/CSV): networks seen, alerts raised,
  handshakes/PMKIDs captured, generated safely from a session (`--export` / GUI Export).
- [x] **GPS/wardriving mode** (Linux `gpsd` integration + WiGLE v1.4 CSV wardriving via `--wardrive` / TUI `W` / GUI `Wardrive…`; T-Deck + GPS/SD also supported).
- [x] **Multi-channel scheduling**: pure `ChannelHopper` covers 2.4 + 5 GHz channels with
  3s EAPOL handshake dwell hold (`--hop` / `--5ghz` / TUI `h` / GUI `Hop ch`).
- [x] **PCAP capture path selector** in GUI + deduped beacon/EAPOL `.pcap` capture.
- [x] **Desktop notifications** (libnotify) for `Critical` alerts (`--notify` / TUI `N` /
  GUI `Notify`) so `watch` and live defense alert in the background too.
- [ ] Config profiles ("lab" vs "field") presetting interface/channel/allow-list.

## M5Stick / ESP32

- [x] **ESP-IDF 5.x / Arduino-ESP32 3.x (PIOArduino) migration**: parallel `*-idf5`
  PIOArduino targets alongside `espressif32 @ 6.9.0` plus `#if ESP_ARDUINO_VERSION_MAJOR >= 3`
  compatibility adapters and promiscuous 802.11 defensive monitoring (`defmon on|off`).
- [x] **BLE scanning** alongside WiFi — asynchronous non-blocking `Esp32BleScanner` with
  free-heap guard feeds BLE tracker/multi-tool detections into RF Guard (`ble on|off`).
- [x] **Known-network memory**: trusted BSSID persistence in NVS (`ESP32`) and config
  (`Linux`) suppresses self evil-twins and escalates untrusted impersonators to `Critical`.
- [x] **Buzzer melodies** tied to mood/severity — `platforms/common/buzzer_melodies.hpp`
  drives M5Unified speaker SFX (`sfx on|off` persisted in NVS).

## Native desktop simulator (`zd_sim`)

- [x] Scripted event-stream fuzzing against the pure reducers (secops + pet_logic) as a
  cheap regression harness (`testPetLogicEventStreamFuzzer`, `testSecOpsEventStreamFuzzer`).
- [x] Animated frame-sequence export (`--ppm-seq <prefix>`, `--gif <out.gif>`, `--frames N`)
  for docs/README animations.

## Web port

- [x] PWA packaging (`manifest.json` + `sw.js` + `icon.svg`) for offline installability.
- [x] Shareable permalink (`Share Link` / `link`) encoding theme/view/mode/profile in the URL hash.

## Cross-cutting (not yet scoped to a specific platform)

- [x] Pet mood (`Mood`/`faceForMood` + `SetSecMoodEvent` / `SyncMonitorSnapshotEvent`)
  visibly reacts to `SecMood` across Linux GUI/TUI, ESP32 promiscuous monitor, and Web Port.
