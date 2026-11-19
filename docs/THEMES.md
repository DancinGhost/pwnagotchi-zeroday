# Theme System & Trademark-Clean Palette Guidelines

pwnagotchi-zeroday ships with a data-driven catalog of **14 original color themes** defined in a single portable source of truth: [`core/include/zd/theme.hpp`](../core/include/zd/theme.hpp) (mirrored in [`platforms/web/js/themes.js`](../platforms/web/js/themes.js) and verified automatically by unit tests). All themes — including stateless zero-RAM procedural backdrop effects (`DigitalRain` and `TacticalHud`) — are built into every binary with no extra files to import and no compile flags required.

---

## Built-In Themes

| # | Slug (`key`) | Display Name | Effect | Inspiration / Aesthetic | `bg` | `fg` | `accent` |
| :-: | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| 1 | `paper` | **Paper Ink** | — | Classic e-paper: charcoal ink on warm cream paper | `#F2F0E6` | `#16181C` | `#303A5C` |
| 2 | `dark` | **Dark Ink** | — | High-contrast crisp white ink on deep black | `#0A0C10` | `#F4F6FA` | `#A5C3FF` |
| 3 | `cyan` | **ZeroDay** | — | Signature cyber cyan & mint on midnight blue | `#060C16` | `#00EEFF` | `#78FFC8` |
| 4 | `green` | **Phosphor** | — | Classic green-phosphor CRT terminal | `#060C06` | `#38FF60` | `#AFFFAF` |
| 5 | `neon` | **Neon Noir** | — | Rain-slick neon nightlife: hot magenta & electric cyan on violet-black | `#0E061A` | `#FF48C4` | `#00E8FF` |
| 6 | `volt` | **Neon Volt** | — | High-voltage visor: acid yellow & electric cyan on carbon black | `#0C0E14` | `#F5F038` | `#28F0E8` |
| 7 | `operator` | **Operator** | — | Security workstation: cool steel ink, cobalt blue accents & crimson alerts | `#0E121C` | `#D8E2F0` | `#4E96FF` |
| 8 | `redteam` | **Red Team** | — | Night-ops tactical red that preserves dark-adapted vision | `#100406` | `#FF5656` | `#FFA468` |
| 9 | `amber` | **Amber CRT** | — | Vintage amber monochrome terminal glow | `#100A02` | `#FFB200` | `#FFD880` |
| 10 | `sunset` | **Sunset Grid** | — | Synthwave horizon: warm tangerine & pink on deep purple | `#1C0A2E` | `#FF9C60` | `#FF5CB2` |
| 11 | `rain` | **Code Rain** | Digital Rain | Cascading emerald digital rain on pitch-black void | `#020804` | `#24FF70` | `#BEFFD2` |
| 12 | `crimson` | **Crimson Ops** | Tactical HUD | Team Red tactical HUD: scarlet ink, corner reticles & radar sweep | `#0C0406` | `#FF4452` | `#FFBCC4` |
| 13 | `redrain` | **Red Rain** | Digital Rain | Team Red cascading crimson code rain on obsidian black | `#0A0204` | `#FF3A4C` | `#FFC4C4` |
| 14 | `blueteam` | **Blue Team** | Tactical HUD | Defensive ops HUD: crisp ice blue, corner reticles & radar sweep | `#060C18` | `#60C0FF` | `#BCE8FF` |

---

## Cycling & Selecting Themes Across Platforms

- **M5Stick / M5Stack Hardware**:
  - **Next theme**: Hold **Button B** (~0.7s).
  - **Previous theme**: Short-click the **Power** button (StickC / StickC Plus) or press **Button C** (M5Stack Core / Core2 / CoreInk).
  - **On-screen toast & persistence**: Switching themes shows a centered `THEME X/14: <NAME>` overlay for 1.6s, updates the pet's commentary, and saves the theme's stable string `key` to ESP32 NVS flash (`Preferences`) so your choice survives power cycles.
- **LILYGO T-Deck / T-Deck Plus**:
  - Roll the trackball **Right** / **Left** to cycle forward / backward, tap / hold (~0.6s) the top header bar (T-Deck Plus), or type `theme <key>` on the QWERTY keyboard.
- **CYD ESP32-2432S028 ("Cheap Yellow Display")**:
  - **Next theme**: Tap the top header bar on the XPT2046 touchscreen.
  - **Previous theme**: Long-press (~0.6s) the top header bar. Changes persist to ESP32 NVS flash.
- **Serial CLI (`115200` baud) & Native Desktop Simulator (`zd_sim`)**:
  - `themes` — list all themes and highlight the active one
  - `theme` / `theme next` / `t` — step forward
  - `theme prev` / `T` — step backward
  - `theme <key>` (e.g. `theme neon`, `theme volt`, `theme operator`) — jump directly
- **Web Port (`platforms/web/index.html`)**:
  - Click the `‹` / `›` buttons in the theme cycler, click any of the 14 palette swatches, hold `[B]` for 0.7s, press `T` / `Shift+T`, or run `theme <key>` in the `/dev/ttyACM0` console.

---

## Adding a New Theme (2 Steps)

1. Append an identifier before `Count_` in `enum class ThemeId` inside [`core/include/zd/domain.hpp`](../core/include/zd/domain.hpp).
2. Append a matching `ThemeSpec` row to `kThemeCatalog` in [`core/include/zd/theme.hpp`](../core/include/zd/theme.hpp) and `THEME_CATALOG` in [`platforms/web/js/themes.js`](../platforms/web/js/themes.js).
3. Run `make test` — compile-time `static_assert`s and unit tests automatically validate:
   - Ordering (`ThemeId` index matches row position)
   - Unique lowercase slug `key` and `<= 12`-char display `name` (so compact `128x64` / `160x80` toasts never clip)
   - WCAG contrast ratios (`fg` vs `bg >= 4.5:1`, `accent` vs `bg >= 3.0:1`, `muted` vs `bg >= 1.6:1`)
   - Exact 1:1 parity between C++ and JavaScript catalogs
   - Trademark & brand cleanliness

---

## Copyright & Trademark Policy

To keep pwnagotchi-zeroday 100% clean for open-source distribution and commercial/custom hardware builds:

1. **Generic Descriptive Names Only**: Name themes after moods, lighting, materials, or generic security roles (`Neon Noir`, `Neon Volt`, `Operator`, `Red Team`, `Amber CRT`). **Never** use third-party product names, OS/distro names, game/film titles, or company names in `ThemeId`, `key`, `name`, `blurb`, or CLI aliases.
2. **No Logos or Branded Glyphs**: Never embed third-party logos, mascots, crests, or trademarked iconography.
3. **Original Hand-Tuned Palettes**: Craft RGB triples from scratch for small TFT/OLED readability rather than copying proprietary brand style guides.
