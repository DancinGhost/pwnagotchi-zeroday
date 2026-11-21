# Theme System & Trademark-Clean Palette Guidelines

pwnagotchi-zeroday ships with a condensed data-driven catalog of **6 original core themes** defined in a single portable source of truth: [`core/include/zd/theme.hpp`](../core/include/zd/theme.hpp) (mirrored in [`platforms/web/js/themes.js`](../platforms/web/js/themes.js) and verified automatically by unit tests). All themes — including stateless zero-RAM procedural backdrop effects (`DigitalRain`, `TacticalHud`, `LightningStorm`, `RadarDish`, and `SatelliteBeam`) — are built into every binary with no extra files to import and no compile flags required.

---

## Built-In Themes

| # | Slug (`key`) | Display Name | Effect | Inspiration / Aesthetic | `bg` | `fg` | `accent` |
| :-: | :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| 1 | `paper` | **Paper Ink** | — | Classic e-paper: charcoal ink on warm cream paper | `#F2F0E6` | `#16181C` | `#303A5C` |
| 2 | `cyan` | **ZeroDay** | Radar Dish | Signature cyber cyan & sweeping dish wavefronts on midnight blue | `#060C16` | `#00EEFF` | `#78FFC8` |
| 3 | `rain` | **Storm Rain** | Lightning Storm | Cascading emerald digital rain with rain streaks & forked lightning strikes | `#020804` | `#24FF70` | `#BEFFD2` |
| 4 | `amber` | **Amber Pulse** | — | Warm amber-orange pocket deck monochrome glow | `#100A02` | `#FFB200` | `#FFD880` |
| 5 | `redteam` | **Red Team** | Satellite Beam | Offensive ops HUD: scarlet ink, corner reticles & orbital satellite beam | `#0C0406` | `#FF4452` | `#FFBCC4` |
| 6 | `blueteam` | **Blue Team** | Tactical HUD | Defensive ops HUD: crisp ice blue, corner reticles & radar sweep | `#060C18` | `#60C0FF` | `#BCE8FF` |

Legacy slugs (`dark`, `neon`, `volt`, `sunset`, `green`, `storm`, `orange`, `crimson`, `redrain`, `operator`) resolve automatically to the closest matching core theme via `themeFromKey`.

---

## Cycling & Selecting Themes Across Platforms

- **M5Stick / M5Stack Hardware**:
  - **Next theme**: Hold **Button B** (~0.7s).
  - **Previous theme**: Short-click the **Power** button (StickC / StickC Plus) or press **Button C** (M5Stack Core / Core2 / CoreInk).
  - **On-screen toast & persistence**: Switching themes shows a centered `THEME X/6: <NAME>` overlay for 1.6s, updates the pet's commentary, and saves the theme's stable string `key` to ESP32 NVS flash (`Preferences`) so your choice survives power cycles.
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
  - Click the `‹` / `›` buttons in the theme cycler, click any of the 6 palette swatches, hold `[B]` for 0.7s, press `T` / `Shift+T`, or run `theme <key>` in the `/dev/ttyACM0` console.

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
