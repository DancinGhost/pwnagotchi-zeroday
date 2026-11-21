// Data-driven, trademark-clean theme catalog (1:1 mirror of core/include/zd/theme.hpp).
//
// `test_web_core.js` parses `core/include/zd/theme.hpp` directly and asserts that every
// id, key, name, lightBackground flag, and 24-bit RGB color in `THEME_CATALOG` stays in
// lockstep with the C++ firmware catalog.
(function (root) {
  'use strict';

  const fp = (root.ZD && root.ZD.fp) || (typeof require === 'function' ? require('./fp.js') : null);

  const ThemeId = Object.freeze({
    PaperInk: 'PaperInk',
    ZeroDayCyan: 'ZeroDayCyan',
    CodeRain: 'CodeRain',
    AmberCrt: 'AmberCrt',
    RedTeam: 'RedTeam',
    BlueTeam: 'BlueTeam'
  });

  const ThemeEffect = Object.freeze({
    None: 'None',
    DigitalRain: 'DigitalRain',
    TacticalHud: 'TacticalHud',
    LightningStorm: 'LightningStorm',
    RadarDish: 'RadarDish',
    SatelliteBeam: 'SatelliteBeam'
  });

  const THEME_TOAST_MS = 1600;

  function rgb565(r, g, b) {
    return (((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)) & 0xFFFF;
  }

  function toHex2(v) {
    const clamped = fp ? fp.clampVal(Math.trunc(v), 0, 255) : Math.max(0, Math.min(255, Math.trunc(v)));
    return clamped.toString(16).padStart(2, '0');
  }

  function makeColor(r, g, b) {
    return Object.freeze({
      r,
      g,
      b,
      hex: '#' + toHex2(r) + toHex2(g) + toHex2(b),
      rgb565: rgb565(r, g, b)
    });
  }

  function makePalette(bg, fg, accent, muted, highlight) {
    return Object.freeze({
      bg: makeColor(bg[0], bg[1], bg[2]),
      fg: makeColor(fg[0], fg[1], fg[2]),
      accent: makeColor(accent[0], accent[1], accent[2]),
      muted: makeColor(muted[0], muted[1], muted[2]),
      highlight: makeColor(highlight[0], highlight[1], highlight[2])
    });
  }

  const THEME_CATALOG = Object.freeze([
    Object.freeze({
      id: ThemeId.PaperInk,
      key: 'paper',
      name: 'Paper Ink',
      blurb: 'Classic e-paper: charcoal ink on warm paper',
      lightBackground: true,
      effect: ThemeEffect.None,
      palette: makePalette([242, 240, 230], [22, 24, 28], [48, 58, 92], [155, 152, 142], [215, 95, 110])
    }),
    Object.freeze({
      id: ThemeId.ZeroDayCyan,
      key: 'cyan',
      name: 'ZeroDay',
      blurb: 'Signature cyber cyan and dish wave scanner',
      lightBackground: false,
      effect: ThemeEffect.RadarDish,
      palette: makePalette([6, 12, 22], [0, 238, 255], [120, 255, 200], [30, 68, 96], [255, 90, 180])
    }),
    Object.freeze({
      id: ThemeId.CodeRain,
      key: 'rain',
      name: 'Storm Rain',
      blurb: 'Cascading digital rain and lightning strikes',
      lightBackground: false,
      effect: ThemeEffect.LightningStorm,
      palette: makePalette([2, 8, 4], [36, 255, 112], [190, 255, 210], [24, 96, 48], [235, 255, 140])
    }),
    Object.freeze({
      id: ThemeId.AmberCrt,
      key: 'amber',
      name: 'Amber Pulse',
      blurb: 'Warm amber-orange pocket deck monochrome glow',
      lightBackground: false,
      effect: ThemeEffect.None,
      palette: makePalette([16, 10, 2], [255, 178, 0], [255, 216, 128], [100, 64, 10], [255, 124, 40])
    }),
    Object.freeze({
      id: ThemeId.RedTeam,
      key: 'redteam',
      name: 'Red Team',
      blurb: 'Offensive ops HUD: orbital satellite beam',
      lightBackground: false,
      effect: ThemeEffect.SatelliteBeam,
      palette: makePalette([12, 4, 6], [255, 68, 82], [255, 188, 196], [132, 34, 48], [255, 146, 56])
    }),
    Object.freeze({
      id: ThemeId.BlueTeam,
      key: 'blueteam',
      name: 'Blue Team',
      blurb: 'Defensive ops HUD: crisp ice blue shield grid',
      lightBackground: false,
      effect: ThemeEffect.TacticalHud,
      palette: makePalette([6, 12, 24], [96, 192, 255], [188, 232, 255], [36, 76, 128], [82, 255, 188])
    })
  ]);

  function themeIndex(idOrKey) {
    for (let i = 0; i < THEME_CATALOG.length; i++) {
      if (THEME_CATALOG[i].id === idOrKey || THEME_CATALOG[i].key === idOrKey) {
        return i;
      }
    }
    return -1;
  }

  function isValidTheme(id) {
    for (let i = 0; i < THEME_CATALOG.length; i++) {
      if (THEME_CATALOG[i].id === id) {
        return true;
      }
    }
    return false;
  }

  function themeSpec(id) {
    const idx = themeIndex(id);
    return idx >= 0 ? THEME_CATALOG[idx] : THEME_CATALOG[0];
  }

  function resolvePalette(id) {
    return themeSpec(id).palette;
  }

  function cycleTheme(current, step) {
    const n = THEME_CATALOG.length;
    const base = themeIndex(current);
    const safeBase = base >= 0 ? base : 0;
    const delta = Math.trunc(Number(step) || 0);
    const idx = (((safeBase + (delta % n)) % n) + n) % n;
    return THEME_CATALOG[idx].id;
  }

  function nextTheme(current) {
    return cycleTheme(current, +1);
  }

  function prevTheme(current) {
    return cycleTheme(current, -1);
  }

  function themeFromKey(input) {
    if (typeof input !== 'string' || input.length === 0) {
      return null;
    }
    const lower = input.trim().toLowerCase();
    for (let i = 0; i < THEME_CATALOG.length; i++) {
      const t = THEME_CATALOG[i];
      if (t.key === lower || t.id.toLowerCase() === lower) {
        return t.id;
      }
    }
    if (lower === 'dark' || lower === 'darkink' || lower === 'neon' || lower === 'neonnoir' ||
        lower === 'volt' || lower === 'neonvolt' || lower === 'sunset' || lower === 'sunsetgrid') {
      return ThemeId.ZeroDayCyan;
    }
    if (lower === 'green' || lower === 'phosphorgreen' || lower === 'storm') {
      return ThemeId.CodeRain;
    }
    if (lower === 'orange') {
      return ThemeId.AmberCrt;
    }
    if (lower === 'crimson' || lower === 'crimsonops' || lower === 'redrain') {
      return ThemeId.RedTeam;
    }
    if (lower === 'operator' || lower === 'operatorblue') {
      return ThemeId.BlueTeam;
    }
    return null;
  }

  function themeLabel(id) {
    return themeSpec(id).name.toUpperCase();
  }

  function isThemeToastVisible(toastUntilMs, nowMs) {
    const until = toastUntilMs >>> 0;
    const now = nowMs >>> 0;
    if (until === 0) {
      return false;
    }
    return ((until - now) | 0) > 0;
  }

  const themes = Object.freeze({
    ThemeId,
    ThemeEffect,
    THEME_CATALOG,
    THEME_COUNT: THEME_CATALOG.length,
    THEME_TOAST_MS,
    rgb565,
    makeColor,
    themeIndex,
    isValidTheme,
    themeSpec,
    resolvePalette,
    cycleTheme,
    nextTheme,
    prevTheme,
    themeFromKey,
    themeLabel,
    isThemeToastVisible
  });

  root.ZD = root.ZD || {};
  root.ZD.themes = themes;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = themes;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
