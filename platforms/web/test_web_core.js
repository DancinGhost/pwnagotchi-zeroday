// Automated Node.js unit tests for the pwnagotchi-zeroday Web Port Functional Core & Pixel Renderer.
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const fp = require('./js/fp.js');
const wifi = require('./js/wifi_analysis.js');
const themes = require('./js/themes.js');
const logic = require('./js/pet_logic.js');
const ui = require('./js/ui_model.js');
const sim = require('./js/airwaves_sim.js');
const gfxMod = require('./js/canvas_gfx.js');

function testFunctionalCombinators() {
  const nums = [5, 1, 4, 2, 3, 6];

  const result = fp.pipe(
    nums,
    fp.filtered((x) => x % 2 === 0),
    fp.mapped((x) => x * 10),
    fp.sortedBy((a, b) => a > b),
    fp.taken(2)
  );

  assert.deepStrictEqual(nums, [5, 1, 4, 2, 3, 6]);
  assert.deepStrictEqual(result, [60, 40]);

  const sum = fp.foldl(nums, 0, (acc, x) => acc + x);
  assert.strictEqual(sum, 21);

  // Exact deterministic PRNG parity
  const kItems = ['alpha', 'beta', 'gamma'];
  const p1 = fp.pickFrom(12345, kItems);
  const p2 = fp.pickFrom(12345, kItems);
  assert.strictEqual(p1.value, p2.value);
  assert.strictEqual(p1.nextSeed, p2.nextSeed);
  assert.ok(p1.nextSeed > 0 && p1.nextSeed <= 0xFFFFFFFF);
}

function testWifiAnalysisPipeline() {
  const raw = [
    { ssid: 'MeshNet', rssi: -72, channel: 6, secure: true },
    { ssid: 'MeshNet', rssi: -49, channel: 6, secure: true },
    { ssid: '', rssi: -81, channel: 11, secure: true },
    { ssid: 'CafeFree', rssi: -63, channel: 1, secure: false },
    { ssid: 'LabRouter\n', rssi: -55, channel: 6, secure: true }
  ];

  const summary = wifi.summarizeScan(raw, 6);
  assert.strictEqual(summary.totalAps, 5);
  assert.strictEqual(summary.secureAps, 4);
  assert.strictEqual(summary.openAps, 1);
  assert.strictEqual(summary.busiestChannel, 6);
  assert.strictEqual(summary.strongestRssi, -49);
  assert.strictEqual(summary.strongestSsid, 'MeshNet');

  assert.strictEqual(summary.topNetworks.length, 4);
  assert.strictEqual(summary.topNetworks[0].ssid, 'MeshNet');
  assert.strictEqual(summary.topNetworks[0].rssi, -49);
  assert.strictEqual(summary.topNetworks[1].ssid, 'LabRouter');
  assert.strictEqual(summary.topNetworks[2].ssid, 'CafeFree');
  assert.strictEqual(summary.topNetworks[3].ssid, '<hidden>');

  assert.strictEqual(wifi.rssiToBars(-48), 4);
  assert.strictEqual(wifi.rssiToBars(-62), 3);
  assert.strictEqual(wifi.rssiToBars(-75), 2);
  assert.strictEqual(wifi.rssiToBars(-85), 1);
  assert.strictEqual(wifi.rssiToBars(-94), 0);
}

function testStateReducerAndPlayfulEvents() {
  const s0 = logic.initialState(42);
  assert.strictEqual(logic.shouldTriggerScan(s0, 500), false);
  assert.strictEqual(logic.shouldTriggerScan(s0, 1600), true);

  const s1 = logic.reduce(s0, { type: 'ScanStarted', nowMs: 1600 });
  assert.strictEqual(s1.isScanning, true);
  assert.strictEqual(s1.mood, logic.Mood.LookingLeft);
  assert.strictEqual(s0.isScanning, false);

  const s2 = logic.reduce(s1, {
    type: 'Tick',
    nowMs: 2100,
    batteryPercent: 88,
    isCharging: false
  });
  assert.strictEqual(s2.mood, logic.Mood.LookingRight);
  assert.strictEqual(s2.batteryPercent, 88);

  const sLonely = logic.reduce(s2, {
    type: 'ScanCompleted',
    nowMs: 3200,
    rawNetworks: []
  });
  assert.strictEqual(sLonely.isScanning, false);
  assert.strictEqual(sLonely.mood, logic.Mood.Lonely);
  assert.strictEqual(sLonely.completedScans, 1);

  const sCool = logic.reduce(sLonely, {
    type: 'ScanCompleted',
    nowMs: 15500,
    rawNetworks: [
      { ssid: 'ZeroDayLab', rssi: -45, channel: 6, secure: true },
      { ssid: 'Guest', rssi: -75, channel: 1, secure: false }
    ]
  });
  assert.strictEqual(sCool.mood, logic.Mood.Cool);

  const crowd = [];
  for (let i = 0; i < 11; i++) {
    crowd.push({ ssid: 'AP_' + i, rssi: -65 - i, channel: (i % 11) + 1, secure: true });
  }
  const sExcited = logic.reduce(sCool, {
    type: 'ScanCompleted',
    nowMs: 28000,
    rawNetworks: crowd
  });
  assert.strictEqual(sExcited.mood, logic.Mood.Excited);
  assert.strictEqual(sExcited.peakApCount, 11);

  const sQuiet = logic.reduce(sExcited, {
    type: 'ScanCompleted',
    nowMs: 30000,
    rawNetworks: [{ ssid: 'FaintAP', rssi: -84, channel: 11, secure: true }]
  });
  assert.strictEqual(sQuiet.mood, logic.Mood.Bored);

  const sSleepy = logic.reduce(sQuiet, {
    type: 'Tick',
    nowMs: 95000,
    batteryPercent: 80,
    isCharging: true
  });
  assert.strictEqual(sSleepy.mood, logic.Mood.Sleepy);
  assert.strictEqual(sSleepy.isCharging, true);

  const sWoken = logic.reduce(sSleepy, { type: 'ButtonAPressed', nowMs: 96000 });
  assert.strictEqual(sWoken.mood, logic.Mood.Bored);
  assert.strictEqual(sWoken.page, logic.ScreenPage.NearbyRadar);

  const sThemed = logic.reduce(sWoken, { type: 'ButtonBLongPressed', nowMs: 96500 });
  assert.strictEqual(sThemed.theme, logic.ThemeId.ZeroDayCyan);

  const sManual = logic.reduce(sThemed, { type: 'ButtonBPressed', nowMs: 97000 });
  assert.strictEqual(sManual.manualScanRequested, true);
  assert.strictEqual(logic.shouldTriggerScan(sManual, 97010), true);

  // Playful hacker toy events
  const sSnack = logic.reduce(sManual, { type: 'SnackFed', nowMs: 98000 });
  assert.strictEqual(sSnack.mood, logic.Mood.Grateful);
  assert.strictEqual(sSnack.snacksFed, 1);

  const sPwn = logic.reduce(sSnack, {
    type: 'ToyHandshake',
    nowMs: 99000,
    targetSsid: 'Gibson_Mainframe'
  });
  assert.strictEqual(sPwn.mood, logic.Mood.Mischief);
  assert.strictEqual(sPwn.toyHandshakes, 1);
  assert.strictEqual(sPwn.highScore, sPwn.xp);

  const sPeer = logic.reduce(sPwn, {
    type: 'PeerSpotted',
    nowMs: 100000,
    peerName: 'cyber-neko',
    peerRssi: -42
  });
  assert.strictEqual(sPeer.mood, logic.Mood.Excited);
  assert.strictEqual(sPeer.peersMet, 1);
  assert.strictEqual(sPeer.lastPeerName, 'cyber-neko');

  const sNamed = logic.reduce(sPeer, {
    type: 'PetRenamed',
    nowMs: 101000,
    petName: 'n3k0_pwn!'
  });
  assert.strictEqual(sNamed.petName, 'n3k0_pwn');

  // OpsMode, BLE tracker & Sub-GHz guard + 10-tier levels
  assert.strictEqual(logic.deriveLevelInfo(0).level, 1);
  assert.strictEqual(logic.deriveLevelInfo(2500).level, 10);
  const sDef = logic.reduce(sNamed, { type: 'CycleOpsMode', nowMs: 102000 });
  assert.strictEqual(sDef.opsMode, logic.OpsMode.Defensive);
  assert.strictEqual(sDef.mood, logic.Mood.ShieldGuard);
  const sBle = logic.reduce(sDef, {
    type: 'BleScanCompleted',
    nowMs: 103000,
    devices: [{ mac: '7a:3c:91:04:88:12', name: 'Tracker_Tag', rssi: -52, companyId: 0x004c, serviceUuid: 0, trackerPayload: true }]
  });
  assert.strictEqual(sBle.threatsDetected, 1);
  assert.strictEqual(sBle.mood, logic.Mood.ThreatAlert);
  const sSub = logic.reduce(sBle, {
    type: 'SubGhzObserved',
    nowMs: 104000,
    signal: { freqKhz: 915000, rssi: -48, protocol: 'OOK', burstCount: 6, anomaly: wifi.SubGhzAnomaly.ReplayBurst }
  });
  assert.strictEqual(sSub.threatsDetected, 2);
}

function testResponsiveUiAndPixelRasterizer() {
  assert.strictEqual(gfxMod.FONT_5X7.length, 95);
  for (let i = 0; i < 95; i++) {
    assert.strictEqual(gfxMod.FONT_5X7[i].length, 5);
  }

  let state = logic.initialState(99);
  const snap = sim.generateAirwaveSnapshot('con', [{ ssid: 'Custom_0day', rssi: -40, channel: 6, secure: false }], 777, 5000);
  assert.ok(snap.networks.length >= 12);

  state = logic.reduce(state, {
    type: 'ScanCompleted',
    nowMs: 75000,
    rawNetworks: snap.networks
  });

  // 240x135 Plus2 frame
  const plusFrame = ui.buildUiFrame(state, { width: 240, height: 135 });
  assert.strictEqual(plusFrame.compact, false);
  assert.ok(plusFrame.headerLine.length <= 39);
  assert.ok(plusFrame.footerLine.length <= 39);

  // 160x80 Classic frame
  const compactFrame = ui.buildUiFrame(state, { width: 160, height: 80 });
  assert.strictEqual(compactFrame.compact, true);
  assert.ok(compactFrame.headerLine.length <= 26);
  assert.ok(compactFrame.footerLine.length <= 26);

  // Paint every mood and every page onto pixel buffer without error and verify foreground pixels exist
  const allMoods = Object.values(logic.Mood);
  for (const mood of allMoods) {
    const moodState = Object.assign({}, state, { mood });
    const frame = ui.buildUiFrame(moodState, { width: 240, height: 135 });
    const buf = gfxMod.createPixelBuffer(240, 135);
    gfxMod.paintUiFrame(buf, frame, { blink: false });

    let nonBgPixels = 0;
    for (let p = 0; p < buf.data.length; p += 4) {
      if (
        buf.data[p] !== frame.palette.bg.r ||
        buf.data[p + 1] !== frame.palette.bg.g ||
        buf.data[p + 2] !== frame.palette.bg.b
      ) {
        nonBgPixels++;
      }
    }
    assert.ok(nonBgPixels > 250, 'Expected visible foreground pixels for mood ' + mood);
  }

  for (const page of Object.values(logic.ScreenPage)) {
    const pageState = Object.assign({}, state, { page });
    const frame = ui.buildUiFrame(pageState, { width: 240, height: 135 });
    const buf = gfxMod.createPixelBuffer(240, 135);
    gfxMod.paintUiFrame(buf, frame);
    const ascii = ui.renderAsciiPreview(frame);
    assert.ok(ascii.includes('+------------------------------------------+'));
  }

  console.log('=== Web Port ASCII Preview (240x135) ===\n' + ui.renderAsciiPreview(plusFrame));
}

function testThemesMultiDeviceAndCppParity() {
  assert.strictEqual(themes.THEME_COUNT, 6);

  // Bidirectional cycling visits all 6 themes and wraps cleanly
  let cur = themes.ThemeId.PaperInk;
  const seen = new Set();
  for (let i = 0; i < themes.THEME_COUNT; i++) {
    seen.add(cur);
    cur = themes.nextTheme(cur);
  }
  assert.strictEqual(cur, themes.ThemeId.PaperInk);
  assert.strictEqual(seen.size, themes.THEME_COUNT);
  assert.strictEqual(themes.prevTheme(themes.ThemeId.PaperInk), themes.ThemeId.BlueTeam);
  assert.strictEqual(themes.themeFromKey('rain'), themes.ThemeId.CodeRain);
  assert.strictEqual(themes.themeFromKey('redteam'), themes.ThemeId.RedTeam);
  assert.strictEqual(themes.themeFromKey('blueteam'), themes.ThemeId.BlueTeam);
  // Legacy aliases
  assert.strictEqual(themes.themeFromKey('neon'), themes.ThemeId.ZeroDayCyan);
  assert.strictEqual(themes.themeFromKey('crimson'), themes.ThemeId.RedTeam);
  assert.strictEqual(themes.themeFromKey('redrain'), themes.ThemeId.RedTeam);
  assert.strictEqual(themes.themeFromKey('operator'), themes.ThemeId.BlueTeam);

  // Toast lifecycle & multi-device rendering across all 5 screen profiles
  let s = logic.initialState(77);
  s = logic.reduce(s, { type: 'SetTheme', nowMs: 5000, theme: 'operator' });
  assert.strictEqual(s.theme, themes.ThemeId.BlueTeam);
  assert.ok(s.themeToastUntilMs === 5000 + themes.THEME_TOAST_MS);

  for (const prof of ui.SCREEN_PROFILES) {
    assert.strictEqual(ui.screenProfileFromKey(prof.key), prof);
    for (const spec of themes.THEME_CATALOG) {
      const st = logic.reduce(s, { type: 'SetTheme', nowMs: 6000, theme: spec.key });
      const frame = ui.buildUiFrame(st, prof.dims);
      assert.strictEqual(frame.toast.visible, true);
      assert.ok(frame.toast.x >= 0 && frame.toast.x + frame.toast.w <= prof.dims.width);
      assert.ok(frame.toast.y > frame.headerDividerY && frame.toast.y + frame.toast.h < frame.footerDividerY);

      const buf = gfxMod.createPixelBuffer(prof.dims.width, prof.dims.height);
      gfxMod.paintUiFrame(buf, frame);
    }
  }

  const expired = logic.reduce(s, {
    type: 'Tick',
    nowMs: 5000 + themes.THEME_TOAST_MS,
    batteryPercent: 95,
    isCharging: false
  });
  assert.strictEqual(ui.buildUiFrame(expired, { width: 240, height: 135 }).toast.visible, false);

  // Trademark & brand cleanliness check on theme metadata and simulated airwaves
  const bannedTerms = [
    'kali',
    'offsec',
    'backtrack',
    'cyberpunk',
    'arasaka',
    'cdpr',
    'night city',
    'ubuntu',
    'flipper',
    'hak5',
    'defcon',
    'def con',
    'linksys',
    'wu_tang',
    'wutang',
    'skynet',
    'nintendo',
    'apple',
    'microsoft',
    'matrix',
    'airtag',
    'findmy',
    'smarttag'
  ];
  for (const kind of Object.values(wifi.BleThreatKind)) {
    const lbl = wifi.bleThreatLabel(kind).toLowerCase();
    for (const term of bannedTerms) {
      assert.strictEqual(
        lbl.includes(term),
        false,
        'bleThreatLabel("' + kind + '") must not contain restricted brand term "' + term + '"'
      );
    }
  }
  for (const presetId of Object.keys(sim.PRESETS)) {
    const bleSnap = sim.generateBleSnapshot(presetId, 777, 5000);
    for (const dev of bleSnap.devices) {
      const lowerDev = String(dev.name || '').toLowerCase();
      for (const term of bannedTerms) {
        assert.strictEqual(
          lowerDev.includes(term),
          false,
          'Simulated BLE device "' + dev.name + '" must not contain restricted brand term "' + term + '"'
        );
      }
    }
  }
  for (const spec of themes.THEME_CATALOG) {
    const combined = (spec.id + ' ' + spec.key + ' ' + spec.name + ' ' + spec.blurb).toLowerCase();
    for (const term of bannedTerms) {
      assert.strictEqual(
        combined.includes(term),
        false,
        'Theme "' + spec.key + '" must not contain restricted brand term "' + term + '"'
      );
    }
  }
  for (const preset of Object.values(sim.PRESETS)) {
    const presetText = (
      preset.label +
      ' ' +
      preset.subtitle +
      ' ' +
      preset.baseNetworks.map((n) => n.ssid).join(' ')
    ).toLowerCase();
    for (const term of bannedTerms) {
      assert.strictEqual(
        presetText.includes(term),
        false,
        'Airwave preset "' + preset.id + '" must not contain restricted brand term "' + term + '"'
      );
    }
  }
  for (const ssid of sim.FUNNY_HACKER_SSIDS) {
    const lower = ssid.toLowerCase();
    for (const term of bannedTerms) {
      assert.strictEqual(
        lower.includes(term),
        false,
        'FUNNY_HACKER_SSIDS entry "' + ssid + '" must not contain restricted brand term "' + term + '"'
      );
    }
  }

  // Exact C++ <-> JS catalog parity against core/include/zd/theme.hpp
  const cppHeaderPath = path.resolve(__dirname, '../../core/include/zd/theme.hpp');
  const cppSrc = fs.readFileSync(cppHeaderPath, 'utf8');

  const toastMatch = cppSrc.match(/kThemeToastMs\s*=\s*(\d+)u/);
  assert.ok(toastMatch, 'Expected kThemeToastMs in C++ theme.hpp');
  assert.strictEqual(Number(toastMatch[1]), themes.THEME_TOAST_MS);

  const entryRe =
    /\{ThemeId::(\w+),\s*"([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*(true|false),\s*ThemeEffect::(\w+),\s*\{\{(\d+),\s*(\d+),\s*(\d+)\},\s*\{(\d+),\s*(\d+),\s*(\d+)\},\s*\{(\d+),\s*(\d+),\s*(\d+)\},\s*\{(\d+),\s*(\d+),\s*(\d+)\},\s*\{(\d+),\s*(\d+),\s*(\d+)\}\}\}/g;

  const cppEntries = [];
  let m;
  while ((m = entryRe.exec(cppSrc)) !== null) {
    cppEntries.push({
      id: m[1],
      key: m[2],
      name: m[3],
      blurb: m[4],
      lightBackground: m[5] === 'true',
      effect: m[6],
      bg: [Number(m[7]), Number(m[8]), Number(m[9])],
      fg: [Number(m[10]), Number(m[11]), Number(m[12])],
      accent: [Number(m[13]), Number(m[14]), Number(m[15])],
      muted: [Number(m[16]), Number(m[17]), Number(m[18])],
      highlight: [Number(m[19]), Number(m[20]), Number(m[21])]
    });
  }

  assert.strictEqual(
    cppEntries.length,
    themes.THEME_CATALOG.length,
    'C++ kThemeCatalog and JS THEME_CATALOG must have identical entry count'
  );

  for (let i = 0; i < cppEntries.length; i++) {
    const c = cppEntries[i];
    const j = themes.THEME_CATALOG[i];
    assert.strictEqual(j.id, c.id);
    assert.strictEqual(j.key, c.key);
    assert.strictEqual(j.name, c.name);
    assert.strictEqual(j.blurb, c.blurb);
    assert.strictEqual(j.lightBackground, c.lightBackground);
    assert.strictEqual(j.effect, c.effect);
    assert.deepStrictEqual([j.palette.bg.r, j.palette.bg.g, j.palette.bg.b], c.bg);
    assert.deepStrictEqual([j.palette.fg.r, j.palette.fg.g, j.palette.fg.b], c.fg);
    assert.deepStrictEqual([j.palette.accent.r, j.palette.accent.g, j.palette.accent.b], c.accent);
    assert.deepStrictEqual([j.palette.muted.r, j.palette.muted.g, j.palette.muted.b], c.muted);
    assert.deepStrictEqual(
      [j.palette.highlight.r, j.palette.highlight.g, j.palette.highlight.b],
      c.highlight
    );
  }
  // Verify animated scenes & storm/dish/satellite backdrops render visibly across ticks
  for (const fxTheme of [themes.ThemeId.ZeroDayCyan, themes.ThemeId.CodeRain, themes.ThemeId.RedTeam]) {
    const fA = ui.buildUiFrame(logic.reduce(s, { type: 'SetTheme', nowMs: 140, theme: fxTheme }), { width: 240, height: 135 });
    const fB = ui.buildUiFrame(logic.reduce(s, { type: 'SetTheme', nowMs: 12 * 140, theme: fxTheme }), { width: 240, height: 135 });
    const bufA = gfxMod.createPixelBuffer(240, 135);
    const bufB = gfxMod.createPixelBuffer(240, 135);
    gfxMod.paintUiFrame(bufA, fA);
    gfxMod.paintUiFrame(bufB, fB);
    assert.notDeepStrictEqual(bufA.data, bufB.data, 'Backdrop effect must animate for ' + fxTheme);
  }

  testWebAccessibilityMarkup();
}

function testWebAccessibilityMarkup() {
  const html = fs.readFileSync(path.resolve(__dirname, './index.html'), 'utf8');
  const css = fs.readFileSync(path.resolve(__dirname, './styles.css'), 'utf8');

  assert.ok(html.includes('<h1 class="brand-logo">'), 'Page must include an <h1> heading');
  assert.ok(!html.includes('1/10'), 'Initial theme counter must not be stale 1/10');
  assert.ok(html.includes('1/' + themes.THEME_COUNT), 'Initial theme counter must match THEME_COUNT');
  assert.ok(html.includes('Content-Security-Policy') && !html.includes("'unsafe-inline'"),
    'index.html must include a strict CSP meta tag without unsafe-inline');
  assert.strictEqual(/\sstyle="/.test(html), false,
    'index.html must not contain inline style= attributes (required by strict CSP)');
  assert.ok(html.includes('class="skip-link" href="#main-workbench"'),
    'Must include keyboard skip link to main workbench');
  assert.ok(html.includes('id="btn-hotkeys"'), 'Must expose WCAG 2.1.4 hotkey toggle button');
  assert.ok(html.includes('id="btn-motion"'), 'Must expose animation motion toggle button');
  assert.ok(html.includes('id="act-boop"'), 'Must expose keyboard-accessible Boop ZeroDay button');
  assert.strictEqual(/id="screen-viewport"[^>]*role="button"/.test(html), false,
    '#screen-viewport must not wrap canvas role="img" inside a role="button"');
  assert.ok(html.includes('<label class="prompt-prefix" for="input-pet-name">'),
    'HANDLE prompt must be a semantic <label for="input-pet-name">');
  assert.ok(html.includes('id="xp-track"') && html.includes('role="progressbar"') &&
    html.includes('aria-valuenow="0"'),
    'XP track must expose ARIA progressbar attributes');
  assert.ok(html.includes('value="2"') && html.includes('value="13"'),
    'Custom beacon channel selector must support all 2.4 GHz channels 1..13');
  assert.ok(html.includes('id="sr-status"') && html.includes('aria-live="polite"'),
    'Must expose screen-reader aria-live status region');
  assert.ok(html.includes('id="pwn-screen"') && html.includes('role="img"'),
    'Canvas must expose role="img" and accessible fallback');
  assert.ok(html.includes('id="term-log"') && html.includes('role="log"') &&
    html.includes('aria-live="off"'),
    'Terminal log must expose role="log" with aria-live="off" so continuous logs do not chatter');
  assert.ok(html.includes('id="select-resolution"') && html.includes('aria-label="Target Hardware Display Profile"'),
    'Select controls must have explicit aria-label');
  assert.ok(css.includes('--border-control:'), 'CSS must define >= 3:1 interactive control border token');
  assert.ok(css.includes(':focus-visible') && css.includes('.skip-link:focus'),
    'CSS must define visible :focus-visible rings and skip-link focus reveal');
  assert.ok(css.includes('body.reduce-motion'), 'CSS must support reduced-motion toggle class');
  assert.ok(css.includes('min-width: 24px') && css.includes('min-height: 24px'),
    'Remove button targets must meet WCAG 2.5.8 24x24px minimum');

  // Verify canvas_gfx zero-copy backing buffer & cross-product fillArc parity.
  const gfxSrc = fs.readFileSync(path.resolve(__dirname, './js/canvas_gfx.js'), 'utf8');
  assert.strictEqual(gfxSrc.includes('Math.atan2'), false,
    'canvas_gfx.js fillArc should use cross-product half-plane test matching surface_rgb565.hpp');
  const shared = new Uint8ClampedArray(128 * 64 * 4);
  const directBuf = gfxMod.createPixelBuffer(128, 64, shared);
  assert.strictEqual(directBuf.data, shared, 'createPixelBuffer must write directly into backing array');

  // Lightweight DOM harness smoke-test of app.js interactions & CSP-safe behavior.
  const vm = require('vm');
  const appSrc = fs.readFileSync(path.resolve(__dirname, './js/app.js'), 'utf8');
  const makeFakeEl = (id) => {
    const attrs = { id: id || '' };
    const listeners = {};
    const cls = new Set();
    return {
      id: id || '',
      tagName: 'DIV',
      value: '',
      checked: false,
      textContent: '',
      title: '',
      style: {},
      childNodes: [],
      classList: {
        add: (c) => cls.add(c),
        remove: (c) => cls.delete(c),
        toggle: (c, f) => (f === undefined ? (cls.has(c) ? cls.delete(c) : cls.add(c)) : (f ? cls.add(c) : cls.delete(c))),
        contains: (c) => cls.has(c)
      },
      setAttribute: (k, v) => { attrs[k] = String(v); },
      getAttribute: (k) => (k in attrs ? attrs[k] : null),
      appendChild: function (c) { this.childNodes.push(c); return c; },
      removeChild: function (c) { const i = this.childNodes.indexOf(c); if (i >= 0) this.childNodes.splice(i, 1); },
      addEventListener: (ev, fn) => { (listeners[ev] = listeners[ev] || []).push(fn); },
      dispatch: (ev, obj) => (listeners[ev] || []).forEach((fn) => fn(obj || {})),
      getContext: () => ({
        imageSmoothingEnabled: false,
        createImageData: (w, h) => ({ width: w, height: h, data: new Uint8ClampedArray(w * h * 4) }),
        putImageData: () => {},
        drawImage: () => {}
      }),
      getBoundingClientRect: () => ({ left: 0, top: 0, width: 240, height: 135 }),
      toDataURL: () => 'data:image/png;base64,'
    };
  };
  const els = {};
  const getEl = (id) => (els[id] = els[id] || makeFakeEl(id));
  const bodyEl = makeFakeEl('body');
  const store = { zd_web_shell: 'INVALID_SHELL', zd_web_fx: 'INVALID_FX' };
  const docObj = {
    body: bodyEl,
    hidden: false,
    activeElement: null,
    getElementById: getEl,
    querySelectorAll: () => [],
    createElement: (tag) => Object.assign(makeFakeEl(''), { tagName: tag.toUpperCase() }),
    createTextNode: (t) => ({ textContent: t }),
    addEventListener: () => {}
  };
  const sandbox = {
    window: null,
    document: docObj,
    navigator: {},
    performance: { now: () => 1000 },
    localStorage: {
      getItem: (k) => (k in store ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); }
    },
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    console
  };
  sandbox.window = sandbox;
  sandbox.ZD = {
    fp: fp,
    wifiAnalysis: wifi,
    themes: themes,
    petLogic: logic,
    uiModel: ui,
    airwavesSim: sim,
    canvasGfx: gfxMod,
    createBuzzer: () => ({ clickA() {}, clickB() {}, themeSwap() {}, boop() {}, pwn() {}, peer() {}, toggle() { return true; } })
  };
  sandbox.requestAnimationFrame = () => 1;
  sandbox.cancelAnimationFrame = () => {};
  sandbox.addEventListener = () => {};
  vm.runInNewContext(appSrc, sandbox);
  assert.strictEqual(bodyEl.getAttribute('data-shell'), 'orange', 'Invalid stored shell must sanitize to orange');
  assert.strictEqual(els['screen-viewport'].getAttribute('data-fx'), 'grid', 'Invalid stored fx must sanitize to grid');
  els['act-boop'].dispatch('click');
  assert.ok(els['term-log'].childNodes.some((n) => JSON.stringify(n).includes('[BOOP]')),
    'Clicking #act-boop must dispatch PetPoked and log [BOOP]');
  els['btn-motion'].dispatch('click');
  assert.strictEqual(els['btn-motion'].textContent, 'MOTION: OFF');
  assert.strictEqual(bodyEl.classList.contains('reduce-motion'), true);
}

testFunctionalCombinators();
testWifiAnalysisPipeline();
testStateReducerAndPlayfulEvents();
testResponsiveUiAndPixelRasterizer();
testThemesMultiDeviceAndCppParity();
console.log('All Web Port pure functional core, pixel rasterizer & C++ parity tests PASSED!');
