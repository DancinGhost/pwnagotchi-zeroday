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
    targetSsid: 'Mainframe_Lab'
  });
  assert.strictEqual(sPwn.mood, logic.Mood.Mischief);
  assert.strictEqual(sPwn.toyHandshakes, 1);
  assert.strictEqual(sPwn.capturesSaved, 1);
  assert.strictEqual(sPwn.lastCaptureLabel, 'EAPOL Mainframe_Lab');
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
  assert.strictEqual(logic.deriveLevelInfo(0).badge, 'SPRT');
  assert.strictEqual(logic.deriveLevelInfo(2500).level, 10);
  assert.strictEqual(logic.deriveLevelInfo(2500).badge, 'LGND');
  assert.strictEqual(logic.prevPage(logic.ScreenPage.PetFace), logic.ScreenPage.Captures);
  assert.strictEqual(logic.nextPage(logic.ScreenPage.RfGuard), logic.ScreenPage.Captures);
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

  // Paint every mood (both ClassicFace and PixelArtMascot themes) onto pixel buffer without error
  const allMoods = Object.values(logic.Mood);
  for (const themeId of [themes.ThemeId.PaperInk, themes.ThemeId.ZeroDayCyan]) {
    for (const mood of allMoods) {
      const moodState = Object.assign({}, state, { mood, theme: themeId });
      const frame = ui.buildUiFrame(moodState, { width: 240, height: 135 });
      assert.strictEqual(frame.faceGeom.centerX, 120);
      assert.strictEqual(frame.faceStyle, themes.themeFaceStyle(themeId));
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

  // FaceStyle is ClassicFace across all themes (PixelArtMascot preserved for future exploration)
  assert.strictEqual(themes.themeFaceStyle(themes.ThemeId.PaperInk), themes.FaceStyle.ClassicFace);
  assert.strictEqual(themes.themeFaceStyle(themes.ThemeId.CodeRain), themes.FaceStyle.ClassicFace);
  assert.strictEqual(themes.themeFaceStyle(themes.ThemeId.ZeroDayCyan), themes.FaceStyle.ClassicFace);
  assert.strictEqual(themes.themeFaceStyle(themes.ThemeId.AmberCrt), themes.FaceStyle.ClassicFace);
  assert.strictEqual(themes.themeFaceStyle(themes.ThemeId.RedTeam), themes.FaceStyle.ClassicFace);
  assert.strictEqual(themes.themeFaceStyle(themes.ThemeId.BlueTeam), themes.FaceStyle.ClassicFace);

  // Highscore baseline, CaptureSaved, notifications & Captures page rendering
  let capSt = logic.initialState(33);
  capSt = logic.reduce(capSt, { type: 'SetHighScore', nowMs: 100, highScore: 30, xp: 0 });
  assert.strictEqual(capSt.highScoreBaseline, 30);
  capSt = logic.reduce(capSt, {
    type: 'CaptureSaved',
    nowMs: 120,
    addedCount: 0,
    path: 'browser://localStorage/zeroday_captures.json',
    label: 'Ready',
    notify: false
  });
  assert.strictEqual(capSt.capturesSaved, 0);
  capSt = logic.reduce(capSt, {
    type: 'CaptureSaved',
    nowMs: 200,
    addedCount: 3,
    path: 'browser://localStorage/zeroday_captures.json',
    label: 'EAPOL x3',
    notify: true
  });
  assert.strictEqual(capSt.capturesSaved, 3);
  assert.strictEqual(capSt.xp, 45);
  assert.strictEqual(capSt.highScoreBeaten, true);
  assert.strictEqual(capSt.level, 2);
  assert.strictEqual(capSt.mood, logic.Mood.LevelUp);
  assert.strictEqual(capSt.notifyKind, logic.NotifyKind.LevelUp);

  assert.deepStrictEqual(ui.formatCapturePathRows('/sd/cap.pcap', 26), ['PATH: /sd/cap.pcap']);
  assert.strictEqual(ui.formatCapturePathRows('browser://localStorage/zeroday_captures.json', 26).length, 2);

  capSt = logic.reduce(capSt, { type: 'SetPage', nowMs: 250, page: logic.ScreenPage.Captures });
  for (const prof of ui.SCREEN_PROFILES) {
    const cf = ui.buildUiFrame(capSt, prof.dims);
    assert.strictEqual(cf.notifyActive, true);
    assert.ok(cf.captureSummary.includes('3'));
    const buf = gfxMod.createPixelBuffer(prof.dims.width, prof.dims.height);
    gfxMod.paintUiFrame(buf, cf);
  }

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
    'smarttag',
    'wall_of_sheep',
    'gibson',
    'zerocool',
    'acidburn',
    'keeloq',
    'lan_solo',
    'starbucks',
    'xfinity'
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
  for (let i = 0; i < 12; i++) {
    const subEv = sim.generateSubGhzEvent('con', 433920, 100 + i * 37);
    const proto = String(subEv.signal.protocol || '').toLowerCase();
    for (const term of bannedTerms) {
      assert.strictEqual(
        proto.includes(term),
        false,
        'SubGHz protocol "' + subEv.signal.protocol + '" must not contain restricted brand term "' + term + '"'
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
  assert.ok(html.includes('data-page="Captures"'), 'index.html must include Captures page button');
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
  assert.ok(html.includes('id="tab-wifi"') && html.includes('id="tab-bt"') &&
    html.includes('aria-controls="airspace-device-list"') &&
    html.includes('aria-labelledby="tab-wifi"') &&
    html.includes('id="act-bt-scan"') && html.includes('id="airspace-device-list"'),
    'index.html must include WAI-ARIA Airspace Devices WiFi/Bluetooth tabs and device list');
  assert.ok(html.includes('id="act-ack"') && html.includes('aria-describedby="btn-b-hint"') &&
    html.includes('id="btn-b-hint"') && html.includes('id="term-log" class="term-log" tabindex="0"'),
    'index.html must include Clear Threat button, Button B description, and keyboard-focusable term log');
  assert.ok(css.includes('--border-control:'), 'CSS must define >= 3:1 interactive control border token');
  assert.ok(css.includes(':focus-visible') && css.includes('.skip-link:focus'),
    'CSS must define visible :focus-visible rings and skip-link focus reveal');
  assert.ok(css.includes('body.reduce-motion'), 'CSS must support reduced-motion toggle class');
  assert.ok(css.includes('min-width: 24px') && css.includes('min-height: 24px'),
    'Remove button targets must meet WCAG 2.5.8 24x24px minimum');

  // Check BLE vendor/service labeling, sorting, and non-spurious sim behavior
  assert.strictEqual(wifi.bleVendorLabel(0x0087), 'Garmin');
  assert.strictEqual(wifi.bleServiceLabel(0x180d), 'HeartRate');
  const sortedBle = wifi.bleTargetsByStrength([
    { mac: '11:22:33:44:55:66', name: 'Watch', rssi: -45, threat: wifi.BleThreatKind.None },
    { mac: 'aa:bb:cc:dd:ee:ff', name: 'Tracker', rssi: -75, threat: wifi.BleThreatKind.AirTagTracker }
  ]);
  assert.strictEqual(sortedBle[0].mac, 'aa:bb:cc:dd:ee:ff');

  const safeBle = sim.generateBleSnapshot('cafe', 777, 5000, { includeThreats: false });
  assert.ok(safeBle.devices.length >= 2);
  assert.strictEqual(safeBle.devices.some((d) =>
    wifi.classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid, d.trackerPayload) !== wifi.BleThreatKind.None
  ), false, 'Default scan BLE snapshot must not inject threats when includeThreats=false');

  const alertBle = sim.generateBleSnapshot('con', 777, 5000, { includeThreats: true });
  assert.strictEqual(alertBle.devices.some((d) =>
    wifi.classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid, d.trackerPayload) !== wifi.BleThreatKind.None
  ), true, 'includeThreats=true must include simulated threat devices');

  // Assert WCAG 2.2 AA theme contrast invariants in JS
  const relLum = (c) => {
    const comp = (v) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * comp(c.r) + 0.7152 * comp(c.g) + 0.0722 * comp(c.b);
  };
  const contrastRatio = (a, b) => {
    const la = relLum(a);
    const lb = relLum(b);
    return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
  };
  for (const spec of themes.THEME_CATALOG) {
    assert.ok(contrastRatio(spec.palette.fg, spec.palette.bg) >= 4.5, spec.key + ' fg/bg');
    assert.ok(contrastRatio(spec.palette.accent, spec.palette.bg) >= 4.5, spec.key + ' accent/bg');
    assert.ok(contrastRatio(spec.palette.highlight, spec.palette.bg) >= 4.5, spec.key + ' highlight/bg');
    assert.ok(contrastRatio(spec.palette.muted, spec.palette.bg) >= 3.0, spec.key + ' muted/bg');
  }

  // Parity check: deriveLevelInfo integer truncation & OpsMode arming/sync & lazy ui_model
  assert.strictEqual(logic.deriveLevelInfo(45).progressPct, 7, 'Math.floor((5*100)/70) === 7 matching C++');
  const baseSt = logic.initialState(42);
  const cycOff = logic.reduce(baseSt, { type: 'SetOpsMode', nowMs: 100, mode: logic.OpsMode.Offensive });
  assert.strictEqual(cycOff.opsMode, logic.OpsMode.Offensive);
  assert.strictEqual(cycOff.offensiveArmed, false, 'SetOpsMode must not flip offensiveArmed');
  const defSt = logic.reduce(baseSt, { type: 'SetOpsMode', nowMs: 120, mode: logic.OpsMode.Defensive });
  const armedSt = logic.reduce(defSt, { type: 'SetOffensiveArmed', nowMs: 150, armed: true });
  assert.strictEqual(armedSt.offensiveArmed, true);
  assert.strictEqual(armedSt.opsMode, logic.OpsMode.Offensive);
  assert.strictEqual(armedSt.preArmedOpsMode, logic.OpsMode.Defensive);
  const blockedCycleWhileArmed = logic.reduce(armedSt, { type: 'CycleOpsMode', nowMs: 160 });
  assert.strictEqual(blockedCycleWhileArmed.opsMode, logic.OpsMode.Offensive);
  const disarmedSt = logic.reduce(armedSt, { type: 'SetOffensiveArmed', nowMs: 200, armed: false });
  assert.strictEqual(disarmedSt.offensiveArmed, false);
  assert.strictEqual(disarmedSt.opsMode, logic.OpsMode.Defensive);
  const syncedSt = logic.reduce(baseSt, {
    type: 'SyncMonitorSnapshot',
    nowMs: 500,
    aps: [{ ssid: 'SyncAP', rssi: -41, channel: 6, secure: true }],
    bleDevices: safeBle.devices,
    threatCount: 1,
    topThreatLabel: 'SYNC-THREAT'
  });
  assert.strictEqual(syncedSt.xp, 0);
  assert.strictEqual(syncedSt.latestScan.totalAps, 1);
  assert.strictEqual(syncedSt.bleDevices.length, safeBle.devices.length);
  const faceFrame = ui.buildUiFrame(syncedSt, { width: 240, height: 135 });
  assert.strictEqual(faceFrame.radarRows.length, 0, 'Lazy ui_model must skip off-page radarRows');
  const thrEv = logic.reduce(baseSt, {
    type: 'SubGhzObserved',
    nowMs: 1000,
    signal: { freqKhz: 433920, rssi: -50, protocol: 'OOK', burstCount: 6, anomaly: wifi.SubGhzAnomaly.ReplayBurst }
  });
  assert.ok(thrEv.lastThreatLabel.length > 0 && thrEv.lastThreatMs === 1000);
  const thrExpired = logic.reduce(thrEv, {
    type: 'Tick',
    nowMs: 1000 + logic.THREAT_DISPLAY_TIMEOUT_MS,
    batteryPercent: 90,
    isCharging: false
  });
  assert.strictEqual(thrExpired.lastThreatLabel, '');
  const thrAck = logic.reduce(thrEv, { type: 'ClearThreat', nowMs: 1500 });
  assert.strictEqual(thrAck.lastThreatLabel, '');

  // Exact faceForMood C++ <-> JS parity
  const petLogicCppPath = path.resolve(__dirname, '../../core/include/zd/pet_logic.hpp');
  const petLogicCpp = fs.readFileSync(petLogicCppPath, 'utf8');
  const faceRe =
    /case\s+Mood::(\w+):\s+return\s+\{EyeGlyph::(\w+),\s*MouthGlyph::(\w+),\s*(true|false),\s*(true|false),\s*(true|false),\s*"([^"]+)",\s*"([^"]+)"\};/g;
  let fm;
  let faceChecked = 0;
  while ((fm = faceRe.exec(petLogicCpp)) !== null) {
    const jf = logic.faceForMood(fm[1]);
    assert.strictEqual(jf.eyes, fm[2], 'EyeGlyph mismatch for Mood::' + fm[1]);
    assert.strictEqual(jf.mouth, fm[3], 'MouthGlyph mismatch for Mood::' + fm[1]);
    assert.strictEqual(jf.showBlush, fm[4] === 'true');
    assert.strictEqual(jf.showTear, fm[5] === 'true');
    assert.strictEqual(jf.showZzz, fm[6] === 'true');
    assert.strictEqual(jf.asciiFace, fm[7], 'asciiFace mismatch for Mood::' + fm[1]);
    assert.strictEqual(jf.moodLabel, fm[8], 'moodLabel mismatch for Mood::' + fm[1]);
    faceChecked++;
  }
  assert.strictEqual(faceChecked, 16, 'Expected 16 C++ faceForMood entries');

  // Verify canvas_gfx zero-copy backing buffer, cross-product fillArc, & no trademarked mascot symbols
  const gfxSrc = fs.readFileSync(path.resolve(__dirname, './js/canvas_gfx.js'), 'utf8');
  assert.strictEqual(/flipper/i.test(gfxSrc), false, 'canvas_gfx.js must not contain trademarked mascot names');
  const painterCpp = fs.readFileSync(path.resolve(__dirname, '../../render/include/zd/render/painter.hpp'), 'utf8');
  assert.strictEqual(/flipper/i.test(painterCpp), false, 'painter.hpp must not contain trademarked mascot names');
  assert.strictEqual(gfxSrc.includes('Math.atan2'), false,
    'canvas_gfx.js fillArc should use cross-product half-plane test matching surface_rgb565.hpp');
  const shared = new Uint8ClampedArray(128 * 64 * 4);
  const directBuf = gfxMod.createPixelBuffer(128, 64, shared);
  assert.strictEqual(directBuf.data, shared, 'createPixelBuffer must write directly into backing array');

  // Verify PWA manifest, service worker, icon SVG & Share Link button
  assert.ok(html.includes('id="btn-share-link"'), 'Must include Share Link permalink button');
  assert.ok(html.includes('rel="manifest" href="./manifest.json"'), 'index.html must link manifest.json');
  const manifest = JSON.parse(fs.readFileSync(path.resolve(__dirname, './manifest.json'), 'utf8'));
  assert.ok(manifest.name && Array.isArray(manifest.icons) && manifest.icons.length > 0);
  const swSrc = fs.readFileSync(path.resolve(__dirname, './sw.js'), 'utf8');
  assert.ok(swSrc.includes('zeroday-web-v3') && swSrc.includes('netResp.clone()'),
    'sw.js must use bumped cache version and stale-while-revalidate cloning');
  assert.ok(fs.readFileSync(path.resolve(__dirname, './icon.svg'), 'utf8').includes('<svg'));

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
  els['act-bt-scan'].dispatch('click');
  assert.ok(els['tab-bt'].textContent.includes('Bluetooth ('),
    'Clicking #act-bt-scan must sweep BT and update Bluetooth tab counter');
  assert.ok(els['airspace-device-list'].childNodes.length >= 1,
    'Airspace device list must populate Bluetooth device rows after Sweep BT');
  els['act-guard'].dispatch('click');
  els['act-ack'].dispatch('click');
  assert.ok(els['term-log'].childNodes.some((n) => JSON.stringify(n).includes('[ACK]')),
    'Clicking #act-ack must clear threat and log [ACK]');
}

function testOui5GhzSpectrumAndSecMoodParity() {
  // 1. Offline OUI catalog & BLE/OUI vendor fallback (bleVendorLabel untouched for companyId=0)
  assert.strictEqual(wifi.bleVendorLabel(0), '-');
  assert.strictEqual(wifi.lookupOuiVendor('b8:27:eb:11:22:33'), 'RaspberryPi');
  assert.strictEqual(wifi.bleVendorOrOuiLabel(0, 'b8:27:eb:11:22:33'), 'RaspberryPi');
  assert.strictEqual(wifi.bleVendorOrOuiLabel(0x004C, 'b8:27:eb:11:22:33'), 'Apple');
  assert.strictEqual(wifi.isLocallyAdministeredMac('02:aa:bb:cc:dd:ee'), true);
  assert.strictEqual(wifi.isLocallyAdministeredMac('00:00:0c:11:22:33'), false);
  assert.strictEqual(wifi.ouiVendorLabel('02:aa:bb:cc:dd:ee'), 'random');
  assert.strictEqual(wifi.ouiVendorLabel('00:00:0c:11:22:33'), 'Cisco');

  // Exact C++ <-> JS OUI_CATALOG parity against core/include/zd/oui.hpp
  const ouiCppPath = path.resolve(__dirname, '../../core/include/zd/oui.hpp');
  const ouiCppSrc = fs.readFileSync(ouiCppPath, 'utf8');
  const ouiRe = /\{0x([0-9A-Fa-f]{6})u,\s*"([^"]+)"\}/g;
  const cppOuis = [];
  let om;
  while ((om = ouiRe.exec(ouiCppSrc)) !== null) {
    cppOuis.push([parseInt(om[1], 16), om[2]]);
  }
  assert.strictEqual(
    cppOuis.length,
    wifi.OUI_CATALOG.length,
    'C++ kOuiCatalog and JS OUI_CATALOG must have identical entry count'
  );
  for (let i = 0; i < cppOuis.length; i++) {
    assert.strictEqual(wifi.OUI_CATALOG[i][0], cppOuis[i][0], 'OUI prefix mismatch at index ' + i);
    assert.strictEqual(wifi.OUI_CATALOG[i][1], cppOuis[i][1], 'OUI vendor mismatch at index ' + i);
  }

  // Captures page FRENS row parity when peersMet > 0
  let peerSt = logic.initialState(21);
  peerSt = logic.reduce(peerSt, { type: 'PeerSpotted', nowMs: 100, peerName: 'cyber-neko', peerRssi: -45 });
  peerSt = logic.reduce(peerSt, { type: 'SetPage', nowMs: 120, page: logic.ScreenPage.Captures });
  const peerFrame = ui.buildUiFrame(peerSt, { width: 240, height: 135 });
  assert.ok(
    peerFrame.captureRows.some((r) => r.includes('FRENS: 1 (cyber-neko)')),
    'Captures page must include FRENS row matching C++ ui_model.hpp'
  );

  // 2. 5 GHz / 6 GHz spectrum & ChannelSpectrum auto-switch
  const mixed = [
    { ssid: 'FiveG_36', rssi: -52, channel: 36, secure: true },
    { ssid: 'SixG_37', rssi: -60, channel: wifi.K_6GHZ_CHANNEL_BASE + 37, secure: true }
  ];
  const hist = wifi.buildChannelHistogram(mixed);
  assert.strictEqual(hist.band24GhzAps, 0);
  assert.strictEqual(hist.band5GhzAps, 1);
  assert.strictEqual(hist.band6GhzAps, 1);

  let st = logic.initialState(55);
  st = logic.reduce(st, { type: 'ScanCompleted', nowMs: 1000, rawNetworks: mixed });
  st = logic.reduce(st, { type: 'SetPage', nowMs: 1100, page: logic.ScreenPage.ChannelSpectrum });
  const specFrame = ui.buildUiFrame(st, { width: 240, height: 135 });
  assert.strictEqual(specFrame.channelBars[0].channel, 36);
  assert.ok(specFrame.spectrumSummary.includes('5GHz'));
  assert.ok(specFrame.spectrumSummary.includes('6G:1'));

  // 3. SetSecMood reducer reaction & SyncMonitorSnapshot reaction
  st = logic.reduce(st, {
    type: 'SetSecMood',
    nowMs: 1200,
    mood: logic.SecMood.Alarmed,
    detail: 'DEAUTH-FLOOD LabNet'
  });
  assert.strictEqual(st.secMood, logic.SecMood.Alarmed);
  assert.strictEqual(st.mood, logic.Mood.ThreatAlert);
  st = logic.reduce(st, { type: 'ClearThreat', nowMs: 1300 });
  assert.strictEqual(st.secMood, logic.SecMood.Calm);
  assert.notStrictEqual(st.mood, logic.Mood.ThreatAlert);
}

testFunctionalCombinators();
testWifiAnalysisPipeline();
testStateReducerAndPlayfulEvents();
testResponsiveUiAndPixelRasterizer();
testThemesMultiDeviceAndCppParity();
testOui5GhzSpectrumAndSecMoodParity();
console.log('All Web Port pure functional core, pixel rasterizer & C++ parity tests PASSED!');
