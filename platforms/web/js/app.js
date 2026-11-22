// Imperative Browser Shell for pwnagotchi-zeroday Web Port.
// Bridges DOM controls, HTML5 Canvas, WebAudio buzzer, simulated RF airwaves,
// and the interactive /dev/ttyACM0 serial console onto the pure Functional Core.
(function () {
  'use strict';

  const fp = window.ZD.fp;
  const themes = window.ZD.themes;
  const logic = window.ZD.petLogic;
  const ui = window.ZD.uiModel;
  const sim = window.ZD.airwavesSim;
  const gfxMod = window.ZD.canvasGfx;
  const buzzer = window.ZD.createBuzzer();

  // --- Boot Entropy & Saved Preferences ---
  function getBootEntropy() {
    if (window.crypto && window.crypto.getRandomValues) {
      const arr = new Uint32Array(1);
      window.crypto.getRandomValues(arr);
      return arr[0] >>> 0;
    }
    return Math.floor(Math.random() * 0xFFFFFFFF) >>> 0;
  }

  function loadPref(key, fallback) {
    try {
      const v = window.localStorage.getItem('zd_web_' + key);
      return v !== null ? v : fallback;
    } catch (_) {
      return fallback;
    }
  }

  function savePref(key, val) {
    try {
      window.localStorage.setItem('zd_web_' + key, String(val));
    } catch (_) {
      // Ignore storage errors in private/file contexts
    }
  }

  // --- Mutable Runtime Boundary State ---
  const bootEpochMs = performance.now();
  let gState = logic.initialState(getBootEntropy());
  let simSeed = fp.nextSeed(gState.rngSeed ^ 0xA5A55A5A);

  let displayMode = ui.screenProfileFromKey(loadPref('res', 'plus')) ? loadPref('res', 'plus') : 'plus';
  let activeEnv = sim.PRESETS[loadPref('env', 'cafe')] ? loadPref('env', 'cafe') : 'cafe';
  let customAps = [];

  let scanFinishAtMs = 0;
  let batteryLevel = 96;
  let batteryCharging = true;
  let manualPowerOverride = false;
  let pwnLedUntilMs = 0;

  // --- DOM Elements ---
  const elScreen = document.getElementById('pwn-screen');
  const elViewport = document.getElementById('screen-viewport');
  const elSrStatus = document.getElementById('sr-status');
  const elFloatingFx = document.getElementById('floating-fx');
  const elHeaderFace = document.getElementById('header-ascii-face');
  const elStatusLed = document.getElementById('status-led');
  const elLedLabel = document.getElementById('led-label');
  const elDimsBadge = document.getElementById('dims-badge');
  const elEnvIndicator = document.getElementById('env-indicator');

  const elSelectRes = document.getElementById('select-resolution');
  const elSelectShell = document.getElementById('select-shell');
  const elSelectFx = document.getElementById('select-fx');
  const elBtnHotkeys = document.getElementById('btn-hotkeys');
  const elBtnSfx = document.getElementById('btn-sfx');
  const elBtnMotion = document.getElementById('btn-motion');
  const elBtnSnapPng = document.getElementById('btn-snap-png');
  const elBtnCopyAscii = document.getElementById('btn-copy-ascii');
  const elBtnShareLink = document.getElementById('btn-share-link');

  let hotkeysEnabled = loadPref('hotkeys', 'on') !== 'off';
  const motionQuery =
    window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  let systemReducedMotion = Boolean(motionQuery && motionQuery.matches);
  let userMotionEnabled = loadPref('motion', 'on') !== 'off';
  const cachedPageBtns = Array.from(document.querySelectorAll('[data-page]'));
  const cachedEnvCards = Array.from(document.querySelectorAll('[data-env]'));
  let cachedSwatches = [];
  let lastCanvasSig = '';
  let lastDashboardSig = '';

  function isAnimationsPaused() {
    return systemReducedMotion || !userMotionEnabled;
  }

  function syncMotionUi() {
    const paused = isAnimationsPaused();
    document.body.classList.toggle('reduce-motion', paused);
    if (elBtnMotion) {
      elBtnMotion.textContent = userMotionEnabled ? 'MOTION: ON' : 'MOTION: OFF';
      elBtnMotion.classList.toggle('active', userMotionEnabled);
      elBtnMotion.setAttribute('aria-pressed', String(userMotionEnabled));
    }
  }

  function announceSr(text) {
    if (elSrStatus && text) {
      elSrStatus.textContent = text;
    }
  }

  const elHwBtnA = document.getElementById('hw-btn-a');
  const elHwBtnB = document.getElementById('hw-btn-b');
  const elBtnBProgress = document.getElementById('btn-b-progress');
  const elBtnThemePrev = document.getElementById('btn-theme-prev');
  const elBtnThemeNext = document.getElementById('btn-theme-next');
  const elActiveThemeLabel = document.getElementById('active-theme-label');
  const elSwatchRow = document.getElementById('swatch-row');

  const elPetNameInput = document.getElementById('input-pet-name');
  const elRankPill = document.getElementById('rank-pill');
  const elHiscorePill = document.getElementById('hiscore-pill');
  const elXpLabel = document.getElementById('xp-label');
  const elXpTrack = document.getElementById('xp-track');
  const elXpFill = document.getElementById('xp-fill');
  const elStatPwns = document.getElementById('stat-pwns');
  const elStatSnacks = document.getElementById('stat-snacks');
  const elStatPeers = document.getElementById('stat-peers');
  const elStatPeak = document.getElementById('stat-peak');

  const elActSnack = document.getElementById('act-snack');
  const elActPwn = document.getElementById('act-pwn');
  const elActPeer = document.getElementById('act-peer');
  const elActScan = document.getElementById('act-scan');
  const elActMode = document.getElementById('act-mode');
  const elActModeLbl = document.getElementById('act-mode-lbl');
  const elActGuard = document.getElementById('act-guard');
  const elActSubGhz = document.getElementById('act-subghz');
  const elActSubGhzLbl = document.getElementById('act-subghz-lbl');
  const elActBoop = document.getElementById('act-boop');

  const elInputBat = document.getElementById('input-battery');
  const elBatVal = document.getElementById('battery-val');
  const elInputChg = document.getElementById('input-charging');

  const elFormBeacon = document.getElementById('form-beacon');
  const elInputSsid = document.getElementById('input-ssid');
  const elBtnRandSsid = document.getElementById('btn-rand-ssid');
  const elInputApCh = document.getElementById('input-ap-ch');
  const elInputApRssi = document.getElementById('input-ap-rssi');
  const elApRssiLabel = document.getElementById('ap-rssi-label');
  const elInputApSec = document.getElementById('input-ap-sec');
  const elBtnClearAps = document.getElementById('btn-clear-aps');
  const elCustomApList = document.getElementById('custom-ap-list');

  const elTermLog = document.getElementById('term-log');
  const elFormTerm = document.getElementById('form-terminal');
  const elInputTerm = document.getElementById('input-terminal');
  const elTermPrompt = document.getElementById('term-prompt-label');
  const elBtnTermAscii = document.getElementById('btn-term-ascii');

  // --- Offscreen Pixel Framebuffer Setup ---
  const displayCtx = elScreen.getContext('2d');
  const offCanvas = document.createElement('canvas');
  const offCtx = offCanvas.getContext('2d');
  let pixelBuf = null;
  let offImageData = null;

  function currentDims() {
    const prof = ui.screenProfileFromKey(displayMode) || ui.screenProfileFromKey('plus');
    const w = prof.dims.width;
    const h = prof.dims.height;
    const scale = Math.max(2, Math.floor(960 / w));
    return { width: w, height: h, scale: scale, monochrome: prof.monochrome, label: prof.label };
  }

  function syncCanvasBuffers() {
    const d = currentDims();
    if (!pixelBuf || pixelBuf.width !== d.width || pixelBuf.height !== d.height) {
      offCanvas.width = d.width;
      offCanvas.height = d.height;
      offImageData = offCtx.createImageData(d.width, d.height);
      pixelBuf = gfxMod.createPixelBuffer(d.width, d.height, offImageData.data);

      elScreen.width = d.width * d.scale;
      elScreen.height = d.height * d.scale;
      elDimsBadge.textContent = d.width + '\u00d7' + d.height + (d.monochrome ? ' 1-BIT' : ' RGB565');
    }
  }

  function nowMs() {
    return Math.max(0, Math.floor(performance.now() - bootEpochMs));
  }

  // --- Serial Monitor Logging ---
  function appendLog(tag, message, cssClass) {
    const row = document.createElement('div');
    row.className = 'log-entry' + (cssClass ? ' ' + cssClass : '');

    const tagSpan = document.createElement('span');
    tagSpan.className = 'log-tag';
    tagSpan.textContent = '[' + tag + '] ';

    const textNode = document.createTextNode(message);
    row.appendChild(tagSpan);
    row.appendChild(textNode);

    elTermLog.appendChild(row);
    while (elTermLog.childNodes.length > 140) {
      elTermLog.removeChild(elTermLog.firstChild);
    }
    elTermLog.scrollTop = elTermLog.scrollHeight;
  }

  function logSerialStatus(eventTag, extraClass) {
    const face = logic.faceForMood(gState.mood);
    const spec = themes.themeSpec(gState.theme);
    const msg =
      face.asciiFace +
      ' ' +
      gState.petName +
      '> "' +
      gState.phrase +
      '" | APs:' +
      gState.latestScan.totalAps +
      ' | BusiestCh:' +
      gState.latestScan.busiestChannel +
      ' | Theme:' +
      spec.key;
    appendLog(eventTag, msg, extraClass || '');
  }

  // --- Floating Screen FX Particles ---
  function spawnFloatingGlyphs(glyphs, colorHex) {
    if (isAnimationsPaused()) {
      return;
    }
    for (let i = 0; i < glyphs.length; i++) {
      setTimeout(function () {
        const span = document.createElement('span');
        span.className = 'float-glyph';
        span.textContent = glyphs[i];
        span.style.left = 18 + Math.random() * 32 + '%';
        span.style.top = 38 + Math.random() * 26 + '%';
        if (colorHex) {
          span.style.color = colorHex;
        }
        elFloatingFx.appendChild(span);
        setTimeout(function () {
          if (span.parentNode) span.parentNode.removeChild(span);
        }, 980);
      }, i * 110);
    }
  }

  // --- Sync Companion Dashboard DOM ---
  function syncDashboardUi() {
    const t = nowMs();
    const pwnActive = !gState.isScanning && t < pwnLedUntilMs;
    const roamSub = activeEnv === 'roam' ? sim.resolveRoamSubPreset(t) : '';
    const dashSig =
      gState.mood + '|' + gState.petName + '|' + gState.xp + '|' + gState.highScore + '|' +
      gState.opsMode + '|' + gState.subGhzFreqKhz + '|' + gState.threatsDetected + '|' +
      gState.toyHandshakes + '|' +
      gState.snacksFed + '|' + gState.peersMet + '|' + gState.peakApCount + '|' +
      gState.isScanning + '|' + pwnActive + '|' + gState.isCharging + '|' +
      activeEnv + '|' + roamSub + '|' + gState.page + '|' + gState.theme + '|' + gState.phrase;
    if (dashSig === lastDashboardSig) {
      return;
    }
    lastDashboardSig = dashSig;

    const face = logic.faceForMood(gState.mood);
    elHeaderFace.textContent = face.asciiFace;
    elTermPrompt.textContent = gState.petName + '@ttyACM0:~$';

    if (document.activeElement !== elPetNameInput) {
      elPetNameInput.value = gState.petName;
    }

    const lvl = logic.deriveLevelInfo(gState.xp);
    elRankPill.textContent = 'Lv.' + lvl.level + ' ' + lvl.title;
    if (elHiscorePill) {
      elHiscorePill.textContent = 'HI: ' + Math.max(gState.highScore || 0, lvl.xp);
    }
    elXpLabel.textContent =
      lvl.progressPct >= 100 && lvl.xp >= 2500
        ? lvl.xp + ' XP (MAX)'
        : lvl.xp + ' / ' + lvl.nextXp + ' XP';
    elXpFill.style.width = lvl.progressPct + '%';
    if (elXpTrack) {
      elXpTrack.setAttribute('aria-valuenow', String(lvl.progressPct));
    }

    if (elActModeLbl) {
      elActModeLbl.textContent = 'Mode: ' + logic.opsModeLabel(gState.opsMode, false);
    }
    if (elActSubGhzLbl) {
      elActSubGhzLbl.textContent = 'SubGHz: ' + window.ZD.wifiAnalysis.formatFreqMhz(gState.subGhzFreqKhz);
    }

    elStatPwns.textContent = String(gState.toyHandshakes);
    elStatSnacks.textContent = String(gState.snacksFed);
    elStatPeers.textContent = String(gState.peersMet);
    elStatPeak.textContent = String(gState.peakApCount);

    // Status LED
    elStatusLed.classList.toggle('scanning', gState.isScanning);
    elStatusLed.classList.toggle('pwn', pwnActive);
    if (gState.isScanning) {
      elLedLabel.textContent = 'SWEEPING WIFI + BLE...';
    } else if (pwnActive) {
      elLedLabel.textContent = 'EAPOL TOY EVENT!';
    } else {
      const preset = sim.PRESETS[activeEnv] || sim.PRESETS.cafe;
      elLedLabel.textContent =
        logic.opsModeLabel(gState.opsMode, false) +
        ' \u2022 ' +
        window.ZD.wifiAnalysis.formatFreqMhz(gState.subGhzFreqKhz);
      const subLabel =
        activeEnv === 'roam'
          ? 'ROAM (' + roamSub.toUpperCase() + ')'
          : preset.label.toUpperCase();
      elEnvIndicator.textContent = 'ENV: ' + subLabel;
    }

    // Active View Segment Buttons
    cachedPageBtns.forEach(function (btn) {
      const isSelected = btn.getAttribute('data-page') === gState.page;
      btn.classList.toggle('active', isSelected);
      btn.setAttribute('aria-pressed', String(isSelected));
    });

    // Active Theme Swatches & Theme Cycler Label
    const activeSpec = themes.themeSpec(gState.theme);
    const activeIdx = Math.max(0, themes.themeIndex(gState.theme));
    if (elActiveThemeLabel) {
      elActiveThemeLabel.textContent =
        activeSpec.name + ' \u2022 ' + (activeIdx + 1) + '/' + themes.THEME_COUNT;
      elActiveThemeLabel.title = activeSpec.blurb;
    }
    cachedSwatches.forEach(function (sw) {
      const isPressed = sw.getAttribute('data-theme') === gState.theme;
      sw.classList.toggle('active', isPressed);
      sw.setAttribute('aria-pressed', String(isPressed));
    });

    // Active Environment Cards
    cachedEnvCards.forEach(function (card) {
      const isPressed = card.getAttribute('data-env') === activeEnv;
      card.classList.toggle('active', isPressed);
      card.setAttribute('aria-pressed', String(isPressed));
    });

    elScreen.setAttribute(
      'aria-label',
      gState.petName + ' display: ' + face.moodLabel + ', ' + gState.phrase +
      ', ' + gState.latestScan.totalAps + ' nearby APs, theme ' + activeSpec.name
    );
  }

  // --- Render Pixel Frame onto Canvas ---
  function renderCurrentState(force) {
    syncCanvasBuffers();
    const d = currentDims();
    const t = nowMs();
    const paused = isAnimationsPaused();

    // Subtle natural blink for 140ms every ~4.6s when idle (suppressed when reduced-motion is active)
    const blinkCycle = t % 4600;
    const isBlinking = !paused && !gState.isScanning && blinkCycle > 4450;

    let frame = ui.buildUiFrame(gState, { width: d.width, height: d.height });
    if (paused && frame.animTick !== 0) {
      frame = Object.assign({}, frame, { animTick: 0 });
    }
    const hasActiveAnim =
      (frame.themeEffect && frame.themeEffect !== 'None') ||
      (frame.scene && frame.scene !== 'None') ||
      frame.page === logic.ScreenPage.PetFace;
    const animKey = hasActiveAnim ? frame.animTick : 0;
    let pageSig = '';
    if (frame.page === logic.ScreenPage.NearbyRadar) {
      pageSig = frame.radarRows.map(function (r) { return r.ssid + ':' + r.details; }).join(';');
    } else if (frame.page === logic.ScreenPage.ChannelSpectrum) {
      pageSig = frame.spectrumSummary + '|' + frame.channelBars.map(function (b) { return b.count; }).join(',');
    } else if (frame.page === logic.ScreenPage.RfGuard) {
      pageSig = frame.rfGuardSummary + '|' + frame.rfGuardRows.map(function (r) { return r.ssid + ':' + r.details; }).join(';');
    }
    const canvasSig =
      d.width + 'x' + d.height + '|' + frame.page + '|' + frame.theme + '|' + animKey + '|' +
      isBlinking + '|' + frame.headerLine + '|' + frame.footerLine + '|' + frame.modeBadge + '|' +
      frame.scene + '|' + frame.rankLine + '|' + frame.xpProgressPct + '|' +
      frame.threatBanner + '|' + frame.face.moodLabel + '|' +
      (frame.toast && frame.toast.visible ? frame.toast.text : '') +
      '|' + frame.phraseLines.join('/') + '|' + frame.spotlightLabel + '|' + pageSig;

    if (force || canvasSig !== lastCanvasSig) {
      lastCanvasSig = canvasSig;
      gfxMod.paintUiFrame(pixelBuf, frame, { blink: isBlinking });

      if (pixelBuf.data !== offImageData.data) {
        offImageData.data.set(pixelBuf.data);
      }
      offCtx.putImageData(offImageData, 0, 0);

      displayCtx.imageSmoothingEnabled = false;
      displayCtx.drawImage(offCanvas, 0, 0, elScreen.width, elScreen.height);
    }

    syncDashboardUi();
  }

  // --- Core Actions ---
  function triggerButtonA() {
    gState = logic.reduce(gState, { type: 'ButtonAPressed', nowMs: nowMs() });
    buzzer.clickA();
    logSerialStatus('BTN_A');
    announceSr('View switched to ' + gState.page);
    renderCurrentState(true);
  }

  function triggerButtonBShort() {
    gState = logic.reduce(gState, { type: 'ButtonBPressed', nowMs: nowMs() });
    buzzer.clickB();
    logSerialStatus('BTN_B');
    checkAndRunScanCycle();
    announceSr('WiFi scan triggered');
    renderCurrentState(true);
  }

  function persistCurrentTheme() {
    savePref('theme', themes.themeSpec(gState.theme).key);
  }

  function triggerThemeCycle(step) {
    const dir = step === undefined ? 1 : step;
    gState = logic.reduce(gState, { type: 'CycleTheme', nowMs: nowMs(), step: dir });
    persistCurrentTheme();
    buzzer.themeSwap();
    logSerialStatus('THEME');
    announceSr('Theme switched to ' + themes.themeSpec(gState.theme).name);
    renderCurrentState(true);
  }

  function persistHighScore() {
    savePref('hiscore', gState.highScore);
  }

  function triggerPetBoop() {
    gState = logic.reduce(gState, { type: 'PetPoked', nowMs: nowMs() });
    persistHighScore();
    buzzer.boop();
    spawnFloatingGlyphs(['\u2665', '*', '~'], '#ff5ca8');
    logSerialStatus('BOOP');
    announceSr(gState.petName + ' says: ' + gState.phrase);
    renderCurrentState(true);
  }

  function triggerFeedSnack() {
    gState = logic.reduce(gState, { type: 'SnackFed', nowMs: nowMs() });
    persistHighScore();
    buzzer.boop();
    spawnFloatingGlyphs(['+10XP', '0xFF', '\u2665'], '#38ff7a');
    logSerialStatus('SNACK', 'log-cmd');
    renderCurrentState();
  }

  function triggerToyHandshake() {
    const t = nowMs();
    const target =
      gState.latestScan.strongestSsid ||
      (customAps.length > 0 ? customAps[0].ssid : 'Mainframe_Lab');
    gState = logic.reduce(gState, {
      type: 'ToyHandshake',
      nowMs: t,
      targetSsid: target
    });
    persistHighScore();
    pwnLedUntilMs = t + 2000;
    buzzer.pwn();
    spawnFloatingGlyphs(['PWN!', 'EAPOL', '+25XP'], '#00e5ff');
    logSerialStatus('TOY_PWN', 'log-pwn');
    renderCurrentState();
  }

  function triggerPeerEncounter(explicitName) {
    const t = nowMs();
    const enc = sim.randomPeerEncounter(simSeed);
    simSeed = enc.nextSeed;
    const peerName = explicitName ? logic.sanitizePetName(explicitName) : enc.peerName;
    gState = logic.reduce(gState, {
      type: 'PeerSpotted',
      nowMs: t,
      peerName,
      peerRssi: enc.peerRssi
    });
    persistHighScore();
    pwnLedUntilMs = t + 1800;
    buzzer.peer();
    spawnFloatingGlyphs(['(^_^)', peerName, '+20XP'], '#ffb020');
    logSerialStatus('PEER', 'log-warn');
    renderCurrentState();
  }

  function switchEnvironment(envId) {
    if (!sim.PRESETS[envId]) return false;
    activeEnv = envId;
    savePref('env', envId);
    appendLog('RF_SIM', 'Switched airspace preset -> ' + sim.PRESETS[envId].label, 'log-cmd');
    if (!gState.isScanning) {
      gState = logic.reduce(gState, { type: 'ButtonBPressed', nowMs: nowMs() });
      checkAndRunScanCycle();
    }
    renderCurrentState();
    return true;
  }

  function renderCustomApTags() {
    elCustomApList.innerHTML = '';
    customAps.forEach(function (ap, idx) {
      const tag = document.createElement('span');
      tag.className = 'ap-tag';
      const lock = ap.secure ? '*' : '';
      tag.textContent = lock + ap.ssid + ' (c' + ui.twoDigit(ap.channel) + ' ' + ap.rssi + 'dB)';

      const rmBtn = document.createElement('button');
      rmBtn.type = 'button';
      rmBtn.textContent = '\u00d7';
      rmBtn.title = 'Stop broadcasting ' + ap.ssid;
      rmBtn.setAttribute('aria-label', 'Stop broadcasting ' + ap.ssid);
      rmBtn.addEventListener('click', function () {
        customAps.splice(idx, 1);
        renderCustomApTags();
        if (!gState.isScanning) {
          gState = logic.reduce(gState, { type: 'ButtonBPressed', nowMs: nowMs() });
          checkAndRunScanCycle();
        }
      });

      tag.appendChild(rmBtn);
      elCustomApList.appendChild(tag);
    });
  }

  function injectCustomAp(ssidRaw, rssiVal, chVal, isSecure) {
    const cleanSsid = window.ZD.wifiAnalysis.sanitizePrintable(ssidRaw);
    const rssi = fp.clampVal(Math.trunc(Number(rssiVal) || -45), -95, -28);
    const channel = fp.clampVal(Math.trunc(Number(chVal) || 6), 1, 13);
    customAps.unshift({
      ssid: cleanSsid === '<hidden>' && String(ssidRaw).trim() !== '' ? 'Custom_AP' : cleanSsid,
      rssi,
      channel,
      secure: Boolean(isSecure),
      enabled: true
    });
    if (customAps.length > 8) {
      customAps.pop();
    }
    renderCustomApTags();
    appendLog(
      'BEACON_TX',
      'Broadcasting virtual SSID "' +
        customAps[0].ssid +
        '" on CH ' +
        channel +
        ' (' +
        rssi +
        ' dBm)',
      'log-cmd'
    );
    if (!gState.isScanning) {
      gState = logic.reduce(gState, { type: 'ButtonBPressed', nowMs: nowMs() });
      checkAndRunScanCycle();
    }
    renderCurrentState();
  }

  // --- Non-Blocking Simulated Scan Loop ---
  function checkAndRunScanCycle() {
    const t = nowMs();

    if (gState.isScanning && t >= scanFinishAtMs) {
      const snap = sim.generateAirwaveSnapshot(activeEnv, customAps, simSeed, t);
      simSeed = snap.nextSeed;
      gState = logic.reduce(gState, {
        type: 'ScanCompleted',
        nowMs: t,
        rawNetworks: snap.networks
      });
      if (sim.generateBleSnapshot) {
        const bleSnap = sim.generateBleSnapshot(activeEnv, simSeed, t);
        simSeed = bleSnap.nextSeed;
        gState = logic.reduce(gState, {
          type: 'BleScanCompleted',
          nowMs: t,
          devices: bleSnap.devices
        });
      }
      savePref('hiscore', gState.highScore);
      buzzer.scanDone(gState.latestScan.totalAps);
      logSerialStatus(gState.latestScan.totalAps > 0 ? 'SCAN_DONE' : 'SCAN_EMPTY');
    }

    if (logic.shouldTriggerScan(gState, t)) {
      gState = logic.reduce(gState, { type: 'ScanStarted', nowMs: t });
      scanFinishAtMs = t + 1350; // ~3 cute left/right eye sweeps
      logSerialStatus('SCAN_START');
    }
  }

  // --- Wire Hardware Buttons (including 700ms Long-Press on Button B) ---
  elHwBtnA.addEventListener('click', function (ev) {
    if (ev && ev.shiftKey) {
      gState = logic.reduce(gState, { type: 'CyclePage', nowMs: nowMs(), step: -1 });
      buzzer.clickA();
      logSerialStatus('BTN_A');
      announceSr('View switched to ' + gState.page);
      renderCurrentState(true);
    } else {
      triggerButtonA();
    }
  });

  let btnBDownAt = 0;
  let btnBLongFired = false;
  let btnBHoldTimer = null;
  let suppressNextBtnBClick = false;

  function clearBtnBHold() {
    btnBDownAt = 0;
    elHwBtnB.classList.remove('pressed');
    elBtnBProgress.style.width = '0%';
    if (btnBHoldTimer) {
      clearInterval(btnBHoldTimer);
      btnBHoldTimer = null;
    }
  }

  elHwBtnB.addEventListener('pointerdown', function (ev) {
    if (ev.button !== undefined && ev.button !== 0) return;
    suppressNextBtnBClick = false;
    btnBDownAt = performance.now();
    btnBLongFired = false;
    elHwBtnB.classList.add('pressed');
    elBtnBProgress.style.width = '0%';

    if (btnBHoldTimer) clearInterval(btnBHoldTimer);
    btnBHoldTimer = setInterval(function () {
      if (!btnBDownAt) return;
      const held = performance.now() - btnBDownAt;
      const pct = Math.min(100, Math.round((held / 700) * 100));
      elBtnBProgress.style.width = pct + '%';
      if (held >= 700 && !btnBLongFired) {
        btnBLongFired = true;
        suppressNextBtnBClick = true;
        clearBtnBHold();
        triggerThemeCycle();
      }
    }, 30);
  });

  window.addEventListener('pointerup', function () {
    if (!btnBDownAt) return;
    const wasLong = btnBLongFired;
    suppressNextBtnBClick = true;
    setTimeout(function () {
      suppressNextBtnBClick = false;
    }, 120);
    clearBtnBHold();
    if (!wasLong) {
      triggerButtonBShort();
    }
  });
  window.addEventListener('pointercancel', clearBtnBHold);

  // Native click path handles keyboard activation and assistive-technology synthetic clicks.
  elHwBtnB.addEventListener('click', function () {
    if (suppressNextBtnBClick) {
      suppressNextBtnBClick = false;
      return;
    }
    triggerButtonBShort();
  });

  // Shift+Enter / Shift+Space on Hardware Button B alternates to Theme Cycle.
  elHwBtnB.addEventListener('keydown', function (ev) {
    if (ev.shiftKey && (ev.key === 'Enter' || ev.key === ' ')) {
      ev.preventDefault();
      triggerThemeCycle(+1);
    }
  });

  // --- Direct LCD Screen Touch / Boop (mouse convenience; keyboard uses #act-boop or K) ---
  elViewport.addEventListener('click', function (ev) {
    const rect = elScreen.getBoundingClientRect();
    const d = currentDims();
    const lx = ((ev.clientX - rect.left) / rect.width) * d.width;
    const ly = ((ev.clientY - rect.top) / rect.height) * d.height;
    const headerH = d.width < 150 || d.height < 72 ? 10 : d.width < 200 || d.height < 100 ? 12 : 17;

    if (ly <= headerH) {
      if (lx >= d.width * 0.72) {
        triggerModeCycle();
      } else {
        triggerThemeCycle(ev.shiftKey ? -1 : +1);
      }
      return;
    }

    // Clicking bottom status bar triggers [A] or [B]
    if (ly >= d.height - (d.width < 200 ? 14 : 18)) {
      if (lx > d.width * 0.72) {
        triggerButtonBShort();
      } else {
        triggerButtonA();
      }
      return;
    }

    // Clicking ZeroDay's centered mascot on PetFace page boops the pet!
    if (gState.page === logic.ScreenPage.PetFace && lx >= d.width * 0.25 && lx <= d.width * 0.75) {
      triggerPetBoop();
    } else {
      triggerButtonA();
    }
  });

  // --- Toolbar & Companion Controls ---
  elSelectRes.value = displayMode;
  elSelectRes.addEventListener('change', function () {
    const prof = ui.screenProfileFromKey(elSelectRes.value) || ui.screenProfileFromKey('plus');
    displayMode = prof.key;
    savePref('res', displayMode);
    appendLog('DISPLAY', 'Switched profile -> ' + prof.label);
    renderCurrentState();
  });

  const VALID_SHELLS = ['orange', 'stealth', 'paper', 'atomic'];
  const rawShell = loadPref('shell', 'orange');
  const savedShell = VALID_SHELLS.indexOf(rawShell) >= 0 ? rawShell : 'orange';
  document.body.setAttribute('data-shell', savedShell);
  elSelectShell.value = savedShell;
  elSelectShell.addEventListener('change', function () {
    const val = VALID_SHELLS.indexOf(elSelectShell.value) >= 0 ? elSelectShell.value : 'orange';
    document.body.setAttribute('data-shell', val);
    savePref('shell', val);
  });

  const VALID_FX = ['grid', 'crt', 'clean'];
  const rawFx = loadPref('fx', 'grid');
  const savedFx = VALID_FX.indexOf(rawFx) >= 0 ? rawFx : 'grid';
  elViewport.setAttribute('data-fx', savedFx);
  elSelectFx.value = savedFx;
  elSelectFx.addEventListener('change', function () {
    const val = VALID_FX.indexOf(elSelectFx.value) >= 0 ? elSelectFx.value : 'grid';
    elViewport.setAttribute('data-fx', val);
    savePref('fx', val);
  });

  syncMotionUi();
  if (motionQuery && motionQuery.addEventListener) {
    motionQuery.addEventListener('change', function (ev) {
      systemReducedMotion = Boolean(ev.matches);
      syncMotionUi();
      renderCurrentState(true);
    });
  }
  if (elBtnMotion) {
    elBtnMotion.addEventListener('click', function () {
      userMotionEnabled = !userMotionEnabled;
      savePref('motion', userMotionEnabled ? 'on' : 'off');
      syncMotionUi();
      announceSr('Screen motion ' + (isAnimationsPaused() ? 'paused' : 'enabled'));
      renderCurrentState(true);
    });
  }

  if (elBtnHotkeys) {
    elBtnHotkeys.textContent = hotkeysEnabled ? 'KEYS: ON' : 'KEYS: OFF';
    elBtnHotkeys.classList.toggle('active', hotkeysEnabled);
    elBtnHotkeys.setAttribute('aria-pressed', String(hotkeysEnabled));
    elBtnHotkeys.addEventListener('click', function () {
      hotkeysEnabled = !hotkeysEnabled;
      savePref('hotkeys', hotkeysEnabled ? 'on' : 'off');
      elBtnHotkeys.textContent = hotkeysEnabled ? 'KEYS: ON' : 'KEYS: OFF';
      elBtnHotkeys.classList.toggle('active', hotkeysEnabled);
      elBtnHotkeys.setAttribute('aria-pressed', String(hotkeysEnabled));
      announceSr('Single-key shortcuts ' + (hotkeysEnabled ? 'enabled' : 'disabled'));
    });
  }

  elBtnSfx.addEventListener('click', function () {
    const on = buzzer.toggle();
    elBtnSfx.textContent = on ? 'SFX: ON' : 'SFX: OFF';
    elBtnSfx.classList.toggle('active', on);
    elBtnSfx.setAttribute('aria-pressed', String(on));
  });

  elBtnSnapPng.addEventListener('click', function () {
    renderCurrentState(true);
    const link = document.createElement('a');
    link.download = 'pwnagotchi-' + gState.petName + '.png';
    link.href = elScreen.toDataURL('image/png');
    link.click();
    appendLog('SNAPSHOT', 'Saved crisp pixel PNG -> ' + link.download, 'log-cmd');
  });

  let copyResetTimer = null;
  function copyAsciiFrameToClipboard() {
    const d = currentDims();
    const frame = ui.buildUiFrame(gState, { width: d.width, height: d.height });
    const ascii = ui.renderAsciiPreview(frame);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(ascii)
        .then(function () {
          elBtnCopyAscii.textContent = 'Copied!';
          announceSr('ASCII frame copied to clipboard');
          if (copyResetTimer) clearTimeout(copyResetTimer);
          copyResetTimer = setTimeout(function () {
            elBtnCopyAscii.textContent = 'Copy ASCII';
            copyResetTimer = null;
          }, 1200);
        })
        .catch(function () {
          appendLog('CLIPBOARD', 'Clipboard unavailable; ASCII frame printed below.', 'log-warn');
        });
    }
    appendLog('ASCII_FRAME', '\n' + ascii.trimEnd());
  }

  elBtnCopyAscii.addEventListener('click', copyAsciiFrameToClipboard);
  elBtnTermAscii.addEventListener('click', copyAsciiFrameToClipboard);

  function buildPermalinkHash() {
    if (typeof URLSearchParams === 'undefined') {
      return '';
    }
    const p = new URLSearchParams();
    p.set('theme', themes.themeSpec(gState.theme).key);
    p.set('page', gState.page);
    p.set('mode', gState.opsMode);
    p.set('res', displayMode);
    p.set('env', activeEnv);
    p.set('subghz', String(gState.subGhzFreqKhz));
    if (elSelectShell && elSelectShell.value) {
      p.set('shell', elSelectShell.value);
    }
    return '#' + p.toString();
  }

  let shareResetTimer = null;
  function copyShareLink() {
    const hash = buildPermalinkHash();
    if (window.location) {
      if (window.history && typeof window.history.replaceState === 'function') {
        window.history.replaceState(null, '', hash);
      } else {
        window.location.hash = hash;
      }
    }
    const url = window.location && window.location.href ? window.location.href : hash;
    if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(function () {
        if (elBtnShareLink) {
          elBtnShareLink.textContent = 'Copied Link!';
          if (shareResetTimer) clearTimeout(shareResetTimer);
          shareResetTimer = setTimeout(function () {
            elBtnShareLink.textContent = 'Share Link';
            shareResetTimer = null;
          }, 1200);
        }
      }).catch(function () {});
    }
    appendLog('LINK', 'Permalink -> ' + url, 'log-cmd');
  }

  if (elBtnShareLink) {
    elBtnShareLink.addEventListener('click', copyShareLink);
  }

  function applyPermalinkHash() {
    if (!window.location || typeof window.location.hash !== 'string' || window.location.hash.length <= 1 ||
        typeof URLSearchParams === 'undefined') {
      return;
    }
    const params = new URLSearchParams(window.location.hash.slice(1));
    const tKey = params.get('theme');
    if (tKey) {
      const tid = themes.themeFromKey(tKey);
      if (tid) {
        gState = logic.reduce(gState, { type: 'SetTheme', nowMs: nowMs(), theme: tid, announce: false });
      }
    }
    const pg = params.get('page') || params.get('view');
    if (pg) {
      const pageMap = {
        '1': logic.ScreenPage.PetFace, petface: logic.ScreenPage.PetFace,
        '2': logic.ScreenPage.NearbyRadar, nearbyradar: logic.ScreenPage.NearbyRadar, radar: logic.ScreenPage.NearbyRadar,
        '3': logic.ScreenPage.ChannelSpectrum, channelspectrum: logic.ScreenPage.ChannelSpectrum, spectrum: logic.ScreenPage.ChannelSpectrum,
        '4': logic.ScreenPage.RfGuard, rfguard: logic.ScreenPage.RfGuard, guard: logic.ScreenPage.RfGuard
      };
      const resolved = pageMap[pg.toLowerCase()];
      if (resolved) {
        gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: resolved });
      }
    }
    const md = params.get('mode');
    if (md) {
      const mLower = md.toLowerCase();
      const resolvedMode = mLower.startsWith('off') ? logic.OpsMode.Offensive
        : (mLower.startsWith('def') ? logic.OpsMode.Defensive
        : (mLower.startsWith('rec') ? logic.OpsMode.Recon : null));
      if (resolvedMode) {
        gState = logic.reduce(gState, { type: 'SetOpsMode', nowMs: nowMs(), mode: resolvedMode });
      }
    }
    const resKey = params.get('res') || params.get('size');
    if (resKey && ui.screenProfileFromKey(resKey)) {
      displayMode = resKey;
      elSelectRes.value = resKey;
    }
    const envKey = params.get('env');
    if (envKey && sim.PRESETS[envKey]) {
      activeEnv = envKey;
    }
    const subghz = params.get('subghz');
    if (subghz) {
      const fKhz = parseInt(subghz, 10);
      if (fKhz >= 300000 && fKhz <= 928000) {
        gState = logic.reduce(gState, { type: 'SetSubGhzFreq', nowMs: nowMs(), freqKhz: fKhz });
      }
    }
    const sh = params.get('shell');
    if (sh && VALID_SHELLS.indexOf(sh) >= 0) {
      document.body.setAttribute('data-shell', sh);
      elSelectShell.value = sh;
    }
  }

  // Page & Theme quick buttons
  document.querySelectorAll('[data-page]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      gState = logic.reduce(gState, {
        type: 'SetPage',
        nowMs: nowMs(),
        page: btn.getAttribute('data-page')
      });
      buzzer.clickA();
      renderCurrentState();
    });
  });

  // Build theme swatches dynamically from the single-source-of-truth THEME_CATALOG
  if (elSwatchRow) {
    elSwatchRow.innerHTML = '';
    themes.THEME_CATALOG.forEach(function (spec, idx) {
      const sw = document.createElement('button');
      sw.type = 'button';
      const isInitialActive = spec.id === gState.theme;
      sw.className = 'theme-swatch' + (isInitialActive ? ' active' : '');
      sw.setAttribute('data-theme', spec.id);
      sw.setAttribute('aria-pressed', String(isInitialActive));
      sw.style.background =
        'linear-gradient(135deg, ' +
        spec.palette.bg.hex +
        ' 46%, ' +
        spec.palette.fg.hex +
        ' 46%, ' +
        spec.palette.fg.hex +
        ' 76%, ' +
        spec.palette.accent.hex +
        ' 76%)';
      sw.title =
        (idx + 1) + '/' + themes.THEME_COUNT + ' ' + spec.name + ' [' + spec.key + '] — ' + spec.blurb;
      sw.setAttribute('aria-label', spec.name);
      sw.addEventListener('click', function () {
        gState = logic.reduce(gState, {
          type: 'SetTheme',
          nowMs: nowMs(),
          theme: spec.id
        });
        persistCurrentTheme();
        buzzer.themeSwap();
        logSerialStatus('THEME');
        renderCurrentState();
      });
      elSwatchRow.appendChild(sw);
      cachedSwatches.push(sw);
    });
  }

  if (elBtnThemePrev) {
    elBtnThemePrev.addEventListener('click', function () {
      triggerThemeCycle(-1);
    });
  }
  if (elBtnThemeNext) {
    elBtnThemeNext.addEventListener('click', function () {
      triggerThemeCycle(+1);
    });
  }

  // Environment cards
  document.querySelectorAll('[data-env]').forEach(function (card) {
    card.addEventListener('click', function () {
      buzzer.clickA();
      switchEnvironment(card.getAttribute('data-env'));
    });
  });

  // Pet handle rename
  const savedName = loadPref('petName', '');
  if (savedName) {
    gState = logic.reduce(gState, { type: 'PetRenamed', nowMs: 0, petName: savedName });
    gState = Object.freeze(Object.assign({}, gState, { phrase: 'Hello world! Ready to scan.' }));
  }
  const savedTheme = loadPref('theme', '');
  const resolvedBootTheme = themes.themeFromKey(savedTheme);
  if (resolvedBootTheme) {
    gState = logic.reduce(gState, {
      type: 'SetTheme',
      nowMs: 0,
      theme: resolvedBootTheme,
      announce: false
    });
  }
  const savedHi = Math.max(0, Math.trunc(Number(loadPref('hiscore', '0')) || 0));
  if (savedHi > 0) {
    gState = logic.reduce(gState, { type: 'SetHighScore', nowMs: 0, highScore: savedHi, xp: 0 });
  }

  const SUBGHZ_BANDS = [315000, 433920, 868350, 915000];
  function triggerModeCycle() {
    gState = logic.reduce(gState, { type: 'CycleOpsMode', nowMs: nowMs() });
    buzzer.clickA();
    logSerialStatus('MODE', 'log-cmd');
    renderCurrentState(true);
  }

  function triggerSubGhzCycle() {
    const idx = SUBGHZ_BANDS.indexOf(gState.subGhzFreqKhz);
    const nextFreq = SUBGHZ_BANDS[(idx + 1) % SUBGHZ_BANDS.length];
    gState = logic.reduce(gState, { type: 'SetSubGhzFreq', nowMs: nowMs(), freqKhz: nextFreq });
    buzzer.clickB();
    logSerialStatus('SUBGHZ', 'log-cmd');
    renderCurrentState(true);
  }

  function triggerGuardAlertSim() {
    const t = nowMs();
    if (sim.generateBleSnapshot) {
      const bleSnap = sim.generateBleSnapshot('con', simSeed, t);
      simSeed = bleSnap.nextSeed;
      gState = logic.reduce(gState, { type: 'BleScanCompleted', nowMs: t, devices: bleSnap.devices });
    }
    if (sim.generateSubGhzEvent) {
      const subSnap = sim.generateSubGhzEvent('con', gState.subGhzFreqKhz, simSeed);
      simSeed = subSnap.nextSeed;
      gState = logic.reduce(gState, { type: 'SubGhzObserved', nowMs: t, signal: subSnap.signal });
    }
    persistHighScore();
    buzzer.peer();
    spawnFloatingGlyphs(['!ALERT', 'BLE', 'SUBGHZ'], '#ff5ca8');
    logSerialStatus('GUARD_ALERT', 'log-warn');
    renderCurrentState(true);
  }

  elPetNameInput.addEventListener('change', function () {
    gState = logic.reduce(gState, {
      type: 'PetRenamed',
      nowMs: nowMs(),
      petName: elPetNameInput.value
    });
    savePref('petName', gState.petName);
    logSerialStatus('RENAME', 'log-cmd');
    renderCurrentState();
  });

  // Toy buttons
  elActSnack.addEventListener('click', function () {
    triggerFeedSnack();
    persistHighScore();
  });
  elActPwn.addEventListener('click', function () {
    triggerToyHandshake();
    persistHighScore();
  });
  elActPeer.addEventListener('click', function () {
    triggerPeerEncounter();
    persistHighScore();
  });
  elActScan.addEventListener('click', triggerButtonBShort);
  if (elActMode) {
    elActMode.addEventListener('click', triggerModeCycle);
  }
  if (elActSubGhz) {
    elActSubGhz.addEventListener('click', triggerSubGhzCycle);
  }
  if (elActGuard) {
    elActGuard.addEventListener('click', triggerGuardAlertSim);
  }
  if (elActBoop) {
    elActBoop.addEventListener('click', function () {
      triggerPetBoop();
      persistHighScore();
    });
  }

  // Battery controls & optional browser Battery API bridge
  elInputBat.addEventListener('input', function () {
    manualPowerOverride = true;
    batteryLevel = Number(elInputBat.value);
    elBatVal.textContent = batteryLevel + '%';
  });

  elInputChg.addEventListener('change', function () {
    manualPowerOverride = true;
    batteryCharging = elInputChg.checked;
  });

  if (navigator.getBattery) {
    navigator
      .getBattery()
      .then(function (bat) {
        function syncHostBat() {
          if (manualPowerOverride) return;
          batteryLevel = Math.round(bat.level * 100);
          batteryCharging = Boolean(bat.charging);
          elInputBat.value = String(batteryLevel);
          elBatVal.textContent = batteryLevel + '%';
          elInputChg.checked = batteryCharging;
        }
        syncHostBat();
        bat.addEventListener('levelchange', syncHostBat);
        bat.addEventListener('chargingchange', syncHostBat);
      })
      .catch(function () {});
  }

  // Custom Beacon Injector Form
  elInputApRssi.addEventListener('input', function () {
    elApRssiLabel.textContent = elInputApRssi.value + 'dB';
  });

  elBtnRandSsid.addEventListener('click', function () {
    const rolled = sim.randomHackerBeacon(simSeed);
    simSeed = rolled.nextSeed;
    elInputSsid.value = rolled.beacon.ssid;
    elInputApCh.value = String(rolled.beacon.channel);
    elInputApRssi.value = String(rolled.beacon.rssi);
    elApRssiLabel.textContent = rolled.beacon.rssi + 'dB';
    elInputApSec.checked = rolled.beacon.secure;
  });

  elFormBeacon.addEventListener('submit', function (ev) {
    ev.preventDefault();
    let ssid = elInputSsid.value.trim();
    if (!ssid) {
      const rolled = sim.randomHackerBeacon(simSeed);
      simSeed = rolled.nextSeed;
      ssid = rolled.beacon.ssid;
    }
    injectCustomAp(ssid, elInputApRssi.value, elInputApCh.value, elInputApSec.checked);
    elInputSsid.value = '';
  });

  elBtnClearAps.addEventListener('click', function () {
    customAps = [];
    renderCustomApTags();
    appendLog('BEACON_TX', 'Cleared all custom fake beacons.');
    if (!gState.isScanning) {
      gState = logic.reduce(gState, { type: 'ButtonBPressed', nowMs: nowMs() });
      checkAndRunScanCycle();
    }
  });

  // --- Interactive /dev/ttyACM0 Terminal Shell ---
  const cmdHistory = [];
  let cmdHistIdx = -1;

  function runTerminalCommand(rawLine) {
    const trimmed = rawLine.trim();
    if (!trimmed) return;

    appendLog('SHELL', '$ ' + trimmed, 'log-cmd');
    const parts = trimmed.split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const arg1 = parts[1] || '';

    switch (cmd) {
      case 'help':
      case '?':
        appendLog(
          'HELP',
          'Commands: scan | view [next|prev|1-4] | mode [recon|defense|offense] | subghz [next|315|433|868|915] | ble | ack | guard | link | theme [next|prev|<key>] | themes | score | size <micro|compact|plus|epaper|wide> | env <cafe|con|lab|roam|quiet|bunker> | pwn | peer [name] | snack | boop | name <handle> | inject <ssid> [rssi] [ch] | ascii | status | clear'
        );
        break;

      case 'ack':
      case 'clear-threat':
        gState = logic.reduce(gState, { type: 'ClearThreat', nowMs: nowMs() });
        appendLog('ACK', 'Cleared active threat alert.');
        renderCurrentState(true);
        break;

      case 'link':
        copyShareLink();
        break;

      case 'mode': {
        const sub = arg1.toLowerCase();
        if (!sub || sub === 'next') {
          triggerModeCycle();
        } else if (sub === 'recon' || sub === 'rcn') {
          gState = logic.reduce(gState, { type: 'SetOpsMode', nowMs: nowMs(), mode: logic.OpsMode.Recon });
          renderCurrentState(true);
        } else if (sub === 'def' || sub === 'defense' || sub === 'defensive') {
          gState = logic.reduce(gState, { type: 'SetOpsMode', nowMs: nowMs(), mode: logic.OpsMode.Defensive });
          renderCurrentState(true);
        } else if (sub === 'off' || sub === 'offense' || sub === 'offensive') {
          gState = logic.reduce(gState, { type: 'SetOpsMode', nowMs: nowMs(), mode: logic.OpsMode.Offensive });
          renderCurrentState(true);
        } else {
          appendLog('ERR', 'Usage: mode [next|recon|defense|offense]', 'log-warn');
        }
        break;
      }

      case 'subghz': {
        if (arg1 === '315') gState = logic.reduce(gState, { type: 'SetSubGhzFreq', nowMs: nowMs(), freqKhz: 315000 });
        else if (arg1 === '433' || arg1 === '433.92') gState = logic.reduce(gState, { type: 'SetSubGhzFreq', nowMs: nowMs(), freqKhz: 433920 });
        else if (arg1 === '868' || arg1 === '868.35') gState = logic.reduce(gState, { type: 'SetSubGhzFreq', nowMs: nowMs(), freqKhz: 868350 });
        else if (arg1 === '915') gState = logic.reduce(gState, { type: 'SetSubGhzFreq', nowMs: nowMs(), freqKhz: 915000 });
        else triggerSubGhzCycle();
        renderCurrentState(true);
        break;
      }

      case 'guard':
      case 'tracker':
        triggerGuardAlertSim();
        break;

      case 'scan':
        triggerButtonBShort();
        break;

      case '1':
        gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.PetFace });
        buzzer.clickA();
        renderCurrentState(true);
        break;

      case '2':
        gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.NearbyRadar });
        buzzer.clickA();
        renderCurrentState(true);
        break;

      case '3':
        gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.ChannelSpectrum });
        buzzer.clickA();
        renderCurrentState(true);
        break;

      case '4':
        gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.RfGuard });
        buzzer.clickA();
        renderCurrentState(true);
        break;

      case 'ble':
        appendLog(
          'BLE',
          'BLE Devices: ' + (gState.bleDevices ? gState.bleDevices.length : 0) +
          ' | Threats: ' + (gState.threatsDetected || 0)
        );
        break;

      case 'score':
      case 'level': {
        const lvl = logic.deriveLevelInfo(gState.xp);
        appendLog(
          'SCORE',
          'Lv.' + lvl.level + ' ' + lvl.title + ' | XP:' + lvl.xp + ' | HighScore:' + (gState.highScore || 0)
        );
        break;
      }

      case 'view':
      case 'page': {
        const sub = arg1.toLowerCase();
        if (sub === 'prev' || sub === 'back' || sub === '-') {
          gState = logic.reduce(gState, { type: 'CyclePage', nowMs: nowMs(), step: -1 });
          buzzer.clickA();
          logSerialStatus('BTN_A');
          renderCurrentState(true);
        } else if (sub === '1' || sub === 'face') {
          gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.PetFace });
          buzzer.clickA();
          renderCurrentState(true);
        } else if (sub === '2' || sub === 'radar') {
          gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.NearbyRadar });
          buzzer.clickA();
          renderCurrentState(true);
        } else if (sub === '3' || sub === 'spectrum') {
          gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.ChannelSpectrum });
          buzzer.clickA();
          renderCurrentState(true);
        } else if (sub === '4' || sub === 'guard' || sub === 'rf') {
          gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.RfGuard });
          buzzer.clickA();
          renderCurrentState(true);
        } else {
          triggerButtonA();
        }
        break;
      }

      case 'themes': {
        const rows = themes.THEME_CATALOG.map(function (t) {
          const mark = t.id === gState.theme ? '*' : ' ';
          return mark + ' ' + t.key.padEnd(9, ' ') + ' ' + t.name.padEnd(12, ' ') + ' — ' + t.blurb;
        });
        appendLog('THEMES', '\n' + rows.join('\n'), 'log-cmd');
        break;
      }

      case 'theme': {
        const sub = arg1.toLowerCase();
        if (!sub || sub === 'next' || sub === '+') {
          triggerThemeCycle(+1);
        } else if (sub === 'prev' || sub === 'back' || sub === '-') {
          triggerThemeCycle(-1);
        } else {
          const target = themes.themeFromKey(sub);
          if (target) {
            gState = logic.reduce(gState, {
              type: 'SetTheme',
              nowMs: nowMs(),
              theme: target
            });
            persistCurrentTheme();
            buzzer.themeSwap();
            logSerialStatus('THEME');
            renderCurrentState();
          } else {
            appendLog(
              'ERR',
              'Unknown theme "' +
                arg1 +
                '". Keys: ' +
                themes.THEME_CATALOG.map(function (t) {
                  return t.key;
                }).join(', '),
              'log-warn'
            );
          }
        }
        break;
      }

      case 'size':
      case 'res': {
        const prof = ui.screenProfileFromKey(arg1.toLowerCase());
        if (prof) {
          displayMode = prof.key;
          elSelectRes.value = displayMode;
          savePref('res', displayMode);
          appendLog('DISPLAY', 'Switched profile -> ' + prof.label);
          renderCurrentState();
        } else {
          appendLog('ERR', 'Choose size: micro, compact, plus, epaper, wide', 'log-warn');
        }
        break;
      }

      case 'env':
        if (!switchEnvironment(arg1.toLowerCase())) {
          appendLog('ERR', 'Choose env: cafe, con, lab, roam, quiet, bunker', 'log-warn');
        }
        break;

      case 'pwn':
      case 'handshake':
        triggerToyHandshake();
        break;

      case 'peer':
      case 'fren':
        triggerPeerEncounter(arg1);
        break;

      case 'snack':
      case 'feed':
      case 'cookie':
        triggerFeedSnack();
        break;

      case 'pet':
      case 'boop':
      case 'poke':
        triggerPetBoop();
        break;

      case 'name':
        if (!arg1) {
          appendLog('ERR', 'Usage: name <new_handle>', 'log-warn');
        } else {
          gState = logic.reduce(gState, { type: 'PetRenamed', nowMs: nowMs(), petName: arg1 });
          savePref('petName', gState.petName);
          renderCurrentState();
        }
        break;

      case 'inject':
        if (!arg1) {
          appendLog('ERR', 'Usage: inject <ssid> [rssi=-44] [ch=6] [open|wpa2]', 'log-warn');
        } else {
          const rssi = parts[2] ? Number(parts[2]) : -44;
          const ch = parts[3] ? Number(parts[3]) : 6;
          const sec = (parts[4] || 'wpa2').toLowerCase() !== 'open';
          injectCustomAp(arg1, rssi, ch, sec);
        }
        break;

      case 'ascii':
        copyAsciiFrameToClipboard();
        break;

      case 'status':
      case 'whoami': {
        const lvl = logic.deriveLevelInfo(gState.xp);
        appendLog(
          'STATUS',
          gState.petName +
            ' | Lv.' +
            lvl.level +
            ' ' +
            lvl.title +
            ' (' +
            lvl.xp +
            ' XP) | Scans:' +
            gState.completedScans +
            ' | ToyPwns:' +
            gState.toyHandshakes +
            ' | Peers:' +
            gState.peersMet
        );
        break;
      }

      case 'clear':
        elTermLog.innerHTML = '';
        break;

      default:
        appendLog('ERR', 'Unknown command "' + cmd + '". Type "help" for options.', 'log-warn');
        break;
    }
  }

  elFormTerm.addEventListener('submit', function (ev) {
    ev.preventDefault();
    const val = elInputTerm.value;
    if (val.trim()) {
      cmdHistory.unshift(val);
      if (cmdHistory.length > 40) cmdHistory.pop();
    }
    cmdHistIdx = -1;
    elInputTerm.value = '';
    runTerminalCommand(val);
  });

  elInputTerm.addEventListener('keydown', function (ev) {
    if (ev.key === 'ArrowUp') {
      ev.preventDefault();
      if (cmdHistIdx + 1 < cmdHistory.length) {
        cmdHistIdx++;
        elInputTerm.value = cmdHistory[cmdHistIdx];
      }
    } else if (ev.key === 'ArrowDown') {
      ev.preventDefault();
      if (cmdHistIdx > 0) {
        cmdHistIdx--;
        elInputTerm.value = cmdHistory[cmdHistIdx];
      } else {
        cmdHistIdx = -1;
        elInputTerm.value = '';
      }
    }
  });

  // --- Global Hardware Keyboard Shortcuts (toggleable for WCAG 2.1.4) ---
  window.addEventListener('keydown', function (ev) {
    if (!hotkeysEnabled) return;
    if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
    const tag = ev.target && ev.target.tagName ? ev.target.tagName.toLowerCase() : '';
    if (tag === 'input' || tag === 'textarea' || tag === 'select') return;

    const k = ev.key.toLowerCase();
    if (k === 'a') {
      ev.preventDefault();
      elHwBtnA.classList.add('pressed');
      setTimeout(function () {
        elHwBtnA.classList.remove('pressed');
      }, 120);
      if (ev.shiftKey) {
        gState = logic.reduce(gState, { type: 'CyclePage', nowMs: nowMs(), step: -1 });
        buzzer.clickA();
        logSerialStatus('BTN_A');
        announceSr('View switched to ' + gState.page);
        renderCurrentState(true);
      } else {
        triggerButtonA();
      }
    } else if (k === 'b') {
      ev.preventDefault();
      triggerButtonBShort();
    } else if (k === 't') {
      ev.preventDefault();
      triggerThemeCycle(ev.shiftKey ? -1 : +1);
    } else if (ev.key === '[') {
      ev.preventDefault();
      triggerThemeCycle(-1);
    } else if (ev.key === ']') {
      ev.preventDefault();
      triggerThemeCycle(+1);
    } else if (k === '1') {
      ev.preventDefault();
      gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.PetFace });
      buzzer.clickA();
      renderCurrentState(true);
    } else if (k === '2') {
      ev.preventDefault();
      gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.NearbyRadar });
      buzzer.clickA();
      renderCurrentState(true);
    } else if (k === '3') {
      ev.preventDefault();
      gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.ChannelSpectrum });
      buzzer.clickA();
      renderCurrentState(true);
    } else if (k === '4') {
      ev.preventDefault();
      gState = logic.reduce(gState, { type: 'SetPage', nowMs: nowMs(), page: logic.ScreenPage.RfGuard });
      buzzer.clickA();
      renderCurrentState(true);
    } else if (k === 'f') {
      ev.preventDefault();
      triggerFeedSnack();
    } else if (k === 'h') {
      ev.preventDefault();
      triggerToyHandshake();
    } else if (k === 'p') {
      ev.preventDefault();
      triggerPeerEncounter();
    } else if (k === 'k') {
      ev.preventDefault();
      triggerPetBoop();
    } else if (k === 'm') {
      ev.preventDefault();
      triggerModeCycle();
    } else if (k === 'g') {
      ev.preventDefault();
      triggerGuardAlertSim();
    } else if (k === 'c') {
      ev.preventDefault();
      triggerSubGhzCycle();
    }
  });

  // --- Visibility-Gated Animation Loop (~16.7 FPS active, zero wakeups when tab hidden) ---
  applyPermalinkHash();
  logSerialStatus('BOOT');
  appendLog(
    'WEB_TOY',
    'Welcome to pwnagotchi-zeroday Web! Click [A], press [B] to scan, or type "help" below.',
    'log-cmd'
  );
  renderCurrentState(true);

  if (navigator && navigator.serviceWorker && window.location &&
      (window.location.protocol === 'https:' || window.location.hostname === 'localhost' ||
       window.location.hostname === '127.0.0.1')) {
    navigator.serviceWorker.register('./sw.js').catch(function () {});
  }

  let lastFrameAt = 0;
  let rafId = 0;
  function stepLoop(ts) {
    rafId = 0;
    if (document.hidden) {
      return;
    }
    if (ts - lastFrameAt >= 60) {
      lastFrameAt = ts;
      const t = nowMs();
      checkAndRunScanCycle();
      gState = logic.reduce(gState, {
        type: 'Tick',
        nowMs: t,
        batteryPercent: batteryLevel,
        isCharging: batteryCharging
      });
      renderCurrentState(false);
    }
    rafId = window.requestAnimationFrame(stepLoop);
  }

  document.addEventListener('visibilitychange', function () {
    if (document.hidden) {
      if (rafId) {
        window.cancelAnimationFrame(rafId);
        rafId = 0;
      }
    } else {
      lastFrameAt = 0;
      renderCurrentState(true);
      if (!rafId) {
        rafId = window.requestAnimationFrame(stepLoop);
      }
    }
  });

  if (!document.hidden) {
    rafId = window.requestAnimationFrame(stepLoop);
  }
})();
