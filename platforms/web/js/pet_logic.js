// Pure domain state, Pwnagotchi moods/faces, phrase PRNG & reducer
// (ported from core/include/zd/domain.hpp & core/include/zd/pet_logic.hpp + playful hacker toy extensions).
(function (root) {
  'use strict';

  const fp = (root.ZD && root.ZD.fp) || (typeof require === 'function' ? require('./fp.js') : null);
  const wifi =
    (root.ZD && root.ZD.wifiAnalysis) ||
    (typeof require === 'function' ? require('./wifi_analysis.js') : null);
  const themes =
    (root.ZD && root.ZD.themes) ||
    (typeof require === 'function' ? require('./themes.js') : null);

  const OpsMode = Object.freeze({
    Recon: 'Recon',
    Defensive: 'Defensive',
    Offensive: 'Offensive'
  });

  function opsModeLabel(mode, compact) {
    switch (mode) {
      case OpsMode.Defensive: return compact ? 'DEF' : 'DEFENSE';
      case OpsMode.Offensive: return compact ? 'OFF' : 'OFFENSE';
      default: return compact ? 'RCN' : 'RECON';
    }
  }

  function cycleOpsMode(current) {
    if (current === OpsMode.Recon) return OpsMode.Defensive;
    if (current === OpsMode.Defensive) return OpsMode.Offensive;
    return OpsMode.Recon;
  }

  const Mood = Object.freeze({
    Awake: 'Awake',
    LookingLeft: 'LookingLeft',
    LookingRight: 'LookingRight',
    Happy: 'Happy',
    Excited: 'Excited',
    Cool: 'Cool',
    Lonely: 'Lonely',
    Bored: 'Bored',
    Sleepy: 'Sleepy',
    Grateful: 'Grateful',
    Mischief: 'Mischief',
    ScanningDish: 'ScanningDish',
    CyberAttack: 'CyberAttack',
    ShieldGuard: 'ShieldGuard',
    ThreatAlert: 'ThreatAlert',
    LevelUp: 'LevelUp'
  });

  const ScreenPage = Object.freeze({
    PetFace: 'PetFace',
    NearbyRadar: 'NearbyRadar',
    ChannelSpectrum: 'ChannelSpectrum',
    RfGuard: 'RfGuard'
  });

  const ThemeId = themes.ThemeId;

  const EyeGlyph = Object.freeze({
    RoundCenter: 'RoundCenter',
    RoundLeft: 'RoundLeft',
    RoundRight: 'RoundRight',
    HappyArc: 'HappyArc',
    WideSparkle: 'WideSparkle',
    Sunglasses: 'Sunglasses',
    SadDroop: 'SadDroop',
    HalfLid: 'HalfLid',
    SleepingLine: 'SleepingLine',
    CyberWink: 'CyberWink',
    LaserVisor: 'LaserVisor',
    ShieldVisor: 'ShieldVisor',
    StarEyes: 'StarEyes',
    AlertRing: 'AlertRing'
  });

  const MouthGlyph = Object.freeze({
    DoubleSmile: 'DoubleSmile',
    BigGrin: 'BigGrin',
    Smirk: 'Smirk',
    FlatLine: 'FlatLine',
    SadWave: 'SadWave',
    Fangs: 'Fangs'
  });

  function faceForMood(mood) {
    switch (mood) {
      case Mood.Awake:
        return {
          eyes: EyeGlyph.RoundCenter,
          mouth: MouthGlyph.DoubleSmile,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '(o_o)',
          moodLabel: 'AWAKE'
        };
      case Mood.LookingLeft:
        return {
          eyes: EyeGlyph.RoundLeft,
          mouth: MouthGlyph.DoubleSmile,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '( o_o)',
          moodLabel: 'SCAN'
        };
      case Mood.LookingRight:
        return {
          eyes: EyeGlyph.RoundRight,
          mouth: MouthGlyph.DoubleSmile,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '(o_o )',
          moodLabel: 'SCAN'
        };
      case Mood.Happy:
        return {
          eyes: EyeGlyph.HappyArc,
          mouth: MouthGlyph.DoubleSmile,
          showBlush: true,
          showTear: false,
          showZzz: false,
          asciiFace: '(^_^)',
          moodLabel: 'HAPPY'
        };
      case Mood.Excited:
        return {
          eyes: EyeGlyph.WideSparkle,
          mouth: MouthGlyph.BigGrin,
          showBlush: true,
          showTear: false,
          showZzz: false,
          asciiFace: '(*O*)',
          moodLabel: 'HYPED'
        };
      case Mood.Cool:
        return {
          eyes: EyeGlyph.Sunglasses,
          mouth: MouthGlyph.Smirk,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '[B_B]',
          moodLabel: 'COOL'
        };
      case Mood.Lonely:
        return {
          eyes: EyeGlyph.SadDroop,
          mouth: MouthGlyph.SadWave,
          showBlush: false,
          showTear: true,
          showZzz: false,
          asciiFace: '(;_;)',
          moodLabel: 'LONELY'
        };
      case Mood.Bored:
        return {
          eyes: EyeGlyph.HalfLid,
          mouth: MouthGlyph.FlatLine,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '(._.)',
          moodLabel: 'BORED'
        };
      case Mood.Sleepy:
        return {
          eyes: EyeGlyph.SleepingLine,
          mouth: MouthGlyph.FlatLine,
          showBlush: false,
          showTear: false,
          showZzz: true,
          asciiFace: '(-_-)',
          moodLabel: 'SLEEPY'
        };
      case Mood.Grateful:
        return {
          eyes: EyeGlyph.HappyArc,
          mouth: MouthGlyph.BigGrin,
          showBlush: true,
          showTear: false,
          showZzz: false,
          asciiFace: '(^o^)',
          moodLabel: 'LUV!'
        };
      case Mood.Mischief:
        return {
          eyes: EyeGlyph.CyberWink,
          mouth: MouthGlyph.Fangs,
          showBlush: true,
          showTear: false,
          showZzz: false,
          asciiFace: '(>_*)',
          moodLabel: 'PWN!'
        };
      case Mood.ScanningDish:
        return {
          eyes: EyeGlyph.RoundLeft,
          mouth: MouthGlyph.FlatLine,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '((o_o))',
          moodLabel: 'DISH'
        };
      case Mood.CyberAttack:
        return {
          eyes: EyeGlyph.LaserVisor,
          mouth: MouthGlyph.Fangs,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '[>_<]',
          moodLabel: 'STRIKE'
        };
      case Mood.ShieldGuard:
        return {
          eyes: EyeGlyph.ShieldVisor,
          mouth: MouthGlyph.FlatLine,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '[O_O]',
          moodLabel: 'GUARD'
        };
      case Mood.ThreatAlert:
        return {
          eyes: EyeGlyph.AlertRing,
          mouth: MouthGlyph.SadWave,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '(!_!)',
          moodLabel: 'ALERT!'
        };
      case Mood.LevelUp:
        return {
          eyes: EyeGlyph.StarEyes,
          mouth: MouthGlyph.BigGrin,
          showBlush: true,
          showTear: false,
          showZzz: false,
          asciiFace: '(*v*)',
          moodLabel: 'LVL UP'
        };
      default:
        return {
          eyes: EyeGlyph.RoundCenter,
          mouth: MouthGlyph.DoubleSmile,
          showBlush: false,
          showTear: false,
          showZzz: false,
          asciiFace: '(o_o)',
          moodLabel: 'AWAKE'
        };
    }
  }

  const PAGE_ORDER = Object.freeze([
    ScreenPage.PetFace,
    ScreenPage.NearbyRadar,
    ScreenPage.ChannelSpectrum,
    ScreenPage.RfGuard
  ]);

  function cyclePage(current, step) {
    const n = PAGE_ORDER.length;
    const base = PAGE_ORDER.indexOf(current);
    const safeBase = base >= 0 ? base : 0;
    const delta = Math.trunc(Number(step) || 0);
    const idx = (((safeBase + (delta % n)) % n) + n) % n;
    return PAGE_ORDER[idx];
  }

  function nextPage(current) {
    return cyclePage(current, +1);
  }

  function prevPage(current) {
    return cyclePage(current, -1);
  }

  const cycleTheme = themes.cycleTheme;
  const nextTheme = themes.nextTheme;
  const prevTheme = themes.prevTheme;

  function deriveMoodFromScan(summary) {
    if (summary.totalAps === 0) {
      return Mood.Lonely;
    }
    if (summary.totalAps >= 10) {
      return Mood.Excited;
    }
    if (summary.strongestRssi >= -50) {
      return Mood.Cool;
    }
    if (summary.totalAps >= 3) {
      return Mood.Happy;
    }
    return Mood.Bored;
  }

  function selectPhrase(mood, scan, seed) {
    switch (mood) {
      case Mood.Awake: {
        const kPhrases = [
          'Antenna warm! Ready to explore.',
          'Listening to 2.4GHz airwaves...',
          'Press [A] for views, [B] to scan!',
          'ZeroDay awake and feeling curious.'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.LookingLeft:
      case Mood.LookingRight: {
        const kPhrases = [
          'Looking around the airwaves...',
          'Sweeping WiFi channels 1 to 13...',
          'Counting nearby WiFi beacons...',
          'Scanning... anyone broadcasting?'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.Happy: {
        const s1 = fp.nextSeed(seed);
        if (s1 % 3 === 0 && scan.busiestChannel > 0) {
          return {
            value:
              'Spotted ' + scan.totalAps + ' APs! Ch ' + scan.busiestChannel + ' is cozy.',
            nextSeed: s1
          };
        }
        const kPhrases = [
          'Nice neighborhood! Good signals.',
          'Found friendly routers nearby~',
          'Cruising through clean airwaves!'
        ];
        return fp.pickFrom(s1, kPhrases);
      }
      case Mood.Excited: {
        const s1 = fp.nextSeed(seed);
        if (s1 % 2 === 0 && scan.totalAps > 0) {
          return {
            value: 'Whoa! ' + scan.totalAps + ' WiFi networks at once!!',
            nextSeed: s1
          };
        }
        const kPhrases = [
          'Spectrum party! Beacons everywhere!',
          'So many signals! My antenna tingles!',
          'Crowded airwaves! Look at all of em!'
        ];
        return fp.pickFrom(s1, kPhrases);
      }
      case Mood.Cool: {
        const s1 = fp.nextSeed(seed);
        if (s1 % 2 === 0 && scan.totalAps > 0) {
          return {
            value: 'Crisp ' + scan.strongestRssi + 'dBm signal right here!',
            nextSeed: s1
          };
        }
        const kPhrases = [
          'Shades on. Full bars in range.',
          'Crystal clear beacon right next door.',
          'Strongest signal in town. Smooth.'
        ];
        return fp.pickFrom(s1, kPhrases);
      }
      case Mood.Lonely: {
        const kPhrases = [
          'Zero networks... is anyone out there?',
          'Radio silence. Are we underground?',
          'Not a single beacon in sight...'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.Bored: {
        const kPhrases = [
          'Only a couple faint signals here.',
          "Quiet airwaves... let's take a walk!",
          'Same quiet routers on the horizon.'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.Sleepy: {
        const kPhrases = [
          'Zzz... resting my pixels...',
          'Power nap... tap or press to wake me.',
          'Dreaming of 5-bar beacons... zZz'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.Grateful: {
        const kPhrases = [
          'Nom nom! Fresh 802.11 snack~',
          'Hehe, that tickles my antenna!',
          'Happy pixels! Ready to hack!',
          'Purring at 2.4 GHz~ thank u!'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.Mischief: {
        const kPhrases = [
          'Toy EAPOL bagged! Pure style.',
          'Zero low-level crimes, 100% vibes!',
          'Simulated 4-way handshake: GOTCHA!',
          'Hack the planet! (in sandbox mode)'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.ScanningDish: {
        const kPhrases = [
          'Dish locked! Sweeping RF spectrum...',
          'Listening across WiFi, BLE & Sub-GHz!',
          'Parabolic sweep active... ping!'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.CyberAttack: {
        const kPhrases = [
          'OFFENSE ARMED! Satellite uplink hot.',
          'Authorized strike mode standing by.',
          'Orbital beam locked on allow-list.'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.ShieldGuard: {
        const kPhrases = [
          'DEFENSE UP! Watching BLE & Sub-GHz.',
          'Shield grid active. Scanning for tags.',
          'Guarding airwaves against rogue gear.'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.ThreatAlert: {
        const kPhrases = [
          'ALERT! Suspicious RF/tracker spotted!',
          'Guard ping! Check RF Guard view!',
          'Warning: unknown beacon or burst!'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      case Mood.LevelUp: {
        const kPhrases = [
          'LEVEL UP! New RF rank unlocked!',
          'XP milestone reached! Highscore up!',
          'Power-up! Antenna sensitivity boosted!'
        ];
        return fp.pickFrom(seed, kPhrases);
      }
      default:
        return { value: 'Ready.', nextSeed: fp.nextSeed(seed) };
    }
  }

  function deriveLevelInfo(xp) {
    const safeXp = Math.max(0, Math.trunc(xp || 0));
    const tiers = [
      { level: 1, minXp: 0, title: 'Packet Sprout' },
      { level: 2, minXp: 40, title: 'Beacon Pup' },
      { level: 3, minXp: 110, title: 'Channel Surfer' },
      { level: 4, minXp: 220, title: 'Frame Ninja' },
      { level: 5, minXp: 380, title: 'Spectrum Scout' },
      { level: 6, minXp: 600, title: 'BLE Tracker' },
      { level: 7, minXp: 900, title: 'SubGHz Stalker' },
      { level: 8, minXp: 1300, title: 'RF Sentinel' },
      { level: 9, minXp: 1850, title: '802.11 Wizard' },
      { level: 10, minXp: 2500, title: 'ZeroDay Legend' }
    ];
    let current = tiers[0];
    let nextTier = tiers[1];
    for (let i = 0; i < tiers.length; i++) {
      if (safeXp >= tiers[i].minXp) {
        current = tiers[i];
        nextTier = tiers[i + 1] || null;
      }
    }
    let progressPct = 100;
    let nextXp = current.minXp;
    if (nextTier) {
      const span = nextTier.minXp - current.minXp;
      progressPct = Math.min(100, Math.round(((safeXp - current.minXp) / span) * 100));
      nextXp = nextTier.minXp;
    }
    return {
      level: current.level,
      title: current.title,
      xp: safeXp,
      nextXp,
      progressPct
    };
  }

  function applyXpFields(state, gain, nowMs) {
    const prevLevel = state.level || deriveLevelInfo(state.xp).level;
    const nextXp = (state.xp || 0) + Math.max(0, Math.trunc(gain || 0));
    const info = deriveLevelInfo(nextXp);
    const highScore = Math.max(state.highScore || 0, nextXp);
    let levelUpUntilMs = state.levelUpUntilMs || 0;
    if (info.level > prevLevel) {
      levelUpUntilMs = ((nowMs >>> 0) + 2400) >>> 0;
      if (levelUpUntilMs === 0) levelUpUntilMs = 1;
    }
    return { xp: nextXp, highScore, level: info.level, levelUpUntilMs };
  }

  function idleMoodForState(s) {
    if (s.offensiveArmed || s.opsMode === OpsMode.Offensive) {
      return Mood.CyberAttack;
    }
    if (s.opsMode === OpsMode.Defensive) {
      return s.lastThreatLabel ? Mood.ThreatAlert : Mood.ShieldGuard;
    }
    return s.hasScannedOnce ? deriveMoodFromScan(s.latestScan) : Mood.Awake;
  }

  function sanitizePetName(rawName) {
    const cleaned = String(rawName == null ? '' : rawName)
      .replace(/[^a-zA-Z0-9_-]/g, '')
      .slice(0, 12);
    return cleaned.length > 0 ? cleaned : 'zeroday';
  }

  function initialState(bootSeed) {
    const seed = bootSeed === undefined ? 0x5EED2026 : (bootSeed >>> 0);
    return Object.freeze({
      uptimeMs: 0,
      lastScanStartMs: 0,
      lastScanCompleteMs: 0,
      lastInteractionMs: 0,
      lastPhraseChangeMs: 0,
      rngSeed: seed === 0 ? 0x5EED2026 : seed,
      completedScans: 0,
      peakApCount: 0,
      hasScannedOnce: false,
      isScanning: false,
      manualScanRequested: false,
      scanAnimTick: 0,
      batteryPercent: 100,
      isCharging: false,
      mood: Mood.Awake,
      page: ScreenPage.PetFace,
      theme: ThemeId.PaperInk,
      themeToastUntilMs: 0,
      petName: 'zeroday',
      phrase: 'Hello world! Ready to scan.',
      latestScan: wifi.emptyScanSummary(),
      offensiveArmed: false,
      // Progression, multi-radio & defensive guard state
      highScore: 0,
      level: 1,
      levelUpUntilMs: 0,
      opsMode: OpsMode.Recon,
      bleDevices: Object.freeze([]),
      subGhzSignals: Object.freeze([]),
      subGhzFreqKhz: 433920,
      threatsDetected: 0,
      lastThreatLabel: '',
      // Playful hacker toy counters
      toyHandshakes: 0,
      snacksFed: 0,
      peersMet: 0,
      pokesCount: 0,
      xp: 0,
      lastPeerName: ''
    });
  }

  function shouldTriggerScan(state, nowMs, autoIntervalMs) {
    const interval = autoIntervalMs === undefined ? 12000 : autoIntervalMs;
    if (state.isScanning) {
      return false;
    }
    if (state.manualScanRequested) {
      return true;
    }
    if (!state.hasScannedOnce) {
      return nowMs >= 1500;
    }
    const effectiveInterval = state.mood === Mood.Sleepy ? interval * 2 : interval;
    return nowMs - state.lastScanCompleteMs >= effectiveInterval;
  }

  function selectThemePhrase(theme, seed) {
    const name = themes.themeSpec(theme).name;
    const s1 = fp.nextSeed(seed);
    switch (s1 % 4) {
      case 0:
        return { value: 'New look: ' + name + '!', nextSeed: s1 };
      case 1:
        return { value: 'Ooh, ' + name + ' suits me.', nextSeed: s1 };
      case 2:
        return { value: 'Repainted in ' + name + '~', nextSeed: s1 };
      default:
        return { value: 'Fresh pixels! ' + name + ' mode.', nextSeed: s1 };
    }
  }

  function applyPage(state, targetPage, nowMs) {
    const now = nowMs >>> 0;
    const validPage = PAGE_ORDER.includes(targetPage) ? targetPage : state.page;
    const next = Object.assign({}, state, {
      uptimeMs: now,
      lastInteractionMs: now,
      page: validPage
    });
    if (!next.isScanning && next.mood === Mood.Sleepy) {
      next.mood = idleMoodForState(next);
      const picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
      next.phrase = picked.value;
      next.rngSeed = picked.nextSeed;
      next.lastPhraseChangeMs = now;
    }
    return Object.freeze(next);
  }

  function applyTheme(state, requestedTheme, nowMs, announce) {
    const now = nowMs >>> 0;
    const resolved = themes.isValidTheme(requestedTheme)
      ? requestedTheme
      : themes.themeFromKey(String(requestedTheme || ''));
    const nextThemeId = resolved || state.theme;
    const next = Object.assign({}, state, {
      uptimeMs: now,
      lastInteractionMs: now,
      theme: nextThemeId
    });
    if (announce !== false) {
      let until = (now + themes.THEME_TOAST_MS) >>> 0;
      if (until === 0) until = 1;
      next.themeToastUntilMs = until;
      if (!next.isScanning) {
        const picked = selectThemePhrase(nextThemeId, next.rngSeed);
        next.phrase = picked.value;
        next.rngSeed = picked.nextSeed;
        next.lastPhraseChangeMs = now;
      }
    }
    return Object.freeze(next);
  }

  function reduce(state, event) {
    if (!event || !event.type) return state;

    switch (event.type) {
      case 'Tick': {
        const next = Object.assign({}, state, {
          uptimeMs: event.nowMs >>> 0,
          batteryPercent: fp.clampVal(Math.trunc(event.batteryPercent), 0, 100),
          isCharging: Boolean(event.isCharging)
        });

        if (next.isScanning) {
          const phase = Math.floor((next.uptimeMs - next.lastScanStartMs) / 450) % 2;
          next.scanAnimTick = phase;
          next.mood =
            next.opsMode === OpsMode.Defensive
              ? Mood.ScanningDish
              : phase === 0
                ? Mood.LookingLeft
                : Mood.LookingRight;
          return Object.freeze(next);
        }

        if (themes.isThemeToastVisible(next.levelUpUntilMs || 0, next.uptimeMs)) {
          if (next.mood !== Mood.LevelUp) {
            next.mood = Mood.LevelUp;
            const picked = selectPhrase(Mood.LevelUp, next.latestScan, next.rngSeed);
            next.phrase = picked.value;
            next.rngSeed = picked.nextSeed;
            next.lastPhraseChangeMs = next.uptimeMs;
          }
          return Object.freeze(next);
        } else if (next.mood === Mood.LevelUp) {
          next.levelUpUntilMs = 0;
          next.mood = idleMoodForState(next);
        }

        const quietArea =
          next.latestScan.totalAps <= 2 &&
          next.opsMode === OpsMode.Recon &&
          !next.offensiveArmed;
        const idleLong =
          next.uptimeMs - next.lastInteractionMs >= 60000 && next.uptimeMs >= 60000;

        if (quietArea && idleLong && next.mood !== Mood.Sleepy) {
          next.mood = Mood.Sleepy;
          const picked = selectPhrase(Mood.Sleepy, next.latestScan, next.rngSeed);
          next.phrase = picked.value;
          next.rngSeed = picked.nextSeed;
          next.lastPhraseChangeMs = next.uptimeMs;
        } else if (next.uptimeMs - next.lastPhraseChangeMs >= 9000 && next.hasScannedOnce) {
          // Settle back to natural scan/mode-derived mood after temporary toy excitement
          if (next.mood === Mood.Grateful || next.mood === Mood.Mischief) {
            next.mood = idleMoodForState(next);
          }
          const picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
          next.phrase = picked.value;
          next.rngSeed = picked.nextSeed;
          next.lastPhraseChangeMs = next.uptimeMs;
        }
        return Object.freeze(next);
      }

      case 'ButtonAPressed': {
        return applyPage(state, nextPage(state.page), event.nowMs);
      }

      case 'CyclePage': {
        return applyPage(
          state,
          cyclePage(state.page, event.step === undefined ? 1 : event.step),
          event.nowMs
        );
      }

      case 'ButtonBPressed': {
        const next = Object.assign({}, state, {
          uptimeMs: event.nowMs >>> 0,
          lastInteractionMs: event.nowMs >>> 0
        });
        if (!next.isScanning) {
          next.manualScanRequested = true;
        }
        return Object.freeze(next);
      }

      case 'ButtonBLongPressed': {
        return applyTheme(state, nextTheme(state.theme), event.nowMs, true);
      }

      case 'CycleTheme': {
        return applyTheme(
          state,
          cycleTheme(state.theme, event.step === undefined ? 1 : event.step),
          event.nowMs,
          event.announce !== false
        );
      }

      case 'ScanStarted': {
        const now = event.nowMs >>> 0;
        const scanMood =
          state.opsMode === OpsMode.Defensive ? Mood.ScanningDish : Mood.LookingLeft;
        const picked = selectPhrase(scanMood, state.latestScan, state.rngSeed);
        return Object.freeze(
          Object.assign({}, state, {
            uptimeMs: now,
            isScanning: true,
            manualScanRequested: false,
            lastScanStartMs: now,
            scanAnimTick: 0,
            mood: scanMood,
            phrase: picked.value,
            rngSeed: picked.nextSeed,
            lastPhraseChangeMs: now
          })
        );
      }

      case 'ScanCompleted': {
        const now = event.nowMs >>> 0;
        const summary = wifi.summarizeScan(event.rawNetworks || [], 12);
        const xpGain = summary.totalAps > 0 ? 3 + Math.min(12, Math.floor(summary.totalAps / 2)) : 1;
        const xpFields = applyXpFields(state, xpGain, now);
        const nextBase = Object.assign({}, state, {
          uptimeMs: now,
          isScanning: false,
          manualScanRequested: false,
          hasScannedOnce: true,
          lastScanCompleteMs: now,
          completedScans: state.completedScans + 1,
          peakApCount: Math.max(state.peakApCount, summary.totalAps),
          latestScan: summary
        }, xpFields);
        const mood = idleMoodForState(nextBase);
        const picked = selectPhrase(mood, summary, state.rngSeed);
        return Object.freeze(
          Object.assign(nextBase, {
            mood,
            phrase: picked.value,
            rngSeed: picked.nextSeed,
            lastPhraseChangeMs: now
          })
        );
      }

      case 'CycleOpsMode': {
        const now = event.nowMs >>> 0;
        const nextMode = cycleOpsMode(state.opsMode);
        const nextBase = Object.assign({}, state, {
          uptimeMs: now,
          lastInteractionMs: now,
          opsMode: nextMode,
          offensiveArmed: nextMode === OpsMode.Offensive
        });
        if (!nextBase.isScanning) {
          nextBase.mood = idleMoodForState(nextBase);
          const picked = selectPhrase(nextBase.mood, nextBase.latestScan, nextBase.rngSeed);
          nextBase.phrase = picked.value;
          nextBase.rngSeed = picked.nextSeed;
          nextBase.lastPhraseChangeMs = now;
        }
        return Object.freeze(nextBase);
      }

      case 'SetOpsMode': {
        const now = event.nowMs >>> 0;
        const nextMode = Object.values(OpsMode).includes(event.mode) ? event.mode : state.opsMode;
        const nextBase = Object.assign({}, state, {
          uptimeMs: now,
          lastInteractionMs: now,
          opsMode: nextMode,
          offensiveArmed: nextMode === OpsMode.Offensive
        });
        if (!nextBase.isScanning) {
          nextBase.mood = idleMoodForState(nextBase);
          const picked = selectPhrase(nextBase.mood, nextBase.latestScan, nextBase.rngSeed);
          nextBase.phrase = picked.value;
          nextBase.rngSeed = picked.nextSeed;
          nextBase.lastPhraseChangeMs = now;
        }
        return Object.freeze(nextBase);
      }

      case 'BleScanCompleted': {
        const now = event.nowMs >>> 0;
        const rawDevs = Array.isArray(event.devices) ? event.devices : [];
        let threatCount = 0;
        let topThreat = '';
        let topThreatRssi = -120;
        const normalized = rawDevs.map(function (d) {
          const threat =
            d.threat && d.threat !== wifi.BleThreatKind.None
              ? d.threat
              : wifi.classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid, d.trackerPayload);
          if (threat !== wifi.BleThreatKind.None) {
            threatCount++;
            if ((d.rssi || -100) > topThreatRssi) {
              topThreatRssi = d.rssi || -100;
              topThreat = wifi.bleThreatLabel(threat) + ' ' + topThreatRssi + 'dB';
            }
          }
          return Object.freeze(Object.assign({}, d, { threat }));
        });
        normalized.sort(function (a, b) {
          const ta = a.threat !== wifi.BleThreatKind.None ? 1 : 0;
          const tb = b.threat !== wifi.BleThreatKind.None ? 1 : 0;
          if (ta !== tb) return tb - ta;
          return (b.rssi || -100) - (a.rssi || -100);
        });
        const trimmed = normalized.slice(0, 16);
        const xpGain = threatCount > 0 ? 25 : trimmed.length > 0 ? 4 : 1;
        const xpFields = applyXpFields(state, xpGain, now);
        const nextBase = Object.assign({}, state, {
          uptimeMs: now,
          bleDevices: Object.freeze(trimmed),
          threatsDetected: (state.threatsDetected || 0) + threatCount,
          lastThreatLabel: topThreat || state.lastThreatLabel
        }, xpFields);
        if (threatCount > 0 && !nextBase.isScanning && nextBase.opsMode !== OpsMode.Offensive) {
          nextBase.mood = Mood.ThreatAlert;
          nextBase.phrase = 'DEFENSE! ' + topThreat + ' nearby!';
          nextBase.lastPhraseChangeMs = now;
        }
        return Object.freeze(nextBase);
      }

      case 'SubGhzObserved': {
        const now = event.nowMs >>> 0;
        const sig = Object.freeze(Object.assign({
          freqKhz: 433920,
          rssi: -60,
          protocol: 'OOK',
          burstCount: 1,
          anomaly: wifi.SubGhzAnomaly.None
        }, event.signal || {}));
        const list = [sig].concat(state.subGhzSignals || []).slice(0, 12);
        const isAnom = sig.anomaly && sig.anomaly !== wifi.SubGhzAnomaly.None;
        const xpFields = applyXpFields(state, isAnom ? 25 : 10, now);
        const threatLbl = isAnom
          ? wifi.formatFreqMhz(sig.freqKhz) + ' ' + wifi.subGhzAnomalyLabel(sig.anomaly)
          : state.lastThreatLabel;
        const nextBase = Object.assign({}, state, {
          uptimeMs: now,
          subGhzFreqKhz: sig.freqKhz,
          subGhzSignals: Object.freeze(list),
          threatsDetected: (state.threatsDetected || 0) + (isAnom ? 1 : 0),
          lastThreatLabel: threatLbl
        }, xpFields);
        if (isAnom && !nextBase.isScanning && nextBase.opsMode !== OpsMode.Offensive) {
          nextBase.mood = Mood.ThreatAlert;
          nextBase.phrase = 'SUBGHZ! ' + threatLbl;
          nextBase.lastPhraseChangeMs = now;
        }
        return Object.freeze(nextBase);
      }

      case 'SetSubGhzFreq': {
        const now = event.nowMs >>> 0;
        const freq = Math.trunc(event.freqKhz || 433920);
        if (freq < 300000 || freq > 928000) return state;
        return Object.freeze(Object.assign({}, state, {
          uptimeMs: now,
          lastInteractionMs: now,
          subGhzFreqKhz: freq,
          phrase: 'CC1101 tuned to ' + wifi.formatFreqMhz(freq),
          lastPhraseChangeMs: now
        }));
      }

      case 'SetHighScore': {
        const now = event.nowMs >>> 0;
        const xp = Math.max(state.xp || 0, Math.trunc(event.xp || 0));
        const hi = Math.max(state.highScore || 0, Math.trunc(event.highScore || 0), xp);
        return Object.freeze(Object.assign({}, state, {
          uptimeMs: now,
          xp,
          highScore: hi,
          level: deriveLevelInfo(xp).level
        }));
      }

      // --- Playful Web-Toy Events ---

      case 'PetPoked': {
        const now = event.nowMs >>> 0;
        const kPokes = [
          'Hehe! Careful with the antenna~',
          'Boop received! Pixels happy!',
          'Purring in 802.11b/g/n mode~',
          'System status: 100% good Lil Hacker!'
        ];
        const picked = fp.pickFrom(state.rngSeed, kPokes);
        return Object.freeze(
          Object.assign({}, state, {
            uptimeMs: now,
            lastInteractionMs: now,
            mood: state.isScanning ? state.mood : Mood.Grateful,
            phrase: picked.value,
            rngSeed: picked.nextSeed,
            lastPhraseChangeMs: now,
            pokesCount: state.pokesCount + 1
          }, applyXpFields(state, 5, now))
        );
      }

      case 'SnackFed': {
        const now = event.nowMs >>> 0;
        const kSnacks = [
          'Nom nom! Crispy beacon bytes!',
          'Yum! Freshly baked 0xDEADBEEF!',
          'Crunching tasty packet cookies~',
          'Battery of my soul: recharged!'
        ];
        const picked = fp.pickFrom(state.rngSeed, kSnacks);
        return Object.freeze(
          Object.assign({}, state, {
            uptimeMs: now,
            lastInteractionMs: now,
            page: ScreenPage.PetFace,
            mood: state.isScanning ? state.mood : Mood.Grateful,
            phrase: picked.value,
            rngSeed: picked.nextSeed,
            lastPhraseChangeMs: now,
            snacksFed: state.snacksFed + 1
          }, applyXpFields(state, 10, now))
        );
      }

      case 'ToyHandshake': {
        const now = event.nowMs >>> 0;
        const target =
          event.targetSsid ||
          (state.latestScan.strongestSsid ? state.latestScan.strongestSsid : 'TestLab_AP');
        const s1 = fp.nextSeed(state.rngSeed);
        const count = state.toyHandshakes + 1;
        const phrases = [
          'Toy pwn #' + count + ' on ' + target + '!',
          'Bagged virtual EAPOL from ' + target + '!',
          'Simulated handshake #' + count + ' -> /dev/fun!'
        ];
        const picked = fp.pickFrom(s1, phrases);
        return Object.freeze(
          Object.assign({}, state, {
            uptimeMs: now,
            lastInteractionMs: now,
            page: ScreenPage.PetFace,
            mood: state.isScanning ? state.mood : Mood.Mischief,
            phrase: picked.value,
            rngSeed: picked.nextSeed,
            lastPhraseChangeMs: now,
            toyHandshakes: count
          }, applyXpFields(state, 25, now))
        );
      }

      case 'PeerSpotted': {
        const now = event.nowMs >>> 0;
        const peer = sanitizePetName(event.peerName || 'unit-404');
        const rssi = Number.isFinite(event.peerRssi) ? event.peerRssi : -44;
        const s1 = fp.nextSeed(state.rngSeed);
        const phrases = [
          'OMG! Peer [' + peer + '] (' + rssi + 'dB) waved hi!',
          'New fren! [' + peer + '] is chirping nearby!',
          'Synced memes with peer [' + peer + ']!'
        ];
        const picked = fp.pickFrom(s1, phrases);
        return Object.freeze(
          Object.assign({}, state, {
            uptimeMs: now,
            lastInteractionMs: now,
            page: ScreenPage.PetFace,
            mood: state.isScanning ? state.mood : Mood.Excited,
            phrase: picked.value,
            rngSeed: picked.nextSeed,
            lastPhraseChangeMs: now,
            peersMet: state.peersMet + 1,
            lastPeerName: peer
          }, applyXpFields(state, 20, now))
        );
      }

      case 'PetRenamed': {
        const now = event.nowMs >>> 0;
        const cleanName = sanitizePetName(event.petName);
        return Object.freeze(
          Object.assign({}, state, {
            uptimeMs: now,
            lastInteractionMs: now,
            petName: cleanName,
            phrase: 'Identity updated! Call me ' + cleanName + '.',
            lastPhraseChangeMs: now
          })
        );
      }

      case 'SetPage': {
        return applyPage(state, event.page, event.nowMs);
      }

      case 'SetTheme': {
        return applyTheme(state, event.theme, event.nowMs, event.announce !== false);
      }

      default:
        return state;
    }
  }

  const petLogic = Object.freeze({
    OpsMode,
    opsModeLabel,
    cycleOpsMode,
    Mood,
    ScreenPage,
    ThemeId,
    EyeGlyph,
    MouthGlyph,
    faceForMood,
    cyclePage,
    nextPage,
    prevPage,
    cycleTheme,
    nextTheme,
    prevTheme,
    selectThemePhrase,
    deriveMoodFromScan,
    selectPhrase,
    deriveLevelInfo,
    sanitizePetName,
    initialState,
    shouldTriggerScan,
    reduce
  });

  root.ZD = root.ZD || {};
  root.ZD.petLogic = petLogic;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = petLogic;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
