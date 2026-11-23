// Pure responsive UI View-Model projection & ASCII preview (1:1 port of core/include/zd/ui_model.hpp).
(function (root) {
  'use strict';

  const fp = (root.ZD && root.ZD.fp) || (typeof require === 'function' ? require('./fp.js') : null);
  const wifi =
    (root.ZD && root.ZD.wifiAnalysis) ||
    (typeof require === 'function' ? require('./wifi_analysis.js') : null);
  const themes =
    (root.ZD && root.ZD.themes) ||
    (typeof require === 'function' ? require('./themes.js') : null);
  const logic =
    (root.ZD && root.ZD.petLogic) ||
    (typeof require === 'function' ? require('./pet_logic.js') : null);

  const SCREEN_PROFILES = Object.freeze([
    Object.freeze({
      key: 'micro',
      label: '128×64 OLED (SSD1306)',
      dims: Object.freeze({ width: 128, height: 64 }),
      monochrome: true
    }),
    Object.freeze({
      key: 'compact',
      label: '160×80 (StickC Classic)',
      dims: Object.freeze({ width: 160, height: 80 }),
      monochrome: false
    }),
    Object.freeze({
      key: 'plus',
      label: '240×135 (StickC Plus2)',
      dims: Object.freeze({ width: 240, height: 135 }),
      monochrome: false
    }),
    Object.freeze({
      key: 'epaper',
      label: '250×122 (2.13" e-Paper)',
      dims: Object.freeze({ width: 250, height: 122 }),
      monochrome: true
    }),
    Object.freeze({
      key: 'wide',
      label: '320×240 (Core2 / CYD)',
      dims: Object.freeze({ width: 320, height: 240 }),
      monochrome: false
    })
  ]);

  const ActivityScene = Object.freeze({
    None: 'None',
    RadarDish: 'RadarDish',
    SatelliteBeam: 'SatelliteBeam',
    ThreatShield: 'ThreatShield'
  });

  function screenProfileFromKey(key) {
    for (let i = 0; i < SCREEN_PROFILES.length; i++) {
      if (SCREEN_PROFILES[i].key === key) {
        return SCREEN_PROFILES[i];
      }
    }
    return null;
  }

  const rgb565 = themes.rgb565;
  const resolvePalette = themes.resolvePalette;

  function twoDigit(val) {
    const clamped = Math.abs(Math.trunc(val)) % 100;
    return String(clamped).padStart(2, '0');
  }

  function formatUptime(uptimeMs, compact) {
    const totalSec = Math.floor(Math.max(0, uptimeMs) / 1000);
    const secs = totalSec % 60;
    const mins = Math.floor(totalSec / 60) % 60;
    const hours = Math.floor(totalSec / 3600) % 100;

    if (compact) {
      if (hours > 0) {
        return twoDigit(hours) + 'h' + twoDigit(mins);
      }
      return twoDigit(mins) + ':' + twoDigit(secs);
    }
    return twoDigit(hours) + ':' + twoDigit(mins) + ':' + twoDigit(secs);
  }

  function truncateText(text, maxChars) {
    const s = String(text || '');
    if (maxChars <= 0) return '';
    if (s.length <= maxChars) return s;
    if (maxChars <= 2) return s.slice(0, maxChars);
    return s.slice(0, maxChars - 2) + '..';
  }

  function wrapWords(text, maxCols, maxLines) {
    const s = String(text || '');
    if (maxCols <= 0 || maxLines <= 0 || s.length === 0) {
      return [];
    }

    const words = s.trim().split(/\s+/).filter(Boolean);
    const lines = [];
    let currentLine = '';

    for (let i = 0; i < words.length; i++) {
      const rawWord = words[i];
      const clippedWord = rawWord.length > maxCols ? truncateText(rawWord, maxCols) : rawWord;

      if (currentLine.length === 0) {
        currentLine = clippedWord;
      } else if (currentLine.length + 1 + clippedWord.length <= maxCols) {
        currentLine += ' ' + clippedWord;
      } else {
        lines.push(currentLine);
        if (lines.length >= maxLines) {
          currentLine = '';
          break;
        }
        currentLine = clippedWord;
      }
    }

    if (currentLine.length > 0 && lines.length < maxLines) {
      lines.push(currentLine);
    }

    return lines;
  }

  function formatCapturePathRows(path, maxCols) {
    const safePath = path || '(unset)';
    if (safePath.length + 6 <= maxCols) {
      return ['PATH: ' + safePath];
    }
    const slash = safePath.lastIndexOf('/');
    if (slash >= 0 && slash + 1 < safePath.length) {
      const dirPart = slash === 0 ? '/' : safePath.slice(0, slash);
      const filePart = safePath.slice(slash + 1);
      return [
        truncateText('DIR:  ' + dirPart, maxCols),
        truncateText('FILE: ' + filePart, maxCols)
      ];
    }
    return [truncateText('PATH: ' + safePath, maxCols)];
  }

  function buildThemeToast(state, dims, compact, bodyTop, bodyBottom) {
    if (!themes.isThemeToastVisible(state.themeToastUntilMs || 0, state.uptimeMs || 0)) {
      return Object.freeze({
        visible: false,
        text: '',
        x: 0,
        y: 0,
        w: 0,
        h: 0,
        textX: 0,
        textY: 0
      });
    }

    const label = themes.themeLabel(state.theme);
    const idx = Math.max(0, themes.themeIndex(state.theme));
    const position = idx + 1 + '/' + themes.THEME_COUNT;
    const maxChars = Math.max(8, Math.floor((dims.width - 16) / 6));
    const text = truncateText(
      compact ? '< ' + label + ' >' : 'THEME ' + position + ': ' + label,
      maxChars
    );

    const padX = compact ? 5 : 8;
    const padY = compact ? 4 : 6;
    const w = text.length * 6 + padX * 2;
    const h = 8 + padY * 2;
    const x = Math.trunc((dims.width - w) / 2);
    const y = bodyTop + Math.trunc((bodyBottom - bodyTop - h) / 2);

    return Object.freeze({
      visible: true,
      text,
      x,
      y,
      w,
      h,
      textX: x + padX,
      textY: y + padY
    });
  }

  function buildUiFrame(state, dimsInput) {
    const dims = {
      width: Math.max(96, dimsInput && dimsInput.width ? Math.trunc(dimsInput.width) : 240),
      height: Math.max(56, dimsInput && dimsInput.height ? Math.trunc(dimsInput.height) : 135)
    };
    const micro = dims.width < 150 || dims.height < 72;
    const compact = dims.width < 200 || dims.height < 100;
    const wide = dims.width >= 300 && dims.height >= 180;
    const palette = resolvePalette(state.theme);
    const face = logic.faceForMood(state.mood);

    const headerH = micro ? 10 : compact ? 12 : 17;
    const footerH = micro ? 10 : compact ? 12 : 17;
    const headerDivY = headerH;
    const footerDivY = dims.height - footerH - 1;
    const maxFrameCols = Math.max(12, Math.floor((dims.width - 4) / 6));
    const effectiveMode = state.offensiveArmed ? logic.OpsMode.Offensive : (state.opsMode || logic.OpsMode.Recon);
    const modeBadge = state.offensiveArmed
      ? (compact ? '[ARM]' : '[ARMED]')
      : '[' + logic.opsModeLabel(effectiveMode, compact) + ']';
    const armBadgeCols = modeBadge.length + 1;
    const maxHeaderCols =
      maxFrameCols > armBadgeCols + 6 ? maxFrameCols - armBadgeCols : maxFrameCols;

    const chText = state.isScanning
      ? 'CH:*'
      : state.latestScan.busiestChannel >= 6001
        ? '6G:' + (state.latestScan.busiestChannel - 6000)
        : state.latestScan.busiestChannel >= 100
          ? 'CH:' + state.latestScan.busiestChannel
          : state.latestScan.busiestChannel > 0
            ? 'CH:' + twoDigit(state.latestScan.busiestChannel)
            : 'CH:--';

    const apText = 'AP:' + state.latestScan.totalAps;
    const upText = 'UP:' + formatUptime(state.uptimeMs, compact);
    const batPrefix = state.isCharging ? '+' : '';
    const batText = batPrefix + state.batteryPercent + '%';

    let headerLine;
    if (micro) {
      headerLine = chText + ' ' + apText + ' ' + batText;
    } else if (compact) {
      headerLine = chText + ' ' + apText + ' ' + formatUptime(state.uptimeMs, true) + ' ' + batText;
    } else {
      const peakPart = '(' + state.peakApCount + ')';
      headerLine = maxHeaderCols <= 34
        ? (chText + ' ' + apText + peakPart + ' ' + formatUptime(state.uptimeMs, false) + ' ' + batText)
        : (chText + '  ' + apText + peakPart + '  ' + upText + '  ' + batText);
    }
    headerLine = truncateText(headerLine, maxHeaderCols);

    let footerLine;
    if (micro) {
      const statusPart = state.isScanning ? 'SCN..' : '#' + twoDigit(state.completedScans);
      const rssiPart =
        state.latestScan.totalAps > 0 ? state.latestScan.strongestRssi + 'dB' : '--dB';
      footerLine = statusPart + ' ' + rssiPart + ' [A]/[B]';
    } else if (compact) {
      const statusPart = state.isScanning ? 'SCAN..' : '#' + twoDigit(state.completedScans);
      const rssiPart =
        state.latestScan.totalAps > 0 ? state.latestScan.strongestRssi + 'dB' : '--dB';
      footerLine = statusPart + ' ' + rssiPart + ' [A]VW [B]SCN';
    } else {
      const statusPart = state.isScanning
        ? 'SCANNING..'
        : 'SCAN #' + twoDigit(state.completedScans);
      const rssiPart =
        state.latestScan.totalAps > 0
          ? 'BEST ' + state.latestScan.strongestRssi + 'dBm'
          : 'BEST --dBm';
      footerLine = statusPart + '  ' + rssiPart + '  [A]PG [B]SCN';
    }
    footerLine = truncateText(footerLine, maxFrameCols);

    const bodyTop = headerDivY + 1;
    const bodyBottom = footerDivY - 1;
    const bodyH = bodyBottom - bodyTop;

    const scene = state.isScanning
      ? ActivityScene.RadarDish
      : effectiveMode === logic.OpsMode.Offensive
        ? ActivityScene.SatelliteBeam
        : effectiveMode === logic.OpsMode.Defensive ||
            state.mood === logic.Mood.ThreatAlert ||
            (state.secMood && state.secMood !== logic.SecMood.Calm)
          ? ActivityScene.ThreatShield
          : ActivityScene.None;
    const faceStyle = themes.themeFaceStyle(state.theme);
    const reserveMascotScene =
      faceStyle === themes.FaceStyle.PixelArtMascot && scene !== ActivityScene.None;

    const centerX = Math.trunc(dims.width / 2);
    let geom;
    let speechX;
    let speechTopY;
    let lineStepY;
    let speechCols;
    let speechMaxLines;

    if (micro) {
      const centerY = bodyTop + Math.trunc(bodyH / 2) + 1;
      geom = {
        centerX,
        centerY,
        eyeOffsetX: 9,
        eyeY: centerY - 2,
        eyeRadius: 4,
        mouthY: centerY + 5,
        mouthRadius: 3,
        bracketOffsetX: 21,
        bracketHalfHeight: 7,
        moodBadgeY: bodyBottom - 8
      };
      speechX = 4;
      speechTopY = bodyTop + 1;
      lineStepY = 8;
      const reserve = reserveMascotScene ? 18 : 0;
      speechCols = Math.max(6, Math.floor((dims.width - 8 - reserve) / 6));
      speechMaxLines = 1;
    } else if (compact) {
      const centerY = bodyTop + Math.trunc(bodyH / 2);
      geom = {
        centerX,
        centerY,
        eyeOffsetX: 11,
        eyeY: centerY - 2,
        eyeRadius: 5,
        mouthY: centerY + 6,
        mouthRadius: 4,
        bracketOffsetX: 26,
        bracketHalfHeight: 10,
        moodBadgeY: bodyBottom - 9
      };
      speechX = 4;
      speechTopY = bodyTop + 2;
      lineStepY = 9;
      const reserve = reserveMascotScene ? 24 : 0;
      speechCols = Math.max(8, Math.floor((dims.width - 8 - reserve) / 6));
      speechMaxLines = 1;
    } else if (wide) {
      const centerY = bodyTop + Math.trunc(bodyH / 2) - 4;
      geom = {
        centerX,
        centerY,
        eyeOffsetX: 22,
        eyeY: centerY - 5,
        eyeRadius: 10,
        mouthY: centerY + 13,
        mouthRadius: 8,
        bracketOffsetX: 54,
        bracketHalfHeight: 26,
        moodBadgeY: bodyBottom - 34
      };
      speechX = 6;
      speechTopY = bodyTop + 4;
      lineStepY = 11;
      const reserve = reserveMascotScene ? 40 : 0;
      speechCols = Math.max(12, Math.floor((dims.width - 12 - reserve) / 6));
      speechMaxLines = 2;
    } else {
      const centerY = bodyTop + Math.trunc(bodyH / 2);
      geom = {
        centerX,
        centerY,
        eyeOffsetX: 16,
        eyeY: centerY - 4,
        eyeRadius: 7,
        mouthY: centerY + 8,
        mouthRadius: 5,
        bracketOffsetX: 38,
        bracketHalfHeight: 14,
        moodBadgeY: bodyBottom - 19
      };
      speechX = 4;
      speechTopY = bodyTop + 2;
      lineStepY = 9;
      const reserve = reserveMascotScene ? 32 : 0;
      speechCols = Math.max(12, Math.floor((dims.width - 8 - reserve) / 6));
      speechMaxLines = 1;
    }

    const onPetFace = state.page === logic.ScreenPage.PetFace;
    const onRadar = state.page === logic.ScreenPage.NearbyRadar;
    const onSpectrum = state.page === logic.ScreenPage.ChannelSpectrum;
    const onRfGuard = state.page === logic.ScreenPage.RfGuard;
    const onCaptures = state.page === logic.ScreenPage.Captures;

    const lvlInfo = logic.deriveLevelInfo(state.xp || 0);
    const highScore = state.highScore || 0;
    const capturesSaved = state.capturesSaved || 0;
    const capturePath = state.capturePath || '/captures/zeroday.pcap';
    const highScoreBeaten = Boolean(state.highScoreBeaten);
    const notifyActive =
      themes.isThemeToastVisible(state.notifyUntilMs || 0, state.uptimeMs || 0) &&
      Boolean(state.notifyText);
    const notifyKind = notifyActive ? (state.notifyKind || logic.NotifyKind.None) : logic.NotifyKind.None;
    const notifyBanner = notifyActive ? truncateText('* ' + state.notifyText, maxFrameCols) : '';

    let promptLabel = '';
    let wrappedPhrase = Object.freeze([]);
    let rankLine = '';
    const threatBanner = state.lastThreatLabel
      ? truncateText('! ' + state.lastThreatLabel, maxFrameCols)
      : '';
    let spotlightLabel = '';

    if (onPetFace) {
      const promptMaxCols = compact
        ? (speechCols > 10 ? Math.min(9, Math.trunc(speechCols / 2)) : speechCols)
        : speechCols;
      promptLabel = truncateText(state.petName + '>', promptMaxCols);
      const phraseCols = compact
        ? (speechCols > promptLabel.length + 1 ? speechCols - promptLabel.length - 1 : 0)
        : speechCols;
      wrappedPhrase = wrapWords(state.phrase, phraseCols, speechMaxLines);

      if (!compact) {
        const maxRankCols = wide
          ? (dims.width > 68 ? Math.floor((dims.width - 64) / 6) : maxFrameCols)
          : 22;
        const hiSuffix = highScoreBeaten ? '!' : '';
        const capPart =
          capturesSaved > 0 ? ((wide ? ' CAP:' : ' C:') + capturesSaved) : '';
        const rawRank = wide
          ? ('LV' + lvlInfo.level + ' ' + lvlInfo.title + ' HI:' + highScore + hiSuffix + capPart)
          : ('LV' + lvlInfo.level + ' HI:' + highScore + hiSuffix + capPart);
        rankLine = truncateText(rawRank, maxRankCols);
      }

      if (!compact && notifyActive) {
        spotlightLabel = notifyBanner;
      } else if (!compact && threatBanner.length > 0) {
        spotlightLabel = threatBanner;
      } else if (!compact && state.latestScan.totalAps > 0 && state.latestScan.strongestSsid.length > 0) {
        const rawSpot =
          '> ' + state.latestScan.strongestSsid + ' (' + state.latestScan.strongestRssi + ')';
        spotlightLabel = truncateText(rawSpot, maxFrameCols);
      }
    }

    const radarRowStep = compact ? 12 : 15;
    const maxRadarRows = Math.max(2, Math.floor((bodyH - (compact ? 4 : 5)) / radarRowStep));
    const maxSsidChars = Math.max(
      6,
      Math.floor((dims.width - (micro ? 80 : compact ? 88 : 126)) / 6)
    );

    let radarRows = Object.freeze([]);
    let radarEmptyHint = '';
    if (onRadar) {
      const visibleAps = fp.take(state.latestScan.topNetworks, maxRadarRows);
      radarRows = fp.map(visibleAps, function (ap) {
        let chStr = 'c--';
        if (ap.channel >= 6001) {
          chStr = '6g' + (ap.channel - 6000);
        } else if (ap.channel >= 100) {
          chStr = 'c' + ap.channel;
        } else if (ap.channel > 0) {
          chStr = 'c' + twoDigit(ap.channel);
        }
        const details = chStr + ' ' + ap.rssi;
        return {
          ssid: truncateText(ap.ssid, maxSsidChars),
          details,
          bars: wifi.rssiToBars(ap.rssi),
          secure: ap.secure
        };
      });
      radarEmptyHint = truncateText(
        state.isScanning
          ? 'Scanning nearby WiFi...'
          : state.hasScannedOnce
            ? 'No WiFi APs in range.'
            : 'Waiting for first scan...',
        maxFrameCols
      );
    }

    const chartBaseY = bodyBottom - (micro ? 9 : compact ? 11 : 14);
    const chartMaxBarH = Math.max(
      14,
      chartBaseY - bodyTop - (micro ? 12 : compact ? 16 : 29)
    );
    const channelBars = [];
    let spectrumSummary = '';
    if (onSpectrum) {
      const hist = state.latestScan.histogram || {};
      const band24 = hist.band24GhzAps || 0;
      const band5 = hist.band5GhzAps || 0;
      const band6 = hist.band6GhzAps || 0;
      const counts5 = hist.counts5Ghz || [];
      const k5Chs = wifi.K_SPECTRUM_5GHZ_CHANNELS || [36, 40, 44, 48, 52, 64, 100, 116, 132, 149, 153, 157, 161];

      if (band24 === 0 && band5 > 0) {
        let maxChCount = 1;
        for (let idx = 0; idx < 13; idx++) {
          if ((counts5[idx] || 0) > maxChCount) {
            maxChCount = counts5[idx];
          }
        }
        for (let idx = 0; idx < 13; idx++) {
          const c = counts5[idx] || 0;
          const barH = c === 0 ? 0 : Math.max(2, Math.trunc((c * chartMaxBarH) / maxChCount));
          channelBars.push({
            channel: k5Chs[idx],
            count: c,
            heightPx: barH
          });
        }
        let rawSummary = compact
          ? '5G SEC:' + state.latestScan.secureAps + ' OPN:' + state.latestScan.openAps
          : '5GHz UNII | SEC:' + state.latestScan.secureAps + ' OPEN:' + state.latestScan.openAps;
        if (!compact && band6 > 0) {
          rawSummary += ' 6G:' + band6;
        }
        spectrumSummary = truncateText(rawSummary, maxFrameCols);
      } else {
        let maxChCount = 1;
        for (let ch = 1; ch <= 13; ch++) {
          if ((hist.counts && hist.counts[ch] || 0) > maxChCount) {
            maxChCount = hist.counts[ch];
          }
        }
        for (let idx = 0; idx < 13; idx++) {
          const c = (hist.counts && hist.counts[idx + 1]) || 0;
          const barH = c === 0 ? 0 : Math.max(2, Math.trunc((c * chartMaxBarH) / maxChCount));
          channelBars.push({
            channel: idx + 1,
            count: c,
            heightPx: barH
          });
        }
        let rawSummary = compact
          ? 'SEC:' + state.latestScan.secureAps + ' OPN:' + state.latestScan.openAps
          : '2.4GHz CH 1-13 | SEC:' + state.latestScan.secureAps + ' OPEN:' + state.latestScan.openAps;
        if (!compact && band5 > 0) {
          rawSummary += ' 5G:' + band5;
        }
        if (!compact && band6 > 0) {
          rawSummary += ' 6G:' + band6;
        }
        spectrumSummary = truncateText(rawSummary, maxFrameCols);
      }
    }

    const rfGuardRows = [];
    let rfGuardSummary = '';
    let rfGuardEmptyHint = '';
    if (onRfGuard) {
      const bleDevs = state.bleDevices || [];
      const subSigs = state.subGhzSignals || [];
      let bleThreatCnt = 0;
      for (let i = 0; i < bleDevs.length; i++) {
        if (bleDevs[i].threat && bleDevs[i].threat !== wifi.BleThreatKind.None) {
          bleThreatCnt++;
        }
      }
      const freqStr = wifi.formatFreqMhz(state.subGhzFreqKhz || 433920);
      rfGuardSummary = compact
        ? 'B:' + bleDevs.length + ' T:' + bleThreatCnt + ' ' + freqStr
        : 'BLE:' + bleDevs.length + ' TAG:' + bleThreatCnt + ' | SUB:' + freqStr;

      const maxGuardRows = Math.max(1, maxRadarRows - 1);
      for (let i = 0; i < bleDevs.length && rfGuardRows.length < maxGuardRows; i++) {
        const d = bleDevs[i];
        const isThreat = Boolean(d.threat && d.threat !== wifi.BleThreatKind.None);
        const baseName = d.name || d.mac || 'BLE';
        const title = isThreat ? '[' + wifi.bleThreatLabel(d.threat) + '] ' + baseName : baseName;
        rfGuardRows.push({
          ssid: truncateText(title, maxSsidChars),
          details: 'BLE ' + d.rssi,
          bars: wifi.rssiToBars(d.rssi),
          secure: isThreat
        });
      }
      for (let i = 0; i < subSigs.length && rfGuardRows.length < maxGuardRows; i++) {
        const sig = subSigs[i];
        const isAnom = Boolean(sig.anomaly && sig.anomaly !== wifi.SubGhzAnomaly.None);
        const title =
          wifi.formatFreqMhz(sig.freqKhz) +
          ' ' +
          sig.protocol +
          (isAnom ? ' ' + wifi.subGhzAnomalyLabel(sig.anomaly) : '');
        rfGuardRows.push({
          ssid: truncateText(title, maxSsidChars),
          details: 'SUB ' + sig.rssi,
          bars: wifi.rssiToBars(sig.rssi),
          secure: isAnom
        });
      }
      rfGuardEmptyHint = truncateText('RF Guard idle (' + freqStr + ')', maxFrameCols);
    }

    let captureSummary = '';
    let captureRows = [];
    if (onCaptures) {
      const bleDevs = state.bleDevices || [];
      const subSigs = state.subGhzSignals || [];
      captureSummary = truncateText(
        compact ? 'SAVED:' + capturesSaved + ' [STORAGE]' : 'CAPTURES SAVED: ' + capturesSaved,
        maxFrameCols
      );
      captureRows = formatCapturePathRows(capturePath, maxFrameCols);
      captureRows.push(
        truncateText(
          'AP:' + state.latestScan.totalAps + ' BLE:' + bleDevs.length + ' SUB:' + subSigs.length,
          maxFrameCols
        )
      );
      if (!micro) {
        captureRows.push(truncateText('LAST: ' + (state.lastCaptureLabel || 'Ready'), maxFrameCols));
      }
      if (wide) {
        captureRows.push(
          truncateText(
            'RANK: Lv.' + lvlInfo.level + ' ' + lvlInfo.title + ' (HI:' + highScore + (highScoreBeaten ? '!' : '') + ')',
            maxFrameCols
          )
        );
      }
      if (!micro && (state.peersMet || 0) > 0) {
        let frens = 'FRENS: ' + state.peersMet;
        if (state.lastPeerName) {
          frens += ' (' + state.lastPeerName + ')';
        }
        captureRows.push(truncateText(frens, maxFrameCols));
      }
    }

    const toast = buildThemeToast(state, dims, compact, bodyTop, bodyBottom);

    return Object.freeze({
      dims,
      compact,
      palette,
      page: state.page,
      headerDividerY: headerDivY,
      footerDividerY: footerDivY,
      headerTextY: micro ? 1 : compact ? 2 : 5,
      footerTextY: footerDivY + (micro ? 2 : compact ? 3 : 5),
      headerLine,
      footerLine,
      face,
      faceGeom: geom,
      speechX,
      speechTopY,
      lineStepY,
      promptLabel,
      phraseLines: wrappedPhrase,
      spotlightLabel,
      radarRows,
      radarEmptyHint,
      channelBars,
      chartBaseY,
      chartMaxBarH,
      spectrumSummary,
      rfGuardRows,
      rfGuardSummary,
      rfGuardEmptyHint,
      capturesSaved,
      capturePath,
      captureSummary,
      captureRows: Object.freeze(captureRows),
      theme: state.theme,
      themeEffect: themes.themeSpec(state.theme).effect,
      faceStyle,
      animTick: Math.floor((state.uptimeMs >>> 0) / 140),
      toast,
      offensiveArmed: Boolean(state.offensiveArmed),
      opsMode: effectiveMode,
      modeBadge,
      level: lvlInfo.level,
      xp: lvlInfo.xp,
      highScore,
      xpProgressPct: lvlInfo.progressPct,
      rankLine,
      scene,
      threatBanner,
      highScoreBeaten,
      levelTitle: lvlInfo.title,
      notifyActive,
      notifyKind,
      notifyBanner
    });
  }

  function renderAsciiPreview(frame) {
    const innerW =
      frame.dims.width === 160 ? 28 : Math.max(22, Math.floor(frame.dims.width / 6));
    const padLine = function (content) {
      const clipped = truncateText(content, innerW);
      return '| ' + clipped + ' '.repeat(innerW - clipped.length) + ' |\n';
    };
    const border = '+-' + '-'.repeat(innerW) + '-+\n';

    let out = border;
    out += padLine(frame.headerLine + ' ' + frame.modeBadge);
    out += border;

    if (frame.toast && frame.toast.visible) {
      out += padLine('** ' + frame.toast.text + ' **');
    }

    if (frame.page === logic.ScreenPage.PetFace) {
      out += padLine(frame.face.asciiFace + '  ' + frame.promptLabel);
      for (let i = 0; i < frame.phraseLines.length; i++) {
        out += padLine('       ' + frame.phraseLines[i]);
      }
      out += padLine('[' + frame.face.moodLabel + '] ' + (frame.rankLine || ''));
      if (frame.spotlightLabel) {
        out += padLine('       ' + frame.spotlightLabel);
      }
    } else if (frame.page === logic.ScreenPage.NearbyRadar) {
      out += padLine('NEARBY WIFI RADAR');
      if (frame.radarRows.length === 0) {
        out += padLine(frame.radarEmptyHint);
      } else {
        for (let i = 0; i < frame.radarRows.length; i++) {
          const row = frame.radarRows[i];
          const lockChar = row.secure ? '*' : ' ';
          out += padLine(lockChar + row.ssid + ' ' + row.details);
        }
      }
    } else if (frame.page === logic.ScreenPage.ChannelSpectrum) {
      out += padLine(frame.spectrumSummary);
      const countsRow =
        'CH:' +
        frame.channelBars
          .map(function (b) {
            return String(b.count);
          })
          .join(' ');
      out += padLine(countsRow);
    } else if (frame.page === logic.ScreenPage.RfGuard) {
      out += padLine(frame.rfGuardSummary);
      if (frame.rfGuardRows.length === 0) {
        out += padLine(frame.rfGuardEmptyHint);
      } else {
        for (let i = 0; i < frame.rfGuardRows.length; i++) {
          const row = frame.rfGuardRows[i];
          const alertChar = row.secure ? '!' : ' ';
          out += padLine(alertChar + row.ssid + ' ' + row.details);
        }
      }
    } else {
      out += padLine(frame.captureSummary);
      for (let i = 0; i < frame.captureRows.length; i++) {
        out += padLine(frame.captureRows[i]);
      }
    }
    if (frame.notifyActive && frame.page !== logic.ScreenPage.PetFace && frame.notifyBanner) {
      out += padLine(frame.notifyBanner);
    }

    out += border;
    out += padLine(frame.footerLine);
    out += border;
    return out;
  }

  const uiModel = Object.freeze({
    ActivityScene,
    SCREEN_PROFILES,
    screenProfileFromKey,
    rgb565,
    resolvePalette,
    twoDigit,
    formatUptime,
    truncateText,
    wrapWords,
    formatCapturePathRows,
    buildThemeToast,
    buildUiFrame,
    renderAsciiPreview
  });

  root.ZD = root.ZD || {};
  root.ZD.uiModel = uiModel;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = uiModel;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
