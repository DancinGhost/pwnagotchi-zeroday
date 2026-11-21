// Pure functional WiFi scan analysis pipeline (ported from core/include/zd/wifi_analysis.hpp).
(function (root) {
  'use strict';

  const fp = (root.ZD && root.ZD.fp) || (typeof require === 'function' ? require('./fp.js') : null);

  function sanitizePrintable(raw) {
    const str = String(raw == null ? '' : raw);
    let cleaned = '';
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      if (code >= 32 && code <= 126) {
        cleaned += str[i];
      }
    }
    cleaned = cleaned.replace(/ +$/, '');
    return cleaned.length === 0 ? '<hidden>' : cleaned;
  }

  function sanitizeAccessPoint(raw) {
    const ch = Number.isFinite(raw.channel) ? Math.trunc(raw.channel) : 0;
    const normalizedChannel = ch >= 1 && ch <= 13 ? ch : 0;
    const rawRssi = Number.isFinite(raw.rssi) ? Math.trunc(raw.rssi) : -100;
    const clampedRssi = fp.clampVal(rawRssi, -100, 0);
    return Object.freeze({
      ssid: sanitizePrintable(raw.ssid),
      rssi: clampedRssi,
      channel: normalizedChannel,
      secure: Boolean(raw.secure)
    });
  }

  function isStrongerAp(a, b) {
    if (a.rssi !== b.rssi) {
      return a.rssi > b.rssi;
    }
    if (a.ssid !== b.ssid) {
      return a.ssid < b.ssid;
    }
    return a.channel < b.channel;
  }

  function deduplicateSortedAps(sortedAps) {
    const result = [];
    const seenSsids = new Set();
    const seenHiddenChannels = new Set();
    for (let i = 0; i < sortedAps.length; i++) {
      const candidate = sortedAps[i];
      if (candidate.ssid === '<hidden>') {
        if (!seenHiddenChannels.has(candidate.channel)) {
          seenHiddenChannels.add(candidate.channel);
          result.push(candidate);
        }
      } else if (!seenSsids.has(candidate.ssid)) {
        seenSsids.add(candidate.ssid);
        result.push(candidate);
      }
    }
    return result;
  }

  function buildChannelHistogram(aps) {
    const counts = new Array(14).fill(0);
    for (let i = 0; i < aps.length; i++) {
      const ch = aps[i].channel;
      const bucket = ch >= 1 && ch <= 13 ? ch : 0;
      if (counts[bucket] < 999) {
        counts[bucket] += 1;
      }
    }
    return Object.freeze({ counts: Object.freeze(counts) });
  }

  function findBusiestChannel(hist) {
    const kChannels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    const best = fp.foldl(kChannels, { channel: 0, count: 0 }, function (current, ch) {
      const c = hist.counts[ch] || 0;
      return c > current.count ? { channel: ch, count: c } : current;
    });
    return best.channel;
  }

  function rssiToBars(rssi) {
    if (rssi >= -55) return 4;
    if (rssi >= -67) return 3;
    if (rssi >= -78) return 2;
    if (rssi >= -88) return 1;
    return 0;
  }

  function emptyScanSummary() {
    return Object.freeze({
      totalAps: 0,
      secureAps: 0,
      openAps: 0,
      strongestRssi: -100,
      busiestChannel: 0,
      strongestSsid: '',
      topNetworks: Object.freeze([]),
      histogram: Object.freeze({ counts: Object.freeze(new Array(14).fill(0)) })
    });
  }

  function summarizeScan(rawNetworks, maxTop) {
    const limit = maxTop === undefined ? 6 : maxTop;
    const sanitized = fp.pipe(
      rawNetworks || [],
      fp.mapped(sanitizeAccessPoint),
      fp.sortedBy(isStrongerAp)
    );

    const total = sanitized.length;
    const secureCount = fp.countIf(sanitized, function (ap) {
      return ap.secure;
    });
    const histogram = buildChannelHistogram(sanitized);
    const busiestCh = findBusiestChannel(histogram);

    const topUnique = fp.pipe(sanitized, deduplicateSortedAps, fp.taken(limit));

    const bestRssi = sanitized.length === 0 ? -100 : sanitized[0].rssi;
    const bestSsid = sanitized.length === 0 ? '' : sanitized[0].ssid;

    return Object.freeze({
      totalAps: total,
      secureAps: secureCount,
      openAps: total - secureCount,
      strongestRssi: bestRssi,
      busiestChannel: busiestCh,
      strongestSsid: bestSsid,
      topNetworks: Object.freeze(topUnique),
      histogram
    });
  }

  const BleThreatKind = Object.freeze({
    None: 'None',
    AirTagTracker: 'AirTagTracker',
    SmartTagTracker: 'SmartTagTracker',
    TileTracker: 'TileTracker',
    MultiToolBle: 'MultiToolBle',
    BleSpam: 'BleSpam'
  });

  const SubGhzAnomaly = Object.freeze({
    None: 'None',
    ReplayBurst: 'ReplayBurst',
    JammingCarrier: 'JammingCarrier',
    RollingCode: 'RollingCode'
  });

  function classifyBleDevice(mac, name, companyId, serviceUuid, trackerPayload) {
    const lowerName = String(name || '').toLowerCase();
    const lowerMac = String(mac || '').toLowerCase();
    const cid = Math.trunc(companyId || 0);
    const uuid = Math.trunc(serviceUuid || 0);

    if ((uuid >= 0x3080 && uuid <= 0x3083) ||
        lowerMac.indexOf('00:80:e1') === 0 ||
        lowerMac.indexOf('0080e1') === 0 ||
        lowerName.indexOf('flipper') === 0) {
      return BleThreatKind.MultiToolBle;
    }
    if ((cid === 0x004c && Boolean(trackerPayload)) ||
        lowerName.indexOf('airtag') >= 0 ||
        lowerName.indexOf('findmy') >= 0) {
      return BleThreatKind.AirTagTracker;
    }
    if ((cid === 0x0075 && Boolean(trackerPayload)) ||
        lowerName.indexOf('smarttag') >= 0) {
      return BleThreatKind.SmartTagTracker;
    }
    if (uuid === 0xfeed || lowerName.indexOf('tile') >= 0) {
      return BleThreatKind.TileTracker;
    }
    if (lowerName.indexOf('spam') >= 0) {
      return BleThreatKind.BleSpam;
    }
    return BleThreatKind.None;
  }

  function bleThreatLabel(kind) {
    switch (kind) {
      case BleThreatKind.AirTagTracker: return 'LOC-TAG!';
      case BleThreatKind.SmartTagTracker: return 'BLE-TAG!';
      case BleThreatKind.TileTracker: return 'KEY-TAG!';
      case BleThreatKind.MultiToolBle: return 'RF-TOOL!';
      case BleThreatKind.BleSpam: return 'SPAM!';
      default: return 'OK';
    }
  }

  function subGhzAnomalyLabel(anomaly) {
    switch (anomaly) {
      case SubGhzAnomaly.ReplayBurst: return 'REPLAY!';
      case SubGhzAnomaly.JammingCarrier: return 'JAMMING!';
      case SubGhzAnomaly.RollingCode: return 'ROLLING';
      default: return 'OK';
    }
  }

  function formatFreqMhz(freqKhz) {
    const k = Math.max(0, Math.trunc(freqKhz || 0));
    const whole = Math.floor(k / 1000);
    const frac = String(Math.floor((k % 1000) / 10)).padStart(2, '0');
    return whole + '.' + frac + 'MHz';
  }

  const wifiAnalysis = Object.freeze({
    BleThreatKind,
    SubGhzAnomaly,
    classifyBleDevice,
    bleThreatLabel,
    subGhzAnomalyLabel,
    formatFreqMhz,
    sanitizePrintable,
    sanitizeAccessPoint,
    isStrongerAp,
    deduplicateSortedAps,
    buildChannelHistogram,
    findBusiestChannel,
    rssiToBars,
    emptyScanSummary,
    summarizeScan
  });

  root.ZD = root.ZD || {};
  root.ZD.wifiAnalysis = wifiAnalysis;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = wifiAnalysis;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
