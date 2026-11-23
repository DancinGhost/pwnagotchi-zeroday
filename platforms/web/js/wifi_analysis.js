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

  const K_6GHZ_CHANNEL_BASE = 6000;
  const K_SPECTRUM_5GHZ_CHANNELS = Object.freeze([36, 40, 44, 48, 52, 64, 100, 116, 132, 149, 153, 157, 161]);

  function is24GhzChannel(ch) {
    return ch >= 1 && ch <= 14;
  }

  function is5GhzChannel(ch) {
    return ch >= 36 && ch <= 177;
  }

  function is6GhzChannel(ch) {
    return ch >= 6001 && ch <= 6233;
  }

  function nearest5GhzBucket(ch) {
    let bestIdx = 0;
    let bestDiff = Math.abs(K_SPECTRUM_5GHZ_CHANNELS[0] - ch);
    for (let i = 1; i < K_SPECTRUM_5GHZ_CHANNELS.length; i++) {
      const diff = Math.abs(K_SPECTRUM_5GHZ_CHANNELS[i] - ch);
      if (diff < bestDiff) {
        bestDiff = diff;
        bestIdx = i;
      }
    }
    return bestIdx;
  }

  function sanitizeAccessPoint(raw) {
    const ch = Number.isFinite(raw.channel) ? Math.trunc(raw.channel) : 0;
    const normalizedChannel = (is24GhzChannel(ch) || is5GhzChannel(ch) || is6GhzChannel(ch)) ? ch : 0;
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
    const counts5Ghz = new Array(13).fill(0);
    let band24GhzAps = 0;
    let band5GhzAps = 0;
    let band6GhzAps = 0;
    for (let i = 0; i < aps.length; i++) {
      const ch = aps[i].channel;
      if (ch >= 1 && ch <= 13) {
        if (counts[ch] < 999) counts[ch] += 1;
        if (band24GhzAps < 999) band24GhzAps += 1;
      } else if (ch === 14) {
        if (counts[0] < 999) counts[0] += 1;
        if (band24GhzAps < 999) band24GhzAps += 1;
      } else if (is5GhzChannel(ch)) {
        if (counts[0] < 999) counts[0] += 1;
        if (band5GhzAps < 999) band5GhzAps += 1;
        const b = nearest5GhzBucket(ch);
        if (counts5Ghz[b] < 999) counts5Ghz[b] += 1;
      } else if (is6GhzChannel(ch)) {
        if (counts[0] < 999) counts[0] += 1;
        if (band6GhzAps < 999) band6GhzAps += 1;
      } else {
        if (counts[0] < 999) counts[0] += 1;
      }
    }
    return Object.freeze({
      counts: Object.freeze(counts),
      counts5Ghz: Object.freeze(counts5Ghz),
      band24GhzAps,
      band5GhzAps,
      band6GhzAps
    });
  }

  function findBusiestChannel(hist) {
    const kChannels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
    const best = fp.foldl(kChannels, { channel: 0, count: 0 }, function (current, ch) {
      const c = hist.counts[ch] || 0;
      return c > current.count ? { channel: ch, count: c } : current;
    });
    if (best.count > 0) {
      return best.channel;
    }
    const c5 = hist.counts5Ghz || [];
    let best5 = { channel: 0, count: 0 };
    for (let i = 0; i < K_SPECTRUM_5GHZ_CHANNELS.length; i++) {
      const c = c5[i] || 0;
      if (c > best5.count) {
        best5 = { channel: K_SPECTRUM_5GHZ_CHANNELS[i], count: c };
      }
    }
    return best5.channel;
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
      histogram: Object.freeze({
        counts: Object.freeze(new Array(14).fill(0)),
        counts5Ghz: Object.freeze(new Array(13).fill(0)),
        band24GhzAps: 0,
        band5GhzAps: 0,
        band6GhzAps: 0
      })
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

  function formatHex16(val) {
    const hex = (Math.trunc(val || 0) & 0xffff).toString(16).toUpperCase();
    return '0x' + hex.padStart(4, '0');
  }

  function bleVendorLabel(companyId) {
    const cid = Math.trunc(companyId || 0) & 0xffff;
    switch (cid) {
      case 0x0000: return '-';
      case 0x004c: return 'Apple';
      case 0x0006: return 'Microsoft';
      case 0x0075: return 'Samsung';
      case 0x00e0: return 'Google';
      case 0x000f: return 'Broadcom';
      case 0x0059: return 'Nordic';
      case 0x0087: return 'Garmin';
      case 0x0047: return 'Sony';
      case 0x0310: return 'Bose';
      case 0x000a: return 'Qualcomm';
      case 0x0157: return 'Huami';
      case 0x00d2: return 'Dialog';
      case 0x000d: return 'TI';
      default: return formatHex16(cid);
    }
  }

  function bleServiceLabel(uuid) {
    const u = Math.trunc(uuid || 0) & 0xffff;
    if (u === 0x0000) return '-';
    if (u >= 0x3080 && u <= 0x3083) return 'RF-Tool';
    switch (u) {
      case 0xfeed: return 'Tile';
      case 0x180d: return 'HeartRate';
      case 0x180f: return 'Battery';
      case 0x1812: return 'HID';
      case 0x110b: return 'Audio';
      case 0xfe2c:
      case 0xfe9f: return 'FastPair';
      case 0xfd6f: return 'Exposure';
      default: return formatHex16(u);
    }
  }

  function bleTargetsByStrength(devices) {
    const list = Array.isArray(devices) ? devices.slice() : [];
    list.sort(function (a, b) {
      const ta = a && a.threat && a.threat !== BleThreatKind.None ? 1 : 0;
      const tb = b && b.threat && b.threat !== BleThreatKind.None ? 1 : 0;
      if (ta !== tb) return tb - ta;
      const ra = Number.isFinite(a && a.rssi) ? a.rssi : -100;
      const rb = Number.isFinite(b && b.rssi) ? b.rssi : -100;
      if (rb !== ra) return rb - ra;
      return String((a && a.mac) || '').localeCompare(String((b && b.mac) || ''));
    });
    return list;
  }

  const OUI_CATALOG = Object.freeze([
    [0x00000c, 'Cisco'],
    [0x00037f, 'Atheros'],
    [0x000393, 'Apple'],
    [0x000a95, 'Apple'],
    [0x000b86, 'Aruba'],
    [0x000c42, 'MikroTik'],
    [0x000ce7, 'MediaTek'],
    [0x000f00, 'Legra'],
    [0x001122, 'Cimsysen'],
    [0x001310, 'Linksys'],
    [0x00146c, 'Netgear'],
    [0x00156d, 'Ubiquiti'],
    [0x0017f2, 'Apple'],
    [0x0018e7, 'Cameo'],
    [0x001a11, 'Google'],
    [0x001b21, 'Intel'],
    [0x001b63, 'Apple'],
    [0x001d7e, 'Linksys'],
    [0x0024a5, 'Buffalo'],
    [0x00259c, 'Linksys'],
    [0x002722, 'Ubiquiti'],
    [0x005056, 'VMware'],
    [0x0050f2, 'Microsoft'],
    [0x0080e1, 'STMicro'],
    [0x00c0ca, 'Alfa'],
    [0x00e04c, 'Realtek'],
    [0x0418d6, 'Ubiquiti'],
    [0x080027, 'VirtualBox'],
    [0x18e829, 'Ubiquiti'],
    [0x240ac4, 'Espressif'],
    [0x2462ab, 'Espressif'],
    [0x24a43c, 'Ubiquiti'],
    [0x286dcd, 'WinnerMicro'],
    [0x2c3ae8, 'Espressif'],
    [0x30aea4, 'Espressif'],
    [0x3c71bf, 'Espressif'],
    [0x44d9e7, 'Ubiquiti'],
    [0x50c7bf, 'TP-Link'],
    [0x58bf25, 'Espressif'],
    [0x600194, 'Espressif'],
    [0x68c63a, 'Espressif'],
    [0x704d7b, 'Asus'],
    [0x74da38, 'Edimax'],
    [0x788a20, 'Ubiquiti'],
    [0x802aa8, 'Ubiquiti'],
    [0x84f3eb, 'Espressif'],
    [0x94b97e, 'Espressif'],
    [0x98ded0, 'TP-Link'],
    [0xa020a6, 'Espressif'],
    [0xa4cf12, 'Espressif'],
    [0xac67b2, 'Espressif'],
    [0xb0b98a, 'Netgear'],
    [0xb4e62d, 'Espressif'],
    [0xb827eb, 'RaspberryPi'],
    [0xbcff4d, 'Espressif'],
    [0xc05627, 'Belkin'],
    [0xc46e1f, 'TP-Link'],
    [0xcc50e3, 'Espressif'],
    [0xd83add, 'RaspberryPi'],
    [0xdc4f22, 'Espressif'],
    [0xdca632, 'RaspberryPi'],
    [0xe09806, 'Espressif'],
    [0xe45f01, 'RaspberryPi'],
    [0xecfa5c, 'Espressif'],
    [0xf09fc2, 'Ubiquiti'],
    [0xf4cfa2, 'Espressif'],
    [0xf8e903, 'Apple'],
    [0xfcecda, 'Ubiquiti']
  ]);

  function parseOui24(mac) {
    const s = String(mac || '');
    let prefix = 0;
    let nibbles = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (ch === ':' || ch === '-' || ch === ' ' || ch === '\t') {
        continue;
      }
      const nib = parseInt(ch, 16);
      if (Number.isNaN(nib)) {
        return null;
      }
      prefix = ((prefix << 4) | nib) >>> 0;
      nibbles++;
      if (nibbles === 6) {
        return prefix;
      }
    }
    return null;
  }

  function lookupOuiVendor(mac) {
    const oui = parseOui24(mac);
    if (oui === null) return '';
    let lo = 0;
    let hi = OUI_CATALOG.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const p = OUI_CATALOG[mid][0];
      if (p === oui) return OUI_CATALOG[mid][1];
      if (p < oui) lo = mid + 1;
      else hi = mid - 1;
    }
    return '';
  }

  function isLocallyAdministeredMac(mac) {
    const oui = parseOui24(mac);
    if (oui === null) return false;
    return (((oui >>> 16) & 0xff) & 0x02) !== 0;
  }

  function ouiVendorLabel(mac, fallback) {
    const v = lookupOuiVendor(mac);
    if (v) return v;
    if (isLocallyAdministeredMac(mac)) return 'random';
    return fallback !== undefined && fallback !== null ? String(fallback) : '-';
  }

  function bleVendorOrOuiLabel(companyId, mac) {
    const cid = Math.trunc(companyId || 0) & 0xffff;
    if (cid !== 0) {
      return bleVendorLabel(cid);
    }
    return ouiVendorLabel(mac, '-');
  }

  const wifiAnalysis = Object.freeze({
    K_6GHZ_CHANNEL_BASE,
    K_SPECTRUM_5GHZ_CHANNELS,
    OUI_CATALOG,
    is24GhzChannel,
    is5GhzChannel,
    is6GhzChannel,
    nearest5GhzBucket,
    parseOui24,
    lookupOuiVendor,
    isLocallyAdministeredMac,
    ouiVendorLabel,
    bleVendorOrOuiLabel,
    BleThreatKind,
    SubGhzAnomaly,
    classifyBleDevice,
    bleThreatLabel,
    bleVendorLabel,
    bleServiceLabel,
    bleTargetsByStrength,
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
