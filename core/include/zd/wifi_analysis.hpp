#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "domain.hpp"
#include "fp.hpp"
#include "oui.hpp"

namespace zd {

// Pure string sanitizer: strips non-printable characters so TFT bitmap fonts render cleanly.
inline std::string sanitizePrintable(const std::string& raw) {
    std::string cleaned;
    cleaned.reserve(raw.size());
    for (unsigned char ch : raw) {
        if (ch >= 32u && ch <= 126u) {
            cleaned.push_back(static_cast<char>(ch));
        }
    }
    // Trim trailing spaces
    while (!cleaned.empty() && cleaned.back() == ' ') {
        cleaned.pop_back();
    }
    return cleaned.empty() ? std::string("<hidden>") : cleaned;
}

constexpr int32_t k6GhzChannelBase = 6000;

constexpr bool is24GhzChannel(int32_t ch) {
    return ch >= 1 && ch <= 14;
}

constexpr bool is5GhzChannel(int32_t ch) {
    return ch >= 36 && ch <= 177;
}

constexpr bool is6GhzChannel(int32_t ch) {
    return ch >= 6001 && ch <= 6233;
}

constexpr std::size_t nearest5GhzBucket(int32_t ch) {
    std::size_t bestIdx = 0u;
    int32_t bestDiff = (kSpectrum5GhzChannels[0] >= ch) ? (kSpectrum5GhzChannels[0] - ch)
                                                       : (ch - kSpectrum5GhzChannels[0]);
    for (std::size_t i = 1u; i < kSpectrum5GhzChannels.size(); ++i) {
        const int32_t c = kSpectrum5GhzChannels[i];
        const int32_t diff = (c >= ch) ? (c - ch) : (ch - c);
        if (diff < bestDiff) {
            bestDiff = diff;
            bestIdx = i;
        }
    }
    return bestIdx;
}

// Pure normalization of a single raw WiFi scan entry.
inline AccessPoint sanitizeAccessPoint(const AccessPoint& raw) {
    const int32_t normalizedChannel =
        (is24GhzChannel(raw.channel) || is5GhzChannel(raw.channel) || is6GhzChannel(raw.channel))
            ? raw.channel
            : 0;
    const int32_t clampedRssi = fp::clampVal<int32_t>(raw.rssi, -100, 0);
    return AccessPoint{
        sanitizePrintable(raw.ssid),
        clampedRssi,
        normalizedChannel,
        raw.secure
    };
}

// Pure comparator: strongest RSSI first, deterministic tie-breaker by SSID then channel.
inline bool isStrongerAp(const AccessPoint& a, const AccessPoint& b) {
    if (a.rssi != b.rssi) {
        return a.rssi > b.rssi;
    }
    if (a.ssid != b.ssid) {
        return a.ssid < b.ssid;
    }
    return a.channel < b.channel;
}

// Deduplicates repeated mesh BSSIDs from a sorted AP list,
// keeping the strongest signal for each named SSID (and per-channel for <hidden>).
// Optional `maxCount` stops as soon as enough unique APs are collected (0 = unlimited).
inline std::vector<AccessPoint> deduplicateSortedAps(const std::vector<AccessPoint>& sortedAps,
                                                     std::size_t maxCount = 0) {
    std::vector<AccessPoint> result;
    result.reserve(maxCount > 0 ? std::min(maxCount, sortedAps.size()) : sortedAps.size());
    const bool useHash = (maxCount == 0u || sortedAps.size() > 32u);
    std::unordered_set<std::string> seenSsids;
    std::unordered_set<int32_t> seenHiddenChannels;
    if (useHash) {
        seenSsids.reserve(sortedAps.size());
    }
    for (const AccessPoint& candidate : sortedAps) {
        const bool isHidden = (candidate.ssid == "<hidden>");
        bool alreadyPresent = false;
        if (useHash) {
            alreadyPresent = isHidden ? !seenHiddenChannels.insert(candidate.channel).second
                                      : !seenSsids.insert(candidate.ssid).second;
        } else {
            for (const AccessPoint& existing : result) {
                if (isHidden ? (existing.ssid == "<hidden>" && existing.channel == candidate.channel)
                             : (existing.ssid == candidate.ssid)) {
                    alreadyPresent = true;
                    break;
                }
            }
        }
        if (!alreadyPresent) {
            result.push_back(candidate);
            if (maxCount > 0 && result.size() >= maxCount) {
                break;
            }
        }
    }
    return result;
}

// Pure fold computing per-channel AP counts across 2.4 GHz (1..13), 5 GHz UNII buckets, and 6 GHz.
inline ChannelHistogram buildChannelHistogram(const std::vector<AccessPoint>& aps) {
    ChannelHistogram hist{};
    auto bump = [](uint16_t& dst) {
        if (dst < 999u) {
            dst = static_cast<uint16_t>(dst + 1u);
        }
    };
    for (const AccessPoint& ap : aps) {
        if (ap.channel >= 1 && ap.channel <= 13) {
            bump(hist.counts[static_cast<std::size_t>(ap.channel)]);
            bump(hist.band24GhzAps);
        } else if (ap.channel == 14) {
            bump(hist.counts[0]);
            bump(hist.band24GhzAps);
        } else if (is5GhzChannel(ap.channel)) {
            bump(hist.counts[0]);
            bump(hist.band5GhzAps);
            bump(hist.counts5Ghz[nearest5GhzBucket(ap.channel)]);
        } else if (is6GhzChannel(ap.channel)) {
            bump(hist.counts[0]);
            bump(hist.band6GhzAps);
        } else {
            bump(hist.counts[0]);
        }
    }
    return hist;
}

// Pure fold finding which 2.4 GHz (or 5 GHz if no 2.4 GHz APs) channel has the most APs.
inline int32_t findBusiestChannel(const ChannelHistogram& hist) {
    constexpr std::array<int32_t, 13> kChannels = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    struct Best {
        int32_t channel;
        uint16_t count;
    };
    const Best best = fp::foldl(
        kChannels,
        Best{0, 0},
        [&](Best current, int32_t ch) {
            const uint16_t c = hist.counts[static_cast<std::size_t>(ch)];
            return (c > current.count) ? Best{ch, c} : current;
        });
    if (best.count > 0u) {
        return best.channel;
    }
    Best best5{0, 0};
    for (std::size_t i = 0u; i < kSpectrum5GhzChannels.size(); ++i) {
        const uint16_t c = hist.counts5Ghz[i];
        if (c > best5.count) {
            best5 = Best{kSpectrum5GhzChannels[i], c};
        }
    }
    return best5.channel;
}

// Pure mapping from RSSI dBm to 0..4 visual signal strength bars.
constexpr int rssiToBars(int32_t rssi) {
    if (rssi >= -55) return 4;
    if (rssi >= -67) return 3;
    if (rssi >= -78) return 2;
    if (rssi >= -88) return 1;
    return 0;
}

// Pure functional pipeline transforming raw scan records into an immutable ScanSummary.
inline ScanSummary summarizeScan(const std::vector<AccessPoint>& rawNetworks,
                                 std::size_t maxTop = 6) {
    std::vector<AccessPoint> sanitized = fp::map(rawNetworks, sanitizeAccessPoint);
    std::sort(sanitized.begin(), sanitized.end(), isStrongerAp);

    const std::size_t total = sanitized.size();
    const std::size_t secureCount = fp::countIf(sanitized, [](const AccessPoint& ap) {
        return ap.secure;
    });
    const ChannelHistogram histogram = buildChannelHistogram(sanitized);
    const int32_t busiestCh = findBusiestChannel(histogram);

    const std::vector<AccessPoint> topUnique = deduplicateSortedAps(sanitized, maxTop);

    const int32_t bestRssi = sanitized.empty() ? -100 : sanitized.front().rssi;
    const std::string bestSsid = sanitized.empty() ? std::string{} : sanitized.front().ssid;

    return ScanSummary{
        total,
        secureCount,
        total - secureCount,
        bestRssi,
        busiestCh,
        bestSsid,
        topUnique,
        histogram
    };
}

// --- Pure BLE Tracker / Multi-Tool & Sub-GHz Helpers ----------------------------------

// Extracts a primary 16-bit BLE Service UUID (0x02/0x03 UUID lists or 0x16 Service Data AD)
// from a raw BLE advertisement payload, prioritizing multi-tool/tracker signatures.
inline uint16_t extractBle16ServiceUuid(const uint8_t* payload, std::size_t len) {
    if (payload == nullptr || len == 0u) {
        return 0u;
    }
    uint16_t firstUuid = 0u;
    std::size_t pos = 0u;
    while (pos < len) {
        const uint8_t adLen = payload[pos];
        if (adLen == 0u || pos + 1u + static_cast<std::size_t>(adLen) > len) {
            break;
        }
        const uint8_t adType = payload[pos + 1u];
        const std::size_t dataStart = pos + 2u;
        const std::size_t dataEnd = pos + 1u + static_cast<std::size_t>(adLen);
        if ((adType == 0x02u || adType == 0x03u) && (dataEnd - dataStart) >= 2u) {
            for (std::size_t k = dataStart; k + 1u < dataEnd; k += 2u) {
                const uint16_t uuid = static_cast<uint16_t>(
                    static_cast<uint16_t>(payload[k]) |
                    (static_cast<uint16_t>(payload[k + 1u]) << 8u));
                if (uuid == 0xFEEDu || (uuid >= 0x3080u && uuid <= 0x3083u)) {
                    return uuid;
                }
                if (firstUuid == 0u && uuid != 0u) {
                    firstUuid = uuid;
                }
            }
        } else if (adType == 0x16u && (dataEnd - dataStart) >= 2u) {
            const uint16_t uuid = static_cast<uint16_t>(
                static_cast<uint16_t>(payload[dataStart]) |
                (static_cast<uint16_t>(payload[dataStart + 1u]) << 8u));
            if (uuid == 0xFEEDu || (uuid >= 0x3080u && uuid <= 0x3083u)) {
                return uuid;
            }
            if (firstUuid == 0u && uuid != 0u) {
                firstUuid = uuid;
            }
        }
        pos = dataEnd;
    }
    return firstUuid;
}

inline std::string toLowerAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

inline BleThreatKind classifyBleDevice(std::string_view mac,
                                       std::string_view name,
                                       uint16_t companyId,
                                       uint16_t serviceUuid,
                                       bool trackerPayload) {
    const std::string lowerName = toLowerAscii(name);
    const std::string lowerMac = toLowerAscii(mac);

    // Multi-tool BLE signatures (e.g. Flipper Zero STMicroelectronics OUI 00:80:e1 or serial/RPC UUIDs 0x3080..0x3083)
    if ((serviceUuid >= 0x3080u && serviceUuid <= 0x3083u) ||
        lowerMac.rfind("00:80:e1", 0) == 0 ||
        lowerMac.rfind("0080e1", 0) == 0 ||
        lowerName.rfind("flipper", 0) == 0) {
        return BleThreatKind::MultiToolBle;
    }
    // Apple FindMy / AirTag (Company ID 0x004C with offline-finding payload or name hint)
    if ((companyId == 0x004Cu && trackerPayload) ||
        lowerName.find("airtag") != std::string::npos ||
        lowerName.find("findmy") != std::string::npos) {
        return BleThreatKind::AirTagTracker;
    }
    // Samsung SmartTag (Company ID 0x0075 with tracker payload or name hint)
    if ((companyId == 0x0075u && trackerPayload) ||
        lowerName.find("smarttag") != std::string::npos) {
        return BleThreatKind::SmartTagTracker;
    }
    // Tile Tracker (Service UUID 0xFEED or name hint)
    if (serviceUuid == 0xFEEDu || lowerName.find("tile") != std::string::npos) {
        return BleThreatKind::TileTracker;
    }
    if (lowerName.find("spam") != std::string::npos) {
        return BleThreatKind::BleSpam;
    }
    return BleThreatKind::None;
}

// True if a single BLE advert matches a known device-pairing notification signature — the
// payloads that Flipper Zero / ESP32 BLE-spam tools flood (Apple Continuity nearby-action /
// SourApple, Google Fast Pair, Microsoft Swift Pair, Samsung EasySetup). A single such advert
// is normal; the ATTACK signal is many of these from rapidly rotating random MACs in a short
// window, which the SecState sliding-window detector scores. Kept pure here for testability.
inline bool looksLikeBlePairingSignature(uint16_t companyId, uint16_t serviceUuid) {
    return companyId == 0x004Cu ||  // Apple Continuity (nearby-action / proximity-pairing)
           companyId == 0x0006u ||  // Microsoft Swift Pair
           companyId == 0x0075u ||  // Samsung EasySetup
           serviceUuid == 0xFE2Cu;  // Google Fast Pair
}

constexpr const char* bleThreatLabel(BleThreatKind kind) {
    switch (kind) {
        case BleThreatKind::None:            return "OK";
        case BleThreatKind::AirTagTracker:   return "LOC-TAG!";
        case BleThreatKind::SmartTagTracker: return "BLE-TAG!";
        case BleThreatKind::TileTracker:     return "KEY-TAG!";
        case BleThreatKind::MultiToolBle:    return "RF-TOOL!";
        case BleThreatKind::BleSpam:         return "SPAM!";
    }
    return "OK";
}

// Pure Bluetooth SIG company ID -> human vendor label (for BLE devices tables).
inline std::string bleVendorLabel(uint16_t companyId) {
    switch (companyId) {
        case 0x0000u: return "-";
        case 0x004Cu: return "Apple";
        case 0x0006u: return "Microsoft";
        case 0x0075u: return "Samsung";
        case 0x00E0u: return "Google";
        case 0x000Fu: return "Broadcom";
        case 0x0059u: return "Nordic";
        case 0x0087u: return "Garmin";
        case 0x0047u: return "Sony";
        case 0x0310u: return "Bose";
        case 0x000Au: return "Qualcomm";
        case 0x0157u: return "Huami";
        case 0x00D2u: return "Dialog";
        case 0x000Du: return "TI";
        default: break;
    }
    static constexpr const char kHex[] = "0123456789ABCDEF";
    std::string out = "0x";
    out.push_back(kHex[(companyId >> 12) & 0xFu]);
    out.push_back(kHex[(companyId >> 8) & 0xFu]);
    out.push_back(kHex[(companyId >> 4) & 0xFu]);
    out.push_back(kHex[companyId & 0xFu]);
    return out;
}

inline std::string bleVendorOrOuiLabel(uint16_t companyId, std::string_view mac) {
    if (companyId != 0u) {
        return bleVendorLabel(companyId);
    }
    return ouiVendorLabel(mac, "-");
}

// Pure 16-bit BLE GATT service UUID -> compact service label.
inline std::string bleServiceLabel(uint16_t uuid) {
    if (uuid == 0x0000u) {
        return "-";
    }
    if (uuid >= 0x3080u && uuid <= 0x3083u) {
        return "RF-Tool";
    }
    switch (uuid) {
        case 0xFEEDu: return "Tile";
        case 0x180Du: return "HeartRate";
        case 0x180Fu: return "Battery";
        case 0x1812u: return "HID";
        case 0x110Bu: return "Audio";
        case 0xFE2Cu:
        case 0xFE9Fu: return "FastPair";
        case 0xFD6Fu: return "Exposure";
        default: break;
    }
    static constexpr const char kHex[] = "0123456789ABCDEF";
    std::string out = "0x";
    out.push_back(kHex[(uuid >> 12) & 0xFu]);
    out.push_back(kHex[(uuid >> 8) & 0xFu]);
    out.push_back(kHex[(uuid >> 4) & 0xFu]);
    out.push_back(kHex[uuid & 0xFu]);
    return out;
}

constexpr const char* subGhzAnomalyLabel(SubGhzAnomaly anomaly) {
    switch (anomaly) {
        case SubGhzAnomaly::None:           return "OK";
        case SubGhzAnomaly::ReplayBurst:    return "REPLAY!";
        case SubGhzAnomaly::JammingCarrier: return "JAMMING!";
        case SubGhzAnomaly::RollingCode:    return "ROLLING";
    }
    return "OK";
}

inline std::string formatFreqMhz(uint32_t freqKhz) {
    const uint32_t whole = freqKhz / 1000u;
    const uint32_t frac = (freqKhz % 1000u) / 10u;  // 2 decimal places
    std::string f = std::to_string(frac);
    if (f.size() < 2u) {
        f = "0" + f;
    }
    return std::to_string(whole) + "." + f + "MHz";
}

}  // namespace zd
