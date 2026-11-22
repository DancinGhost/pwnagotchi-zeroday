#pragma once

// Pure, host-testable parsers for Linux WiFi-tool output.
//
// These contain NO subprocess or socket calls: they turn the textual output of `nmcli`,
// `iw dev scan`, and `airodump-ng`'s CSV dump into portable `zd` value types. Keeping the
// parsing pure means tests/core/test_linux_parsers.cpp can validate them against captured
// sample output with zero hardware or root. The thin IO adapters (cli_backend.hpp) only
// shell out and hand the resulting text to these functions.

#include <array>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "zd/domain.hpp"
#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"

namespace zd {
namespace linux_backend {

inline std::string trim(const std::string& s) {
    std::size_t a = 0;
    std::size_t b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) {
        ++a;
    }
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) {
        --b;
    }
    return s.substr(a, b - a);
}

// Map a human security string ("WPA2", "WPA3 802.1X", "--", "CCMP", "OPN") to Encryption.
inline sec::Encryption encryptionFromText(const std::string& raw) {
    std::string up;
    up.reserve(raw.size());
    for (char c : raw) {
        up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (up.find("WPA3") != std::string::npos || up.find("SAE") != std::string::npos) {
        return sec::Encryption::Wpa3;
    }
    if (up.find("WPA2") != std::string::npos || up.find("RSN") != std::string::npos ||
        up.find("CCMP") != std::string::npos) {
        return sec::Encryption::Wpa2;
    }
    if (up.find("WPA") != std::string::npos) {
        return sec::Encryption::Wpa;
    }
    if (up.find("WEP") != std::string::npos) {
        return sec::Encryption::Wep;
    }
    const std::string t = trim(up);
    if (t.empty() || t == "--" || t.find("OPN") != std::string::npos ||
        t.find("OPEN") != std::string::npos || t.find("NONE") != std::string::npos) {
        return sec::Encryption::Open;
    }
    return sec::Encryption::Unknown;
}

// nmcli signal 0..100 -> approximate dBm (nmcli reports quality, not raw dBm).
inline int32_t nmcliSignalToDbm(int quality) {
    if (quality <= 0) {
        return -100;
    }
    if (quality >= 100) {
        return -30;
    }
    return static_cast<int32_t>(-100 + (quality * 70) / 100);
}

// Split a terminal-colon-escaped nmcli line ("-t" mode) honoring backslash escapes.
inline std::vector<std::string> splitNmcliFields(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '\\' && i + 1 < line.size()) {
            cur.push_back(line[++i]);
        } else if (c == ':') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

// Parse `nmcli -t -f BSSID,SSID,CHAN,SECURITY,SIGNAL dev wifi list`.
// Returns both legacy AccessPoint rows (for IRadioScanner) and richer WifiTarget-ish data.
inline std::vector<AccessPoint> parseNmcliScan(const std::string& text) {
    std::vector<AccessPoint> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (trim(line).empty()) {
            continue;
        }
        const std::vector<std::string> f = splitNmcliFields(line);
        if (f.size() < 5) {
            continue;
        }
        const std::string rawBssid = trim(f[0]);
        if (!sec::isValidMac(rawBssid)) {
            continue;
        }
        // Fields: BSSID, SSID, CHAN, SECURITY, SIGNAL
        AccessPoint ap;
        ap.ssid = sec::sanitizePrintableText(trim(f[1]));
        ap.channel = sec::detail::parseI32(f[2]);
        const sec::Encryption enc = encryptionFromText(f[3]);
        ap.secure = (enc != sec::Encryption::Open && enc != sec::Encryption::Unknown);
        ap.rssi = nmcliSignalToDbm(sec::detail::parseI32(f[4]));
        out.push_back(ap);
    }
    return out;
}

// Richer variant retaining BSSID + encryption + WPS exposure, used to feed the security engine.
struct ScannedAp {
    std::string bssid;
    std::string ssid;
    int32_t channel = 0;
    int32_t rssi = -100;
    sec::Encryption enc = sec::Encryption::Unknown;
    bool wps = false;
};

inline int32_t freqMhzToChannel(int32_t mhz) {
    if (mhz >= 2412 && mhz <= 2472) {
        return (mhz - 2407) / 5;
    }
    if (mhz == 2484) {
        return 14;
    }
    if (mhz >= 5005 && mhz <= 5895) {
        return (mhz - 5000) / 5;
    }
    return 0;
}

inline std::vector<ScannedAp> parseIwScanDetailed(const std::string& text) {
    std::vector<ScannedAp> out;
    std::istringstream in(text);
    std::string line;

    bool inBss = false;
    ScannedAp cur{};
    bool hasRsn = false;
    bool hasWpa = false;
    bool hasSae = false;
    bool hasPrivacy = false;

    auto flush = [&]() {
        if (!inBss || !sec::isValidMac(cur.bssid)) {
            return;
        }
        if (hasSae) {
            cur.enc = sec::Encryption::Wpa3;
        } else if (hasRsn) {
            cur.enc = sec::Encryption::Wpa2;
        } else if (hasWpa) {
            cur.enc = sec::Encryption::Wpa;
        } else if (hasPrivacy) {
            cur.enc = sec::Encryption::Wep;
        } else {
            cur.enc = sec::Encryption::Open;
        }
        out.push_back(std::move(cur));
        cur = ScannedAp{};
        hasRsn = hasWpa = hasSae = hasPrivacy = false;
        inBss = false;
    };

    while (std::getline(in, line)) {
        const std::string t = trim(line);
        if (t.rfind("BSS ", 0) == 0) {
            flush();
            std::string macPart = t.substr(4);
            const auto paren = macPart.find('(');
            if (paren != std::string::npos) {
                macPart.resize(paren);
            }
            const auto space = macPart.find(' ');
            if (space != std::string::npos) {
                macPart.resize(space);
            }
            macPart = trim(macPart);
            if (sec::isValidMac(macPart)) {
                inBss = true;
                cur = ScannedAp{};
                cur.bssid = sec::normalizeMac(macPart);
            }
            continue;
        }
        if (!inBss) {
            continue;
        }
        if (t.rfind("SSID:", 0) == 0) {
            cur.ssid = sec::sanitizePrintableText(trim(t.substr(5)), 64u);
        } else if (t.rfind("signal:", 0) == 0) {
            cur.rssi = sec::detail::parseI32(trim(t.substr(7)));
        } else if (t.rfind("DS Parameter set: channel", 0) == 0) {
            cur.channel = sec::detail::parseI32(trim(t.substr(25)));
        } else if (t.rfind("freq:", 0) == 0 && cur.channel == 0) {
            cur.channel = freqMhzToChannel(sec::detail::parseI32(trim(t.substr(5))));
        } else if (t.rfind("RSN:", 0) == 0) {
            hasRsn = true;
        } else if (t.rfind("WPA:", 0) == 0) {
            hasWpa = true;
        } else if (t.rfind("WPS:", 0) == 0) {
            cur.wps = true;
        } else if (t.find("SAE") != std::string::npos) {
            hasSae = true;
        } else if (t.rfind("capability:", 0) == 0 && t.find("Privacy") != std::string::npos) {
            hasPrivacy = true;
        }
    }
    flush();
    return out;
}

inline std::vector<ScannedAp> parseNmcliScanDetailed(const std::string& text) {
    std::vector<ScannedAp> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (trim(line).empty()) {
            continue;
        }
        const std::vector<std::string> f = splitNmcliFields(line);
        if (f.size() < 5) {
            continue;
        }
        const std::string rawBssid = trim(f[0]);
        if (!sec::isValidMac(rawBssid)) {
            continue;
        }
        ScannedAp ap;
        ap.bssid = sec::normalizeMac(rawBssid);
        ap.ssid = sec::sanitizePrintableText(trim(f[1]));
        ap.channel = sec::detail::parseI32(f[2]);
        ap.enc = encryptionFromText(f[3]);
        ap.rssi = nmcliSignalToDbm(sec::detail::parseI32(f[4]));
        out.push_back(ap);
    }
    return out;
}

// Parse the AP section of an airodump-ng "-w prefix --output-format csv" dump.
// airodump CSV has two comma-separated sections separated by a blank line:
//   Section 1 header: BSSID, First time seen, Last time seen, channel, Speed, Privacy,
//                     Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length,
//                     ESSID, Key
//   Section 2 header: Station MAC, First time seen, Last time seen, Power, # packets,
//                     BSSID, Probed ESSIDs
// We emit ApObserved-style rows for section 1 and client rows for section 2.
struct AirodumpAp {
    std::string bssid;
    std::string ssid;
    int32_t channel;
    int32_t rssi;
    sec::Encryption enc;
    uint32_t beacons;
};

struct AirodumpStation {
    std::string mac;
    std::string bssid;   // associated BSSID, or "" when "(not associated)"
    std::vector<std::string> probedEssids;
};

struct AirodumpDump {
    std::vector<AirodumpAp> aps;
    std::vector<AirodumpStation> stations;
};

inline std::vector<std::string> splitCsvRaw(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : line) {
        if (c == ',') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    out.push_back(cur);
    return out;
}

inline std::vector<std::string> splitCsv(const std::string& line) {
    std::vector<std::string> out = splitCsvRaw(line);
    for (std::string& field : out) {
        field = trim(field);
    }
    return out;
}

inline AirodumpDump parseAirodumpCsv(const std::string& text) {
    AirodumpDump dump;
    std::istringstream in(text);
    std::string line;
    bool inStations = false;
    while (std::getline(in, line)) {
        const std::string t = trim(line);
        if (t.empty()) {
            continue;
        }
        if (t.rfind("BSSID,", 0) == 0 || t.rfind("BSSID ,", 0) == 0) {
            inStations = false;
            continue;  // AP header
        }
        if (t.rfind("Station MAC", 0) == 0) {
            inStations = true;
            continue;  // station header
        }
        const std::vector<std::string> raw = splitCsvRaw(line);
        if (!inStations) {
            if (raw.size() < 14 || !sec::isValidMac(trim(raw[0]))) {
                continue;
            }
            AirodumpAp ap;
            ap.bssid = sec::normalizeMac(trim(raw[0]));
            ap.channel = sec::detail::parseI32(raw[3]);
            // Privacy(5) + Cipher(6) + Authentication(7) describe encryption.
            ap.enc = encryptionFromText(trim(raw[5]) + " " + trim(raw[6]) + " " + trim(raw[7]));
            ap.rssi = sec::detail::parseI32(raw[8]);
            const int32_t rawBeacons = sec::detail::parseI32(raw[9]);
            ap.beacons = (rawBeacons > 0) ? static_cast<uint32_t>(rawBeacons) : 0u;
            // Rejoin ESSID if it contained commas (columns 0..12 fixed, last column is Key),
            // preserving internal spaces after commas (e.g. "Coffee, Tea").
            std::string rawEssid = raw[13];
            if (raw.size() > 15u) {
                for (std::size_t col = 14u; col + 1u < raw.size(); ++col) {
                    rawEssid += "," + raw[col];
                }
            }
            ap.ssid = sec::sanitizePrintableText(trim(rawEssid));
            dump.aps.push_back(ap);
        } else {
            if (raw.size() < 6) {
                continue;
            }
            const std::string mac = trim(raw[0]);
            if (!sec::isValidMac(mac)) {
                continue;
            }
            AirodumpStation st;
            st.mac = sec::normalizeMac(mac);
            const std::string assoc = trim(raw[5]);
            st.bssid = sec::isValidMac(assoc) ? sec::normalizeMac(assoc) : std::string{};
            for (std::size_t k = 6; k < raw.size(); ++k) {
                const std::string cleaned = sec::sanitizePrintableText(trim(raw[k]));
                if (!cleaned.empty()) {
                    st.probedEssids.push_back(cleaned);
                }
            }
            dump.stations.push_back(st);
        }
    }
    return dump;
}

// --- Pure BLE & Sub-GHz tool line parsers (BlueZ / hcitool / rtl_433) ---------------

struct ScannedBleDevice {
    std::string mac;
    std::string name;
    int32_t rssi = -100;
    uint16_t companyId = 0;
    uint16_t serviceUuid = 0;
    bool trackerPayload = false;
    BleThreatKind threat = BleThreatKind::None;
};

struct ScannedSubGhzSignal {
    uint32_t freqKhz = 433920u;
    int32_t rssi = -100;
    std::string protocol;
    uint32_t burstCount = 1u;
    bool continuousCarrier = false;
};

// Parses lines such as:
//   "AA:BB:CC:DD:EE:FF|-55|Tracker_Tag|0x004C|0x0000|1"
//   "Device 00:80:E1:11:22:33 MultiTool_Unit"
//   "00:80:E1:11:22:33 MultiTool_Unit"
inline std::optional<ScannedBleDevice> parseBluezBleLine(std::string_view rawLine) {
    std::string line = trim(std::string(rawLine));
    if (line.empty()) {
        return std::nullopt;
    }
    ScannedBleDevice dev{};
    if (line.find('|') != std::string::npos) {
        std::vector<std::string> parts;
        std::string cur;
        for (char c : line) {
            if (c == '|') {
                parts.push_back(trim(cur));
                cur.clear();
            } else {
                cur.push_back(c);
            }
        }
        parts.push_back(trim(cur));
        if (parts.size() < 2 || !sec::isValidMac(parts[0])) {
            return std::nullopt;
        }
        dev.mac = sec::normalizeMac(parts[0]);
        dev.rssi = sec::detail::parseI32(parts[1]);
        if (parts.size() >= 3) dev.name = sec::sanitizePrintableText(parts[2], 48u);
        auto parseHexOrDec = [](const std::string& s) -> uint16_t {
            if (s.empty()) return 0u;
            if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
                uint32_t val = 0u;
                for (std::size_t i = 2u; i < s.size(); ++i) {
                    const char ch = s[i];
                    uint32_t nib = 0u;
                    if (ch >= '0' && ch <= '9') nib = static_cast<uint32_t>(ch - '0');
                    else if (ch >= 'a' && ch <= 'f') nib = static_cast<uint32_t>(10 + ch - 'a');
                    else if (ch >= 'A' && ch <= 'F') nib = static_cast<uint32_t>(10 + ch - 'A');
                    else break;
                    val = (val << 4u) | nib;
                }
                return static_cast<uint16_t>(val & 0xFFFFu);
            }
            return static_cast<uint16_t>(sec::detail::parseU32(s) & 0xFFFFu);
        };
        if (parts.size() >= 4) dev.companyId = parseHexOrDec(parts[3]);
        if (parts.size() >= 5) dev.serviceUuid = parseHexOrDec(parts[4]);
        if (parts.size() >= 6) dev.trackerPayload = (parts[5] == "1" || parts[5] == "true");
    } else {
        if (line.rfind("Device ", 0) == 0) {
            line = trim(line.substr(7));
        }
        const std::size_t sp = line.find(' ');
        const std::string macPart = (sp == std::string::npos) ? line : line.substr(0, sp);
        if (!sec::isValidMac(macPart)) {
            return std::nullopt;
        }
        dev.mac = sec::normalizeMac(macPart);
        dev.rssi = -65;
        if (sp != std::string::npos) {
            dev.name = sec::sanitizePrintableText(trim(line.substr(sp + 1)), 48u);
        }
    }
    dev.threat = classifyBleDevice(dev.mac, dev.name, dev.companyId, dev.serviceUuid,
                                   dev.trackerPayload);
    return dev;
}

// Parses compact Sub-GHz capture lines such as:
//   "SUBGHZ|433920|-52|OOK|6|0"
//   "433.92MHz|-55|OOK_Keyfob|2|0"
inline std::optional<ScannedSubGhzSignal> parseRtl433Line(std::string_view rawLine) {
    const std::string line = trim(std::string(rawLine));
    if (line.empty()) {
        return std::nullopt;
    }
    std::vector<std::string> parts;
    std::string cur;
    for (char c : line) {
        if (c == '|') {
            parts.push_back(trim(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    parts.push_back(trim(cur));
    std::size_t off = 0u;
    if (!parts.empty() && parts[0] == "SUBGHZ") {
        off = 1u;
    }
    if (parts.size() < off + 3u) {
        return std::nullopt;
    }
    const std::string& fStr = parts[off];
    uint32_t freqKhz = 0u;
    if (fStr.find('.') != std::string::npos) {
        const std::size_t dot = fStr.find('.');
        const uint32_t mhz = sec::detail::parseU32(fStr.substr(0, dot));
        std::string fracStr;
        for (std::size_t i = dot + 1; i < fStr.size() && std::isdigit(static_cast<unsigned char>(fStr[i])); ++i) {
            fracStr.push_back(fStr[i]);
        }
        while (fracStr.size() < 3u) fracStr.push_back('0');
        if (fracStr.size() > 3u) fracStr.resize(3u);
        freqKhz = mhz * 1000u + sec::detail::parseU32(fracStr);
    } else {
        freqKhz = sec::detail::parseU32(fStr);
        if (freqKhz > 0u && freqKhz < 1000u) {
            freqKhz *= 1000u;
        }
    }
    if (freqKhz < 300000u || freqKhz > 928000u) {
        return std::nullopt;
    }
    ScannedSubGhzSignal sig{};
    sig.freqKhz = freqKhz;
    sig.rssi = sec::detail::parseI32(parts[off + 1u]);
    sig.protocol = sec::sanitizePrintableText(parts[off + 2u], 24u);
    if (parts.size() > off + 3u) {
        sig.burstCount = sec::detail::parseU32(parts[off + 3u]);
        if (sig.burstCount == 0u) sig.burstCount = 1u;
    }
    if (parts.size() > off + 4u) {
        sig.continuousCarrier = (parts[off + 4u] == "1" || parts[off + 4u] == "true");
    }
    return sig;
}

}  // namespace linux_backend
}  // namespace zd
