#pragma once

// Pure, host-testable parsers for Linux WiFi-tool output.
//
// These contain NO subprocess or socket calls: they turn the textual output of `nmcli`,
// `iw dev scan`, and `airodump-ng`'s CSV dump into portable `zd` value types. Keeping the
// parsing pure means tests/core/test_linux_parsers.cpp can validate them against captured
// sample output with zero hardware or root. The thin IO adapters (cli_backend.hpp) only
// shell out and hand the resulting text to these functions.

#include <array>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "zd/domain.hpp"
#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"
#include "nmea.hpp"

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
    sec::PmfStatus pmf = sec::PmfStatus::Disabled;
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
    if (mhz == 5935) {
        return zd::k6GhzChannelBase + 2;
    }
    if (mhz >= 5955 && mhz <= 7115) {
        return zd::k6GhzChannelBase + (mhz - 5950) / 5;
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
    bool hasMfpCap = false;
    bool hasMfpReq = false;

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
        if (hasMfpReq) {
            cur.pmf = sec::PmfStatus::Required;
        } else if (hasMfpCap) {
            cur.pmf = sec::PmfStatus::Optional;
        } else {
            cur.pmf = sec::PmfStatus::Disabled;
        }
        out.push_back(std::move(cur));
        cur = ScannedAp{};
        hasRsn = hasWpa = hasSae = hasPrivacy = hasMfpCap = hasMfpReq = false;
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
        } else if (t.find("MFP-required") != std::string::npos) {
            hasMfpReq = true;
        } else if (t.find("MFP-capable") != std::string::npos) {
            hasMfpCap = true;
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
    int32_t channel = 0;
    int32_t rssi = -100;
    sec::Encryption enc = sec::Encryption::Unknown;
    uint32_t beacons = 0u;
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

// Strip ANSI escape sequences (CSI / OSC / single-char ESC) emitted by interactive tools.
inline std::string stripAnsiEscapes(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (std::size_t i = 0u; i < raw.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        if (c == 0x1Bu) {
            if (i + 1u < raw.size()) {
                const unsigned char next = static_cast<unsigned char>(raw[i + 1u]);
                if (next == '[') {
                    i += 2u;
                    while (i < raw.size() &&
                           !(static_cast<unsigned char>(raw[i]) >= 0x40u &&
                             static_cast<unsigned char>(raw[i]) <= 0x7Eu)) {
                        ++i;
                    }
                    continue;
                }
                if (next == ']') {
                    i += 2u;
                    while (i < raw.size()) {
                        if (raw[i] == '\a') {
                            break;
                        }
                        if (raw[i] == '\x1b' && i + 1u < raw.size() && raw[i + 1u] == '\\') {
                            ++i;
                            break;
                        }
                        ++i;
                    }
                    continue;
                }
                ++i;
            }
            continue;
        }
        if (c == '\r') {
            continue;
        }
        out.push_back(static_cast<char>(c));
    }
    return out;
}

namespace ble_parse_detail {

inline uint16_t parseHex16(std::string_view raw) {
    std::string s = trim(std::string(raw));
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        s.erase(0, 2);
    }
    uint32_t val = 0u;
    bool any = false;
    for (char ch : s) {
        uint32_t nib = 0u;
        if (ch >= '0' && ch <= '9') nib = static_cast<uint32_t>(ch - '0');
        else if (ch >= 'a' && ch <= 'f') nib = static_cast<uint32_t>(10 + ch - 'a');
        else if (ch >= 'A' && ch <= 'F') nib = static_cast<uint32_t>(10 + ch - 'A');
        else break;
        any = true;
        val = (val << 4u) | nib;
    }
    return any ? static_cast<uint16_t>(val & 0xFFFFu) : 0u;
}

inline std::optional<int32_t> parseBluezRssi(std::string_view raw) {
    const std::size_t lp = raw.find('(');
    std::string numStr = (lp != std::string_view::npos) ? std::string(raw.substr(lp + 1u))
                                                        : std::string(raw);
    const std::size_t rp = numStr.find(')');
    if (rp != std::string::npos) {
        numStr.resize(rp);
    }
    numStr = trim(numStr);
    if (numStr.empty()) {
        return std::nullopt;
    }
    if (numStr.rfind("0x", 0) == 0 || numStr.rfind("0X", 0) == 0) {
        uint32_t u = 0u;
        for (std::size_t i = 2u; i < numStr.size(); ++i) {
            const char ch = numStr[i];
            uint32_t nib = 0u;
            if (ch >= '0' && ch <= '9') nib = static_cast<uint32_t>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') nib = static_cast<uint32_t>(10 + ch - 'a');
            else if (ch >= 'A' && ch <= 'F') nib = static_cast<uint32_t>(10 + ch - 'A');
            else break;
            u = (u << 4u) | nib;
        }
        const int32_t signedVal = static_cast<int32_t>(u);
        return (signedVal >= -127 && signedVal <= 20) ? std::optional<int32_t>(signedVal)
                                                      : std::nullopt;
    }
    const int32_t val = sec::detail::parseI32(numStr);
    if (val < -127 || val > 20 || (val == 0 && numStr != "0" && numStr != "+0")) {
        return std::nullopt;
    }
    return val;
}

inline uint16_t parseShortBleUuid(std::string_view raw) {
    const std::string lower = toLowerAscii(raw);
    const std::size_t basePos = lower.find("-0000-1000-8000-00805f9b34fb");
    if (basePos != std::string::npos && basePos >= 4u) {
        return parseHex16(std::string_view(lower).substr(basePos - 4u, 4u));
    }
    const std::size_t xPos = lower.find("0x");
    if (xPos != std::string::npos) {
        return parseHex16(std::string_view(lower).substr(xPos));
    }
    return 0u;
}

inline void assignPriorityServiceUuid(uint16_t& dst, uint16_t cand) {
    if (cand == 0u) {
        return;
    }
    if (cand == 0xFEEDu || (cand >= 0x3080u && cand <= 0x3083u)) {
        dst = cand;
    } else if (dst == 0u) {
        dst = cand;
    }
}

inline bool isPlaceholderMacName(std::string_view name, std::string_view normMac) {
    const std::string trimmed = trim(std::string(name));
    if (trimmed.empty()) {
        return true;
    }
    std::string normCand;
    normCand.reserve(trimmed.size());
    for (unsigned char c : trimmed) {
        normCand.push_back((c == '-') ? ':' : static_cast<char>(std::tolower(c)));
    }
    return normCand == normMac;
}

inline std::vector<uint8_t> parseHexBytesLine(std::string_view raw) {
    std::vector<uint8_t> out;
    std::istringstream in{std::string(raw)};
    std::string tok;
    while (in >> tok && out.size() < 64u) {
        if (tok.rfind("0x", 0) == 0 || tok.rfind("0X", 0) == 0) {
            tok.erase(0, 2);
        }
        if (tok.size() == 2u && std::isxdigit(static_cast<unsigned char>(tok[0])) &&
            std::isxdigit(static_cast<unsigned char>(tok[1]))) {
            out.push_back(static_cast<uint8_t>(parseHex16(tok) & 0xFFu));
        }
    }
    return out;
}

inline bool extractJsonStringField(std::string_view json, std::string_view key, std::string& out) {
    const std::string pat = "\"" + std::string(key) + "\"";
    std::size_t pos = json.find(pat);
    while (pos != std::string_view::npos) {
        std::size_t p = pos + pat.size();
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
        if (p < json.size() && json[p] == ':') {
            ++p;
            while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
            if (p < json.size() && json[p] == '"') {
                ++p;
                std::string val;
                while (p < json.size() && json[p] != '"') {
                    if (json[p] == '\\' && p + 1u < json.size()) {
                        ++p;
                    }
                    val.push_back(json[p++]);
                }
                if (p < json.size() && json[p] == '"') {
                    out = std::move(val);
                    return true;
                }
            }
        }
        pos = json.find(pat, pos + pat.size());
    }
    return false;
}

inline bool extractJsonNumberField(std::string_view json, std::string_view key, double& out) {
    const std::string pat = "\"" + std::string(key) + "\"";
    std::size_t pos = json.find(pat);
    while (pos != std::string_view::npos) {
        std::size_t p = pos + pat.size();
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
        if (p < json.size() && json[p] == ':') {
            ++p;
            while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
            if (p < json.size() &&
                (json[p] == '-' || json[p] == '+' || std::isdigit(static_cast<unsigned char>(json[p])))) {
                char buf[48] = {0};
                std::size_t len = 0u;
                while (p + len < json.size() && len + 1u < sizeof(buf)) {
                    const char c = json[p + len];
                    if (std::isdigit(static_cast<unsigned char>(c)) || c == '.' || c == '-' ||
                        c == '+' || c == 'e' || c == 'E') {
                        buf[len++] = c;
                    } else {
                        break;
                    }
                }
                char* endPtr = nullptr;
                const double val = std::strtod(buf, &endPtr);
                if (endPtr != buf && std::isfinite(val)) {
                    out = val;
                    return true;
                }
            }
        }
        pos = json.find(pat, pos + pat.size());
    }
    return false;
}

inline bool extractJsonBoolField(std::string_view json, std::string_view key, bool& out) {
    const std::string pat = "\"" + std::string(key) + "\"";
    std::size_t pos = json.find(pat);
    while (pos != std::string_view::npos) {
        std::size_t p = pos + pat.size();
        while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
        if (p < json.size() && json[p] == ':') {
            ++p;
            while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
            if (json.substr(p, 4u) == "true" || json.substr(p, 1u) == "1") {
                out = true;
                return true;
            }
            if (json.substr(p, 5u) == "false" || json.substr(p, 1u) == "0") {
                out = false;
                return true;
            }
        }
        pos = json.find(pat, pos + pat.size());
    }
    return false;
}

}  // namespace ble_parse_detail

// Parses lines such as:
//   "AA:BB:CC:DD:EE:FF|-55|Tracker_Tag|0x004C|0x0000|1"
//   "Device 00:80:E1:11:22:33 MultiTool_Unit"
//   "00:80:E1:11:22:33 MultiTool_Unit"
inline std::optional<ScannedBleDevice> parseBluezBleLine(std::string_view rawLine) {
    std::string line = trim(stripAnsiEscapes(rawLine));
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
                return ble_parse_detail::parseHex16(s);
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
            const std::string candName = sec::sanitizePrintableText(trim(line.substr(sp + 1)), 48u);
            if (!ble_parse_detail::isPlaceholderMacName(candName, dev.mac)) {
                dev.name = candName;
            }
        }
    }
    dev.threat = classifyBleDevice(dev.mac, dev.name, dev.companyId, dev.serviceUuid,
                                   dev.trackerPayload);
    return dev;
}

// Enrich a ScannedBleDevice from `bluetoothctl info <MAC>` output.
inline bool parseBluezDeviceInfo(std::string_view text, ScannedBleDevice& dev) {
    bool updated = false;
    std::istringstream in{stripAnsiEscapes(text)};
    std::string raw;
    bool expectingMfgBytes = false;
    while (std::getline(in, raw)) {
        const std::string t = trim(raw);
        if (t.empty()) {
            expectingMfgBytes = false;
            continue;
        }
        if (t.rfind("Name:", 0) == 0) {
            expectingMfgBytes = false;
            const std::string n = sec::sanitizePrintableText(trim(t.substr(5)), 48u);
            if (!n.empty() && !ble_parse_detail::isPlaceholderMacName(n, dev.mac)) {
                dev.name = n;
                updated = true;
            }
        } else if (t.rfind("Alias:", 0) == 0) {
            expectingMfgBytes = false;
            const std::string a = sec::sanitizePrintableText(trim(t.substr(6)), 48u);
            if ((dev.name.empty() || ble_parse_detail::isPlaceholderMacName(dev.name, dev.mac)) &&
                !a.empty() && !ble_parse_detail::isPlaceholderMacName(a, dev.mac)) {
                dev.name = a;
                updated = true;
            }
        } else if (t.rfind("RSSI:", 0) == 0) {
            expectingMfgBytes = false;
            if (const auto r = ble_parse_detail::parseBluezRssi(t.substr(5))) {
                dev.rssi = *r;
                updated = true;
            }
        } else if (t.rfind("ManufacturerData Key:", 0) == 0 ||
                   t.rfind("ManufacturerData.Key:", 0) == 0) {
            const std::size_t colon = t.find(':');
            const uint16_t cid = ble_parse_detail::parseHex16(t.substr(colon + 1u));
            if (cid != 0u) {
                dev.companyId = cid;
                expectingMfgBytes = true;
                updated = true;
            }
        } else if (t.rfind("ManufacturerData Value:", 0) == 0 ||
                   t.rfind("ManufacturerData.Value:", 0) == 0) {
            const std::size_t colon = t.find(':');
            const auto bytes = ble_parse_detail::parseHexBytesLine(t.substr(colon + 1u));
            if (dev.companyId == 0x004Cu && !bytes.empty() && bytes[0] == 0x12u) {
                dev.trackerPayload = true;
                updated = true;
            } else if (dev.companyId == 0x0075u && bytes.size() >= 2u) {
                dev.trackerPayload = true;
                updated = true;
            }
            expectingMfgBytes = bytes.empty() && (dev.companyId != 0u);
        } else if (expectingMfgBytes && t.find(':') == std::string::npos) {
            const auto bytes = ble_parse_detail::parseHexBytesLine(t);
            if (!bytes.empty()) {
                if (dev.companyId == 0x004Cu && bytes[0] == 0x12u) {
                    dev.trackerPayload = true;
                    updated = true;
                } else if (dev.companyId == 0x0075u && bytes.size() >= 2u) {
                    dev.trackerPayload = true;
                    updated = true;
                }
            }
            expectingMfgBytes = false;
        } else if (t.rfind("UUID:", 0) == 0) {
            expectingMfgBytes = false;
            const uint16_t uuid = ble_parse_detail::parseShortBleUuid(t);
            if (uuid != 0u) {
                ble_parse_detail::assignPriorityServiceUuid(dev.serviceUuid, uuid);
                updated = true;
            }
        } else {
            expectingMfgBytes = false;
        }
    }
    dev.threat = classifyBleDevice(dev.mac, dev.name, dev.companyId, dev.serviceUuid,
                                   dev.trackerPayload);
    return updated;
}

// Parse live `bluetoothctl --timeout N scan on` output and merge events per normalized MAC.
inline std::vector<ScannedBleDevice> parseBluezScanOutput(std::string_view text) {
    std::unordered_map<std::string, ScannedBleDevice> byMac;
    std::vector<std::string> order;
    auto upsert = [&](const std::string& rawMac) -> ScannedBleDevice* {
        if (!sec::isValidMac(rawMac)) {
            return nullptr;
        }
        const std::string mac = sec::normalizeMac(rawMac);
        if (mac.empty() || sec::isBroadcastMac(mac)) {
            return nullptr;
        }
        auto it = byMac.find(mac);
        if (it == byMac.end()) {
            ScannedBleDevice d{};
            d.mac = mac;
            d.rssi = -100;
            order.push_back(mac);
            it = byMac.emplace(mac, std::move(d)).first;
        }
        return &it->second;
    };

    std::istringstream in{stripAnsiEscapes(text)};
    std::string raw;
    std::string lastMac;
    while (std::getline(in, raw)) {
        const std::string line = trim(raw);
        if (line.empty()) {
            continue;
        }
        if (line.rfind("[DEL] Device ", 0) == 0) {
            lastMac.clear();
            continue;
        }
        std::string_view rest = line;
        if (rest.rfind("[NEW] ", 0) == 0 || rest.rfind("[CHG] ", 0) == 0) {
            rest.remove_prefix(6u);
        }
        if (rest.rfind("Device ", 0) == 0) {
            rest.remove_prefix(7u);
            const std::size_t sp = rest.find(' ');
            const std::string macTok(rest.substr(0, sp));
            ScannedBleDevice* dev = upsert(macTok);
            if (dev == nullptr) {
                lastMac.clear();
                continue;
            }
            lastMac = dev->mac;
            const std::string payload = (sp == std::string_view::npos) ? std::string{}
                                                                       : trim(std::string(rest.substr(sp + 1u)));
            if (payload.empty()) {
                continue;
            }
            if (payload.rfind("RSSI:", 0) == 0) {
                if (const auto r = ble_parse_detail::parseBluezRssi(payload.substr(5u))) {
                    dev->rssi = *r;
                }
            } else if (payload.rfind("Name:", 0) == 0) {
                const std::string n = sec::sanitizePrintableText(trim(payload.substr(5u)), 48u);
                if (!n.empty() && !ble_parse_detail::isPlaceholderMacName(n, dev->mac)) {
                    dev->name = n;
                }
            } else if (payload.rfind("Alias:", 0) == 0) {
                const std::string a = sec::sanitizePrintableText(trim(payload.substr(6u)), 48u);
                if ((dev->name.empty() || ble_parse_detail::isPlaceholderMacName(dev->name, dev->mac)) &&
                    !a.empty() && !ble_parse_detail::isPlaceholderMacName(a, dev->mac)) {
                    dev->name = a;
                }
            } else if (payload.rfind("ManufacturerData Key:", 0) == 0 ||
                       payload.rfind("ManufacturerData.Key:", 0) == 0) {
                const std::size_t colon = payload.find(':');
                const uint16_t cid = ble_parse_detail::parseHex16(payload.substr(colon + 1u));
                if (cid != 0u) {
                    dev->companyId = cid;
                }
            } else if (payload.rfind("ManufacturerData Value:", 0) == 0 ||
                       payload.rfind("ManufacturerData.Value:", 0) == 0) {
                const std::size_t colon = payload.find(':');
                const auto bytes = ble_parse_detail::parseHexBytesLine(payload.substr(colon + 1u));
                if (dev->companyId == 0x004Cu && !bytes.empty() && bytes[0] == 0x12u) {
                    dev->trackerPayload = true;
                } else if (dev->companyId == 0x0075u && bytes.size() >= 2u) {
                    dev->trackerPayload = true;
                }
            } else if (payload.rfind("UUIDs:", 0) == 0) {
                const uint16_t uuid = ble_parse_detail::parseShortBleUuid(payload.substr(6u));
                ble_parse_detail::assignPriorityServiceUuid(dev->serviceUuid, uuid);
            } else if (payload.find(':') == std::string::npos) {
                const std::string n = sec::sanitizePrintableText(payload, 48u);
                if (!n.empty() && !ble_parse_detail::isPlaceholderMacName(n, dev->mac)) {
                    dev->name = n;
                }
            }
        } else if (!lastMac.empty()) {
            auto it = byMac.find(lastMac);
            if (it != byMac.end() &&
                (line.rfind("Key:", 0) == 0 || line.rfind("0x", 0) == 0)) {
                if (line.rfind("Key:", 0) == 0) {
                    const uint16_t cid = ble_parse_detail::parseHex16(line.substr(4u));
                    if (cid != 0u) {
                        it->second.companyId = cid;
                    }
                }
            }
        }
    }

    std::vector<ScannedBleDevice> out;
    out.reserve(order.size());
    for (const std::string& mac : order) {
        ScannedBleDevice& d = byMac[mac];
        d.threat = classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid, d.trackerPayload);
        out.push_back(std::move(d));
    }
    return out;
}

// Parse `btmgmt find` stdout into deduplicated ScannedBleDevice records.
inline std::vector<ScannedBleDevice> parseBtmgmtFindOutput(std::string_view text) {
    std::unordered_map<std::string, ScannedBleDevice> byMac;
    std::vector<std::string> order;
    std::istringstream in{stripAnsiEscapes(text)};
    std::string raw;
    std::string curMac;
    while (std::getline(in, raw)) {
        const std::string line = trim(raw);
        if (line.empty()) {
            continue;
        }
        const std::size_t df = line.find("dev_found:");
        if (df != std::string::npos) {
            std::string body = trim(line.substr(df + 10u));
            const std::size_t sp = body.find(' ');
            const std::string macTok = (sp == std::string::npos) ? body : body.substr(0, sp);
            if (!sec::isValidMac(macTok)) {
                curMac.clear();
                continue;
            }
            const std::string mac = sec::normalizeMac(macTok);
            auto it = byMac.find(mac);
            if (it == byMac.end()) {
                ScannedBleDevice d{};
                d.mac = mac;
                d.rssi = -65;
                order.push_back(mac);
                it = byMac.emplace(mac, std::move(d)).first;
            }
            curMac = mac;
            const std::size_t rssiPos = line.find("rssi ");
            if (rssiPos != std::string::npos) {
                const int32_t r = sec::detail::parseI32(line.substr(rssiPos + 5u));
                if (r >= -127 && r <= 20) {
                    it->second.rssi = r;
                }
            }
            const std::size_t namePos = line.find(" name ");
            if (namePos != std::string::npos) {
                const std::string n = sec::sanitizePrintableText(trim(line.substr(namePos + 6u)), 48u);
                if (!n.empty() && !ble_parse_detail::isPlaceholderMacName(n, mac)) {
                    it->second.name = n;
                }
            }
        } else if (line.rfind("name ", 0) == 0 && !curMac.empty()) {
            auto it = byMac.find(curMac);
            if (it != byMac.end()) {
                const std::string n = sec::sanitizePrintableText(trim(line.substr(5u)), 48u);
                if (!n.empty() && !ble_parse_detail::isPlaceholderMacName(n, curMac)) {
                    it->second.name = n;
                }
            }
        }
    }
    std::vector<ScannedBleDevice> out;
    out.reserve(order.size());
    for (const std::string& mac : order) {
        ScannedBleDevice& d = byMac[mac];
        d.threat = classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid, d.trackerPayload);
        out.push_back(std::move(d));
    }
    return out;
}

// Parses both `rtl_433 -F json` lines and compact legacy capture lines:
//   `{"model":"Acurite-Tower","freq":433.92,"rssi":-48}`
//   "SUBGHZ|433920|-52|OOK|6|0"
//   "433.92MHz|-55|OOK_Keyfob|2|0"
inline std::optional<ScannedSubGhzSignal> parseRtl433Line(std::string_view rawLine,
                                                          uint32_t defaultFreqKhz = 433920u) {
    const std::string line = trim(stripAnsiEscapes(rawLine));
    if (line.empty()) {
        return std::nullopt;
    }
    if (line.front() == '{') {
        std::string model;
        std::string proto;
        std::string mod;
        double freqVal = 0.0;
        double rssiVal = 0.0;
        double burstVal = 1.0;
        bool carrier = false;
        const bool hasModel = ble_parse_detail::extractJsonStringField(line, "model", model);
        const bool hasProto = ble_parse_detail::extractJsonStringField(line, "protocol", proto);
        const bool hasMod = ble_parse_detail::extractJsonStringField(line, "mod", mod);
        const bool hasFreq = ble_parse_detail::extractJsonNumberField(line, "freq", freqVal) ||
                             ble_parse_detail::extractJsonNumberField(line, "frequency", freqVal);
        const bool hasRssi = ble_parse_detail::extractJsonNumberField(line, "rssi", rssiVal) ||
                             ble_parse_detail::extractJsonNumberField(line, "snr", rssiVal);
        if (!hasModel && !hasProto && !hasMod && !hasFreq && !hasRssi) {
            return std::nullopt;
        }
        uint32_t freqKhz = defaultFreqKhz;
        if (hasFreq && freqVal > 0.0) {
            if (freqVal > 1000000.0) {
                freqKhz = static_cast<uint32_t>(std::lround(freqVal / 1000.0));
            } else if (freqVal > 1000.0) {
                freqKhz = static_cast<uint32_t>(std::lround(freqVal));
            } else {
                freqKhz = static_cast<uint32_t>(std::lround(freqVal * 1000.0));
            }
        }
        if (freqKhz < 300000u || freqKhz > 928000u) {
            return std::nullopt;
        }
        ScannedSubGhzSignal sig{};
        sig.freqKhz = freqKhz;
        sig.rssi = hasRssi ? static_cast<int32_t>(std::lround(rssiVal)) : -65;
        if (sig.rssi < -120) sig.rssi = -120;
        if (sig.rssi > 0) sig.rssi = 0;
        const std::string& rawProto = !model.empty() ? model : (!proto.empty() ? proto : mod);
        sig.protocol = sec::sanitizePrintableText(rawProto.empty() ? "rtl_433" : rawProto, 24u);
        if (ble_parse_detail::extractJsonNumberField(line, "burst_count", burstVal) ||
            ble_parse_detail::extractJsonNumberField(line, "repeats", burstVal)) {
            sig.burstCount = (burstVal >= 1.0 && burstVal < 100000.0)
                                 ? static_cast<uint32_t>(std::lround(burstVal))
                                 : 1u;
        }
        (void)ble_parse_detail::extractJsonBoolField(line, "continuous", carrier);
        sig.continuousCarrier = carrier;
        return sig;
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

// Parse one line from gpsd (JSON TPV/SKY or raw NMEA-0183 sentence) into `gps`.
// Returns true when the line contained recognized TPV, SKY, or checksum-valid NMEA data.
inline bool parseGpsdLine(const std::string& line, zd::esp32_common::GpsState& gps, uint32_t nowMs) {
    const std::string t = trim(line);
    if (t.empty()) {
        return false;
    }
    if (t[0] == '$') {
        return zd::esp32_common::processNmeaSentence(gps, t, nowMs);
    }
    if (t[0] != '{') {
        return false;
    }
    std::string cls;
    if (!ble_parse_detail::extractJsonStringField(t, "class", cls)) {
        return false;
    }
    if (cls == "TPV") {
        double mode = 0.0;
        if (!ble_parse_detail::extractJsonNumberField(t, "mode", mode)) {
            return false;
        }
        if (mode < 2.0) {
            gps.hasFix = false;
            return true;
        }
        double lat = 0.0;
        double lon = 0.0;
        if (!ble_parse_detail::extractJsonNumberField(t, "lat", lat) ||
            !ble_parse_detail::extractJsonNumberField(t, "lon", lon) ||
            !std::isfinite(lat) || !std::isfinite(lon) ||
            lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) {
            return false;
        }
        gps.hasFix = true;
        gps.latitude = static_cast<float>(lat);
        gps.longitude = static_cast<float>(lon);
        gps.lastSentenceMs = nowMs;
        std::string isoTime;
        if (ble_parse_detail::extractJsonStringField(t, "time", isoTime) && isoTime.size() >= 19u &&
            isoTime[10] == 'T') {
            std::snprintf(gps.utcDate, sizeof(gps.utcDate), "%.10s", isoTime.c_str());
            gps.hasDate = true;
            std::snprintf(gps.utcTime, sizeof(gps.utcTime), "%.8s", isoTime.c_str() + 11);
        }
        return true;
    }
    if (cls == "SKY") {
        double uSat = 0.0;
        if (ble_parse_detail::extractJsonNumberField(t, "uSat", uSat) ||
            ble_parse_detail::extractJsonNumberField(t, "nSat", uSat)) {
            const double clamped = (uSat < 0.0) ? 0.0 : (uSat > 99.0 ? 99.0 : uSat);
            gps.satellites = static_cast<uint8_t>(clamped);
        }
        return true;
    }
    return false;
}

}  // namespace linux_backend
}  // namespace zd
