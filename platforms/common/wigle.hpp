#pragma once

// Pure WiGLE v1.4 CSV wardriving formatter & per-BSSID deduplicating batch builder.
// Zero OS or SD-card dependencies so it can be unit-tested on the host.

#include <zd/wifi_analysis.hpp>
#include <nmea.hpp>

#include <cstdio>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

namespace zd {

inline std::string formatWigleHeader(const std::string& device = "t-deck",
                                     const std::string& model = "T-Deck",
                                     const std::string& board = "ESP32-S3") {
    return "WigleWifi-1.4,appRelease=pwnagotchi-zd,model=" + model +
           ",release=2.0,device=" + device + ",display=TFT,board=" + board +
           ",brand=Zeroday\n"
           "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n";
}

inline std::string sanitizeWigleCsvCell(const std::string& raw) {
    std::string clean;
    clean.reserve(raw.size());
    for (unsigned char c : raw) {
        if (c == '\r' || c == '\n' || c < 0x20u || c >= 0x7Fu) {
            clean.push_back(' ');
        } else {
            clean.push_back(static_cast<char>(c));
        }
    }
    if (!clean.empty()) {
        std::size_t firstNonWs = 0u;
        while (firstNonWs < clean.size() && (clean[firstNonWs] == ' ' || clean[firstNonWs] == '\t')) {
            ++firstNonWs;
        }
        if (firstNonWs < clean.size()) {
            const char f = clean[firstNonWs];
            if (f == '=' || f == '+' || f == '-' || f == '@') {
                clean.insert(clean.begin(), '\'');
            }
        }
    }
    std::string quoted = "\"";
    quoted.reserve(clean.size() + 4u);
    for (char c : clean) {
        if (c == '"') {
            quoted += "\"\"";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('"');
    return quoted;
}

inline std::string formatWigleCsvRow(const std::string& bssid,
                                     const AccessPoint& ap,
                                     const zd::esp32_common::GpsState& gps,
                                     const std::string& seenUtc = "1970-01-01 00:00:00") {
    const std::string mac = bssid.empty() ? "00:00:00:00:00:00" : bssid;
    const std::string auth = ap.secure ? "[WPA2-PSK-CCMP][ESS]" : "[ESS]";
    char geoBuf[96];
    std::snprintf(geoBuf, sizeof(geoBuf), "%.6f,%.6f,0.0,%.1f",
                  static_cast<double>(gps.latitude),
                  static_cast<double>(gps.longitude),
                  gps.satellites >= 6u ? 5.0 : 12.0);

    return sanitizeWigleCsvCell(mac) + "," +
           sanitizeWigleCsvCell(ap.ssid) + "," +
           sanitizeWigleCsvCell(auth) + "," +
           sanitizeWigleCsvCell(seenUtc) + "," +
           std::to_string(ap.channel) + "," +
           std::to_string(ap.rssi) + "," +
           std::string(geoBuf) + ",WIFI\n";
}

class WigleLogger {
public:
    static constexpr std::size_t kMaxTrackedBssids = 512u;

    void reset() {
        seenRssi_.clear();
        seenOrder_.clear();
        loggedCount_ = 0u;
    }

    uint32_t loggedCount() const { return loggedCount_; }

    std::vector<std::string> recordScan(const std::vector<AccessPoint>& aps,
                                        const std::vector<std::string>& bssids,
                                        const zd::esp32_common::GpsState& gps,
                                        const std::string& seenUtc = "") {
        std::vector<std::string> lines;
        if (!gps.hasFix) {
            return lines;
        }
        const std::string fallbackDate = gps.hasDate ? std::string(gps.utcDate) : std::string("1970-01-01");
        const std::string fallbackTime =
            (gps.utcTime[0] != '\0') ? std::string(gps.utcTime) : std::string("00:00:00");
        const std::string stamp =
            seenUtc.empty() ? (fallbackDate + " " + fallbackTime) : seenUtc;
        for (std::size_t i = 0u; i < aps.size(); ++i) {
            const AccessPoint& ap = aps[i];
            const std::string mac = (i < bssids.size()) ? bssids[i] : std::string{};
            if (mac.empty()) {
                continue;
            }
            const auto it = seenRssi_.find(mac);
            if (it != seenRssi_.end() && (ap.rssi - it->second) < 8) {
                continue;
            }
            if (it == seenRssi_.end()) {
                while (seenRssi_.size() >= kMaxTrackedBssids && !seenOrder_.empty()) {
                    seenRssi_.erase(seenOrder_.front());
                    seenOrder_.pop_front();
                }
                seenOrder_.push_back(mac);
            }
            seenRssi_[mac] = ap.rssi;
            lines.push_back(formatWigleCsvRow(mac, ap, gps, stamp));
            ++loggedCount_;
        }
        return lines;
    }

private:
    std::unordered_map<std::string, int32_t> seenRssi_{};
    std::deque<std::string> seenOrder_{};
    uint32_t loggedCount_ = 0u;
};

}  // namespace zd
