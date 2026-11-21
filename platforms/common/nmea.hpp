#pragma once

// Portable NMEA-0183 GNSS parser (zero Arduino/OS headers, zero heap allocations).
// Used by LILYGO T-Deck Plus (MIA-M10Q GNSS) and host unit tests.

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

namespace zd {
namespace esp32_common {

struct GpsState {
    bool hasFix = false;
    float latitude = 0.0f;
    float longitude = 0.0f;
    uint8_t satellites = 0;
    char utcTime[10] = "00:00:00";
    uint32_t lastSentenceMs = 0;
};

// Verify standard NMEA-0183 XOR checksum ($body*XX), rejecting trailing garbage.
inline bool verifyNmeaChecksum(std::string_view line) {
    if (line.size() < 6u || line.front() != '$') {
        return false;
    }
    const std::size_t star = line.rfind('*');
    if (star == std::string_view::npos || star + 3u != line.size()) {
        return false;
    }
    auto hexNib = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
    };
    const int hi = hexNib(line[star + 1u]);
    const int lo = hexNib(line[star + 2u]);
    if (hi < 0 || lo < 0) {
        return false;
    }
    uint8_t x = 0u;
    for (std::size_t i = 1u; i < star; ++i) {
        x ^= static_cast<uint8_t>(line[i]);
    }
    return x == static_cast<uint8_t>((hi << 4) | lo);
}

// Zero-heap-allocation NMEA field tokenizer using a fixed stack array.
inline std::size_t parseNmeaFields(std::string_view line, std::array<std::string_view, 16>& fields) {
    std::size_t count = 0u;
    std::size_t start = 0u;
    for (std::size_t i = 0u; i < line.size() && count < fields.size(); ++i) {
        if (line[i] == ',' || line[i] == '*') {
            fields[count++] = line.substr(start, i - start);
            start = i + 1u;
            if (line[i] == '*') {
                break;
            }
        }
    }
    if (count < fields.size() && start <= line.size()) {
        fields[count++] = line.substr(start);
    }
    return count;
}

// Parse NMEA ddmm.mmmm (lat) or dddmm.mmmm (lon) strictly; rejects NaN/garbage/out-of-range.
inline bool parseNmeaCoord(std::string_view raw, bool isLat, float& outDeg) {
    if (raw.empty() || raw.size() >= 16u) {
        return false;
    }
    char buf[16] = {0};
    std::memcpy(buf, raw.data(), raw.size());
    char* endPtr = nullptr;
    const float rawVal = std::strtof(buf, &endPtr);
    if (endPtr == buf || *endPtr != '\0' || !std::isfinite(rawVal) || rawVal < 0.0f) {
        return false;
    }
    const float wholeDeg = std::floor(rawVal / 100.0f);
    const float mins = rawVal - (wholeDeg * 100.0f);
    if (mins < 0.0f || mins >= 60.0f) {
        return false;
    }
    const float deg = wholeDeg + (mins / 60.0f);
    const float maxDeg = isLat ? 90.0f : 180.0f;
    if (deg > maxDeg) {
        return false;
    }
    outDeg = deg;
    return true;
}

inline void expireStaleGpsFix(GpsState& gps, uint32_t nowMs) {
    const uint32_t elapsed = nowMs - gps.lastSentenceMs;
    if (gps.hasFix && elapsed < 0x80000000u && elapsed > 5000u) {
        gps.hasFix = false;
        gps.satellites = 0;
    }
}

// Process one complete NMEA line (without trailing CR/LF). Returns true when checksum-valid.
inline bool processNmeaSentence(GpsState& gps, std::string_view line, uint32_t nowMs) {
    if (!verifyNmeaChecksum(line)) {
        return false;
    }
    std::array<std::string_view, 16> f{};
    const std::size_t n = parseNmeaFields(line, f);
    if (n == 0u) {
        return false;
    }
    if (f[0] == "$GNRMC" || f[0] == "$GPRMC") {
        if (n >= 7u && f[2] == "A") {
            float lat = 0.0f;
            float lon = 0.0f;
            const bool latHemOk = (f[4] == "N" || f[4] == "S");
            const bool lonHemOk = (f[6] == "E" || f[6] == "W");
            if (!parseNmeaCoord(f[3], true, lat) || !parseNmeaCoord(f[5], false, lon) ||
                !latHemOk || !lonHemOk) {
                gps.hasFix = false;
                gps.satellites = 0;
                return true;
            }
            if (f[4] == "S") lat = -lat;
            if (f[6] == "W") lon = -lon;
            gps.hasFix = true;
            gps.lastSentenceMs = nowMs;
            gps.latitude = lat;
            gps.longitude = lon;
            if (f[1].size() >= 6u) {
                std::snprintf(gps.utcTime, sizeof(gps.utcTime), "%.2s:%.2s:%.2s",
                              f[1].data(), f[1].data() + 2, f[1].data() + 4);
            }
        } else if (n >= 3u && f[2] == "V") {
            gps.hasFix = false;
            gps.satellites = 0;
        }
    } else if (f[0] == "$GNGGA" || f[0] == "$GPGGA") {
        if (n >= 8u && !f[7].empty() && f[7].size() <= 3u) {
            uint32_t sats = 0u;
            bool ok = true;
            for (char c : f[7]) {
                if (c < '0' || c > '9') {
                    ok = false;
                    break;
                }
                sats = sats * 10u + static_cast<uint32_t>(c - '0');
            }
            if (ok && sats <= 255u) {
                gps.satellites = static_cast<uint8_t>(sats);
            }
        }
    }
    return true;
}

}  // namespace esp32_common
}  // namespace zd
