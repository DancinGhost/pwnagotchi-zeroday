#pragma once

// Pure, zero-dependency Hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL) line formatter.
//
// Produces ready-to-crack `WPA*01*` (PMKID) and `WPA*02*` (4-way EAPOL) lines directly
// from captured material, eliminating the external `hcxpcapngtool` conversion step on
// both Linux and ESP32. Zero OS / socket / SDK headers so it compiles and is unit-tested
// on the host under `-fno-exceptions -fno-rtti`.
//
// Reference format (one record per line):
//   WPA*01*<PMKID>*<MAC_AP>*<MAC_STA>*<ESSID>***
//   WPA*02*<MIC>*<MAC_AP>*<MAC_STA>*<ESSID>*<ANONCE>*<EAPOL>*<MESSAGEPAIR>
// where MACs are 12 lowercase hex nibbles (no separators), ESSID/ANONCE/EAPOL are hex,
// and MESSAGEPAIR is the 2-hex hcxtools pair code.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace zd {
namespace hashcat {

enum class HcType : uint8_t { Pmkid = 1u, Eapol = 2u };

// hcxtools message-pair codes (low 3 bits). We only emit the two highest-confidence,
// replay-counter-correlated pairs, both using the STA's M2 MIC/EAPOL.
enum class MessagePair : uint8_t {
    M1M2E2 = 0x00u,  // ANONCE from M1, MIC+EAPOL from M2 (replay counters equal)
    M2M3E2 = 0x02u,  // ANONCE from M3, MIC+EAPOL from M2 (M3 replay counter == M2 + 1)
};

// Byte offset + length of the Key MIC field inside a captured EAPOL-Key frame (measured
// from the EAPOL header start). hashcat requires the MIC zeroed inside the EAPOL blob.
constexpr std::size_t kEapolMicOffset = 81u;
constexpr std::size_t kEapolMicLen = 16u;

struct HandshakeRecord {
    HcType type = HcType::Eapol;
    std::array<uint8_t, 6> apMac{};
    std::array<uint8_t, 6> staMac{};
    std::string essid;                  // raw SSID bytes (hex-encoded on output)
    std::array<uint8_t, 16> pmkid{};    // HcType::Pmkid
    std::array<uint8_t, 16> mic{};      // HcType::Eapol
    std::array<uint8_t, 32> anonce{};   // HcType::Eapol
    std::vector<uint8_t> eapol;         // HcType::Eapol: full EAPOL-Key frame (MIC zeroed on output)
    MessagePair messagePair = MessagePair::M1M2E2;
};

inline char hexNibble(uint8_t v) {
    return static_cast<char>(v < 10u ? ('0' + v) : ('a' + (v - 10u)));
}

inline std::string toHex(const uint8_t* p, std::size_t n) {
    std::string out;
    out.reserve(n * 2u);
    for (std::size_t i = 0u; i < n; ++i) {
        out.push_back(hexNibble(static_cast<uint8_t>(p[i] >> 4u)));
        out.push_back(hexNibble(static_cast<uint8_t>(p[i] & 0x0Fu)));
    }
    return out;
}

inline bool allZero(const uint8_t* p, std::size_t n) {
    for (std::size_t i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return false;
        }
    }
    return true;
}

// Parse "aa:bb:cc:dd:ee:ff" (also accepts '-' separators or bare 12-hex) into 6 bytes.
inline std::optional<std::array<uint8_t, 6>> macBytesFromString(const std::string& s) {
    std::array<uint8_t, 6> out{};
    int nibbles = 0;
    uint8_t cur = 0u;
    for (char c : s) {
        if (c == ':' || c == '-') {
            continue;
        }
        uint8_t v;
        if (c >= '0' && c <= '9') {
            v = static_cast<uint8_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v = static_cast<uint8_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v = static_cast<uint8_t>(c - 'A' + 10);
        } else {
            return std::nullopt;
        }
        cur = static_cast<uint8_t>((cur << 4u) | v);
        if ((++nibbles & 1) == 0) {
            const int idx = (nibbles / 2) - 1;
            if (idx >= 6) {
                return std::nullopt;
            }
            out[static_cast<std::size_t>(idx)] = cur;
            cur = 0u;
        }
    }
    if (nibbles != 12) {
        return std::nullopt;
    }
    return out;
}

// True when the record carries everything hashcat needs to actually crack it. A missing
// ESSID, an all-zero PMKID/MIC/ANONCE, or an absent EAPOL blob makes the line useless, so
// we refuse to emit it rather than produce a hash that silently never matches.
inline bool isCrackable(const HandshakeRecord& r) {
    if (r.essid.empty()) {
        return false;
    }
    if (r.type == HcType::Pmkid) {
        return !allZero(r.pmkid.data(), r.pmkid.size());
    }
    if (allZero(r.mic.data(), r.mic.size()) || allZero(r.anonce.data(), r.anonce.size())) {
        return false;
    }
    // EAPOL blob must at least span through the MIC field we zero.
    return r.eapol.size() >= (kEapolMicOffset + kEapolMicLen);
}

// Format one record as a hashcat 22000 line (no trailing newline), or nullopt if the
// material is not crackable.
inline std::optional<std::string> toHc22000Line(const HandshakeRecord& r) {
    if (!isCrackable(r)) {
        return std::nullopt;
    }
    const std::string ap = toHex(r.apMac.data(), r.apMac.size());
    const std::string sta = toHex(r.staMac.data(), r.staMac.size());
    const std::string essid =
        toHex(reinterpret_cast<const uint8_t*>(r.essid.data()), r.essid.size());

    if (r.type == HcType::Pmkid) {
        return "WPA*01*" + toHex(r.pmkid.data(), r.pmkid.size()) + "*" + ap + "*" + sta + "*" +
               essid + "***";
    }

    // Zero the MIC field inside a copy of the EAPOL blob (hashcat recomputes it).
    std::vector<uint8_t> eapol = r.eapol;
    for (std::size_t i = 0u; i < kEapolMicLen; ++i) {
        eapol[kEapolMicOffset + i] = 0u;
    }
    char mp[3];
    const uint8_t mpv = static_cast<uint8_t>(r.messagePair);
    mp[0] = hexNibble(static_cast<uint8_t>(mpv >> 4u));
    mp[1] = hexNibble(static_cast<uint8_t>(mpv & 0x0Fu));
    mp[2] = '\0';
    return "WPA*02*" + toHex(r.mic.data(), r.mic.size()) + "*" + ap + "*" + sta + "*" + essid +
           "*" + toHex(r.anonce.data(), r.anonce.size()) + "*" +
           toHex(eapol.data(), eapol.size()) + "*" + std::string(mp);
}

// Join many records into a multi-line .hc22000 file body (crackable records only).
inline std::string toHc22000File(const std::vector<HandshakeRecord>& records) {
    std::string out;
    for (const HandshakeRecord& r : records) {
        if (const std::optional<std::string> line = toHc22000Line(r)) {
            out += *line;
            out.push_back('\n');
        }
    }
    return out;
}

}  // namespace hashcat
}  // namespace zd
