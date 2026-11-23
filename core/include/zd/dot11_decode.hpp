#pragma once

// Portable, pure 802.11 / radiotap frame decoder (Functional Core).
//
// Turns a raw monitor-mode 802.11 management/data frame (or radiotap-prefixed capture
// buffer) into a `zd::sec::CapturedFrame`. Contains zero OS, socket, libpcap, or SDK
// headers so Linux and ESP32 promiscuous RX paths share identical decoding and every
// parser branch is directly host-testable without hardware.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

#include "secops.hpp"
#include "secops_hal.hpp"

namespace zd {
namespace dot11 {

inline std::string macToString(const uint8_t* p) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", p[0], p[1], p[2], p[3], p[4],
                  p[5]);
    return std::string(buf);
}

struct RadiotapInfo {
    uint16_t length = 0;
    int32_t signalDbm = -100;
    bool hasSignal = false;
};

// Parse a radiotap header: returns its byte length and, when present, the dBm signal.
inline RadiotapInfo parseRadiotap(const uint8_t* data, std::size_t len) {
    RadiotapInfo info;
    if (len < 8 || data[0] != 0x00) {  // version 0
        return info;
    }
    const uint16_t rtLen = static_cast<uint16_t>(data[2] | (data[3] << 8));
    if (rtLen < 8 || rtLen > len) {
        return info;
    }

    const uint32_t firstPresent =
        static_cast<uint32_t>(data[4]) |
        (static_cast<uint32_t>(data[5]) << 8u) |
        (static_cast<uint32_t>(data[6]) << 16u) |
        (static_cast<uint32_t>(data[7]) << 24u);
    // Skip any extended present-flag words (bit 31 chains another word).
    std::size_t off = 8;
    uint32_t present = firstPresent;
    while (present & 0x80000000u) {
        if (off + 4 > rtLen) {
            return info;
        }
        present =
            static_cast<uint32_t>(data[off]) |
            (static_cast<uint32_t>(data[off + 1]) << 8u) |
            (static_cast<uint32_t>(data[off + 2]) << 16u) |
            (static_cast<uint32_t>(data[off + 3]) << 24u);
        off += 4;
    }
    info.length = rtLen;

    auto advanceField = [&](std::size_t a, std::size_t sz) noexcept -> bool {
        off = (off + (a - 1u)) & ~(a - 1u);
        if (off + sz > rtLen) {
            return false;
        }
        off += sz;
        return true;
    };
    const uint32_t pbit = firstPresent;
    if ((pbit & (1u << 0)) && !advanceField(8, 8)) return info;  // TSFT
    if ((pbit & (1u << 1)) && !advanceField(1, 1)) return info;  // Flags
    if ((pbit & (1u << 2)) && !advanceField(1, 1)) return info;  // Rate
    if ((pbit & (1u << 3)) && !advanceField(2, 4)) return info;  // Channel
    if ((pbit & (1u << 4)) && !advanceField(2, 2)) return info;  // FHSS
    if (pbit & (1u << 5)) {                                      // dBm antenna signal
        if (off < rtLen) {
            info.signalDbm = static_cast<int8_t>(data[off]);
            info.hasSignal = true;
        }
    }
    return info;
}

// Shared RSN IE walker: returns byte offset right after AKM list (start of RSN Capabilities),
// or 0 on truncated/malformed input.
inline std::size_t rsnCapabilitiesOffset(const uint8_t* ie, std::size_t len,
                                         sec::Encryption* encOut = nullptr) {
    if (encOut != nullptr) {
        *encOut = sec::Encryption::Wpa2;
    }
    // version(2) group(4) pairwiseCount(2) pairwise(4*n) akmCount(2) akm(4*m) [rsnCaps(2)]
    if (len < 8u) {
        return 0u;
    }
    std::size_t off = 2u + 4u;  // skip version + group cipher
    const uint16_t pairwiseCount = static_cast<uint16_t>(ie[off] | (ie[off + 1u] << 8u));
    off += 2u;
    if (static_cast<std::size_t>(pairwiseCount) > (len - off) / 4u) {
        return 0u;
    }
    off += static_cast<std::size_t>(pairwiseCount) * 4u;
    if (off + 2u > len) {
        return 0u;
    }
    const uint16_t akmCount = static_cast<uint16_t>(ie[off] | (ie[off + 1u] << 8u));
    off += 2u;
    if (static_cast<std::size_t>(akmCount) > (len - off) / 4u) {
        return 0u;
    }
    for (uint16_t i = 0; i < akmCount && off + 4u <= len; ++i, off += 4u) {
        // IEEE 802.11 AKM suite: OUI 00:0F:AC + suite type (8 = SAE/WPA3, 18 = OWE).
        if (encOut != nullptr && ie[off] == 0x00 && ie[off + 1u] == 0x0F &&
            ie[off + 2u] == 0xAC) {
            const uint8_t suiteType = ie[off + 3u];
            if (suiteType == 8u || suiteType == 18u) {
                *encOut = sec::Encryption::Wpa3;
            }
        }
    }
    return off;
}

// Map an RSN information element (tag 48 body) to WPA2/WPA3 by inspecting the AKM suites.
inline sec::Encryption encryptionFromRsn(const uint8_t* ie, std::size_t len) {
    sec::Encryption enc = sec::Encryption::Wpa2;
    (void)rsnCapabilitiesOffset(ie, len, &enc);
    return enc;
}

// Inspect the 802.11w Protected Management Frames bits in an RSN IE's Capabilities field.
// Bit 6 (0x0040) = MFPR (Required), Bit 7 (0x0080) = MFPC (Capable/Optional).
inline sec::PmfStatus pmfFromRsn(const uint8_t* ie, std::size_t len) {
    const std::size_t off = rsnCapabilitiesOffset(ie, len, nullptr);
    if (off == 0u || off + 2u > len) {
        return sec::PmfStatus::Disabled;
    }
    const uint16_t rsnCaps = static_cast<uint16_t>(ie[off] | (ie[off + 1u] << 8u));
    const bool mfpr = (rsnCaps & 0x0040u) != 0u;
    const bool mfpc = (rsnCaps & 0x0080u) != 0u;
    if (mfpr) {
        return sec::PmfStatus::Required;
    }
    if (mfpc) {
        return sec::PmfStatus::Optional;
    }
    return sec::PmfStatus::Disabled;
}

// Parse the tagged parameters of a beacon/probe body: fills SSID, channel, encryption, PMF, CSA.
inline void parseTaggedParams(const uint8_t* tags, std::size_t tlen, bool privacyBit,
                              sec::CapturedFrame& out) {
    bool rsn = false;
    sec::Encryption rsnEnc = sec::Encryption::Wpa2;
    bool wpaVendor = false;
    std::size_t i = 0;
    while (i + 2 <= tlen) {
        const uint8_t id = tags[i];
        const uint8_t tl = tags[i + 1];
        const std::size_t body = i + 2;
        if (body + tl > tlen) {
            break;
        }
        if (id == 0) {  // SSID
            std::string ssid;
            for (std::size_t k = 0; k < tl; ++k) {
                const unsigned char c = tags[body + k];
                if (c >= 32u && c <= 126u) {
                    ssid.push_back(static_cast<char>(c));
                }
            }
            out.ssid = ssid;  // empty => hidden
        } else if (id == 3 && tl >= 1) {  // DS parameter: current channel
            out.channel = tags[body];
        } else if (id == 37 && tl >= 3) {  // Channel Switch Announcement (CSA)
            out.csaChannel = tags[body + 1];
            out.csaCount = tags[body + 2];
        } else if (id == 60 && tl >= 4) {  // Extended CSA (ECSA)
            out.csaChannel = tags[body + 2];
            out.csaCount = tags[body + 3];
        } else if (id == 48) {  // RSN
            rsn = true;
            rsnEnc = encryptionFromRsn(tags + body, tl);
            out.pmf = pmfFromRsn(tags + body, tl);
        } else if (id == 221 && tl >= 4) {  // vendor-specific
            if (tags[body] == 0x00 && tags[body + 1] == 0x50 && tags[body + 2] == 0xF2) {
                if (tags[body + 3] == 0x01) {
                    wpaVendor = true;  // Microsoft WPA1 IE
                } else if (tags[body + 3] == 0x04) {
                    out.wps = true;    // Wi-Fi Protected Setup (WPS) IE
                }
            }
        }
        i = body + tl;
    }
    if (rsn) {
        out.enc = rsnEnc;
    } else if (wpaVendor) {
        out.enc = sec::Encryption::Wpa;
    } else if (privacyBit) {
        out.enc = sec::Encryption::Wep;
    } else {
        out.enc = sec::Encryption::Open;
    }
}

// Returns the offset of the EAPOL payload (after 802.11 MAC + LLC/SNAP headers) if the
// data frame carries an EAPOL-Key (0x888E, EAPOL type 3) packet, or 0 otherwise.
inline std::size_t eapolKeyPayloadOffset(const uint8_t* f, std::size_t len) {
    if (len < 24) {
        return 0u;
    }
    const uint8_t fc1 = f[1];
    if ((fc1 & 0x40) != 0) {  // Protected (encrypted) frame cannot carry plaintext EAPOL
        return 0u;
    }
    const bool toDs = (fc1 & 0x01) != 0;
    const bool fromDs = (fc1 & 0x02) != 0;
    const uint8_t subtype = static_cast<uint8_t>((f[0] >> 4) & 0xF);
    if ((subtype & 0x04) != 0) {  // Null / CF-Ack / CF-Poll data subtypes carry no body
        return 0u;
    }
    std::size_t hdr = (toDs && fromDs) ? 30 : 24;
    if ((subtype & 0x08) != 0) {  // QoS data: +2 byte QoS control
        hdr += 2;
    }
    if ((fc1 & 0x80) != 0 && (subtype & 0x08) != 0) {  // Order/HT Control (+4 bytes)
        hdr += 4;
    }
    // LLC/SNAP: AA AA 03 00 00 00 <ethertype=0x888E>
    if (hdr + 8u + 4u > len) {
        return 0u;
    }
    const uint8_t* llc = f + hdr;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) {
        return 0u;
    }
    const uint16_t ethertype = static_cast<uint16_t>((static_cast<uint16_t>(llc[6]) << 8u) | llc[7]);
    if (ethertype != 0x888Eu) {
        return 0u;
    }
    const std::size_t eapolOff = hdr + 8u;
    // EAPOL header: version(1), type(1 == 3 for Key), bodyLen(2).
    if (f[eapolOff + 1] != 0x03) {
        return 0u;
    }
    return eapolOff;
}

// True if a data frame carries an EAPOL-Key (0x888E, type 3) payload.
inline bool looksLikeEapol(const uint8_t* f, std::size_t len) {
    return eapolKeyPayloadOffset(f, len) != 0u;
}

// Classify an EAPOL-Key frame into 4-way handshake message 1..4 via IEEE 802.11 Key Info
// bits (big-endian at eapol[5..6]). Returns 1..4, or 255 if unclassifiable/group/invalid.
inline uint8_t classifyEapolKeyMessage(const uint8_t* f, std::size_t len) {
    const std::size_t eapolOff = eapolKeyPayloadOffset(f, len);
    if (eapolOff == 0u || eapolOff + 4u + 95u > len) {
        return 255u;
    }
    const uint8_t* eapol = f + eapolOff;
    const uint8_t descType = eapol[4];
    if (descType != 2u && descType != 254u) {  // RSN (2) or WPA1 (254)
        return 255u;
    }
    const uint16_t keyInfo =
        static_cast<uint16_t>((static_cast<uint16_t>(eapol[5]) << 8u) | eapol[6]);
    const bool pairwise = (keyInfo & 0x0008u) != 0u;
    const bool install  = (keyInfo & 0x0040u) != 0u;
    const bool ack      = (keyInfo & 0x0080u) != 0u;
    const bool mic      = (keyInfo & 0x0100u) != 0u;
    const bool secure   = (keyInfo & 0x0200u) != 0u;
    if (!pairwise) {
        return 255u;
    }
    if (ack && !mic && !install) {
        return 1u;
    }
    if (!ack && mic && !install && !secure) {
        return 2u;
    }
    if (ack && mic && (install || secure)) {
        return 3u;
    }
    if (!ack && mic && !install && secure) {
        return 4u;
    }
    return 255u;
}

// Parses the EAPOL-Key Key Data TLV list for an RSN PMKID KDE (tag 0xDD, len >= 20,
// OUI 00-0F-AC, data type 0x04, and non-zero 16-byte PMKID).
inline bool carriesPmkid(const uint8_t* f, std::size_t len) {
    const std::size_t eapolOff = eapolKeyPayloadOffset(f, len);
    // EAPOL header (4) + EAPOL-Key fixed body (95) = 99 bytes before Key Data.
    constexpr std::size_t kEapolKeyHeaderLen = 4u + 95u;
    if (eapolOff == 0u || eapolOff + kEapolKeyHeaderLen > len) {
        return false;
    }
    const uint8_t* eapol = f + eapolOff;
    const std::size_t keyDataLen =
        (static_cast<std::size_t>(eapol[4u + 93u]) << 8u) | eapol[4u + 94u];
    const std::size_t keyDataOff = eapolOff + kEapolKeyHeaderLen;
    if (keyDataLen == 0u || keyDataOff + keyDataLen > len) {
        return false;
    }
    const uint8_t* kd = f + keyDataOff;
    std::size_t i = 0u;
    while (i + 2u <= keyDataLen) {
        const uint8_t tag = kd[i];
        const uint8_t kl = kd[i + 1u];
        if (tag == 0xDD && kl == 0u) {
            break;  // padding sentinel
        }
        if (i + 2u + kl > keyDataLen) {
            break;
        }
        if (tag == 0xDD && kl >= 20u &&
            kd[i + 2u] == 0x00 && kd[i + 3u] == 0x0F && kd[i + 4u] == 0xAC && kd[i + 5u] == 0x04) {
            bool nonZero = false;
            for (std::size_t p = 0; p < 16u; ++p) {
                if (kd[i + 6u + p] != 0u) {
                    nonZero = true;
                    break;
                }
            }
            if (nonZero) {
                return true;
            }
        }
        i += 2u + kl;
    }
    return false;
}

// Extract the crackable EAPOL-Key material (replay counter, key nonce, MIC, full EAPOL
// frame bytes, and RSN PMKID) into `out`, for the native .hc22000 export path. Fields are
// only set when actually present/non-zero; leaves `out` untouched for non-EAPOL frames.
inline void extractEapolKeyMaterial(const uint8_t* f, std::size_t len, sec::CapturedFrame& out) {
    const std::size_t eapolOff = eapolKeyPayloadOffset(f, len);
    constexpr std::size_t kFixedBody = 4u + 95u;  // EAPOL header + fixed EAPOL-Key body
    if (eapolOff == 0u || eapolOff + kFixedBody > len) {
        return;
    }
    const uint8_t* eapol = f + eapolOff;
    // Replay counter: 8 bytes big-endian at body offset 9.
    uint64_t rc = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        rc = (rc << 8u) | static_cast<uint64_t>(eapol[9u + i]);
    }
    out.eapolReplayCounter = rc;
    // Key nonce: 32 bytes at body offset 17.
    bool nonceNonZero = false;
    for (std::size_t i = 0u; i < 32u; ++i) {
        const uint8_t b = eapol[17u + i];
        out.eapolNonce[i] = b;
        nonceNonZero = nonceNonZero || (b != 0u);
    }
    out.hasEapolNonce = nonceNonZero;
    // Key MIC: 16 bytes at body offset 81.
    bool micNonZero = false;
    for (std::size_t i = 0u; i < 16u; ++i) {
        const uint8_t b = eapol[81u + i];
        out.eapolMic[i] = b;
        micNonZero = micNonZero || (b != 0u);
    }
    out.hasEapolMic = micNonZero;
    // Full EAPOL-Key frame bytes (header + body + key data), bounded by the capture length.
    const std::size_t bodyLen = (static_cast<std::size_t>(eapol[2]) << 8u) | eapol[3];
    std::size_t frameLen = 4u + bodyLen;
    if (frameLen < kFixedBody || eapolOff + frameLen > len) {
        frameLen = len - eapolOff;  // trust capture bounds over a lying length field
    }
    out.eapolBody.assign(eapol, eapol + frameLen);
    // RSN PMKID KDE (16 bytes), if present and non-zero.
    const std::size_t keyDataLen =
        (static_cast<std::size_t>(eapol[4u + 93u]) << 8u) | eapol[4u + 94u];
    const std::size_t keyDataOff = eapolOff + kFixedBody;
    if (keyDataLen != 0u && keyDataOff + keyDataLen <= len) {
        const uint8_t* kd = f + keyDataOff;
        std::size_t i = 0u;
        while (i + 2u <= keyDataLen) {
            const uint8_t tag = kd[i];
            const uint8_t kl = kd[i + 1u];
            if (tag == 0xDD && kl == 0u) {
                break;
            }
            if (i + 2u + kl > keyDataLen) {
                break;
            }
            if (tag == 0xDD && kl >= 20u && kd[i + 2u] == 0x00 && kd[i + 3u] == 0x0F &&
                kd[i + 4u] == 0xAC && kd[i + 5u] == 0x04) {
                for (std::size_t p = 0u; p < 16u; ++p) {
                    out.pmkid[p] = kd[i + 6u + p];
                }
                break;
            }
            i += 2u + kl;
        }
    }
}

// Decode one 802.11 frame (no radiotap). `rssi`/`nowMs` supplied by caller.
inline std::optional<sec::CapturedFrame> decodeDot11(const uint8_t* f, std::size_t len,
                                                     uint32_t nowMs, int32_t rssi) {
    if (len < 24) {
        return std::nullopt;
    }
    const uint8_t fc0 = f[0];
    const uint8_t type = static_cast<uint8_t>((fc0 >> 2) & 0x3);
    const uint8_t subtype = static_cast<uint8_t>((fc0 >> 4) & 0xF);
    const uint8_t fc1 = f[1];
    const bool toDs = (fc1 & 0x01) != 0;
    const bool fromDs = (fc1 & 0x02) != 0;

    const uint8_t* addr1 = f + 4;
    const uint8_t* addr2 = f + 10;
    const uint8_t* addr3 = f + 16;

    sec::CapturedFrame out;
    out.nowMs = nowMs;
    out.rssi = rssi;

    if (type == 0) {  // management
        out.source = macToString(addr2);
        out.dest = macToString(addr1);
        out.bssid = macToString(addr3);
        if (subtype == 8 || subtype == 5) {  // Beacon / Probe Response
            out.kind = sec::FrameKind::Beacon;
            if (len >= 36) {
                const uint16_t caps = static_cast<uint16_t>(f[34] | (f[35] << 8));
                const bool privacy = (caps & 0x0010) != 0;
                parseTaggedParams(f + 36, len - 36, privacy, out);
            }
            return out;
        }
        if (subtype == 4) {  // Probe Request
            out.kind = sec::FrameKind::ProbeRequest;
            if (len > 24) {
                parseTaggedParams(f + 24, len - 24, false, out);
            }
            return out;
        }
        if (subtype == 12) {
            out.kind = sec::FrameKind::Deauth;
            return out;
        }
        if (subtype == 10) {
            out.kind = sec::FrameKind::Disassoc;
            return out;
        }
        if (subtype == 13 && len >= 26) {  // Action frame (CSA / ECSA)
            const uint8_t cat = f[24];
            const uint8_t act = f[25];
            if (cat == 0u && act == 4u) {
                // Spectrum Management CSA Action: Tag 37 element or compact 3-byte CSA body.
                if (len >= 31u && f[26] == 37u && f[27] >= 3u) {
                    out.kind = sec::FrameKind::Csa;
                    out.csaChannel = f[29];
                    out.csaCount = f[30];
                    return out;
                }
                if (len >= 29u) {
                    out.kind = sec::FrameKind::Csa;
                    out.csaChannel = f[27];
                    out.csaCount = f[28];
                    return out;
                }
            } else if (cat == 4u && (act == 0u || act == 4u)) {
                // Public Action Extended CSA (Tag 60 or 4-byte ECSA body).
                if (len >= 32u && f[26] == 60u && f[27] >= 4u) {
                    out.kind = sec::FrameKind::Csa;
                    out.csaChannel = f[30];
                    out.csaCount = f[31];
                    return out;
                }
                if (len >= 30u) {
                    out.kind = sec::FrameKind::Csa;
                    out.csaChannel = f[28];
                    out.csaCount = f[29];
                    return out;
                }
            }
        }
        return std::nullopt;
    }

    if (type == 2) {  // data
        out.hasStation = true;
        if (!toDs && !fromDs) {
            out.bssid = macToString(addr3);
            out.source = macToString(addr2);
            out.dest = macToString(addr1);
            out.station = out.source;
        } else if (!toDs && fromDs) {
            out.bssid = macToString(addr2);
            out.dest = macToString(addr1);
            out.source = macToString(addr3);
            out.station = out.dest;
        } else if (toDs && !fromDs) {
            out.bssid = macToString(addr1);
            out.source = macToString(addr2);
            out.dest = macToString(addr3);
            out.station = out.source;
        } else {
            out.bssid = macToString(addr1);
            out.source = macToString(addr2);
            out.dest = macToString(addr3);
            out.station.clear();
        }
        if (looksLikeEapol(f, len)) {
            out.eapolMsg = classifyEapolKeyMessage(f, len);
            out.hasPmkid = carriesPmkid(f, len);
            extractEapolKeyMaterial(f, len, out);
            out.kind = out.hasPmkid ? sec::FrameKind::Pmkid : sec::FrameKind::Eapol;
            return out;
        }
        out.kind = sec::FrameKind::Data;
        return out;
    }

    return std::nullopt;
}

// Full decode from a radiotap-prefixed capture buffer (what libpcap hands us in DLT_IEEE802_11_RADIO).
inline std::optional<sec::CapturedFrame> decodeRadiotapFrame(const uint8_t* buf, std::size_t len,
                                                             uint32_t nowMs) {
    const RadiotapInfo rt = parseRadiotap(buf, len);
    if (rt.length == 0 || rt.length >= len) {
        return std::nullopt;
    }
    const int32_t rssi = rt.hasSignal ? rt.signalDbm : -100;
    return decodeDot11(buf + rt.length, len - rt.length, nowMs, rssi);
}

}  // namespace dot11
}  // namespace zd
