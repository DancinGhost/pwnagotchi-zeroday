#pragma once

// Pure, zero-dependency multi-transport peer discovery + original-Pwnagotchi interop.
//
// Lets ZeroDay units greet each other and passively detect classic Pwnagotchi / Palnagotchi
// units in the wild, over any transport:
//   - WiFi: a vendor-specific IE in our own beacons (and the well-known Pwnagotchi signature
//           source address for classic units),
//   - BLE:  the same advert payload in manufacturer data,
//   - LoRa: the same payload in an SX1262 packet (km-range team WIDS alert sharing).
//
// Contains zero Arduino/OS/socket headers so the wire formats, classifier, and registry
// compile under `-fno-exceptions -fno-rtti` and are fully host-unit-tested.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace zd {
namespace peer {

enum class PeerKind : uint8_t { Unknown = 0, ZeroDay, Pwnagotchi, Palnagotchi };
enum class PeerTransport : uint8_t { Wifi = 0, Ble, Lora };

inline const char* peerKindLabel(PeerKind k) {
    switch (k) {
        case PeerKind::ZeroDay:     return "ZeroDay";
        case PeerKind::Pwnagotchi:  return "Pwnagotchi";
        case PeerKind::Palnagotchi: return "Palnagotchi";
        case PeerKind::Unknown:     break;
    }
    return "peer";
}

inline const char* peerTransportLabel(PeerTransport t) {
    switch (t) {
        case PeerTransport::Wifi: return "WiFi";
        case PeerTransport::Ble:  return "BLE";
        case PeerTransport::Lora: return "LoRa";
    }
    return "?";
}

// Classic Pwnagotchi / Palnagotchi advertisement beacons use this well-known signature as the
// source + BSSID address (pwnagotchi `SignatureAddress`). Passive detection = a community hook.
inline constexpr std::array<uint8_t, 6> kPwnagotchiSignature = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE,
                                                                0xAD};
// ZeroDay vendor-specific OUI ("ZD0") + advert type byte for our own WiFi IE / BLE mfg data.
inline constexpr std::array<uint8_t, 3> kZeroDayOui = {0x5A, 0x44, 0x30};
inline constexpr uint8_t kZeroDayAdvertType = 0x01;
inline constexpr uint8_t kAdvertVersion = 1u;

inline constexpr uint8_t kFlagWidsAlert = 0x01;      // this unit is currently raising a WIDS alert
inline constexpr uint8_t kFlagAuthenticated = 0x02;  // 4-byte keyed auth tag appended to advert

inline constexpr std::size_t kMaxPeerName = 16u;

// Compact peer identity broadcast over any transport.
struct PeerAdvert {
    uint8_t version = kAdvertVersion;
    std::string name;    // display name, clamped to kMaxPeerName
    uint16_t pwned = 0u;  // handshakes captured so far (bragging rights / grid stats)
    uint8_t flags = 0u;   // bit0 = kFlagWidsAlert, bit1 = kFlagAuthenticated
    uint32_t authTag = 0u;
};

// Keyed 32-bit integrity/authenticity tag for LoRa / WiFi / BLE ZeroDay team adverts.
inline uint32_t computePeerAuthTag(const PeerAdvert& a, uint32_t meshKey) {
    uint32_t h = 0x811C9DC5u ^ meshKey;
    auto mix = [&](uint8_t b) {
        h ^= b;
        h *= 0x01000193u;
    };
    std::string name = a.name;
    if (name.size() > kMaxPeerName) {
        name.resize(kMaxPeerName);
    }
    mix(a.version);
    mix(static_cast<uint8_t>(name.size()));
    for (char c : name) {
        mix(static_cast<uint8_t>(c));
    }
    mix(static_cast<uint8_t>(a.pwned & 0xFFu));
    mix(static_cast<uint8_t>((a.pwned >> 8u) & 0xFFu));
    mix(static_cast<uint8_t>(a.flags & ~kFlagAuthenticated));
    h ^= h >> 16u;
    h *= 0x85EBCA6Bu;
    h ^= h >> 13u;
    h *= 0xC2B2AE35u;
    h ^= h >> 16u;
    return h;
}

inline void signPeerAdvert(PeerAdvert& a, uint32_t meshKey) {
    a.flags = static_cast<uint8_t>(a.flags | kFlagAuthenticated);
    a.authTag = computePeerAuthTag(a, meshKey);
}

inline bool verifyPeerAdvert(const PeerAdvert& a, uint32_t meshKey) {
    return (a.flags & kFlagAuthenticated) != 0u && a.authTag == computePeerAuthTag(a, meshKey);
}

// Serialize a PeerAdvert: ver(1) nameLen(1) name(n<=16) pwned(2 LE) flags(1) [authTag(4 LE)].
inline std::vector<uint8_t> encodePeerAdvert(const PeerAdvert& a) {
    std::string name = a.name;
    if (name.size() > kMaxPeerName) {
        name.resize(kMaxPeerName);
    }
    const bool hasTag = (a.flags & kFlagAuthenticated) != 0u;
    std::vector<uint8_t> out;
    out.reserve(5u + name.size() + (hasTag ? 4u : 0u));
    out.push_back(a.version);
    out.push_back(static_cast<uint8_t>(name.size()));
    for (char c : name) {
        out.push_back(static_cast<uint8_t>(c));
    }
    out.push_back(static_cast<uint8_t>(a.pwned & 0xFFu));
    out.push_back(static_cast<uint8_t>((a.pwned >> 8u) & 0xFFu));
    out.push_back(a.flags);
    if (hasTag) {
        out.push_back(static_cast<uint8_t>(a.authTag & 0xFFu));
        out.push_back(static_cast<uint8_t>((a.authTag >> 8u) & 0xFFu));
        out.push_back(static_cast<uint8_t>((a.authTag >> 16u) & 0xFFu));
        out.push_back(static_cast<uint8_t>((a.authTag >> 24u) & 0xFFu));
    }
    return out;
}

// Parse a PeerAdvert from a buffer; nullopt if malformed/truncated.
inline std::optional<PeerAdvert> decodePeerAdvert(const uint8_t* data, std::size_t len) {
    if (data == nullptr || len < 5u) {
        return std::nullopt;
    }
    PeerAdvert a;
    a.version = data[0];
    const std::size_t nameLen = data[1];
    if (nameLen > kMaxPeerName || 2u + nameLen + 3u > len) {
        return std::nullopt;
    }
    a.name.assign(reinterpret_cast<const char*>(data + 2), nameLen);
    const std::size_t p = 2u + nameLen;
    a.pwned = static_cast<uint16_t>(data[p] | (static_cast<uint16_t>(data[p + 1u]) << 8u));
    a.flags = data[p + 2u];
    if ((a.flags & kFlagAuthenticated) != 0u) {
        if (p + 7u > len) {
            return std::nullopt;
        }
        a.authTag = static_cast<uint32_t>(data[p + 3u]) |
                    (static_cast<uint32_t>(data[p + 4u]) << 8u) |
                    (static_cast<uint32_t>(data[p + 5u]) << 16u) |
                    (static_cast<uint32_t>(data[p + 6u]) << 24u);
    }
    return a;
}

// Build the ZeroDay WiFi vendor-specific IE (tag 0xDD) carrying `advert`, for embedding in a
// beacon this unit transmits so other ZeroDay units greet it. Layout: DD len OUI(3) type(1) payload.
inline std::vector<uint8_t> buildZeroDayAdvertIe(const PeerAdvert& advert) {
    const std::vector<uint8_t> payload = encodePeerAdvert(advert);
    std::vector<uint8_t> ie;
    ie.reserve(2u + 4u + payload.size());
    ie.push_back(0xDD);
    ie.push_back(static_cast<uint8_t>(4u + payload.size()));  // OUI(3)+type(1)+payload
    ie.push_back(kZeroDayOui[0]);
    ie.push_back(kZeroDayOui[1]);
    ie.push_back(kZeroDayOui[2]);
    ie.push_back(kZeroDayAdvertType);
    ie.insert(ie.end(), payload.begin(), payload.end());
    return ie;
}

// Upper bound for a greeting beacon: 24 hdr + 12 fixed + SSID(2+10) + rates(2+4) + vendor IE
// (2 + 4 + advert payload up to 5+16). Rounded up for safety.
inline constexpr std::size_t kMaxGreetingBeaconLen = 96u;
// Fixed SSID broadcast by ZeroDay greeting beacons (so humans/tools can spot a ZeroDay grid).
inline constexpr char kGreetingSsid[] = "ZeroDay";

// Build a full 802.11 beacon frame advertising this unit to other ZeroDay peers: standard
// beacon header + fixed params + a short SSID + basic rates + our vendor IE carrying `advert`.
// `src` is this unit's MAC (also used as BSSID). `out` must hold kMaxGreetingBeaconLen bytes.
// Pure byte serialization only; the imperative shell decides whether/when to transmit it.
inline std::size_t buildZeroDayGreetingBeacon(uint8_t* out, const uint8_t src[6],
                                              const PeerAdvert& advert) {
    std::size_t n = 0;
    out[n++] = 0x80;  // FC: mgmt type (00), subtype Beacon (1000)
    out[n++] = 0x00;
    out[n++] = 0x00;  // Duration
    out[n++] = 0x00;
    for (std::size_t i = 0; i < 6; ++i) out[n++] = 0xFF;    // addr1 DA = broadcast
    for (std::size_t i = 0; i < 6; ++i) out[n++] = src[i];  // addr2 SA
    for (std::size_t i = 0; i < 6; ++i) out[n++] = src[i];  // addr3 BSSID
    out[n++] = 0x00;  // Sequence control (hardware overwrites)
    out[n++] = 0x00;
    for (std::size_t i = 0; i < 8; ++i) out[n++] = 0x00;  // Timestamp
    out[n++] = 0x64;  // Beacon interval = 100 TU
    out[n++] = 0x00;
    out[n++] = 0x00;  // Capability info (IBSS/none set — presence only, not an AP offering assoc)
    out[n++] = 0x00;
    // SSID element.
    const std::size_t ssidLen = sizeof(kGreetingSsid) - 1u;  // exclude NUL
    out[n++] = 0x00;
    out[n++] = static_cast<uint8_t>(ssidLen);
    for (std::size_t i = 0; i < ssidLen; ++i) out[n++] = static_cast<uint8_t>(kGreetingSsid[i]);
    // Supported Rates element: 1, 2, 5.5, 11 Mbps.
    out[n++] = 0x01;
    out[n++] = 0x04;
    out[n++] = 0x82;
    out[n++] = 0x84;
    out[n++] = 0x8B;
    out[n++] = 0x96;
    // ZeroDay vendor IE carrying the advert.
    const std::vector<uint8_t> ie = buildZeroDayAdvertIe(advert);
    for (uint8_t b : ie) out[n++] = b;
    return n;
}

// --- BLE transport ------------------------------------------------------------------------
// BLE "Manufacturer Specific Data" payload (the bytes BLEAdvertising::setManufacturerData wants,
// i.e. starting at the company identifier; the stack prepends the AD length/type 0xFF). We use
// company id 0xFFFF (reserved by the Bluetooth SIG for testing / "no company") so we never
// impersonate a real vendor. Layout: companyId(2 LE) type(1)=kZeroDayAdvertType advert(n).
inline constexpr uint16_t kBleCompanyId = 0xFFFFu;

inline std::vector<uint8_t> buildZeroDayBleManufacturerData(const PeerAdvert& advert) {
    const std::vector<uint8_t> payload = encodePeerAdvert(advert);
    std::vector<uint8_t> out;
    out.reserve(3u + payload.size());
    out.push_back(static_cast<uint8_t>(kBleCompanyId & 0xFFu));
    out.push_back(static_cast<uint8_t>((kBleCompanyId >> 8u) & 0xFFu));
    out.push_back(kZeroDayAdvertType);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// Parse manufacturer-specific data from a scanned BLE advert; nullopt unless it is ours.
inline std::optional<PeerAdvert> parseZeroDayBleManufacturerData(const uint8_t* data,
                                                                 std::size_t len) {
    if (data == nullptr || len < 4u) {
        return std::nullopt;
    }
    const uint16_t company = static_cast<uint16_t>(data[0] | (static_cast<uint16_t>(data[1]) << 8u));
    if (company != kBleCompanyId || data[2] != kZeroDayAdvertType) {
        return std::nullopt;
    }
    return decodePeerAdvert(data + 3, len - 3u);
}

// --- LoRa transport -----------------------------------------------------------------------
// Raw SX1262 LoRa packet payload. Prefixed with the ZeroDay OUI ("ZD0") + advert type so a
// ZeroDay packet is distinguishable from other LoRa traffic on the air. Layout:
// 'Z','D','0' type(1)=kZeroDayAdvertType advert(n). Km-range team WIDS alert sharing rides the
// advert's kFlagWidsAlert bit.
inline std::vector<uint8_t> buildZeroDayLoraPacket(const PeerAdvert& advert) {
    const std::vector<uint8_t> payload = encodePeerAdvert(advert);
    std::vector<uint8_t> out;
    out.reserve(4u + payload.size());
    out.push_back(kZeroDayOui[0]);
    out.push_back(kZeroDayOui[1]);
    out.push_back(kZeroDayOui[2]);
    out.push_back(kZeroDayAdvertType);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

// Parse a received LoRa packet payload; nullopt unless it carries a ZeroDay advert.
inline std::optional<PeerAdvert> parseZeroDayLoraPacket(const uint8_t* data, std::size_t len) {
    if (data == nullptr || len < 5u || data[0] != kZeroDayOui[0] || data[1] != kZeroDayOui[1] ||
        data[2] != kZeroDayOui[2] || data[3] != kZeroDayAdvertType) {
        return std::nullopt;
    }
    return decodePeerAdvert(data + 4, len - 4u);
}

namespace detail {
inline bool macEq(const uint8_t* a, const uint8_t* b) {
    for (std::size_t i = 0u; i < 6u; ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}
inline std::string macToStr(const uint8_t* m) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(17u);
    for (std::size_t i = 0u; i < 6u; ++i) {
        if (i != 0u) {
            s.push_back(':');
        }
        s.push_back(kHex[(m[i] >> 4u) & 0xFu]);
        s.push_back(kHex[m[i] & 0xFu]);
    }
    return s;
}
}  // namespace detail

struct WifiPeerHit {
    PeerKind kind = PeerKind::Unknown;
    std::string id;           // source MAC
    PeerAdvert advert{};      // valid only when hasAdvert
    bool hasAdvert = false;
};

// A classified WiFi peer plus the signal/timestamp of the sighting, so an imperative shell
// (e.g. the Linux capture backend) can hand peer observations across a thread boundary for a
// PeerRegistry to aggregate without re-parsing raw frames.
struct PeerSighting {
    WifiPeerHit hit{};
    int32_t rssi = -100;
    uint32_t nowMs = 0u;
};

// Inspect a raw 802.11 management frame (no radiotap) for a peer: the classic Pwnagotchi
// signature address, or a ZeroDay vendor IE in a beacon/probe-response. nullopt if not a peer.
inline std::optional<WifiPeerHit> classifyWifiPeer(const uint8_t* f, std::size_t len) {
    if (f == nullptr || len < 24u) {
        return std::nullopt;
    }
    const uint8_t type = static_cast<uint8_t>((f[0] >> 2u) & 0x3u);
    if (type != 0u) {  // management frames only
        return std::nullopt;
    }
    const uint8_t subtype = static_cast<uint8_t>((f[0] >> 4u) & 0xFu);
    const uint8_t* addr2 = f + 10;  // source
    const uint8_t* addr3 = f + 16;  // BSSID

    // 1. Classic Pwnagotchi / Palnagotchi signature address.
    if (detail::macEq(addr2, kPwnagotchiSignature.data()) ||
        detail::macEq(addr3, kPwnagotchiSignature.data())) {
        WifiPeerHit hit;
        hit.kind = PeerKind::Pwnagotchi;
        hit.id = detail::macToStr(addr2);
        return hit;
    }

    // 2. ZeroDay vendor IE inside a beacon (8) or probe-response (5): skip the 12-byte fixed
    //    params (timestamp+interval+caps) then scan tagged elements.
    if (subtype == 8u || subtype == 5u) {
        std::size_t i = 36u;  // 24 header + 12 fixed params
        while (i + 2u <= len) {
            const uint8_t tag = f[i];
            const std::size_t tlen = f[i + 1u];
            if (i + 2u + tlen > len) {
                break;
            }
            if (tag == 0xDD && tlen >= 4u && f[i + 2u] == kZeroDayOui[0] &&
                f[i + 3u] == kZeroDayOui[1] && f[i + 4u] == kZeroDayOui[2] &&
                f[i + 5u] == kZeroDayAdvertType) {
                WifiPeerHit hit;
                hit.kind = PeerKind::ZeroDay;
                hit.id = detail::macToStr(addr2);
                if (const auto adv = decodePeerAdvert(f + i + 6u, tlen - 4u)) {
                    hit.advert = *adv;
                    hit.hasAdvert = true;
                }
                return hit;
            }
            i += 2u + tlen;
        }
    }
    return std::nullopt;
}

// A discovered peer, aggregated across sightings.
struct Peer {
    std::string id;                        // MAC (wifi/ble) or node id (lora)
    std::string name;
    PeerKind kind = PeerKind::Unknown;
    PeerTransport transport = PeerTransport::Wifi;
    int32_t rssi = -100;
    uint16_t pwned = 0u;
    bool widsAlert = false;
    bool authenticated = false;
    uint32_t firstSeenMs = 0u;
    uint32_t lastSeenMs = 0u;
    uint32_t sightings = 0u;
};

// Bounded registry of discovered peers. Tracks a monotonic "peers met" count (new distinct
// peers greeted this session) for the pet's grid stats / UI.
class PeerRegistry {
public:
    static constexpr std::size_t kMaxPeers = 64u;

    // Register a sighting. Returns true when `id` is seen for the FIRST time (a new greeting).
    bool observe(const std::string& id, PeerKind kind, PeerTransport transport, int32_t rssi,
                 const std::string& name, uint16_t pwned, bool widsAlert, uint32_t nowMs,
                 bool authenticated = false) {
        if (id.empty()) {
            return false;
        }
        for (Peer& p : peers_) {
            if (p.id == id) {
                p.kind = kind;
                p.transport = transport;
                p.rssi = rssi;
                if (!name.empty()) {
                    p.name = name;
                }
                p.pwned = pwned;
                p.widsAlert = widsAlert;
                p.authenticated = authenticated;
                p.lastSeenMs = nowMs;
                p.sightings += 1u;
                return false;
            }
        }
        // New peer. Evict the least-recently-seen entry if full.
        if (peers_.size() >= kMaxPeers) {
            std::size_t oldest = 0u;
            for (std::size_t i = 1u; i < peers_.size(); ++i) {
                if (peers_[i].lastSeenMs < peers_[oldest].lastSeenMs) {
                    oldest = i;
                }
            }
            peers_.erase(peers_.begin() + static_cast<std::ptrdiff_t>(oldest));
        }
        Peer p;
        p.id = id;
        p.name = name;
        p.kind = kind;
        p.transport = transport;
        p.rssi = rssi;
        p.pwned = pwned;
        p.widsAlert = widsAlert;
        p.authenticated = authenticated;
        p.firstSeenMs = nowMs;
        p.lastSeenMs = nowMs;
        p.sightings = 1u;
        peers_.push_back(std::move(p));
        peersMet_ += 1u;
        return true;
    }

    // Convenience: register a WiFi classifier hit.
    bool observeWifi(const WifiPeerHit& hit, int32_t rssi, uint32_t nowMs, uint32_t meshKey = 0u) {
        const bool authed =
            (meshKey != 0u && hit.hasAdvert) ? verifyPeerAdvert(hit.advert, meshKey) : false;
        return observe(hit.id, hit.kind, PeerTransport::Wifi, rssi,
                       hit.hasAdvert ? hit.advert.name : std::string{},
                       hit.hasAdvert ? hit.advert.pwned : 0u,
                       hit.hasAdvert && (hit.advert.flags & kFlagWidsAlert) != 0u, nowMs, authed);
    }

    const std::vector<Peer>& peers() const { return peers_; }
    uint32_t peersMet() const { return peersMet_; }
    std::size_t size() const { return peers_.size(); }
    const Peer* find(const std::string& id) const {
        for (const Peer& p : peers_) {
            if (p.id == id) {
                return &p;
            }
        }
        return nullptr;
    }
    // True if any currently-known peer is broadcasting a WIDS alert (team-shared threat).
    bool anyWidsAlert(bool requireAuthenticated = false) const {
        for (const Peer& p : peers_) {
            if (p.widsAlert && (!requireAuthenticated || p.authenticated)) {
                return true;
            }
        }
        return false;
    }

private:
    std::vector<Peer> peers_{};
    uint32_t peersMet_ = 0u;
};

}  // namespace peer
}  // namespace zd
