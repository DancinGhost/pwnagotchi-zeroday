#pragma once

// Portable, zero-dependency security-operations engine (Functional Core).
//
// This header carries ZERO OS, socket, libpcap, libnl, or SDK headers. It is the pure,
// host-testable brain of the Linux desktop build's offensive + defensive features. The
// imperative shell (platforms/linux/*) feeds observed 802.11 activity in as `SecEvent`s
// and renders the resulting immutable `SecState`; it never embeds policy here.
//
// Responsibilities:
//   - Model observed access points / clients and offensive capture progress
//     (WPA handshakes, PMKIDs) as immutable values.
//   - Defensive intrusion monitors expressed as pure reducers:
//       * deauthentication / disassociation flood detection (sliding window),
//       * evil-twin detection (one SSID advertised by multiple BSSIDs),
//       * open-network downgrade detection (encrypted SSID reappears open),
//       * "mana"/karma beacon detection (one BSSID advertising many SSIDs).
//   - A strict AUTHORIZATION gate: no transmit (deauth injection) is ever permitted
//     unless the operator has both confirmed authorization AND explicitly allow-listed
//     the target BSSID. This is the single chokepoint the shell must consult before TX.
//
// Design mirrors pet_logic.hpp: `reduce(SecState, SecEvent) -> SecState`, never mutating
// its input. Everything here is deterministic and unit-tested in tests/core/test_secops.cpp.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include "wifi_analysis.hpp"

namespace zd {
namespace sec {

// --- Value types ---------------------------------------------------------------------

enum class Encryption : uint8_t { Unknown = 0, Open, Wep, Wpa, Wpa2, Wpa3 };

inline const char* encryptionLabel(Encryption e) {
    switch (e) {
        case Encryption::Open:    return "OPEN";
        case Encryption::Wep:     return "WEP";
        case Encryption::Wpa:     return "WPA";
        case Encryption::Wpa2:    return "WPA2";
        case Encryption::Wpa3:    return "WPA3";
        case Encryption::Unknown: break;
    }
    return "??";
}

// Pure MAC normalizer: lower-case, colon-separated "aa:bb:cc:dd:ee:ff".
// Accepts "AABBCCDDEEFF", "aa-bb-...", mixed case, surrounding spaces. Non-hex chars are
// dropped; a string without exactly 12 hex nibbles is returned trimmed+lowered as-is so
// callers can still compare/display it (defensive: never throws).
inline std::string normalizeMac(const std::string& raw) {
    if (raw.size() == 17u) {
        bool canonical = true;
        for (std::size_t i = 0u; i < 17u; ++i) {
            const unsigned char c = static_cast<unsigned char>(raw[i]);
            if ((i % 3u) == 2u) {
                if (c != ':') {
                    canonical = false;
                    break;
                }
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                canonical = false;
                break;
            }
        }
        if (canonical) {
            return raw;
        }
    }
    std::string hex;
    hex.reserve(12);
    for (unsigned char c : raw) {
        if (std::isxdigit(c)) {
            hex.push_back(static_cast<char>(std::tolower(c)));
        }
    }
    if (hex.size() != 12u) {
        std::string lowered;
        lowered.reserve(raw.size());
        for (unsigned char c : raw) {
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                lowered.push_back(static_cast<char>(std::tolower(c)));
            }
        }
        return lowered;
    }
    std::string out;
    out.reserve(17);
    for (std::size_t i = 0; i < 12u; i += 2u) {
        if (i != 0u) {
            out.push_back(':');
        }
        out.push_back(hex[i]);
        out.push_back(hex[i + 1u]);
    }
    return out;
}

inline bool isBroadcastMac(const std::string& mac) {
    return mac == "ff:ff:ff:ff:ff:ff" || mac.empty();
}

// True if `raw` is empty, broadcast, or an IEEE 802 group/multicast address (bit 0 of the
// first octet set, e.g. ff:ff:ff:ff:ff:ff, 01:00:5e:xx:xx:xx, 33:33:xx:xx:xx). Used to keep
// multicast group frames from polluting the client station table or inflating clientCount.
inline bool isMulticastMac(const std::string& raw) {
    const std::string n = normalizeMac(raw);
    if (isBroadcastMac(n)) {
        return true;
    }
    if (n.size() == 17u && std::isxdigit(static_cast<unsigned char>(n[1]))) {
        const char c = n[1];
        const int nibble = (c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10);
        return (nibble & 1) != 0;
    }
    return false;
}

// True if `raw` contains exactly 12 hex digits once separators/whitespace are stripped,
// i.e. normalizeMac(raw) would produce a well-formed "aa:bb:cc:dd:ee:ff" address rather than
// just returning the (lowered/trimmed) input verbatim. Used to reject malformed BSSID/client
// values at input boundaries (CLI args, GUI text fields) before they reach a subprocess argv.
inline bool isValidMac(const std::string& raw) {
    std::size_t hexCount = 0;
    for (unsigned char c : raw) {
        if (std::isxdigit(c)) {
            ++hexCount;
        } else if (c != ':' && c != '-' && c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            return false;  // stray character that isn't hex or a separator (e.g. a stray flag)
        }
    }
    return hexCount == 12u;
}

// True if `client` is empty (broadcast), ff:ff:ff:ff:ff:ff, or a valid unicast MAC.
// Rejects malformed addresses and non-broadcast group/multicast MACs (e.g. 01:00:5e:...).
inline bool isValidClientTarget(const std::string& client) {
    if (client.empty()) {
        return true;
    }
    if (!isValidMac(client)) {
        return false;
    }
    const std::string n = normalizeMac(client);
    return isBroadcastMac(n) || !isMulticastMac(n);
}

// True if `iface` is a legal Linux network interface name (1..15 chars, IFNAMSIZ - 1,
// alphanumeric or '_', '-', '.', and not starting with '-' or '.'). Prevents option/argument
// injection (CWE-88) when `iface` is passed to privileged tools (airmon-ng, airodump-ng, iw).
inline bool isValidIfaceName(const std::string& iface) noexcept {
    if (iface.empty() || iface.size() >= 16u) {
        return false;
    }
    if (iface.front() == '-' || iface.front() == '.') {
        return false;
    }
    for (unsigned char c : iface) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) {
            return false;
        }
    }
    return true;
}

// Strips ASCII control characters (< 0x20 or >= 0x7F, such as ANSI escape sequences \x1b,
// \r, \n) from untrusted over-the-air strings before terminal or log output (CWE-150).
inline std::string sanitizePrintableText(const std::string& raw, std::size_t maxLen = 64u) {
    std::string out;
    out.reserve(raw.size() < maxLen ? raw.size() : maxLen);
    for (std::size_t i = 0; i < raw.size() && out.size() < maxLen; ++i) {
        const unsigned char c = static_cast<unsigned char>(raw[i]);
        if (c >= 0x20u && c <= 0x7Eu) {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

// An access point observed over the air or via an active scan.
struct WifiTarget {
    std::string bssid;              // normalized
    std::string ssid;              // may be "" for hidden networks
    int32_t channel = 0;
    int32_t rssi = -100;
    Encryption enc = Encryption::Unknown;
    uint32_t beacons = 0;
    uint32_t dataFrames = 0;
    uint32_t deauthsSeen = 0;      // deauth/disassoc frames referencing this BSSID
    uint32_t clientCount = 0;
    bool handshake = false;        // WPA 4-way handshake captured
    bool pmkid = false;            // PMKID captured
    bool wps = false;              // WPS (Wi-Fi Protected Setup) IE observed - common attack surface
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
    uint32_t lastEvilTwinAlertMs = 0;
    uint32_t lastDowngradeAlertMs = 0;
};

// --- Defensive alerts ----------------------------------------------------------------

enum class Severity : uint8_t { Info = 0, Warn, Critical };

enum class AlertKind : uint8_t {
    DeauthFlood = 0,     // sustained deauth/disassoc burst against a BSSID (possible attack/jam)
    EvilTwin,            // same SSID advertised by a second BSSID
    OpenDowngrade,       // a previously-encrypted SSID reappeared as Open (rogue/MITM bait)
    KarmaBeacon,         // one BSSID advertising an abnormal number of SSIDs (mana/karma AP)
    HandshakeCaptured,   // offensive progress marker
    PmkidCaptured,       // offensive progress marker
    TxBlocked,           // an injection was refused by the authorization gate
    BleTrackerDetected,  // AirTag / FindMy / SmartTag / Tile tracker or BLE spam detected
    MultiToolDetected,   // Flipper Zero / BLE multi-tool signature detected
    SubGhzAnomaly        // Sub-GHz replay burst or jamming carrier detected
};

inline const char* alertKindLabel(AlertKind k) {
    switch (k) {
        case AlertKind::DeauthFlood:        return "DEAUTH-FLOOD";
        case AlertKind::EvilTwin:           return "EVIL-TWIN";
        case AlertKind::OpenDowngrade:      return "OPEN-DOWNGRADE";
        case AlertKind::KarmaBeacon:        return "KARMA-BEACON";
        case AlertKind::HandshakeCaptured:  return "HANDSHAKE";
        case AlertKind::PmkidCaptured:      return "PMKID";
        case AlertKind::TxBlocked:          return "TX-BLOCKED";
        case AlertKind::BleTrackerDetected: return "BLE-TRACKER";
        case AlertKind::MultiToolDetected:  return "MULTI-TOOL";
        case AlertKind::SubGhzAnomaly:      return "SUBGHZ-ALERT";
    }
    return "ALERT";
}

struct Alert {
    uint32_t nowMs = 0;
    Severity severity = Severity::Info;
    AlertKind kind = AlertKind::DeauthFlood;
    std::string bssid;
    std::string ssid;
    std::string message;
};

// --- Authorization gate --------------------------------------------------------------
//
// The one place that decides whether a transmit (deauth injection) is permitted. Pure &
// total. The shell MUST call `authorize()` and only proceed on `Allowed`.

enum class AuthDecision : uint8_t {
    Allowed = 0,
    BlockedUnconfirmed,    // operator has not asserted authorization
    BlockedNotAllowlisted, // target BSSID not on the explicit allow-list (or invalid/multicast)
    BlockedAuditFailed     // audit trail could not be durably written (fail-closed)
};

struct Authorization {
    bool operatorConfirmed = false;      // set only by explicit operator action (flag / dialog)
    std::vector<std::string> allowedBssids;  // sorted normalized BSSIDs the operator owns
    bool allowAll = false;               // "*" wildcard; STILL requires operatorConfirmed

    bool allow(const std::string& bssid) {
        if (!isValidMac(bssid) || isMulticastMac(bssid)) {
            return false;
        }
        const std::string n = normalizeMac(bssid);
        const auto it = std::lower_bound(allowedBssids.begin(), allowedBssids.end(), n);
        if (it == allowedBssids.end() || *it != n) {
            allowedBssids.insert(it, n);
        }
        return true;
    }

    bool isAllowed(const std::string& bssid) const {
        if (!isValidMac(bssid)) {
            return false;
        }
        const std::string n = normalizeMac(bssid);
        return std::binary_search(allowedBssids.begin(), allowedBssids.end(), n);
    }

    bool disallow(const std::string& bssid) {
        if (!isValidMac(bssid)) {
            return false;
        }
        const std::string n = normalizeMac(bssid);
        const auto it = std::lower_bound(allowedBssids.begin(), allowedBssids.end(), n);
        if (it == allowedBssids.end() || *it != n) {
            return false;
        }
        allowedBssids.erase(it);
        return true;
    }
};

inline AuthDecision authorize(const Authorization& auth, const std::string& bssid) {
    if (!auth.operatorConfirmed) {
        return AuthDecision::BlockedUnconfirmed;
    }
    // Reject invalid, broadcast, or multicast BSSIDs even when allowAll is enabled.
    if (!isValidMac(bssid) || isMulticastMac(bssid)) {
        return AuthDecision::BlockedNotAllowlisted;
    }
    if (auth.allowAll || auth.isAllowed(bssid)) {
        return AuthDecision::Allowed;
    }
    return AuthDecision::BlockedNotAllowlisted;
}

inline const char* authDecisionLabel(AuthDecision d) {
    switch (d) {
        case AuthDecision::Allowed:               return "ALLOWED";
        case AuthDecision::BlockedUnconfirmed:    return "BLOCKED: authorization not confirmed";
        case AuthDecision::BlockedNotAllowlisted: return "BLOCKED: BSSID not on allow-list";
        case AuthDecision::BlockedAuditFailed:    return "BLOCKED: audit log write failed";
    }
    return "BLOCKED";
}

// --- Events fed from the imperative shell --------------------------------------------

struct ApObserved {      // from beacon/probe-response or active scan
    uint32_t nowMs = 0u;
    std::string bssid;
    std::string ssid;
    int32_t channel = 0;
    int32_t rssi = -100;
    Encryption enc = Encryption::Unknown;
    bool wps = false;
};

struct ClientObserved {  // a station associated with / probing a BSSID
    uint32_t nowMs = 0u;
    std::string bssid;
    std::string client;
};

struct DataFrameObserved {
    uint32_t nowMs = 0u;
    std::string bssid;
};

struct DeauthObserved {  // management deauth or disassociation frame
    uint32_t nowMs = 0u;
    std::string bssid;
    std::string source;
    std::string dest;
};

struct HandshakeObserved {
    uint32_t nowMs = 0u;
    std::string bssid;
};

struct PmkidObserved {
    uint32_t nowMs = 0u;
    std::string bssid;
};

// A client probing for a (possibly not-yet-associated) network by SSID. Probe requests
// leak a station's preferred-network list even over broadcast/unassociated probes, which
// is why this is tracked independently of ClientObserved (which requires a known BSSID).
struct ProbeRequestObserved {
    uint32_t nowMs = 0u;
    std::string client;
    std::string ssid;   // SSID being probed for; may be "" for a wildcard/broadcast probe
};

// Recorded whenever the shell asks the gate about a transmit; keeps the decision in the
// state/alert stream so the UI and audit log stay consistent. `allowed` mirrors the gate.
struct InjectionAttempt {
    uint32_t nowMs = 0u;
    std::string bssid;
    std::string client;   // target station, or "" for broadcast
    uint32_t count = 0u;  // frames requested
    AuthDecision decision = AuthDecision::BlockedUnconfirmed;
};

struct BleObserved {
    uint32_t nowMs = 0u;
    std::string mac;
    std::string name;
    int32_t rssi = -100;
    uint16_t companyId = 0;
    uint16_t serviceUuid = 0;
    bool trackerPayload = false;
};

struct SubGhzObserved {
    uint32_t nowMs = 0u;
    uint32_t freqKhz = 0u;
    int32_t rssi = -100;
    std::string protocol;
    uint32_t burstCount = 1;
    bool continuousCarrier = false;
};

using SecEvent = std::variant<
    ApObserved,
    ClientObserved,
    DataFrameObserved,
    DeauthObserved,
    HandshakeObserved,
    PmkidObserved,
    ProbeRequestObserved,
    InjectionAttempt,
    BleObserved,
    SubGhzObserved>;

// --- Immutable aggregate state -------------------------------------------------------

// Tuning constants for the defensive monitors and bounded state collections.
constexpr uint32_t kDeauthWindowMs = 10000u;   // sliding window for flood detection
constexpr std::size_t kDeauthFloodThreshold = 8u;  // frames in window => flood
constexpr uint32_t kAlertCooldownMs = 15000u;  // per-(kind,bssid) alert de-dupe window
constexpr std::size_t kKarmaSsidThreshold = 6u;    // distinct SSIDs per BSSID => karma
constexpr std::size_t kMaxAlerts = 200u;       // ring cap on retained alerts
constexpr std::size_t kMaxTargets = 500u;      // ring cap; evicts least-recently-seen AP
constexpr std::size_t kMaxDeauthTrackers = 256u;   // ring cap; evicts oldest BSSID tracker
constexpr std::size_t kMaxDeauthTimestamps = 64u;  // cap per-BSSID sliding-window vector under flood
constexpr std::size_t kMaxBssidSsids = 256u;   // ring cap; evicts oldest BSSID-SSID set
constexpr std::size_t kMaxSsidsPerBssid = 32u; // cap per-BSSID advertised SSIDs list
constexpr std::size_t kMaxProbedSsidsPerStation = 16u;  // cap per-station probed-SSID list
constexpr std::size_t kMaxStations = 500u;     // ring cap; evicts least-recently-seen station
constexpr std::size_t kMaxBleTargets = 256u;
constexpr std::size_t kMaxSubGhzCaptures = 128u;

struct BleTarget {
    std::string mac;
    std::string name;
    int32_t rssi = -100;
    uint16_t companyId = 0;
    uint16_t serviceUuid = 0;
    bool trackerPayload = false;
    BleThreatKind threat = BleThreatKind::None;
    uint32_t seenCount = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
    uint32_t lastAlertMs = 0;
};

struct SubGhzCapture {
    uint32_t freqKhz = 433920u;
    int32_t rssi = -100;
    std::string protocol;
    uint32_t burstCount = 1;
    bool continuousCarrier = false;
    uint32_t seenMs = 0;
};

// Per-BSSID sliding window of recent deauth timestamps (defensive flood detector).
struct DeauthTracker {
    std::string bssid;
    std::vector<uint32_t> recentMs;
    uint32_t lastFloodAlertMs = 0;
};

// Per-BSSID set of advertised SSIDs (evil-twin reverse lookup is by SSID below).
struct BssidSsids {
    std::string bssid;
    std::vector<std::string> ssids;
    uint32_t lastKarmaAlertMs = 0;
    uint32_t lastSeenMs = 0;
};

// A client station observed either associating with a known BSSID or sending probe
// requests (which can happen before association, or to networks it never joins).
// Tracked separately from WifiTarget to surface a station's probed-SSID history - a
// passive privacy/recon signal (phones leak their preferred-network list on every probe).
struct Station {
    std::string mac;                       // normalized
    std::vector<std::string> probedSsids;  // distinct SSIDs this station has probed for
    std::string lastBssid;                 // most recent BSSID observed associating with it
    uint32_t probeCount = 0;
    uint32_t firstSeenMs = 0;
    uint32_t lastSeenMs = 0;
};

struct SecState {
    std::vector<WifiTarget> targets;
    std::vector<DeauthTracker> deauthTrackers;
    std::vector<BssidSsids> bssidSsids;
    std::vector<Station> stations;
    std::vector<BleTarget> bleTargets;
    std::vector<SubGhzCapture> subGhzCaptures;
    std::deque<Alert> alerts;         // most-recent appended last, capped at kMaxAlerts
    uint32_t totalDeauths = 0;
    uint32_t totalHandshakes = 0;
    uint32_t totalPmkids = 0;
    uint32_t blockedInjections = 0;
    uint32_t allowedInjections = 0;
    uint32_t totalAlertsEmitted = 0;  // monotonic count even after alerts wrap kMaxAlerts
    uint64_t revision = 0;            // monotonic counter incremented on every reduce()
    uint32_t lastEventMs = 0;         // high-water timestamp of processed events

    // O(1) lookup indices synchronized with the bounded vectors above.
    std::unordered_map<std::string, std::size_t> targetIndex;
    std::unordered_map<std::string, std::size_t> stationIndex;
    std::unordered_map<std::string, std::size_t> bleIndex;
    std::unordered_map<std::string, std::size_t> deauthIndex;
    std::unordered_map<std::string, std::size_t> bssidSsidIndex;
    std::unordered_map<std::string, std::vector<std::string>> ssidToBssids;
    std::vector<std::string> trustedBssids;  // normalized sorted BSSIDs marked trusted by operator
};

inline bool isTrustedBssid(const SecState& s, const std::string& rawBssid) {
    const std::string bssid = normalizeMac(rawBssid);
    return !bssid.empty() &&
           std::find(s.trustedBssids.begin(), s.trustedBssids.end(), bssid) !=
               s.trustedBssids.end();
}

inline bool trustBssid(SecState& s, const std::string& rawBssid) {
    const std::string bssid = normalizeMac(rawBssid);
    if (!isValidMac(bssid) || isMulticastMac(bssid)) {
        return false;
    }
    if (isTrustedBssid(s, bssid)) {
        return true;
    }
    s.trustedBssids.push_back(bssid);
    std::sort(s.trustedBssids.begin(), s.trustedBssids.end());
    return true;
}

inline bool untrustBssid(SecState& s, const std::string& rawBssid) {
    const std::string bssid = normalizeMac(rawBssid);
    const auto it = std::find(s.trustedBssids.begin(), s.trustedBssids.end(), bssid);
    if (it == s.trustedBssids.end()) {
        return false;
    }
    s.trustedBssids.erase(it);
    return true;
}

// --- Pure helpers (exposed for tests & shell convenience) ----------------------------

inline WifiTarget* findTarget(SecState& s, const std::string& bssid) {
    const auto it = s.targetIndex.find(bssid);
    if (it != s.targetIndex.end() && it->second < s.targets.size()) {
        return &s.targets[it->second];
    }
    return nullptr;
}

inline const WifiTarget* findTarget(const SecState& s, const std::string& bssid) {
    const auto it = s.targetIndex.find(bssid);
    if (it != s.targetIndex.end() && it->second < s.targets.size()) {
        return &s.targets[it->second];
    }
    return nullptr;
}

inline Station* findStation(SecState& s, const std::string& mac) {
    const auto it = s.stationIndex.find(mac);
    if (it != s.stationIndex.end() && it->second < s.stations.size()) {
        return &s.stations[it->second];
    }
    return nullptr;
}

inline const Station* findStation(const SecState& s, const std::string& mac) {
    const auto it = s.stationIndex.find(mac);
    if (it != s.stationIndex.end() && it->second < s.stations.size()) {
        return &s.stations[it->second];
    }
    return nullptr;
}

inline BleTarget* findBleTarget(SecState& s, const std::string& mac) {
    const auto it = s.bleIndex.find(mac);
    if (it != s.bleIndex.end() && it->second < s.bleTargets.size()) {
        return &s.bleTargets[it->second];
    }
    return nullptr;
}

inline const BleTarget* findBleTarget(const SecState& s, const std::string& mac) {
    const auto it = s.bleIndex.find(mac);
    if (it != s.bleIndex.end() && it->second < s.bleTargets.size()) {
        return &s.bleTargets[it->second];
    }
    return nullptr;
}

namespace detail {

// Wrap-safe and clock-skew-safe elapsed time helpers (32-bit ms clock wraps every ~49.7d).
inline constexpr bool elapsedAtLeast(uint32_t nowMs, uint32_t prevMs, uint32_t deltaMs) {
    const uint32_t diff = nowMs - prevMs;
    return diff < 0x80000000u && diff >= deltaMs;
}

inline constexpr bool elapsedMoreThan(uint32_t nowMs, uint32_t prevMs, uint32_t deltaMs) {
    const uint32_t diff = nowMs - prevMs;
    return diff < 0x80000000u && diff > deltaMs;
}

inline constexpr uint32_t wrapSafeAgeMs(uint32_t nowMs, uint32_t prevMs) {
    const uint32_t diff = nowMs - prevMs;
    return (diff < 0x80000000u) ? diff : 0u;
}

inline void pushAlert(SecState& s, Alert a) {
    s.totalAlertsEmitted += 1u;
    s.alerts.push_back(std::move(a));
    while (s.alerts.size() > kMaxAlerts) {
        s.alerts.pop_front();
    }
}

inline void removeSsidBssid(SecState& s, const std::string& ssid, const std::string& bssid) {
    if (ssid.empty()) {
        return;
    }
    const auto it = s.ssidToBssids.find(ssid);
    if (it == s.ssidToBssids.end()) {
        return;
    }
    auto& vec = it->second;
    vec.erase(std::remove(vec.begin(), vec.end(), bssid), vec.end());
    if (vec.empty()) {
        s.ssidToBssids.erase(it);
    }
}

inline void addSsidBssid(SecState& s, const std::string& ssid, const std::string& bssid) {
    if (ssid.empty()) {
        return;
    }
    auto& vec = s.ssidToBssids[ssid];
    if (std::find(vec.begin(), vec.end(), bssid) == vec.end()) {
        vec.push_back(bssid);
    }
}

// Shared LRU eviction helper for bounded vectors paired with an O(1) swap-and-pop index map.
template <typename Vec, typename IndexMap, typename KeyFn, typename TimeFn, typename OnEvict>
inline void evictOldestIfFull(Vec& vec, IndexMap& index, std::size_t cap, uint32_t nowMs,
                              KeyFn&& keyOf, TimeFn&& timeOf, OnEvict&& onEvict) {
    if (vec.size() < cap || vec.empty()) {
        return;
    }
    std::size_t oldestIdx = 0u;
    uint32_t maxAge = wrapSafeAgeMs(nowMs, timeOf(vec[0]));
    for (std::size_t i = 1u; i < vec.size(); ++i) {
        const uint32_t age = wrapSafeAgeMs(nowMs, timeOf(vec[i]));
        if (age > maxAge) {
            maxAge = age;
            oldestIdx = i;
        }
    }
    onEvict(vec[oldestIdx]);
    index.erase(keyOf(vec[oldestIdx]));
    const std::size_t lastIdx = vec.size() - 1u;
    if (oldestIdx != lastIdx) {
        vec[oldestIdx] = std::move(vec[lastIdx]);
        index[keyOf(vec[oldestIdx])] = oldestIdx;
    }
    vec.pop_back();
}

// Upserts a target AP, evicting the least-recently-seen one first if at kMaxTargets.
inline WifiTarget& targetFor(SecState& s, const std::string& bssid, uint32_t nowMs,
                             bool* isNewOut = nullptr) {
    if (WifiTarget* existing = findTarget(s, bssid)) {
        if (isNewOut != nullptr) {
            *isNewOut = false;
        }
        return *existing;
    }
    evictOldestIfFull(
        s.targets, s.targetIndex, kMaxTargets, nowMs,
        [](const WifiTarget& t) -> const std::string& { return t.bssid; },
        [](const WifiTarget& t) { return t.lastSeenMs; },
        [&](const WifiTarget& victim) { removeSsidBssid(s, victim.ssid, victim.bssid); });
    const std::size_t newIdx = s.targets.size();
    s.targets.push_back(WifiTarget{});
    s.targets.back().bssid = bssid;
    s.targetIndex[bssid] = newIdx;
    if (isNewOut != nullptr) {
        *isNewOut = true;
    }
    return s.targets.back();
}

inline DeauthTracker& trackerFor(SecState& s, const std::string& bssid, uint32_t nowMs) {
    const auto it = s.deauthIndex.find(bssid);
    if (it != s.deauthIndex.end() && it->second < s.deauthTrackers.size()) {
        return s.deauthTrackers[it->second];
    }
    evictOldestIfFull(
        s.deauthTrackers, s.deauthIndex, kMaxDeauthTrackers, nowMs,
        [](const DeauthTracker& tr) -> const std::string& { return tr.bssid; },
        [](const DeauthTracker& tr) {
            return tr.recentMs.empty() ? 0u : tr.recentMs.back();
        },
        [](const DeauthTracker&) {});
    const std::size_t newIdx = s.deauthTrackers.size();
    s.deauthTrackers.push_back(DeauthTracker{bssid, {}, 0u});
    s.deauthIndex[bssid] = newIdx;
    return s.deauthTrackers.back();
}

inline BssidSsids& ssidsFor(SecState& s, const std::string& bssid, uint32_t nowMs) {
    const auto it = s.bssidSsidIndex.find(bssid);
    if (it != s.bssidSsidIndex.end() && it->second < s.bssidSsids.size()) {
        return s.bssidSsids[it->second];
    }
    evictOldestIfFull(
        s.bssidSsids, s.bssidSsidIndex, kMaxBssidSsids, nowMs,
        [](const BssidSsids& bs) -> const std::string& { return bs.bssid; },
        [](const BssidSsids& bs) { return bs.lastSeenMs; },
        [](const BssidSsids&) {});
    const std::size_t newIdx = s.bssidSsids.size();
    s.bssidSsids.push_back(BssidSsids{bssid, {}, 0u, nowMs});
    s.bssidSsidIndex[bssid] = newIdx;
    return s.bssidSsids.back();
}

// Upserts a station, evicting the least-recently-seen one first if at the ring cap.
inline Station& stationFor(SecState& s, const std::string& mac, uint32_t nowMs,
                           bool* isNewOut = nullptr) {
    if (Station* existing = findStation(s, mac)) {
        if (isNewOut != nullptr) {
            *isNewOut = false;
        }
        return *existing;
    }
    evictOldestIfFull(
        s.stations, s.stationIndex, kMaxStations, nowMs,
        [](const Station& st) -> const std::string& { return st.mac; },
        [](const Station& st) { return st.lastSeenMs; },
        [&](const Station& victim) {
            if (!victim.lastBssid.empty()) {
                if (WifiTarget* t = findTarget(s, victim.lastBssid)) {
                    if (t->clientCount > 0u) {
                        t->clientCount -= 1u;
                    }
                }
            }
        });
    const std::size_t newIdx = s.stations.size();
    s.stations.push_back(Station{});
    s.stations.back().mac = mac;
    s.stationIndex[mac] = newIdx;
    if (isNewOut != nullptr) {
        *isNewOut = true;
    }
    return s.stations.back();
}

inline BleTarget& bleTargetFor(SecState& s, const std::string& mac, uint32_t nowMs,
                               bool* isNewOut = nullptr) {
    if (BleTarget* existing = findBleTarget(s, mac)) {
        if (isNewOut != nullptr) {
            *isNewOut = false;
        }
        return *existing;
    }
    evictOldestIfFull(
        s.bleTargets, s.bleIndex, kMaxBleTargets, nowMs,
        [](const BleTarget& b) -> const std::string& { return b.mac; },
        [](const BleTarget& b) { return b.lastSeenMs; },
        [](const BleTarget&) {});
    const std::size_t newIdx = s.bleTargets.size();
    s.bleTargets.push_back(BleTarget{});
    s.bleTargets.back().mac = mac;
    s.bleIndex[mac] = newIdx;
    if (isNewOut != nullptr) {
        *isNewOut = true;
    }
    return s.bleTargets.back();
}

// Count how many distinct BSSIDs currently advertise `ssid` (evil-twin signal).
inline std::size_t bssidsAdvertising(const SecState& s, const std::string& ssid) {
    if (ssid.empty()) {
        return 0u;
    }
    const auto it = s.ssidToBssids.find(ssid);
    return (it != s.ssidToBssids.end()) ? it->second.size() : 0u;
}

}  // namespace detail

// --- The reducer ---------------------------------------------------------------------

// Takes `SecState` by value: callers passing `const SecState&` get pure immutability via copy,
// while single-owner pipelines (`SecSession::dispatch`, `replaySecEvents`) can `std::move`
// their state in for O(1) ownership transfer with zero deep copies per packet.
inline SecState reduce(SecState s, const SecEvent& event) {
    s.revision += 1u;

    std::visit(
        [&](const auto& ev) {
            using E = std::decay_t<decltype(ev)>;
            if (s.revision == 1u || !detail::elapsedMoreThan(s.lastEventMs, ev.nowMs, 0u)) {
                s.lastEventMs = ev.nowMs;
            }

            if constexpr (std::is_same_v<E, ApObserved>) {
                const std::string bssid = normalizeMac(ev.bssid);
                if (bssid.empty()) {
                    return;
                }
                const std::string cleanSsid = sanitizePrintableText(ev.ssid, 64u);
                bool isNew = false;
                WifiTarget& targetRef = detail::targetFor(s, bssid, ev.nowMs, &isNew);
                WifiTarget* t = &targetRef;
                if (isNew) {
                    t->firstSeenMs = ev.nowMs;
                    uint32_t priorClients = 0u;
                    for (const Station& st : s.stations) {
                        if (st.lastBssid == bssid) {
                            ++priorClients;
                        }
                    }
                    t->clientCount = priorClients;
                }
                const std::string prevSsid = t->ssid;
                if (!isNew && prevSsid != cleanSsid) {
                    detail::removeSsidBssid(s, prevSsid, bssid);
                }
                if (!cleanSsid.empty() && (isNew || prevSsid != cleanSsid)) {
                    detail::addSsidBssid(s, cleanSsid, bssid);
                }
                t->ssid = cleanSsid;
                t->channel = ev.channel;
                t->rssi = ev.rssi;
                t->enc = ev.enc;
                t->wps = ev.wps;
                t->beacons += 1u;
                t->lastSeenMs = ev.nowMs;

                const bool trustedSelf = isTrustedBssid(s, bssid);

                // Evil-twin: a second BSSID now advertises this SSID (rate-limited per BSSID).
                // Trusted BSSIDs suppress alerts for themselves; untrusted APs impersonating a
                // trusted AP escalate to Critical.
                if (!trustedSelf && !cleanSsid.empty() &&
                    detail::bssidsAdvertising(s, cleanSsid) >= 2u &&
                    (isNew || prevSsid != cleanSsid) &&
                    (t->lastEvilTwinAlertMs == 0u ||
                     detail::elapsedAtLeast(ev.nowMs, t->lastEvilTwinAlertMs, kAlertCooldownMs))) {
                    bool impersonatingTrusted = false;
                    const auto ssidIt = s.ssidToBssids.find(cleanSsid);
                    if (ssidIt != s.ssidToBssids.end()) {
                        for (const std::string& otherBssid : ssidIt->second) {
                            if (otherBssid != bssid && isTrustedBssid(s, otherBssid)) {
                                impersonatingTrusted = true;
                                break;
                            }
                        }
                    }
                    t->lastEvilTwinAlertMs = (ev.nowMs == 0u) ? 1u : ev.nowMs;
                    detail::pushAlert(
                        s, Alert{ev.nowMs,
                                 impersonatingTrusted ? Severity::Critical : Severity::Warn,
                                 AlertKind::EvilTwin, bssid, cleanSsid,
                                 impersonatingTrusted
                                     ? ("Untrusted AP impersonating trusted SSID '" + cleanSsid + "'")
                                     : ("SSID '" + cleanSsid + "' advertised by multiple BSSIDs")});
                }
                // Open-downgrade: SSID that was encrypted now seen Open on a different BSSID
                // (rate-limited per BSSID so a fast rogue beacon cannot flood the alert ring).
                if (!trustedSelf && ev.enc == Encryption::Open && !cleanSsid.empty() &&
                    (t->lastDowngradeAlertMs == 0u ||
                     detail::elapsedAtLeast(ev.nowMs, t->lastDowngradeAlertMs, kAlertCooldownMs))) {
                    const auto ssidIt = s.ssidToBssids.find(cleanSsid);
                    if (ssidIt != s.ssidToBssids.end()) {
                        for (const std::string& otherBssid : ssidIt->second) {
                            if (otherBssid == bssid) {
                                continue;
                            }
                            const WifiTarget* other = findTarget(s, otherBssid);
                            if (other != nullptr && other->enc != Encryption::Open &&
                                other->enc != Encryption::Unknown) {
                                t->lastDowngradeAlertMs = (ev.nowMs == 0u) ? 1u : ev.nowMs;
                                detail::pushAlert(
                                    s, Alert{ev.nowMs, Severity::Critical, AlertKind::OpenDowngrade,
                                             bssid, cleanSsid,
                                             "Open AP impersonating encrypted SSID '" + cleanSsid +
                                                 "'"});
                                break;
                            }
                        }
                    }
                }
                // Karma/mana: this BSSID advertising many distinct SSIDs.
                if (!cleanSsid.empty()) {
                    BssidSsids& bs = detail::ssidsFor(s, bssid, ev.nowMs);
                    bs.lastSeenMs = ev.nowMs;
                    if (std::find(bs.ssids.begin(), bs.ssids.end(), cleanSsid) == bs.ssids.end() &&
                        bs.ssids.size() < kMaxSsidsPerBssid) {
                        bs.ssids.push_back(cleanSsid);
                    }
                    if (bs.ssids.size() >= kKarmaSsidThreshold &&
                        (bs.lastKarmaAlertMs == 0u ||
                         detail::elapsedAtLeast(ev.nowMs, bs.lastKarmaAlertMs, kAlertCooldownMs))) {
                        bs.lastKarmaAlertMs = (ev.nowMs == 0u) ? 1u : ev.nowMs;
                        detail::pushAlert(
                            s, Alert{ev.nowMs, Severity::Warn, AlertKind::KarmaBeacon, bssid,
                                     cleanSsid,
                                     "BSSID advertising " + std::to_string(bs.ssids.size()) +
                                         " SSIDs (possible karma/mana AP)"});
                    }
                }

            } else if constexpr (std::is_same_v<E, ClientObserved>) {
                const std::string bssid = normalizeMac(ev.bssid);
                const std::string client = normalizeMac(ev.client);
                if (client.empty() || isMulticastMac(client) || client == bssid) {
                    return;
                }
                bool isNewStation = false;
                Station& st = detail::stationFor(s, client, ev.nowMs, &isNewStation);
                if (isNewStation) {
                    st.firstSeenMs = ev.nowMs;
                }
                const std::string prevBssid = st.lastBssid;
                const bool newlyAssociated = (isNewStation || prevBssid != bssid);
                st.lastBssid = bssid;
                st.lastSeenMs = ev.nowMs;

                // Decrement old AP's clientCount when a station roams to another BSSID.
                if (!isNewStation && !prevBssid.empty() && prevBssid != bssid) {
                    if (WifiTarget* prevT = findTarget(s, prevBssid)) {
                        if (prevT->clientCount > 0u) {
                            prevT->clientCount -= 1u;
                        }
                    }
                }

                WifiTarget* t = findTarget(s, bssid);
                if (t != nullptr) {
                    if (newlyAssociated) {
                        t->clientCount += 1u;
                    }
                    t->lastSeenMs = ev.nowMs;
                }

            } else if constexpr (std::is_same_v<E, ProbeRequestObserved>) {
                const std::string client = normalizeMac(ev.client);
                if (client.empty() || isMulticastMac(client)) {
                    return;
                }
                const std::string cleanSsid = sanitizePrintableText(ev.ssid, 64u);
                bool isNewStation = false;
                Station& st = detail::stationFor(s, client, ev.nowMs, &isNewStation);
                if (isNewStation) {
                    st.firstSeenMs = ev.nowMs;
                }
                st.lastSeenMs = ev.nowMs;
                st.probeCount += 1u;
                if (!cleanSsid.empty() &&
                    std::find(st.probedSsids.begin(), st.probedSsids.end(), cleanSsid) ==
                        st.probedSsids.end() &&
                    st.probedSsids.size() < kMaxProbedSsidsPerStation) {
                    st.probedSsids.push_back(cleanSsid);
                }

            } else if constexpr (std::is_same_v<E, DataFrameObserved>) {
                WifiTarget* t = findTarget(s, normalizeMac(ev.bssid));
                if (t != nullptr) {
                    t->dataFrames += 1u;
                    t->lastSeenMs = ev.nowMs;
                }

            } else if constexpr (std::is_same_v<E, DeauthObserved>) {
                const std::string bssid = normalizeMac(ev.bssid);
                s.totalDeauths += 1u;
                if (WifiTarget* t = findTarget(s, bssid)) {
                    t->deauthsSeen += 1u;
                    t->lastSeenMs = ev.nowMs;
                }
                DeauthTracker& dt = detail::trackerFor(s, bssid, ev.nowMs);
                // Drop timestamps outside the sliding window (wrap-safe & clock-skew-safe).
                dt.recentMs.erase(
                    std::remove_if(dt.recentMs.begin(), dt.recentMs.end(), [&](uint32_t t) {
                        return detail::elapsedMoreThan(ev.nowMs, t, kDeauthWindowMs);
                    }),
                    dt.recentMs.end());
                if (dt.recentMs.size() >= kMaxDeauthTimestamps) {
                    dt.recentMs.erase(
                        dt.recentMs.begin(),
                        dt.recentMs.begin() +
                            static_cast<std::ptrdiff_t>(dt.recentMs.size() -
                                                        kMaxDeauthTimestamps + 1u));
                }
                dt.recentMs.push_back(ev.nowMs);
                if (dt.recentMs.size() >= kDeauthFloodThreshold &&
                    (dt.lastFloodAlertMs == 0u ||
                     detail::elapsedAtLeast(ev.nowMs, dt.lastFloodAlertMs, kAlertCooldownMs))) {
                    dt.lastFloodAlertMs = (ev.nowMs == 0u) ? 1u : ev.nowMs;
                    const WifiTarget* t = findTarget(s, bssid);
                    detail::pushAlert(
                        s, Alert{ev.nowMs, Severity::Critical, AlertKind::DeauthFlood, bssid,
                                 t != nullptr ? t->ssid : std::string{},
                                 std::to_string(dt.recentMs.size()) +
                                     " deauth/disassoc frames in " +
                                     std::to_string(kDeauthWindowMs / 1000u) + "s"});
                }

            } else if constexpr (std::is_same_v<E, HandshakeObserved>) {
                const std::string bssid = normalizeMac(ev.bssid);
                if (bssid.empty()) {
                    return;
                }
                bool isNewTarget = false;
                WifiTarget& t = detail::targetFor(s, bssid, ev.nowMs, &isNewTarget);
                if (isNewTarget) {
                    t.firstSeenMs = ev.nowMs;
                }
                const bool wasNew = isNewTarget || !t.handshake;
                t.handshake = true;
                t.lastSeenMs = ev.nowMs;
                if (wasNew) {
                    s.totalHandshakes += 1u;
                    detail::pushAlert(s, Alert{ev.nowMs, Severity::Info, AlertKind::HandshakeCaptured,
                                               bssid, t.ssid, "WPA handshake captured"});
                }

            } else if constexpr (std::is_same_v<E, PmkidObserved>) {
                const std::string bssid = normalizeMac(ev.bssid);
                if (bssid.empty()) {
                    return;
                }
                bool isNewTarget = false;
                WifiTarget& t = detail::targetFor(s, bssid, ev.nowMs, &isNewTarget);
                if (isNewTarget) {
                    t.firstSeenMs = ev.nowMs;
                }
                const bool wasNew = isNewTarget || !t.pmkid;
                t.pmkid = true;
                t.lastSeenMs = ev.nowMs;
                if (wasNew) {
                    s.totalPmkids += 1u;
                    detail::pushAlert(s, Alert{ev.nowMs, Severity::Info, AlertKind::PmkidCaptured,
                                               bssid, t.ssid, "PMKID captured"});
                }

            } else if constexpr (std::is_same_v<E, InjectionAttempt>) {
                const std::string bssid = normalizeMac(ev.bssid);
                if (ev.decision == AuthDecision::Allowed) {
                    s.allowedInjections += 1u;
                } else {
                    s.blockedInjections += 1u;
                    const WifiTarget* t = findTarget(s, bssid);
                    detail::pushAlert(
                        s, Alert{ev.nowMs, Severity::Warn, AlertKind::TxBlocked, bssid,
                                 t != nullptr ? t->ssid : std::string{},
                                 std::string("Injection refused - ") +
                                     authDecisionLabel(ev.decision)});
                }

            } else if constexpr (std::is_same_v<E, BleObserved>) {
                const std::string mac = normalizeMac(ev.mac);
                if (mac.empty() || isBroadcastMac(mac)) {
                    return;
                }
                const std::string cleanName = sanitizePrintableText(ev.name, 48u);
                bool isNew = false;
                BleTarget& bt = detail::bleTargetFor(s, mac, ev.nowMs, &isNew);
                if (isNew) {
                    bt.firstSeenMs = ev.nowMs;
                }
                bt.name = cleanName;
                bt.rssi = ev.rssi;
                bt.companyId = ev.companyId;
                bt.serviceUuid = ev.serviceUuid;
                bt.trackerPayload = ev.trackerPayload;
                bt.seenCount += 1u;
                bt.lastSeenMs = ev.nowMs;
                bt.threat = classifyBleDevice(mac, cleanName, ev.companyId, ev.serviceUuid,
                                              ev.trackerPayload);
                if (bt.threat != BleThreatKind::None &&
                    (bt.lastAlertMs == 0u ||
                     detail::elapsedAtLeast(ev.nowMs, bt.lastAlertMs, kAlertCooldownMs))) {
                    bt.lastAlertMs = (ev.nowMs == 0u) ? 1u : ev.nowMs;
                    if (bt.threat == BleThreatKind::MultiToolBle) {
                        detail::pushAlert(
                            s, Alert{ev.nowMs, Severity::Warn, AlertKind::MultiToolDetected, mac,
                                     cleanName,
                                     "BLE multi-tool signature detected (" +
                                         (cleanName.empty() ? mac : cleanName) + ")"});
                    } else {
                        const Severity sev =
                            (ev.rssi >= -60 || bt.seenCount >= 3u) ? Severity::Critical : Severity::Warn;
                        detail::pushAlert(
                            s, Alert{ev.nowMs, sev, AlertKind::BleTrackerDetected, mac, cleanName,
                                     std::string(bleThreatLabel(bt.threat)) + " tracker detected at " +
                                         std::to_string(ev.rssi) + " dBm"});
                    }
                }

            } else if constexpr (std::is_same_v<E, SubGhzObserved>) {
                const std::string cleanProto = sanitizePrintableText(ev.protocol, 24u);
                if (s.subGhzCaptures.size() >= kMaxSubGhzCaptures) {
                    s.subGhzCaptures.erase(s.subGhzCaptures.begin());
                }
                s.subGhzCaptures.push_back(SubGhzCapture{
                    ev.freqKhz, ev.rssi, cleanProto, ev.burstCount, ev.continuousCarrier, ev.nowMs});
                if (ev.continuousCarrier) {
                    detail::pushAlert(
                        s, Alert{ev.nowMs, Severity::Critical, AlertKind::SubGhzAnomaly,
                                 formatFreqMhz(ev.freqKhz), cleanProto,
                                 "Sub-GHz continuous jamming carrier detected on " +
                                     formatFreqMhz(ev.freqKhz)});
                } else if (ev.burstCount >= 5u) {
                    detail::pushAlert(
                        s, Alert{ev.nowMs, Severity::Warn, AlertKind::SubGhzAnomaly,
                                 formatFreqMhz(ev.freqKhz), cleanProto,
                                 "Sub-GHz rapid replay burst x" + std::to_string(ev.burstCount) +
                                     " (" + cleanProto + ")"});
                }
            }
        },
        event);

    return s;
}

// Sort targets strongest-signal-first for display (pure, returns a copy).
inline std::vector<WifiTarget> targetsByStrength(const SecState& s) {
    std::vector<WifiTarget> out = s.targets;
    std::sort(out.begin(), out.end(), [](const WifiTarget& a, const WifiTarget& b) {
        if (a.rssi != b.rssi) {
            return a.rssi > b.rssi;
        }
        return a.bssid < b.bssid;
    });
    return out;
}

// --- Channel band classification & distribution (recon helper) ----------------------
//
// Unlike the portable pet UI's 2.4GHz-only ChannelHistogram (shared with ESP32 hardware
// that is physically incapable of 5GHz), the Linux security engine already records every
// target's real channel number untouched, so it can report the full band picture.

enum class Band : uint8_t { Unknown = 0, Band24GHz, Band5GHz };

inline const char* bandLabel(Band b) {
    switch (b) {
        case Band::Band24GHz: return "2.4GHz";
        case Band::Band5GHz:  return "5GHz";
        case Band::Unknown:   break;
    }
    return "?";
}

// Classify a channel number into its band by numeric range. Covers every current 2.4GHz
// (1-14) and 5GHz U-NII (36-177) channel; anything else (6GHz, out-of-range) is Unknown
// rather than guessed, since 6GHz channel numbers alias 2.4GHz ones without extra band info.
constexpr Band classifyChannel(int32_t channel) {
    if (channel >= 1 && channel <= 14) {
        return Band::Band24GHz;
    }
    if (channel >= 36 && channel <= 177) {
        return Band::Band5GHz;
    }
    return Band::Unknown;
}

struct ChannelCount {
    int32_t channel;
    Band band;
    uint32_t count;
};

// Pure fold: how many currently-tracked targets sit on each channel, across every band the
// Linux backend can observe. Sorted by channel ascending.
inline std::vector<ChannelCount> channelDistribution(const SecState& s) {
    std::unordered_map<int32_t, uint32_t> counts;
    counts.reserve(16u);
    for (const WifiTarget& t : s.targets) {
        counts[t.channel] += 1u;
    }
    std::vector<ChannelCount> out;
    out.reserve(counts.size());
    for (const auto& kv : counts) {
        out.push_back(ChannelCount{kv.first, classifyChannel(kv.first), kv.second});
    }
    std::sort(out.begin(), out.end(),
              [](const ChannelCount& a, const ChannelCount& b) { return a.channel < b.channel; });
    return out;
}

// Sort stations by probing activity (most active first) for display (pure, returns a copy).
inline std::vector<Station> stationsByActivity(const SecState& s) {
    std::vector<Station> out = s.stations;
    std::sort(out.begin(), out.end(), [](const Station& a, const Station& b) {
        if (a.probeCount != b.probeCount) {
            return a.probeCount > b.probeCount;
        }
        return a.mac < b.mac;
    });
    return out;
}

// Pure check: true if any SSID in `st.probedSsids` matches a common default router or
// open public-hotspot pattern (making the client susceptible to rogue-AP / Karma attacks).
inline bool hasWeakOrDefaultProbe(const Station& st) {
    constexpr const char* kPatterns[] = {
        "linksys", "netgear", "dlink", "d-link", "default", "tp-link", "asus",
        "xfinitywifi", "attwifi", "starbucks", "guest", "freewifi", "free_wifi",
        "free wifi", "airport", "hotel"
    };
    for (const std::string& ssid : st.probedSsids) {
        std::string lower;
        lower.reserve(ssid.size());
        for (unsigned char c : ssid) {
            lower.push_back(static_cast<char>(std::tolower(c)));
        }
        for (const char* pat : kPatterns) {
            if (lower.find(pat) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

// --- Ambient "pet mood" signal from defensive alerts ---------------------------------
//
// The portable Mood enum (domain.hpp/pet_logic.hpp) is shared by every platform, including
// hardware that has never heard of secops. Rather than reach into that cross-platform
// surface for a signal only the Linux desktop currently produces, this is a small,
// independent, purely-derived enum a host UI (GUI pet widget, TUI status line) can use to
// make the pet visibly react to live threats.

enum class SecMood : uint8_t { Calm = 0, Watchful, Alarmed };

inline const char* secMoodLabel(SecMood m) {
    switch (m) {
        case SecMood::Calm:     return "CALM";
        case SecMood::Watchful: return "WATCHFUL";
        case SecMood::Alarmed:  return "ALARMED";
    }
    return "CALM";
}

// Pure: looks at alerts within `recentMs` of `nowMs`, most-recent-first. Any Critical
// alert in that window => Alarmed; any Warn => Watchful; otherwise Calm. Alerts are
// append-ordered oldest-to-newest, so the reverse scan can stop at the first one that
// falls outside the window.
inline SecMood deriveSecMood(const SecState& s, uint32_t nowMs, uint32_t recentMs = 30000u) {
    bool anyWarn = false;
    for (auto it = s.alerts.rbegin(); it != s.alerts.rend(); ++it) {
        if (detail::elapsedMoreThan(nowMs, it->nowMs, recentMs)) {
            break;
        }
        if (it->severity == Severity::Critical) {
            return SecMood::Alarmed;
        }
        if (it->severity == Severity::Warn) {
            anyWarn = true;
        }
    }
    return anyWarn ? SecMood::Watchful : SecMood::Calm;
}

// --- Session record & replay: pure text wire format for SecEvent --------------------
//
// One SecEvent per line, '|'-delimited. String fields come straight off the air (SSIDs,
// BSSIDs, alert text) and are not trusted, so they are escaped rather than assumed free of
// the delimiter. File I/O is the imperative shell's job (fopen/fwrite); this is only the
// pure encode/decode + replay-through-the-reducer primitives, so it stays host-testable
// without any backend. A session recorded this way replays deterministically through
// `reduce()` to reproduce the exact same SecState, for review, demos, or regression tests.

namespace detail {

inline std::string escapeRecordField(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        if (c == '\\' || c == '|') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\r') {
            out += "\\r";
        } else {
            out.push_back(c);
        }
    }
    return out;
}

inline std::string unescapeRecordField(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (std::size_t i = 0; i < raw.size(); ++i) {
        const char c = raw[i];
        if (c == '\\' && i + 1 < raw.size()) {
            const char n = raw[++i];
            if (n == 'n') {
                out.push_back('\n');
            } else if (n == 'r') {
                out.push_back('\r');
            } else {
                out.push_back(n);
            }
        } else {
            out.push_back(c);
        }
    }
    return out;
}

// Splits on unescaped '|', leaving escape sequences intact for unescapeRecordField().
inline std::vector<std::string> splitRecordFields(const std::string& line) {
    std::vector<std::string> fields;
    std::string cur;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '\\' && i + 1 < line.size()) {
            cur.push_back(c);
            cur.push_back(line[++i]);
        } else if (c == '|') {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    fields.push_back(cur);
    return fields;
}

inline std::string joinRecordFields(const std::vector<std::string>& fields) {
    std::string out;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (i != 0u) {
            out.push_back('|');
        }
        out += escapeRecordField(fields[i]);
    }
    return out;
}

// Exception-free integer parsers so core/ stays compatible with -fno-exceptions builds.
inline uint32_t parseU32(const std::string& s) {
    std::size_t i = 0u;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
        ++i;
    }
    if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
        return 0u;
    }
    uint64_t val = 0u;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        val = val * 10u + static_cast<uint64_t>(s[i] - '0');
        if (val > 0xFFFFFFFFull) {
            return 0u;
        }
        ++i;
    }
    return static_cast<uint32_t>(val);
}

inline int32_t parseI32(const std::string& s) {
    std::size_t i = 0u;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) {
        ++i;
    }
    if (i >= s.size()) {
        return 0;
    }
    bool neg = false;
    if (s[i] == '-') {
        neg = true;
        ++i;
    } else if (s[i] == '+') {
        ++i;
    }
    if (i >= s.size() || !std::isdigit(static_cast<unsigned char>(s[i]))) {
        return 0;
    }
    const uint64_t limit = neg ? 2147483648ull : 2147483647ull;
    uint64_t val = 0u;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        val = val * 10u + static_cast<uint64_t>(s[i] - '0');
        if (val > limit) {
            return 0;
        }
        ++i;
    }
    return neg ? static_cast<int32_t>(-static_cast<int64_t>(val))
               : static_cast<int32_t>(val);
}

}  // namespace detail

inline std::string encodeSecEvent(const SecEvent& event) {
    return std::visit(
        [](const auto& ev) -> std::string {
            using E = std::decay_t<decltype(ev)>;
            if constexpr (std::is_same_v<E, ApObserved>) {
                return detail::joinRecordFields(
                    {"AP", std::to_string(ev.nowMs), ev.bssid, ev.ssid,
                     std::to_string(ev.channel), std::to_string(ev.rssi),
                     std::to_string(static_cast<int>(ev.enc)), ev.wps ? "1" : "0"});
            } else if constexpr (std::is_same_v<E, ClientObserved>) {
                return detail::joinRecordFields(
                    {"CLIENT", std::to_string(ev.nowMs), ev.bssid, ev.client});
            } else if constexpr (std::is_same_v<E, DataFrameObserved>) {
                return detail::joinRecordFields({"DATA", std::to_string(ev.nowMs), ev.bssid});
            } else if constexpr (std::is_same_v<E, DeauthObserved>) {
                return detail::joinRecordFields(
                    {"DEAUTH", std::to_string(ev.nowMs), ev.bssid, ev.source, ev.dest});
            } else if constexpr (std::is_same_v<E, HandshakeObserved>) {
                return detail::joinRecordFields({"HANDSHAKE", std::to_string(ev.nowMs), ev.bssid});
            } else if constexpr (std::is_same_v<E, PmkidObserved>) {
                return detail::joinRecordFields({"PMKID", std::to_string(ev.nowMs), ev.bssid});
            } else if constexpr (std::is_same_v<E, ProbeRequestObserved>) {
                return detail::joinRecordFields(
                    {"PROBE", std::to_string(ev.nowMs), ev.client, ev.ssid});
            } else if constexpr (std::is_same_v<E, InjectionAttempt>) {
                return detail::joinRecordFields(
                    {"INJECT", std::to_string(ev.nowMs), ev.bssid, ev.client,
                     std::to_string(ev.count), std::to_string(static_cast<int>(ev.decision))});
            } else if constexpr (std::is_same_v<E, BleObserved>) {
                return detail::joinRecordFields(
                    {"BLE", std::to_string(ev.nowMs), ev.mac, ev.name, std::to_string(ev.rssi),
                     std::to_string(ev.companyId), std::to_string(ev.serviceUuid),
                     ev.trackerPayload ? "1" : "0"});
            } else if constexpr (std::is_same_v<E, SubGhzObserved>) {
                return detail::joinRecordFields(
                    {"SUBGHZ", std::to_string(ev.nowMs), std::to_string(ev.freqKhz),
                     std::to_string(ev.rssi), ev.protocol, std::to_string(ev.burstCount),
                     ev.continuousCarrier ? "1" : "0"});
            }
            return std::string{};
        },
        event);
}

inline std::optional<SecEvent> decodeSecEvent(const std::string& line) {
    if (line.empty()) {
        return std::nullopt;
    }
    std::vector<std::string> f;
    for (const std::string& raw : detail::splitRecordFields(line)) {
        f.push_back(detail::unescapeRecordField(raw));
    }
    if (f.empty()) {
        return std::nullopt;
    }
    const std::string& tag = f[0];
    using detail::parseI32;
    using detail::parseU32;

    if (tag == "AP" && f.size() == 8u) {
        const int32_t encRaw = parseI32(f[6]);
        if (encRaw < 0 || encRaw > static_cast<int32_t>(Encryption::Wpa3)) {
            return std::nullopt;
        }
        return SecEvent{ApObserved{parseU32(f[1]), f[2], f[3], parseI32(f[4]), parseI32(f[5]),
                                   static_cast<Encryption>(encRaw), f[7] == "1"}};
    }
    if (tag == "CLIENT" && f.size() == 4u) {
        return SecEvent{ClientObserved{parseU32(f[1]), f[2], f[3]}};
    }
    if (tag == "DATA" && f.size() == 3u) {
        return SecEvent{DataFrameObserved{parseU32(f[1]), f[2]}};
    }
    if (tag == "DEAUTH" && f.size() == 5u) {
        return SecEvent{DeauthObserved{parseU32(f[1]), f[2], f[3], f[4]}};
    }
    if (tag == "HANDSHAKE" && f.size() == 3u) {
        return SecEvent{HandshakeObserved{parseU32(f[1]), f[2]}};
    }
    if (tag == "PMKID" && f.size() == 3u) {
        return SecEvent{PmkidObserved{parseU32(f[1]), f[2]}};
    }
    if (tag == "PROBE" && f.size() == 4u) {
        return SecEvent{ProbeRequestObserved{parseU32(f[1]), f[2], f[3]}};
    }
    if (tag == "INJECT" && f.size() == 6u) {
        const int32_t decRaw = parseI32(f[5]);
        if (decRaw < 0 || decRaw > static_cast<int32_t>(AuthDecision::BlockedAuditFailed)) {
            return std::nullopt;
        }
        return SecEvent{InjectionAttempt{parseU32(f[1]), f[2], f[3], parseU32(f[4]),
                                         static_cast<AuthDecision>(decRaw)}};
    }
    if (tag == "BLE" && f.size() == 8u) {
        return SecEvent{BleObserved{
            parseU32(f[1]), f[2], f[3], parseI32(f[4]),
            static_cast<uint16_t>(parseU32(f[5]) & 0xFFFFu),
            static_cast<uint16_t>(parseU32(f[6]) & 0xFFFFu),
            f[7] == "1"}};
    }
    if (tag == "SUBGHZ" && f.size() == 7u) {
        return SecEvent{SubGhzObserved{
            parseU32(f[1]), parseU32(f[2]), parseI32(f[3]), f[4],
            parseU32(f[5]), f[6] == "1"}};
    }
    return std::nullopt;
}

// Encodes a whole session to one line per event, in order (ready to join with "\n" and
// write to a file - the imperative shell's job).
template <typename Container = std::vector<SecEvent>>
inline std::vector<std::string> encodeSecEvents(const Container& events) {
    std::vector<std::string> lines;
    lines.reserve(events.size());
    for (const SecEvent& ev : events) {
        lines.push_back(encodeSecEvent(ev));
    }
    return lines;
}

// Decodes a recorded session back into events, silently skipping any line that fails to
// parse (e.g. a truncated last line) rather than aborting the whole replay.
inline std::vector<SecEvent> decodeSecEvents(const std::vector<std::string>& lines) {
    std::vector<SecEvent> events;
    events.reserve(lines.size());
    for (const std::string& line : lines) {
        if (std::optional<SecEvent> ev = decodeSecEvent(line)) {
            events.push_back(*ev);
        }
    }
    return events;
}

// Pure fold: replays a recorded event log through `reduce()` from an empty SecState,
// reproducing the exact SecState a live session would have reached - a deterministic
// replay is the whole point of recording through a pure reducer in the first place.
inline SecState replaySecEvents(const std::vector<SecEvent>& events) {
    SecState s{};
    for (const SecEvent& ev : events) {
        s = reduce(std::move(s), ev);
    }
    return s;
}

// Pure multi-band WiFi channel hopper with EAPOL handshake dwell hold.
class ChannelHopper {
public:
    struct Config {
        bool include5Ghz = false;
        uint32_t dwellMs = 350u;
        uint32_t handshakeHoldMs = 3000u;
    };

    ChannelHopper() : ChannelHopper(Config{}) {}

    explicit ChannelHopper(Config cfg) : cfg_(cfg) {
        channels_ = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10};
        if (cfg_.include5Ghz) {
            constexpr int k5Ghz[] = {36, 40, 44, 48, 149, 153, 157, 161, 165};
            for (int ch : k5Ghz) {
                channels_.push_back(ch);
            }
        }
    }

    const Config& config() const { return cfg_; }

    void setInclude5Ghz(bool enable) {
        if (enable == cfg_.include5Ghz) {
            return;
        }
        cfg_.include5Ghz = enable;
        *this = ChannelHopper(cfg_);
    }

    int currentChannel() const {
        return channels_.empty() ? 1 : channels_[index_ % channels_.size()];
    }

    void notifyEapolActivity(uint32_t nowMs) {
        uint32_t until = nowMs + cfg_.handshakeHoldMs;
        if (until == 0u) {
            until = 1u;
        }
        holdUntilMs_ = until;
    }

    bool isHolding(uint32_t nowMs) const {
        if (holdUntilMs_ == 0u) {
            return false;
        }
        const uint32_t remaining = holdUntilMs_ - nowMs;
        return remaining > 0u && remaining < 0x80000000u;
    }

    // Advances to the next channel if dwellMs elapsed and no EAPOL handshake hold is active.
    std::optional<int> step(uint32_t nowMs) {
        if (channels_.empty() || isHolding(nowMs)) {
            return std::nullopt;
        }
        if (!initialized_) {
            initialized_ = true;
            lastHopMs_ = nowMs;
            return currentChannel();
        }
        if (detail::elapsedAtLeast(nowMs, lastHopMs_, cfg_.dwellMs)) {
            index_ = (index_ + 1u) % channels_.size();
            lastHopMs_ = nowMs;
            return currentChannel();
        }
        return std::nullopt;
    }

    const std::vector<int>& schedule() const { return channels_; }

private:
    Config cfg_{};
    std::vector<int> channels_{};
    std::size_t index_ = 0u;
    uint32_t lastHopMs_ = 0u;
    uint32_t holdUntilMs_ = 0u;
    bool initialized_ = false;
};

}  // namespace sec
}  // namespace zd
