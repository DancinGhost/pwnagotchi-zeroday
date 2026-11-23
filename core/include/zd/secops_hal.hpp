#pragma once

// Portable adapter contracts for the Linux desktop security backend + a thin coordinator.
//
// Zero OS / socket / libpcap / libnl headers live here. Concrete implementations in
// platforms/linux/backend/ provide either native (libpcap / libnl / nl80211) or
// CLI-tool (iw / airodump-ng / aireplay-ng / airmon-ng) realizations of these interfaces.
// The `SecSession` coordinator is the imperative boundary that owns `SecState`, applies
// the pure reducer, and enforces the authorization gate on every transmit.

#include <array>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "hashcat.hpp"
#include "peering.hpp"
#include "secops.hpp"

namespace zd {
namespace sec {

// A single decoded 802.11 frame of interest, produced by a monitor-mode capture source.
enum class FrameKind : uint8_t {
    Beacon = 0,       // or probe-response: carries SSID/enc/channel
    ProbeRequest,
    Data,
    Deauth,
    Disassoc,
    Eapol,            // 4-way handshake message
    Pmkid,            // PMKID present (e.g. first EAPOL / RSN IE)
    Csa               // Channel Switch Announcement (beacon/probe-resp or management Action)
};

struct CapturedFrame {
    uint32_t nowMs = 0;
    FrameKind kind = FrameKind::Beacon;
    std::string bssid;
    std::string source;
    std::string dest;
    std::string ssid;             // for Beacon / ProbeRequest
    int32_t channel = 0;
    int32_t rssi = -100;
    Encryption enc = Encryption::Unknown;
    bool wps = false;             // WPS vendor IE (00:50:F2:04) present in beacon/probe-resp
    PmfStatus pmf = PmfStatus::Disabled;  // 802.11w RSN Capabilities (MFPR / MFPC)
    bool hasPmkid = false;        // true when EAPOL frame (e.g. M1) carries a non-zero RSN PMKID
    uint8_t eapolMsg = 0u;        // 0 = synthetic/pre-validated; 1..4 = EAPOL M1..M4; 255 = ignore
    bool hasStation = false;      // true when decoded Data/EAPOL provides `station` explicitly
    std::string station{};        // wireless STA MAC (empty for WDS 4-address frames)
    int32_t csaChannel = -1;      // >= 0 when Tag 37/60 or Action CSA carried a target channel
    uint8_t csaCount = 0u;        // CSA switch count

    // --- Crackable EAPOL / PMKID material (populated by dot11_decode for real captures;
    //     left empty for synthetic/CLI-replayed frames). Feeds the native .hc22000 export. ---
    uint64_t eapolReplayCounter = 0u;         // EAPOL-Key replay counter (host byte order)
    bool hasEapolNonce = false;               // true when eapolNonce is populated
    std::array<uint8_t, 32> eapolNonce{};     // ANonce (M1/M3) or SNonce (M2/M4)
    bool hasEapolMic = false;                 // true when eapolMic is populated (non-zero)
    std::array<uint8_t, 16> eapolMic{};       // EAPOL-Key MIC (M2/M3/M4)
    std::array<uint8_t, 16> pmkid{};          // 16-byte RSN PMKID when hasPmkid
    std::vector<uint8_t> eapolBody{};         // full EAPOL-Key frame bytes (for hashcat EAPOL field)
};

// --- Adapter interfaces --------------------------------------------------------------

// Puts an interface into (and out of) monitor mode and controls channel selection.
class IMonitorControl {
public:
    virtual ~IMonitorControl() = default;
    // Enable monitor mode. Returns the monitor interface name (e.g. "wlan0mon") or empty on failure.
    virtual std::string enableMonitor(const std::string& iface) = 0;
    virtual void disableMonitor() = 0;
    virtual bool setChannel(int channel) = 0;
    virtual bool isMonitor() const = 0;
    virtual std::string monitorIface() const = 0;
};

// Non-blocking monitor-mode frame source (libpcap or airodump-ng CSV/pcap tail).
class ICaptureSource {
public:
    virtual ~ICaptureSource() = default;
    virtual bool start(const std::string& monitorIface) = 0;
    // Drain any frames decoded since the last poll. Never blocks the UI loop.
    virtual std::vector<CapturedFrame> poll() = 0;
    // Drain any ZeroDay/Pwnagotchi/Palnagotchi peer sightings seen since the last poll.
    // Default: none (backends without access to raw frames, e.g. the CSV/tail backend).
    virtual std::vector<zd::peer::PeerSighting> pollPeers() { return {}; }
    virtual void stop() = 0;
    virtual bool running() const = 0;
};

// Result of a transmit request, so the shell can surface success/refusal uniformly.
struct InjectResult {
    AuthDecision decision = AuthDecision::BlockedUnconfirmed;
    bool transmitted = false;    // true only if the backend actually sent frames
    std::string detail;          // human-readable backend message / audit note
};

// Frame injector (deauthentication). Implementations MUST assume the caller has already
// cleared the authorization gate; `SecSession::requestDeauth` is the only intended caller.
class IInjector {
public:
    virtual ~IInjector() = default;
    virtual bool available() const = 0;
    // Send `count` deauth frames against `bssid`. `client` empty => broadcast to all stations.
    virtual InjectResult deauth(const std::string& bssid, const std::string& client,
                                uint32_t count) = 0;

    // Clientless PMKID probe: solicit an EAPOL M1 (which may carry an RSN PMKID) from a
    // WPA2-PSK AP by sending an open-system Authentication followed by an Association Request
    // bearing an RSN IE, from a throwaway (locally-administered) source MAC — WITHOUT kicking
    // any associated client. `count` auth+assoc attempts are sent. The solicited M1 is NOT
    // consumed here; it returns over the normal RX path and is correlated by
    // SecSession::ingest()->collectPmkid(). This COMPLEMENTS deauth and never replaces it:
    // PMKID capture does not exist on WPA3-SAE and is blunted by PMF, so the deauth path
    // remains the fallback against those targets. Default: unsupported by this backend.
    virtual InjectResult pmkidProbe(const std::string& bssid, const std::string& ssid,
                                    uint32_t count) {
        (void)bssid;
        (void)ssid;
        (void)count;
        return InjectResult{AuthDecision::Allowed, false,
                            "clientless PMKID probe unsupported by this backend"};
    }
};

// Optional audit sink: a durable record of every transmit decision (allowed or blocked).
// Returns true if the record was durably persisted; returning false causes beginDeauth()
// to fail closed and refuse transmission.
class IAuditLog {
public:
    virtual ~IAuditLog() = default;
    virtual bool record(const std::string& line) = 0;
};

// Optional sink for live session event recording (--record <file>).
class ISessionRecorder {
public:
    virtual ~ISessionRecorder() = default;
    virtual void recordEvent(const std::string& encodedLine) = 0;
};

// --- Coordinator ---------------------------------------------------------------------

constexpr std::size_t kMaxRecordedEvents = 4096u;
constexpr std::size_t kMaxEapolTrackers = 512u;

class SecSession {
private:
    // Per-(bssid|sta) accumulation of 4-way handshake material, used to assemble a strictly
    // validated, replay-counter-correlated crackable record for hashcat export.
    struct EapolTracker {
        uint8_t mask = 0u;                       // observed-message bitmask (M1..M4 => bit0..3)
        bool hasApNonce = false;                 // ANonce captured from an AP message (M1/M3)
        uint8_t apNonceMsg = 0u;                 // which AP message supplied the ANonce (1 or 3)
        uint64_t apRc = 0u;                      // its replay counter
        std::array<uint8_t, 32> anonce{};
        bool hasM2 = false;                      // M2 (SNonce + MIC + EAPOL) captured
        uint64_t m2Rc = 0u;
        std::array<uint8_t, 16> m2Mic{};
        std::vector<uint8_t> m2Eapol{};
        bool exported = false;                   // a crackable record was already emitted
    };

public:
    const SecState& state() const { return state_; }
    SecState& mutableState() { return state_; }

    bool trustBssid(const std::string& bssid) { return zd::sec::trustBssid(state_, bssid); }
    bool untrustBssid(const std::string& bssid) { return zd::sec::untrustBssid(state_, bssid); }
    void setTrustedBssids(const std::vector<std::string>& bssids) {
        state_.trustedBssids.clear();
        for (const auto& b : bssids) {
            zd::sec::trustBssid(state_, b);
        }
    }

    Authorization& authorization() { return auth_; }
    const Authorization& authorization() const { return auth_; }

    const std::deque<SecEvent>& events() const { return events_; }

    void setRecorder(ISessionRecorder* rec) { recorder_ = rec; }

    // Configure how many SecEvents are retained in memory for saveSession() (0 disables
    // in-memory retention — recommended for RAM-constrained embedded targets like ESP32).
    void setMaxRecordedEvents(std::size_t cap) {
        maxRecordedEvents_ = cap;
        if (maxRecordedEvents_ == 0u) {
            events_.clear();
        } else {
            while (events_.size() > maxRecordedEvents_) {
                events_.pop_front();
            }
        }
    }

    // Replace current state by replaying a sequence of recorded events through reduce().
    void loadEvents(const std::vector<SecEvent>& recorded) {
        state_ = replaySecEvents(recorded);
        eapolState_.clear();
        eapolOrder_.clear();
        handshakes_.clear();
        handshakeKeys_.clear();
        lastEapolMs_ = 0u;
        events_.clear();
        if (maxRecordedEvents_ == 0u) {
            return;
        }
        const std::size_t start =
            (recorded.size() > maxRecordedEvents_) ? (recorded.size() - maxRecordedEvents_) : 0u;
        for (std::size_t i = start; i < recorded.size(); ++i) {
            events_.push_back(recorded[i]);
        }
    }

    // Feed one observed frame into the pure engine.
    void ingest(const CapturedFrame& f) {
        switch (f.kind) {
            case FrameKind::Beacon:
                dispatch(ApObserved{f.nowMs, f.bssid, f.ssid, f.channel, f.rssi, f.enc, f.wps,
                                    f.pmf});
                if (f.csaChannel >= 0) {
                    dispatch(CsaObserved{f.nowMs, f.bssid, f.csaChannel, f.csaCount});
                }
                break;
            case FrameKind::ProbeRequest:
                // A probe request reveals a station; attribute to BSSID if known (directed
                // probe) and always record the probed SSID as a station-level signal, since
                // broadcast/unassociated probes (no BSSID) still leak a preferred network.
                if (!f.bssid.empty() && !isBroadcastMac(f.bssid)) {
                    dispatch(ClientObserved{f.nowMs, f.bssid, f.source});
                }
                if (!f.source.empty() && !isBroadcastMac(f.source)) {
                    dispatch(ProbeRequestObserved{f.nowMs, f.source, f.ssid});
                }
                break;
            case FrameKind::Data: {
                dispatch(DataFrameObserved{f.nowMs, f.bssid});
                const std::string& rawSta = f.hasStation ? f.station : f.source;
                const std::string normSta = normalizeMac(rawSta);
                if (!normSta.empty() && !isBroadcastMac(normSta) &&
                    normSta != normalizeMac(f.bssid)) {
                    dispatch(ClientObserved{f.nowMs, f.bssid, normSta});
                }
                break;
            }
            case FrameKind::Deauth:
            case FrameKind::Disassoc:
                dispatch(DeauthObserved{f.nowMs, f.bssid, f.source, f.dest});
                break;
            case FrameKind::Eapol:
                trackEapolHandshake(f);
                if (f.hasPmkid) {
                    dispatch(PmkidObserved{f.nowMs, f.bssid});
                    collectPmkid(f);
                }
                break;
            case FrameKind::Pmkid:
                dispatch(PmkidObserved{f.nowMs, f.bssid});
                collectPmkid(f);
                if (f.eapolMsg >= 1u && f.eapolMsg <= 4u) {
                    trackEapolHandshake(f);
                }
                break;
            case FrameKind::Csa:
                dispatch(CsaObserved{f.nowMs, f.bssid,
                                     (f.csaChannel >= 0) ? f.csaChannel : 0, f.csaCount});
                break;
        }
    }

    uint32_t lastEapolMs() const { return lastEapolMs_; }

    void dispatch(const SecEvent& ev) {
        state_ = reduce(std::move(state_), ev);
        if (maxRecordedEvents_ > 0u) {
            while (events_.size() >= maxRecordedEvents_) {
                events_.pop_front();
            }
            events_.push_back(ev);
        }
        if (recorder_ != nullptr) {
            recorder_->recordEvent(encodeSecEvent(ev));
        }
    }

    // Fast, synchronous half of the transmit chokepoint: resolves the authorization
    // decision and records the attempt (state + audit log) immediately. Fails closed if
    // an audit sink is configured and fails to durably record an Allowed transmit.
    AuthDecision beginDeauth(const std::string& bssid, const std::string& client, uint32_t count,
                             uint32_t nowMs, IAuditLog* audit = nullptr) {
        AuthDecision decision = authorize(auth_, bssid);
        if (decision == AuthDecision::Allowed && !isValidClientTarget(client)) {
            decision = AuthDecision::BlockedNotAllowlisted;
        }
        const std::string normBssid = normalizeMac(bssid);
        const std::string normClient =
            (client.empty() || isBroadcastMac(normalizeMac(client))) ? std::string{}
                                                                     : normalizeMac(client);
        if (audit != nullptr) {
            if (decision == AuthDecision::Allowed) {
                const bool persisted = audit->record(
                    "DEAUTH ALLOWED bssid=" + normBssid +
                    " client=" + (normClient.empty() ? std::string("broadcast") : normClient) +
                    " count=" + std::to_string(count));
                if (!persisted) {
                    decision = AuthDecision::BlockedAuditFailed;
                }
            } else {
                (void)audit->record("DEAUTH BLOCKED bssid=" + normBssid +
                                    " reason=" + std::string(authDecisionLabel(decision)));
            }
        }
        dispatch(InjectionAttempt{nowMs, bssid, normClient, count, decision});
        return decision;
    }

    // THE transmit chokepoint for synchronous callers (fine for one-shot, non-interactive
    // CLI use): gates via beginDeauth(), then transmits immediately on the calling thread.
    // A front-end driving a responsive UI loop should call beginDeauth() directly and run
    // the injector off-thread instead (see AppController::requestDeauth in the Linux
    // desktop shell), since injector.deauth() can block for a while.
    InjectResult requestDeauth(IInjector& injector, const std::string& bssid,
                               const std::string& client, uint32_t count, uint32_t nowMs,
                               IAuditLog* audit = nullptr) {
        const AuthDecision decision = beginDeauth(bssid, client, count, nowMs, audit);
        InjectResult res{};
        res.decision = decision;
        if (decision != AuthDecision::Allowed) {
            res.transmitted = false;
            res.detail = authDecisionLabel(decision);
            return res;
        }
        res = injector.deauth(bssid, client, count);
        res.decision = decision;  // preserve the gate decision regardless of backend detail
        return res;
    }

    // Synchronous gate half for a clientless PMKID probe. Flows through the SAME
    // authorization gate as deauth (authorize() => operator-armed + BSSID allow-listed) and
    // the same durable audit sink, then records the attempt in the state/alert stream. The
    // probe is AP-directed (no client target), so there is no client allow-list check.
    AuthDecision beginPmkidProbe(const std::string& bssid, uint32_t count, uint32_t nowMs,
                                 IAuditLog* audit = nullptr) {
        AuthDecision decision = authorize(auth_, bssid);
        const std::string normBssid = normalizeMac(bssid);
        if (audit != nullptr) {
            if (decision == AuthDecision::Allowed) {
                const bool persisted = audit->record("PMKID PROBE ALLOWED bssid=" + normBssid +
                                                      " count=" + std::to_string(count));
                if (!persisted) {
                    decision = AuthDecision::BlockedAuditFailed;
                }
            } else {
                (void)audit->record("PMKID PROBE BLOCKED bssid=" + normBssid +
                                    " reason=" + std::string(authDecisionLabel(decision)));
            }
        }
        // Reuse InjectionAttempt (client empty = AP-directed) so the UI/audit stream stays
        // uniform across both active-offense paths.
        dispatch(InjectionAttempt{nowMs, bssid, std::string{}, count, decision});
        return decision;
    }

    // Synchronous transmit chokepoint for a clientless PMKID probe: gates via
    // beginPmkidProbe(), then (if Allowed) asks the backend to send the auth->assoc sequence.
    InjectResult requestPmkidProbe(IInjector& injector, const std::string& bssid,
                                   const std::string& ssid, uint32_t count, uint32_t nowMs,
                                   IAuditLog* audit = nullptr) {
        const AuthDecision decision = beginPmkidProbe(bssid, count, nowMs, audit);
        InjectResult res{};
        res.decision = decision;
        if (decision != AuthDecision::Allowed) {
            res.transmitted = false;
            res.detail = authDecisionLabel(decision);
            return res;
        }
        res = injector.pmkidProbe(bssid, ssid, count);
        res.decision = decision;
        return res;
    }

public:
    // Strictly validated, crackable handshakes/PMKIDs captured this session (for export).
    const std::vector<hashcat::HandshakeRecord>& collectedHandshakes() const { return handshakes_; }
    // Serialize every crackable record as a hashcat 22000 (.hc22000) file body.
    std::string exportHc22000() const { return hashcat::toHc22000File(handshakes_); }

private:
    // Resolve the wireless station MAC from a frame, preferring the explicit station field.
    static std::string deriveStation(const CapturedFrame& f, const std::string& bssid) {
        if (f.hasStation && !f.station.empty()) {
            return normalizeMac(f.station);
        }
        const std::string normSrc = normalizeMac(f.source);
        return normalizeMac((!normSrc.empty() && normSrc != bssid) ? f.source : f.dest);
    }

    void trackEapolHandshake(const CapturedFrame& f) {
        lastEapolMs_ = f.nowMs;
        if (f.eapolMsg == 0u) {
            dispatch(HandshakeObserved{f.nowMs, f.bssid});
            return;
        }
        if (f.eapolMsg < 1u || f.eapolMsg > 4u) {
            return;
        }
        const std::string bssid = normalizeMac(f.bssid);
        const std::string sta = deriveStation(f, bssid);
        if (bssid.empty() || sta.empty() || isBroadcastMac(sta) || isMulticastMac(sta) ||
            sta == bssid) {
            return;
        }
        if (f.eapolMsg == 1u) {
            dispatch(EapolM1Observed{f.nowMs, bssid, sta});
        }
        const std::string key = bssid + "|" + sta;
        if (eapolState_.find(key) == eapolState_.end()) {
            while (eapolState_.size() >= kMaxEapolTrackers && !eapolOrder_.empty()) {
                eapolState_.erase(eapolOrder_.front());
                eapolOrder_.pop_front();
            }
            eapolOrder_.push_back(key);
        } else if (f.eapolMsg == 1u || f.eapolMsg == 3u) {
            for (auto it = eapolOrder_.begin(); it != eapolOrder_.end(); ++it) {
                if (*it == key) {
                    eapolOrder_.erase(it);
                    eapolOrder_.push_back(key);
                    break;
                }
            }
        }
        EapolTracker& tr = eapolState_[key];
        tr.mask = static_cast<uint8_t>(tr.mask | static_cast<uint8_t>(1u << (f.eapolMsg - 1u)));
        // Accumulate crackable material from real captures (synthetic frames carry none).
        if ((f.eapolMsg == 1u || f.eapolMsg == 3u) && f.hasEapolNonce) {
            tr.hasApNonce = true;
            tr.apNonceMsg = f.eapolMsg;
            tr.apRc = f.eapolReplayCounter;
            tr.anonce = f.eapolNonce;
        }
        if (f.eapolMsg == 2u && f.hasEapolMic &&
            f.eapolBody.size() >= (hashcat::kEapolMicOffset + hashcat::kEapolMicLen)) {
            tr.hasM2 = true;
            tr.m2Rc = f.eapolReplayCounter;
            tr.m2Mic = f.eapolMic;
            tr.m2Eapol = f.eapolBody;
        }
        // Coarse signal (unchanged): an M1+M2 or M2+M3 exchange was seen (drives pet/alerts).
        if ((tr.mask & 0x03u) == 0x03u || (tr.mask & 0x06u) == 0x06u) {
            dispatch(HandshakeObserved{f.nowMs, f.bssid});
        }
        maybeAssembleHandshake(tr, bssid, sta);
    }

    // Strictly validate + assemble a crackable WPA*02* record: requires the STA's M2
    // MIC/EAPOL plus an AP ANonce whose replay counter correlates (M1 rc == M2 rc, or
    // M3 rc == M2 rc + 1). Rejects mismatched replay counters, zero nonces/MIC, and (via
    // isCrackable) a missing ESSID. Emits at most one record per (bssid, sta).
    void maybeAssembleHandshake(EapolTracker& tr, const std::string& bssid,
                                const std::string& sta) {
        if (tr.exported || !tr.hasM2 || !tr.hasApNonce) {
            return;
        }
        hashcat::MessagePair mp;
        if (tr.apNonceMsg == 1u && tr.apRc == tr.m2Rc) {
            mp = hashcat::MessagePair::M1M2E2;
        } else if (tr.apNonceMsg == 3u && tr.apRc == tr.m2Rc + 1u) {
            mp = hashcat::MessagePair::M2M3E2;
        } else {
            return;  // replay counters don't correlate: not a trustworthy pair
        }
        const auto ap = hashcat::macBytesFromString(bssid);
        const auto st = hashcat::macBytesFromString(sta);
        if (!ap || !st) {
            return;
        }
        hashcat::HandshakeRecord rec;
        rec.type = hashcat::HcType::Eapol;
        rec.apMac = *ap;
        rec.staMac = *st;
        rec.anonce = tr.anonce;
        rec.mic = tr.m2Mic;
        rec.eapol = tr.m2Eapol;
        rec.messagePair = mp;
        const WifiTarget* t = findTarget(state_, bssid);
        rec.essid = (t != nullptr) ? t->ssid : std::string{};
        if (!hashcat::isCrackable(rec)) {
            return;  // e.g. SSID not yet observed; a later frame can still complete it
        }
        tr.exported = true;
        addHandshake("E|" + bssid + "|" + sta, std::move(rec));
    }

    // Assemble a crackable WPA*01* (clientless PMKID) record from a real RSN PMKID KDE.
    void collectPmkid(const CapturedFrame& f) {
        bool nonZero = false;
        for (uint8_t b : f.pmkid) {
            if (b != 0u) {
                nonZero = true;
                break;
            }
        }
        if (!nonZero) {
            return;
        }
        const std::string bssid = normalizeMac(f.bssid);
        const std::string sta = deriveStation(f, bssid);
        const auto ap = hashcat::macBytesFromString(bssid);
        const auto st = hashcat::macBytesFromString(sta);
        if (!ap || !st) {
            return;
        }
        hashcat::HandshakeRecord rec;
        rec.type = hashcat::HcType::Pmkid;
        rec.apMac = *ap;
        rec.staMac = *st;
        rec.pmkid = f.pmkid;
        const WifiTarget* t = findTarget(state_, bssid);
        rec.essid = (t != nullptr) ? t->ssid : std::string{};
        if (!hashcat::isCrackable(rec)) {
            return;
        }
        addHandshake("P|" + bssid + "|" + sta, std::move(rec));
    }

    // Insert or refresh a crackable record, deduped by a stable per-pair key.
    void addHandshake(const std::string& key, hashcat::HandshakeRecord&& rec) {
        const auto it = handshakeKeys_.find(key);
        if (it != handshakeKeys_.end()) {
            handshakes_[it->second] = std::move(rec);
            return;
        }
        handshakeKeys_[key] = handshakes_.size();
        handshakes_.push_back(std::move(rec));
    }

    SecState state_{};
    Authorization auth_{};
    std::deque<SecEvent> events_{};
    std::unordered_map<std::string, EapolTracker> eapolState_{};
    std::deque<std::string> eapolOrder_{};
    uint32_t lastEapolMs_ = 0u;
    std::size_t maxRecordedEvents_ = kMaxRecordedEvents;
    ISessionRecorder* recorder_ = nullptr;
    std::vector<hashcat::HandshakeRecord> handshakes_{};  // strictly validated, crackable
    std::unordered_map<std::string, std::size_t> handshakeKeys_{};  // dedup key -> index
};

}  // namespace sec
}  // namespace zd
