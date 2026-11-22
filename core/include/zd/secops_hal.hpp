#pragma once

// Portable adapter contracts for the Linux desktop security backend + a thin coordinator.
//
// Zero OS / socket / libpcap / libnl headers live here. Concrete implementations in
// platforms/linux/backend/ provide either native (libpcap / libnl / nl80211) or
// CLI-tool (iw / airodump-ng / aireplay-ng / airmon-ng) realizations of these interfaces.
// The `SecSession` coordinator is the imperative boundary that owns `SecState`, applies
// the pure reducer, and enforces the authorization gate on every transmit.

#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

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
    Pmkid             // PMKID present (e.g. first EAPOL / RSN IE)
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
    bool hasPmkid = false;        // true when EAPOL frame (e.g. M1) carries a non-zero RSN PMKID
    uint8_t eapolMsg = 0u;        // 0 = synthetic/pre-validated; 1..4 = EAPOL M1..M4; 255 = ignore
    bool hasStation = false;      // true when decoded Data/EAPOL provides `station` explicitly
    std::string station{};        // wireless STA MAC (empty for WDS 4-address frames)
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

constexpr std::size_t kMaxRecordedEvents = 10000u;
constexpr std::size_t kMaxEapolTrackers = 512u;

class SecSession {
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
                dispatch(ApObserved{f.nowMs, f.bssid, f.ssid, f.channel, f.rssi, f.enc, f.wps});
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
                }
                break;
            case FrameKind::Pmkid:
                dispatch(PmkidObserved{f.nowMs, f.bssid});
                if (f.eapolMsg >= 1u && f.eapolMsg <= 4u) {
                    trackEapolHandshake(f);
                }
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

private:
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
        std::string rawSta;
        if (f.hasStation) {
            rawSta = f.station;
        } else {
            const std::string normSrc = normalizeMac(f.source);
            rawSta = (!normSrc.empty() && normSrc != bssid) ? f.source : f.dest;
        }
        const std::string sta = normalizeMac(rawSta);
        if (bssid.empty() || sta.empty() || isBroadcastMac(sta) || isMulticastMac(sta) ||
            sta == bssid) {
            return;
        }
        const std::string key = bssid + "|" + sta;
        if (eapolState_.size() >= kMaxEapolTrackers &&
            eapolState_.find(key) == eapolState_.end()) {
            eapolState_.clear();
        }
        uint8_t& mask = eapolState_[key];
        mask = static_cast<uint8_t>(mask | static_cast<uint8_t>(1u << (f.eapolMsg - 1u)));
        // Require at least an observed M1+M2 or M2+M3 exchange for a valid handshake.
        if ((mask & 0x03u) == 0x03u || (mask & 0x06u) == 0x06u) {
            dispatch(HandshakeObserved{f.nowMs, f.bssid});
        }
    }

    SecState state_{};
    Authorization auth_{};
    std::deque<SecEvent> events_{};
    std::unordered_map<std::string, uint8_t> eapolState_{};
    uint32_t lastEapolMs_ = 0u;
    std::size_t maxRecordedEvents_ = kMaxRecordedEvents;
    ISessionRecorder* recorder_ = nullptr;
};

}  // namespace sec
}  // namespace zd
