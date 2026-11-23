// Host unit tests for pure portable ESP32 common helpers (`nmea.hpp`, `frame_pacer.hpp`,
// `esp32_sec_cmd.hpp`), compiled with `-fno-exceptions -fno-rtti` under GCC/Clang to enforce
// zero-Arduino/zero-exception portability across all embedded targets.

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "buzzer_melodies.hpp"
#include "esp32_defensive.hpp"
#include "esp32_sd_capture.hpp"
#include "esp32_sec_cmd.hpp"
#include "frame_pacer.hpp"
#include "nmea.hpp"
#include "wigle.hpp"
#include "zd/pet_logic.hpp"

namespace {

std::string nmeaWithChecksum(const std::string& body) {
    uint8_t x = 0u;
    for (char c : body) {
        x ^= static_cast<uint8_t>(c);
    }
    const char hex[] = "0123456789ABCDEF";
    return "$" + body + "*" + hex[(x >> 4) & 0x0F] + hex[x & 0x0F];
}

void testNmeaParserHardening() {
    using namespace zd::esp32_common;

    // 1. Checksum verification rejects malformed lines & trailing garbage after *XX.
    const std::string rmcOk =
        nmeaWithChecksum("GNRMC,123519.00,A,3746.4940,N,12225.1640,W,0.1,0.0,211126,,,A");
    assert(verifyNmeaChecksum(rmcOk));
    assert(!verifyNmeaChecksum(rmcOk + "EXTRA"));
    assert(!verifyNmeaChecksum("GNRMC,123519.00,A*00"));
    assert(!verifyNmeaChecksum("$*00"));

    // 2. Valid RMC + GGA populates lat/lon (with S/W sign), UTC time & date, satellites.
    GpsState gps{};
    assert(processNmeaSentence(gps, rmcOk, 1000u));
    assert(gps.hasFix);
    assert(gps.hasDate);
    assert(std::string(gps.utcTime) == "12:35:19");
    assert(std::string(gps.utcDate) == "2026-11-21");
    assert(gps.latitude > 37.77f && gps.latitude < 37.78f);
    assert(gps.longitude < -122.41f && gps.longitude > -122.43f);

    const std::string ggaOk = nmeaWithChecksum("GNGGA,123519.00,3746.4940,N,12225.1640,W,1,09,1.0");
    assert(processNmeaSentence(gps, ggaOk, 1100u));
    assert(gps.satellites == 9u);

    // 3. Out-of-range coordinates (minutes >= 60, lat > 90, garbage suffix) invalidate fix.
    const std::string badMin =
        nmeaWithChecksum("GPRMC,123520.00,A,3765.0000,N,12225.1640,W,0.1,0.0,211126,,,A");
    assert(processNmeaSentence(gps, badMin, 2000u));
    assert(!gps.hasFix);

    const std::string garbageCoord =
        nmeaWithChecksum("GPRMC,123521.00,A,3746abc,N,12225.1640,W,0.1,0.0,211126,,,A");
    assert(processNmeaSentence(gps, garbageCoord, 2100u));
    assert(!gps.hasFix);

    // 4. Re-acquire valid fix then verify stale expiry (> 5000 ms) including 32-bit wrap safety.
    assert(processNmeaSentence(gps, rmcOk, 0xFFFFFF00u));
    assert(gps.hasFix);
    expireStaleGpsFix(gps, 0xFFFFFF00u + 1000u);  // wraps to ~0x00000300 -> elapsed = 1000ms
    assert(gps.hasFix);
    expireStaleGpsFix(gps, 0xFFFFFF00u + 6000u);  // elapsed = 6000ms > 5000ms
    assert(!gps.hasFix);
}

void testDirtyFramePacer() {
    zd::esp32_common::DirtyFramePacer pacer;
    zd::AppState st = zd::initialState(42u);

    // Initial render always fires.
    assert(pacer.shouldRender(st, 0u));
    // Within 25 ms cooldown, even a state change is coalesced.
    st.page = zd::ScreenPage::NearbyRadar;
    assert(!pacer.shouldRender(st, 10u));
    // Once cooldown passes, immediate dirty change renders.
    assert(pacer.shouldRender(st, 30u));

    // Static theme (PaperInk) stays quiet until 1000 ms uptime fallback.
    assert(!pacer.shouldRender(st, 500u));
    assert(pacer.shouldRender(st, 1030u));

    // Animated theme renders immediately on switch, ignores same tick at >= 25 ms cooldown,
    // and re-renders once animTick (nowMs / 140) steps from tick 7 (1060ms) to tick 8 (1130ms).
    st.theme = zd::ThemeId::CodeRain;
    assert(pacer.shouldRender(st, 1060u));  // theme changed -> immediate (1060/140 == 7)
    assert(!pacer.shouldRender(st, 1100u)); // same tick 7 & >= 25ms cooldown elapsed
    assert(pacer.shouldRender(st, 1130u));  // 1130/140 == 8 != 7 -> animation tick step

    // Offensive arming & OpsMode flip dirty state immediately.
    st.offensiveArmed = true;
    assert(pacer.shouldRender(st, 1300u));
    st.opsMode = zd::OpsMode::Defensive;
    assert(pacer.shouldRender(st, 1350u));
}

void testOffensiveConsoleCore() {
    using namespace zd::esp32_common;

    struct FakeInjector final : public IOffensiveChannelInjector {
        int channel = 1;
        int sentCalls = 0;
        int pmkidCalls = 0;
        std::string lastClient;
        std::string lastProbeSsid;
        uint32_t lastCount = 0;
        uint32_t lastPmkidCount = 0;
        bool available() const override { return true; }
        void setChannel(int ch) override { channel = ch; }
        zd::sec::InjectResult deauth(const std::string&, const std::string& client,
                                     uint32_t count) override {
            ++sentCalls;
            lastClient = client;
            lastCount = count;
            return {zd::sec::AuthDecision::Allowed, true, "ok"};
        }
        zd::sec::InjectResult pmkidProbe(const std::string&, const std::string& ssid,
                                         uint32_t count) override {
            ++pmkidCalls;
            lastProbeSsid = ssid;
            lastPmkidCount = count;
            return {zd::sec::AuthDecision::Allowed, true, "pmkid-ok"};
        }
    } inj;

    struct FakeAudit final : public zd::sec::IAuditLog, public IAuditCounters {
        bool allowWrites = true;
        unsigned long tx = 0;
        unsigned long blk = 0;
        unsigned long pmkidTx = 0;
        std::vector<std::string> lines;
        bool record(const std::string& line) override {
            lines.push_back(line);
            if (!allowWrites &&
                (line.rfind("DEAUTH ALLOWED", 0) == 0 ||
                 line.rfind("PMKID PROBE ALLOWED", 0) == 0 ||
                 line.rfind("ARM ", 0) == 0)) {
                return false;
            }
            if (line.rfind("DEAUTH ALLOWED", 0) == 0) {
                ++tx;
            } else if (line.rfind("PMKID PROBE ALLOWED", 0) == 0) {
                ++pmkidTx;
            } else if (line.rfind("DEAUTH BLOCKED", 0) == 0 ||
                       line.rfind("PMKID PROBE BLOCKED", 0) == 0) {
                ++blk;
            }
            return true;
        }
        unsigned long transmittedTotal() const override { return tx; }
        unsigned long blockedTotal() const override { return blk; }
        unsigned long pmkidProbeTotal() const override { return pmkidTx; }
    } audit;

    struct FakeScanner final : public IOffensiveScanner {
        std::string runScan(uint32_t nowMs, zd::sec::SecSession& s) override {
            s.dispatch(zd::sec::ApObserved{nowMs, "02:aa:bb:cc:dd:01", "LabAP", 11, -45,
                                           zd::sec::Encryption::Wpa2, false});
            return "scan: 1 networks\n";
        }
    } scanner;

    OffensiveConsoleCore console(inj, audit, scanner, &audit);
    assert(!console.isArmed());

    // Discover target AP via scan.
    assert(console.handleLine("sec scan", 100u).find("1 networks") != std::string::npos);

    // Cannot arm with wrong token; cannot allow multicast MAC.
    assert(console.handleLine("sec arm wrong-token", 110u).find("To confirm") != std::string::npos);
    assert(!console.isArmed());
    assert(console.handleLine("sec allow 01:00:5e:00:00:01", 120u).find("usage:") !=
           std::string::npos);

    // Reject invalid burst counts and multicast client MACs cleanly.
    assert(console.handleLine("sec deauth 02:aa:bb:cc:dd:01 abc", 130u).find("invalid count") !=
           std::string::npos);
    assert(console.handleLine("sec deauth 02:aa:bb:cc:dd:01 0", 131u).find("invalid count") !=
           std::string::npos);
    assert(console.handleLine("sec deauth 02:aa:bb:cc:dd:01 4 01:00:5e:00:00:01", 132u)
               .find("invalid client MAC") != std::string::npos);

    // Cannot arm when audit log fails (fail-closed ARM).
    audit.allowWrites = false;
    assert(console.handleLine("sec arm I-HAVE-AUTHORIZATION", 145u).find("BLOCKED:") !=
           std::string::npos);
    assert(!console.isArmed());

    // Arm + allow target -> burst capped to 64 and channel synced to AP's ch 11.
    audit.allowWrites = true;
    assert(console.handleLine("sec allow 02:aa:bb:cc:dd:01", 140u).find("allow-listed") !=
           std::string::npos);
    assert(console.handleLine("sec arm I-HAVE-AUTHORIZATION", 150u).find("ARMED") !=
           std::string::npos);
    assert(console.isArmed());

    // Fail-closed audit refuses TX when audit log fails!
    audit.allowWrites = false;
    assert(console.handleLine("sec deauth 02:aa:bb:cc:dd:01 999", 160u).find("BLOCKED:") !=
           std::string::npos);
    assert(inj.sentCalls == 0);

    // Once audit succeeds, count=999 clamps to 64 and unicast client passes.
    audit.allowWrites = true;
    assert(console.handleLine("sec deauth 02:aa:bb:cc:dd:01 999 02:11:22:33:44:55", 170u)
               .find("OK:") != std::string::npos);
    assert(inj.sentCalls == 1);
    assert(inj.channel == 11);
    assert(inj.lastCount == OffensiveConsoleCore::kMaxBurst);
    assert(inj.lastClient == "02:11:22:33:44:55");

    // Clientless `sec pmkid`: rejects non-allowlisted target, invalid count, and audit failure;
    // when armed+allowlisted and audit succeeds, clamps count to 64 and forwards AP SSID.
    assert(console.handleLine("sec pmkid 02:aa:bb:cc:dd:99 4", 171u).find("unknown BSSID") !=
           std::string::npos);
    assert(console.handleLine("sec pmkid 02:aa:bb:cc:dd:01 0", 172u).find("invalid count") !=
           std::string::npos);
    audit.allowWrites = false;
    assert(console.handleLine("sec pmkid 02:aa:bb:cc:dd:01 4", 173u).find("BLOCKED:") !=
           std::string::npos);
    assert(inj.pmkidCalls == 0);
    audit.allowWrites = true;
    assert(console.handleLine("sec pmkid 02:aa:bb:cc:dd:01 999", 174u).find("OK:") !=
           std::string::npos);
    assert(inj.pmkidCalls == 1);
    assert(inj.lastProbeSsid == "LabAP");
    assert(inj.lastPmkidCount == OffensiveConsoleCore::kMaxBurst);
    assert(console.handleLine("sec status", 175u).find("pmkid_tx=1") != std::string::npos);

    assert(console.handleLine("sec disarm", 180u).find("DISARMED") != std::string::npos);
    assert(!console.isArmed());
    assert(console.handleLine("sec pmkid 02:aa:bb:cc:dd:01 4", 181u).find("BLOCKED:") !=
           std::string::npos);
    assert(inj.pmkidCalls == 1);
}

void testMelodiesWigleAndPacerExtensions() {
    // 1. MelodyPlayer non-blocking note stepping & mute stop
    zd::MelodyPlayer mp;
    mp.trigger(zd::MelodyId::Boot, 1000u);
    assert(mp.isPlaying());
    const auto c1 = mp.step(1000u);
    assert(c1.has_value() && c1->active && c1->freqHz == 523u);
    assert(!mp.step(1020u).has_value());
    const auto c2 = mp.step(1060u);
    assert(c2.has_value() && c2->active && c2->freqHz == 659u);
    mp.setMuted(true);
    const auto stopCmd = mp.step(1070u);
    assert(stopCmd.has_value() && !stopCmd->active);
    assert(!mp.isPlaying());

    // 2. WigleLogger dedup, GPS UTC date, FIFO eviction & leading-whitespace CSV protection
    zd::WigleLogger wl;
    zd::esp32_common::GpsState noFix{};
    assert(wl.recordScan({{"Test", -50, 6, true}}, {"02:aa:bb:cc:dd:01"}, noFix).empty());
    zd::esp32_common::GpsState fix{};
    fix.hasFix = true;
    fix.latitude = 37.7749f;
    fix.longitude = -122.4194f;
    fix.satellites = 7u;
    fix.hasDate = true;
    std::snprintf(fix.utcTime, sizeof(fix.utcTime), "12:30:00");
    std::snprintf(fix.utcDate, sizeof(fix.utcDate), "2026-11-21");
    fix.lastSentenceMs = 2000u;
    const auto rows1 = wl.recordScan({{" =evil", -65, 6, true}}, {"02:aa:bb:cc:dd:01"}, fix);
    assert(rows1.size() == 1u && wl.loggedCount() == 1u);
    assert(rows1[0].find("\"' =evil\"") != std::string::npos);
    assert(rows1[0].find("2026-11-21 12:30:00") != std::string::npos);
    // Small RSSI fluctuation (+3 dB) deduplicated; >= 8 dB improvement logged
    assert(wl.recordScan({{" =evil", -62, 6, true}}, {"02:aa:bb:cc:dd:01"}, fix).empty());
    assert(wl.recordScan({{" =evil", -50, 6, true}}, {"02:aa:bb:cc:dd:01"}, fix).size() == 1u);

    // FIFO eviction after kMaxTrackedBssids allows re-logging evicted earliest BSSID
    char wigleMac[24];
    for (std::size_t i = 0u; i < zd::WigleLogger::kMaxTrackedBssids; ++i) {
        std::snprintf(wigleMac, sizeof(wigleMac), "02:55:00:00:%02x:%02x",
                      static_cast<unsigned>((i >> 8) & 0xFFu), static_cast<unsigned>(i & 0xFFu));
        (void)wl.recordScan({{"N", -60, 1, true}}, {wigleMac}, fix);
    }
    assert(wl.recordScan({{" =evil", -65, 6, true}}, {"02:aa:bb:cc:dd:01"}, fix).size() == 1u);

    // 3. DirtyFramePacer SubGHz/Threat changes & static PaperInk PetFace (ClassicFace) gating
    zd::esp32_common::DirtyFramePacer pacer;
    zd::AppState st = zd::initialState(1u);
    st.theme = zd::ThemeId::PaperInk;
    assert(pacer.shouldRender(st, 100u));
    assert(!pacer.shouldRender(st, 280u));  // ClassicFace PetFace stays quiet when idle
    assert(pacer.shouldRender(st, 1150u));  // 1 Hz uptime tick still refreshes
    st = zd::reduce(st, zd::SetSubGhzFreqEvent{1200u, 915000u});
    assert(pacer.shouldRender(st, 1230u));  // immediate render on SubGhzFreq change despite < 140ms
    st = zd::reduce(st, zd::CaptureSavedEvent{1300u, 1u, "sd:/wigle_zd.csv", "WiGLE +1 AP", true});
    assert(pacer.shouldRender(st, 1340u));  // immediate render on capture/notification
}

void testEsp32DefensiveMonitorCore() {
    using namespace zd::esp32_common;

    Esp32DefensiveMonitorCore defMon;
    zd::sec::SecSession sec;
    zd::hal::PlatformSession pet;
    pet.boot(42u, 0u);

    // 1. Enqueue raw 802.11 Beacon frame with RSN PMF Required (MFPR=0x0040)
    const uint8_t bssid[6] = {0x02, 0xCA, 0xFE, 0xBA, 0xBE, 0x01};
    std::vector<uint8_t> beacon(36, 0x00);
    beacon[0] = 0x80;
    for (int i = 4; i < 10; ++i) beacon[i] = 0xFF;
    for (int i = 0; i < 6; ++i) {
        beacon[10 + i] = bssid[i];
        beacon[16 + i] = bssid[i];
    }
    beacon[34] = 0x11;
    // SSID "EspGuard"
    beacon.push_back(0u);
    beacon.push_back(8u);
    const char* ssid = "EspGuard";
    beacon.insert(beacon.end(), ssid, ssid + 8);
    // RSN IE (WPA2, MFPR + MFPC = 0x00C0)
    const uint8_t rsn[] = {
        48u, 20u,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02,
        0xC0, 0x00
    };
    beacon.insert(beacon.end(), std::begin(rsn), std::end(rsn));
    assert(defMon.enqueueFromIsr(beacon.data(), beacon.size(), -48, 100u));

    // 2. Enqueue 8 Deauth frames to trigger DeauthFlood -> Critical -> SecMood::Alarmed
    std::vector<uint8_t> deauth(26, 0x00);
    deauth[0] = 0xC0;
    for (int i = 4; i < 10; ++i) deauth[i] = 0xFF;
    for (int i = 0; i < 6; ++i) {
        deauth[10 + i] = bssid[i];
        deauth[16 + i] = bssid[i];
    }
    for (uint32_t i = 0u; i < 8u; ++i) {
        assert(defMon.enqueueFromIsr(deauth.data(), deauth.size(), -42, 200u + i * 20u));
    }

    const uint32_t decoded = defMon.step(sec, 400u, &pet);
    assert(decoded == 9u);
    assert(sec.state().targets.size() == 1u);
    assert(sec.state().targets[0].ssid == "EspGuard");
    assert(sec.state().targets[0].pmf == zd::sec::PmfStatus::Required);
    assert(sec.state().totalDeauths == 8u);
    assert(sec.state().totalAlertsEmitted >= 1u);
    assert(pet.state().secMood == zd::SecMood::Alarmed);
    assert(pet.state().mood == zd::Mood::ThreatAlert);
    assert(defMon.formatStatus(sec.state()).find("DEFMON: ON") != std::string::npos);

    // 3. Ring overflow without draining must drop safely without out-of-bounds access
    defMon.reset();
    for (std::size_t i = 0u; i < Esp32DefensiveMonitorCore::kRingCapacity + 4u; ++i) {
        (void)defMon.enqueueFromIsr(deauth.data(), deauth.size(), -55, 500u + static_cast<uint32_t>(i));
    }
    assert(defMon.droppedPackets() == 4u);

    // 4. Passive peer discovery through the ring: a classic Pwnagotchi signature beacon is
    //    greeted as a peer while draining.
    zd::sec::SecSession peerSec;
    zd::esp32_common::Esp32DefensiveMonitorCore peerMon;
    peerMon.setEnabled(true);
    std::vector<uint8_t> pwnBeacon = {0x80u, 0x00u, 0x00u, 0x00u};  // FC beacon + duration
    for (int i = 0; i < 6; ++i) pwnBeacon.push_back(0xFFu);          // addr1 broadcast
    for (uint8_t b : zd::peer::kPwnagotchiSignature) pwnBeacon.push_back(b);  // addr2 signature
    for (uint8_t b : zd::peer::kPwnagotchiSignature) pwnBeacon.push_back(b);  // addr3 signature
    pwnBeacon.push_back(0x00u);
    pwnBeacon.push_back(0x00u);  // seq
    assert(peerMon.enqueueFromIsr(pwnBeacon.data(), pwnBeacon.size(), -60, 100u));
    peerMon.step(peerSec, 120u);
    assert(peerMon.peersMet() == 1u);
    assert(peerMon.peers().peers().at(0).kind == zd::peer::PeerKind::Pwnagotchi);
}

void testSdCaptureBuffer() {
    zd::esp32_common::SdCaptureBuffer buf(32u);  // tiny cap to exercise overflow

    // 1. Event buffering: lines accumulate newline-terminated and drain atomically.
    assert(!buf.hasPendingEvents());
    buf.recordEvent("AP|1|aa");
    buf.recordEvent("DEAUTH|2|bb");
    assert(buf.hasPendingEvents());
    const std::string drained = buf.takePendingEvents();
    assert(drained == "AP|1|aa\nDEAUTH|2|bb\n");
    assert(!buf.hasPendingEvents());  // take() cleared it

    // 2. Overflow: once full the buffer drops lines and raises the overflow flag; take()
    //    (and clear()) reset it.
    zd::esp32_common::SdCaptureBuffer tiny(8u);
    tiny.recordEvent("12345678");  // 8 + newline > 8 => dropped
    assert(!tiny.hasPendingEvents());
    assert(tiny.overflowed());
    tiny.clear();
    assert(!tiny.overflowed());

    // 3. Handshake watermark: reports growth once, until the new count is marked flushed.
    assert(buf.handshakesChanged(0u) == false);
    assert(buf.handshakesChanged(3u) == true);
    buf.markHandshakesFlushed(3u);
    assert(buf.handshakesChanged(3u) == false);
    assert(buf.handshakesChanged(5u) == true);

    // 4. Acts as a live ISessionRecorder for a SecSession, capturing the .zds event stream.
    zd::sec::SecSession sess;
    zd::esp32_common::SdCaptureBuffer rec(4096u);
    sess.setRecorder(&rec);
    sess.dispatch(zd::sec::ApObserved{10u, "aa:bb:cc:00:00:01", "Lab", 6, -40,
                                      zd::sec::Encryption::Wpa2});
    assert(rec.hasPendingEvents());
    assert(rec.takePendingEvents().find("aa:bb:cc:00:00:01") != std::string::npos);
}

}  // namespace

int main() {
    testNmeaParserHardening();
    testDirtyFramePacer();
    testOffensiveConsoleCore();
    testMelodiesWigleAndPacerExtensions();
    testEsp32DefensiveMonitorCore();
    testSdCaptureBuffer();
    std::cout << "[esp32-common] all portable ESP32 helper tests passed\n";
    return 0;
}
