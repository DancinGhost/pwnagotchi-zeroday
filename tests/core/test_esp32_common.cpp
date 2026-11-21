// Host unit tests for pure portable ESP32 common helpers (`nmea.hpp`, `frame_pacer.hpp`,
// `esp32_sec_cmd.hpp`), compiled with `-fno-exceptions -fno-rtti` under GCC/Clang to enforce
// zero-Arduino/zero-exception portability across all embedded targets.

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "esp32_sec_cmd.hpp"
#include "frame_pacer.hpp"
#include "nmea.hpp"
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

    // 2. Valid RMC + GGA populates lat/lon (with S/W sign), UTC time, satellites.
    GpsState gps{};
    assert(processNmeaSentence(gps, rmcOk, 1000u));
    assert(gps.hasFix);
    assert(std::string(gps.utcTime) == "12:35:19");
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
        std::string lastClient;
        uint32_t lastCount = 0;
        bool available() const override { return true; }
        void setChannel(int ch) override { channel = ch; }
        zd::sec::InjectResult deauth(const std::string&, const std::string& client,
                                     uint32_t count) override {
            ++sentCalls;
            lastClient = client;
            lastCount = count;
            return {zd::sec::AuthDecision::Allowed, true, "ok"};
        }
    } inj;

    struct FakeAudit final : public zd::sec::IAuditLog, public IAuditCounters {
        bool allowWrites = true;
        unsigned long tx = 0;
        unsigned long blk = 0;
        std::vector<std::string> lines;
        bool record(const std::string& line) override {
            lines.push_back(line);
            if (line.rfind("DEAUTH ALLOWED", 0) == 0) {
                if (!allowWrites) return false;
                ++tx;
            } else if (line.rfind("DEAUTH BLOCKED", 0) == 0) {
                ++blk;
            }
            return true;
        }
        unsigned long transmittedTotal() const override { return tx; }
        unsigned long blockedTotal() const override { return blk; }
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

    // Arm + allow target -> burst capped to 64 and channel synced to AP's ch 11.
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
    assert(console.handleLine("sec disarm", 180u).find("DISARMED") != std::string::npos);
    assert(!console.isArmed());
}

}  // namespace

int main() {
    testNmeaParserHardening();
    testDirtyFramePacer();
    testOffensiveConsoleCore();
    std::cout << "[esp32-common] all portable ESP32 helper tests passed\n";
    return 0;
}
