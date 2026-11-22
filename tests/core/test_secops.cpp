// Host unit tests for the portable security engine (core/include/zd/secops.hpp).
// Pure, hardware-free: exercises the reducer, defensive monitors, and the authorization gate.

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "zd/report.hpp"
#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"

namespace {

using namespace zd::sec;

bool hasAlert(const SecState& s, AlertKind k, const std::string& bssidSubstr = "") {
    for (const Alert& a : s.alerts) {
        if (a.kind == k && (bssidSubstr.empty() || a.bssid.find(bssidSubstr) != std::string::npos)) {
            return true;
        }
    }
    return false;
}

std::size_t countAlerts(const SecState& s, AlertKind k) {
    std::size_t n = 0;
    for (const Alert& a : s.alerts) {
        if (a.kind == k) {
            ++n;
        }
    }
    return n;
}

void testMacNormalization() {
    assert(normalizeMac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff");
    assert(normalizeMac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff");
    assert(normalizeMac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff");
    assert(normalizeMac("  aa:bb:cc:dd:ee:ff ") == "aa:bb:cc:dd:ee:ff");
    assert(isBroadcastMac(normalizeMac("ff:ff:ff:ff:ff:ff")));
    assert(isMulticastMac("ff:ff:ff:ff:ff:ff"));
    assert(isMulticastMac("01:00:5e:00:00:fb"));   // IPv4 mDNS multicast
    assert(isMulticastMac("33:33:00:00:00:01"));   // IPv6 all-nodes multicast
    assert(!isMulticastMac("00:11:22:33:44:55"));  // unicast
    assert(!isMulticastMac("02:11:22:33:44:55"));  // locally-administered unicast
}

void testMacValidation() {
    assert(isValidMac("AA:BB:CC:DD:EE:FF"));
    assert(isValidMac("aabbccddeeff"));
    assert(isValidMac("AA-BB-CC-DD-EE-FF"));
    assert(isValidMac("  aa:bb:cc:dd:ee:ff "));
    assert(!isValidMac(""));
    assert(!isValidMac("not-a-mac"));
    assert(!isValidMac("--i-am-authorized"));       // a stray CLI flag, not a MAC
    assert(!isValidMac("aa:bb:cc:dd:ee"));           // too short (10 hex digits)
    assert(!isValidMac("aa:bb:cc:dd:ee:ff:00"));     // too long (14 hex digits)

    // Interface name validation (CWE-88 guard)
    assert(isValidIfaceName("wlan0"));
    assert(isValidIfaceName("wlan0mon"));
    assert(isValidIfaceName("wlx00c0ca123456"));
    assert(!isValidIfaceName(""));
    assert(!isValidIfaceName("-w"));
    assert(!isValidIfaceName("--help"));
    assert(!isValidIfaceName(".hidden"));
    assert(!isValidIfaceName("wlan0;rm -rf /"));
    assert(!isValidIfaceName("interface_name_way_too_long_for_linux"));

    // Out-of-range enum values in decodeSecEvent must be rejected
    assert(!decodeSecEvent("AP|100|aa:bb:cc:00:00:01|Test|6|-40|99|0").has_value());
    assert(!decodeSecEvent("INJECT|100|aa:bb:cc:00:00:01||5|99").has_value());
}

void testChannelBands() {
    assert(classifyChannel(1) == Band::Band24GHz);
    assert(classifyChannel(14) == Band::Band24GHz);
    assert(classifyChannel(36) == Band::Band5GHz);
    assert(classifyChannel(149) == Band::Band5GHz);
    assert(classifyChannel(177) == Band::Band5GHz);
    assert(classifyChannel(0) == Band::Unknown);
    assert(classifyChannel(20) == Band::Unknown);
    assert(classifyChannel(200) == Band::Unknown);

    SecState s;
    s = reduce(s, ApObserved{0u, "aa:bb:cc:00:00:01", "A", 6, -40, Encryption::Wpa2});
    s = reduce(s, ApObserved{0u, "aa:bb:cc:00:00:02", "B", 6, -40, Encryption::Wpa2});
    s = reduce(s, ApObserved{0u, "aa:bb:cc:00:00:03", "C", 149, -40, Encryption::Wpa2});

    const std::vector<ChannelCount> dist = channelDistribution(s);
    assert(dist.size() == 2u);
    assert(dist[0].channel == 6 && dist[0].band == Band::Band24GHz && dist[0].count == 2u);
    assert(dist[1].channel == 149 && dist[1].band == Band::Band5GHz && dist[1].count == 1u);
}

void testAuthorizationGate() {
    Authorization auth;
    // Default: everything blocked (unconfirmed).
    assert(authorize(auth, "aa:bb:cc:dd:ee:ff") == AuthDecision::BlockedUnconfirmed);

    // Confirmed but no allow-list entry => still blocked.
    auth.operatorConfirmed = true;
    assert(authorize(auth, "aa:bb:cc:dd:ee:ff") == AuthDecision::BlockedNotAllowlisted);

    // Allow-listed (case/format-insensitive) => allowed; disallow revokes it cleanly.
    assert(auth.allow("AABBCCDDEEFF"));
    assert(!auth.allow("not-a-mac"));
    assert(!auth.allow("ff:ff:ff:ff:ff:ff"));
    assert(!auth.allow("01:00:5e:00:00:fb"));  // multicast rejected
    assert(auth.isAllowed("aa:bb:cc:dd:ee:ff"));
    assert(authorize(auth, "aa:bb:cc:dd:ee:ff") == AuthDecision::Allowed);
    assert(authorize(auth, "11:22:33:44:55:66") == AuthDecision::BlockedNotAllowlisted);
    assert(auth.disallow("AA-BB-CC-DD-EE-FF"));
    assert(!auth.isAllowed("aa:bb:cc:dd:ee:ff"));
    assert(!auth.disallow("aa:bb:cc:dd:ee:ff"));
    assert(authorize(auth, "aa:bb:cc:dd:ee:ff") == AuthDecision::BlockedNotAllowlisted);

    // allowAll wildcard still requires confirmation AND a valid unicast MAC.
    Authorization wild;
    wild.allowAll = true;
    assert(authorize(wild, "aa:bb:cc:dd:ee:ff") == AuthDecision::BlockedUnconfirmed);
    wild.operatorConfirmed = true;
    assert(authorize(wild, "aa:bb:cc:dd:ee:ff") == AuthDecision::Allowed);
    assert(authorize(wild, "any") == AuthDecision::BlockedNotAllowlisted);
    assert(authorize(wild, "--flag") == AuthDecision::BlockedNotAllowlisted);
    // Broadcast/multicast/empty BSSID is always rejected even with wildcard.
    assert(authorize(wild, "ff:ff:ff:ff:ff:ff") == AuthDecision::BlockedNotAllowlisted);
    assert(authorize(wild, "01:00:5e:00:00:fb") == AuthDecision::BlockedNotAllowlisted);
    assert(authorize(wild, "") == AuthDecision::BlockedNotAllowlisted);
}

void testApTrackingAndEvilTwin() {
    SecState s;
    s = reduce(s, ApObserved{1000u, "aa:bb:cc:00:00:01", "HomeNet", 6, -40, Encryption::Wpa2});
    assert(s.targets.size() == 1u);
    assert(findTarget(s, "aa:bb:cc:00:00:01") != nullptr);
    assert(!hasAlert(s, AlertKind::EvilTwin));

    // Second BSSID advertising the SAME SSID => evil twin.
    s = reduce(s, ApObserved{1100u, "aa:bb:cc:00:00:02", "HomeNet", 11, -55, Encryption::Wpa2});
    assert(s.targets.size() == 2u);
    assert(hasAlert(s, AlertKind::EvilTwin, "00:00:02"));
}

void testOpenDowngrade() {
    SecState s;
    s = reduce(s, ApObserved{1000u, "aa:bb:cc:00:00:01", "SecureCorp", 6, -45, Encryption::Wpa2});
    // A different BSSID now broadcasts the same SSID as Open => downgrade/impersonation.
    s = reduce(s, ApObserved{1050u, "de:ad:be:ef:00:99", "SecureCorp", 6, -50, Encryption::Open});
    assert(hasAlert(s, AlertKind::OpenDowngrade, "de:ad:be:ef:00:99"));
    assert(countAlerts(s, AlertKind::OpenDowngrade) == 1u);
    // Cooldown prevents rogue open beacons from flooding the alert ring.
    for (uint32_t i = 1; i <= 20u; ++i) {
        s = reduce(s, ApObserved{1050u + i * 100u, "de:ad:be:ef:00:99", "SecureCorp", 6, -50,
                                 Encryption::Open});
    }
    assert(countAlerts(s, AlertKind::OpenDowngrade) == 1u);
}

void testDeauthFloodDetection() {
    SecState s;
    s = reduce(s, ApObserved{0u, "aa:bb:cc:00:00:01", "Victim", 6, -40, Encryption::Wpa2});

    // Fewer than the threshold within the window => no flood alert yet.
    for (uint32_t i = 0; i < kDeauthFloodThreshold - 1u; ++i) {
        s = reduce(s, DeauthObserved{100u + i * 10u, "aa:bb:cc:00:00:01", "", ""});
    }
    assert(!hasAlert(s, AlertKind::DeauthFlood));

    // One more within the window crosses the threshold.
    s = reduce(s, DeauthObserved{100u + kDeauthFloodThreshold * 10u, "aa:bb:cc:00:00:01", "", ""});
    assert(hasAlert(s, AlertKind::DeauthFlood, "00:00:01"));
    assert(s.totalDeauths == kDeauthFloodThreshold);

    // Cooldown: a second immediate flood does not spam a new alert.
    const std::size_t before = countAlerts(s, AlertKind::DeauthFlood);
    s = reduce(s, DeauthObserved{100u + kDeauthFloodThreshold * 10u + 5u, "aa:bb:cc:00:00:01", "", ""});
    assert(countAlerts(s, AlertKind::DeauthFlood) == before);
}

void testDeauthWindowExpiry() {
    SecState s;
    // Spread deauths far apart so the sliding window never fills => no flood.
    for (uint32_t i = 0; i < kDeauthFloodThreshold + 4u; ++i) {
        s = reduce(s, DeauthObserved{i * (kDeauthWindowMs + 1000u), "aa:bb:cc:00:00:07", "", ""});
    }
    assert(!hasAlert(s, AlertKind::DeauthFlood));
}

void testKarmaBeacon() {
    SecState s;
    const std::string bssid = "ca:fe:00:00:00:01";
    const char* ssids[] = {"Starbucks", "attwifi", "xfinitywifi", "HomeNet",
                           "Guest", "Airport_Free", "FreeWiFi"};
    for (std::size_t i = 0; i < sizeof(ssids) / sizeof(ssids[0]); ++i) {
        s = reduce(s, ApObserved{static_cast<uint32_t>(1000u + i), bssid, ssids[i], 6, -30,
                                 Encryption::Open});
    }
    assert(hasAlert(s, AlertKind::KarmaBeacon, bssid));
}

void testWpsFlag() {
    SecState s;
    s = reduce(s, ApObserved{1000u, "aa:bb:cc:00:00:01", "NoWps", 6, -40, Encryption::Wpa2, false});
    assert(!findTarget(s, "aa:bb:cc:00:00:01")->wps);
    s = reduce(s, ApObserved{1100u, "aa:bb:cc:00:00:02", "HasWps", 6, -40, Encryption::Wpa2, true});
    assert(findTarget(s, "aa:bb:cc:00:00:02")->wps);
    // A later observation without the flag updates it back down (reflects live state).
    s = reduce(s, ApObserved{1200u, "aa:bb:cc:00:00:02", "HasWps", 6, -40, Encryption::Wpa2, false});
    assert(!findTarget(s, "aa:bb:cc:00:00:02")->wps);
}

void testStationProbeTracking() {
    SecState s;
    const std::string client = "12:22:33:44:55:66";

    s = reduce(s, ProbeRequestObserved{1000u, client, "HomeNet"});
    assert(findStation(s, client) != nullptr);
    assert(findStation(s, client)->probedSsids.size() == 1u);
    assert(findStation(s, client)->probeCount == 1u);

    // Repeated SSID doesn't duplicate; a new one is appended.
    s = reduce(s, ProbeRequestObserved{1100u, client, "HomeNet"});
    s = reduce(s, ProbeRequestObserved{1200u, client, "CoffeeShop"});
    const Station* st = findStation(s, client);
    assert(st->probeCount == 3u);
    assert(st->probedSsids.size() == 2u);

    // Broadcast probes with no station MAC don't create a phantom station.
    s = reduce(s, ProbeRequestObserved{1300u, "ff:ff:ff:ff:ff:ff", "Ignored"});
    assert(findStation(s, "ff:ff:ff:ff:ff:ff") == nullptr);

    // Association (ClientObserved) upserts the same station record and sets lastBssid.
    s = reduce(s, ApObserved{1350u, "aa:bb:cc:00:00:01", "HomeNet", 6, -40, Encryption::Wpa2});
    s = reduce(s, ClientObserved{1400u, "aa:bb:cc:00:00:01", client});
    st = findStation(s, client);
    assert(st->lastBssid == "aa:bb:cc:00:00:01");
    assert(st->probedSsids.size() == 2u);  // untouched by association
    assert(findTarget(s, "aa:bb:cc:00:00:01")->clientCount == 1u);

    // Repeated data frames from the same associated station must not inflate clientCount.
    s = reduce(s, ClientObserved{1450u, "aa:bb:cc:00:00:01", client});
    assert(findTarget(s, "aa:bb:cc:00:00:01")->clientCount == 1u);

    // Broadcast/AP-self addresses must not create phantom stations or inflate clientCount.
    s = reduce(s, ClientObserved{1460u, "aa:bb:cc:00:00:01", "ff:ff:ff:ff:ff:ff"});
    s = reduce(s, ClientObserved{1470u, "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:01"});
    assert(findTarget(s, "aa:bb:cc:00:00:01")->clientCount == 1u);
    assert(findStation(s, "ff:ff:ff:ff:ff:ff") == nullptr);
    assert(findStation(s, "aa:bb:cc:00:00:01") == nullptr);

    // stationsByActivity sorts most-active first.
    s = reduce(s, ProbeRequestObserved{1500u, "76:88:99:aa:bb:cc", "Solo"});
    const std::vector<Station> ranked = stationsByActivity(s);
    assert(ranked.front().mac == client);
}

void testProbedSsidCap() {
    SecState s;
    const std::string client = "aa:aa:aa:aa:aa:aa";
    for (std::size_t i = 0; i < kMaxProbedSsidsPerStation + 5u; ++i) {
        s = reduce(s, ProbeRequestObserved{static_cast<uint32_t>(1000u + i), client,
                                           "Net" + std::to_string(i)});
    }
    assert(findStation(s, client)->probedSsids.size() == kMaxProbedSsidsPerStation);
}

void testSecMood() {
    SecState s;
    assert(deriveSecMood(s, 10000u) == SecMood::Calm);

    s = reduce(s, ApObserved{1000u, "aa:bb:cc:00:00:01", "HomeNet", 6, -40, Encryption::Wpa2});
    s = reduce(s, ApObserved{1100u, "aa:bb:cc:00:00:02", "HomeNet", 11, -55, Encryption::Wpa2});
    assert(hasAlert(s, AlertKind::EvilTwin));  // Warn severity
    assert(deriveSecMood(s, 1200u) == SecMood::Watchful);

    s = reduce(s, ApObserved{2000u, "de:ad:be:ef:00:99", "HomeNet", 6, -50, Encryption::Open});
    // Need a prior encrypted entry with the same SSID to trigger OpenDowngrade (Critical);
    // reuse the earlier encrypted "HomeNet" AP already present above.
    assert(hasAlert(s, AlertKind::OpenDowngrade));
    assert(deriveSecMood(s, 2100u) == SecMood::Alarmed);

    // Outside the recency window, the alarm fades back to calm.
    assert(deriveSecMood(s, 2100u + 60000u, 30000u) == SecMood::Calm);
}

void testSessionRecordReplay() {
    SecState original;
    std::vector<SecEvent> events = {
        ApObserved{1000u, "aa:bb:cc:00:00:01", "Weird|Name\\With\nNewline", 6, -40,
                   Encryption::Wpa2, true},
        ClientObserved{1100u, "aa:bb:cc:00:00:01", "12:22:33:44:55:66"},
        ProbeRequestObserved{1150u, "12:22:33:44:55:66", "CoffeeShop"},
        DataFrameObserved{1200u, "aa:bb:cc:00:00:01"},
        DeauthObserved{1300u, "aa:bb:cc:00:00:01", "src", "dst"},
        HandshakeObserved{1400u, "aa:bb:cc:00:00:01"},
        PmkidObserved{1500u, "aa:bb:cc:00:00:01"},
        InjectionAttempt{1600u, "aa:bb:cc:00:00:01", "", 5u, AuthDecision::BlockedUnconfirmed},
    };
    for (const SecEvent& ev : events) {
        original = reduce(original, ev);
    }

    const std::vector<std::string> lines = encodeSecEvents(events);
    const std::vector<SecEvent> decoded = decodeSecEvents(lines);
    assert(decoded.size() == events.size());

    const SecState replayed = replaySecEvents(decoded);
    assert(replayed.targets.size() == original.targets.size());
    assert(findTarget(replayed, "aa:bb:cc:00:00:01")->ssid ==
           findTarget(original, "aa:bb:cc:00:00:01")->ssid);
    assert(findTarget(replayed, "aa:bb:cc:00:00:01")->wps);
    assert(replayed.totalDeauths == original.totalDeauths);
    assert(replayed.totalHandshakes == original.totalHandshakes);
    assert(replayed.totalPmkids == original.totalPmkids);
    assert(replayed.blockedInjections == original.blockedInjections);
    assert(replayed.stations.size() == original.stations.size());
    assert(findStation(replayed, "12:22:33:44:55:66")->probedSsids ==
           findStation(original, "12:22:33:44:55:66")->probedSsids);

    // A corrupt/truncated line is skipped, not fatal.
    std::vector<std::string> withJunk = lines;
    withJunk.push_back("TOTALLY|BOGUS");
    withJunk.push_back("");
    assert(decodeSecEvents(withJunk).size() == events.size());
}

void testHandshakeAndPmkid() {
    SecState s;
    s = reduce(s, ApObserved{1000u, "aa:bb:cc:00:00:01", "Target", 6, -40, Encryption::Wpa2});
    s = reduce(s, HandshakeObserved{1500u, "aa:bb:cc:00:00:01"});
    assert(findTarget(s, "aa:bb:cc:00:00:01")->handshake);
    assert(s.totalHandshakes == 1u);
    // Idempotent: re-observing the handshake does not double-count.
    s = reduce(s, HandshakeObserved{1600u, "aa:bb:cc:00:00:01"});
    assert(s.totalHandshakes == 1u);

    s = reduce(s, PmkidObserved{1700u, "aa:bb:cc:00:00:01"});
    assert(findTarget(s, "aa:bb:cc:00:00:01")->pmkid);
    assert(s.totalPmkids == 1u);
    assert(hasAlert(s, AlertKind::HandshakeCaptured));
    assert(hasAlert(s, AlertKind::PmkidCaptured));
}

// A fake injector proving the SecSession gate blocks TX unless authorized.
class SpyInjector : public IInjector {
public:
    int sent = 0;
    bool available() const override { return true; }
    InjectResult deauth(const std::string& bssid, const std::string&, uint32_t count) override {
        sent += static_cast<int>(count);
        InjectResult r;
        r.transmitted = true;
        r.detail = "spy sent " + std::to_string(count) + " to " + bssid;
        return r;
    }
};

void testSessionDeauthGate() {
    SecSession session;
    SpyInjector inj;
    const std::string bssid = "aa:bb:cc:00:00:01";

    // Unconfirmed => blocked, nothing transmitted, TxBlocked alert recorded.
    InjectResult r1 = session.requestDeauth(inj, bssid, "", 5u, 1000u);
    assert(r1.decision == AuthDecision::BlockedUnconfirmed);
    assert(!r1.transmitted);
    assert(inj.sent == 0);
    assert(hasAlert(session.state(), AlertKind::TxBlocked));
    assert(session.state().blockedInjections == 1u);

    // Confirm + allow-list => transmit proceeds.
    session.authorization().operatorConfirmed = true;
    session.authorization().allow(bssid);
    InjectResult r2 = session.requestDeauth(inj, bssid, "", 5u, 2000u);
    assert(r2.decision == AuthDecision::Allowed);
    assert(r2.transmitted);
    assert(inj.sent == 5);
    assert(session.state().allowedInjections == 1u);
}

void testBeginDeauthMatchesRequestDeauth() {
    // beginDeauth() is the fast/synchronous half that requestDeauth() is now built from;
    // verify it gates and records identically when driven by hand (as an async front-end
    // would, running the injector itself off-thread).
    SecSession session;
    SpyInjector inj;
    const std::string bssid = "aa:bb:cc:00:00:09";

    AuthDecision d = session.beginDeauth(bssid, "", 3u, 1000u);
    assert(d == AuthDecision::BlockedUnconfirmed);
    assert(session.state().blockedInjections == 1u);
    assert(inj.sent == 0);  // beginDeauth() must never touch the injector

    session.authorization().operatorConfirmed = true;
    session.authorization().allow(bssid);
    d = session.beginDeauth(bssid, "", 3u, 2000u);
    assert(d == AuthDecision::Allowed);
    assert(session.state().allowedInjections == 1u);
    assert(inj.sent == 0);  // still never touched; caller runs the injector itself
    const InjectResult r = inj.deauth(bssid, "", 3u);
    assert(r.transmitted && inj.sent == 3);
}

void testSessionIngest() {
    SecSession session;
    session.ingest(CapturedFrame{10u, FrameKind::Beacon, "aa:bb:cc:00:00:01", "", "",
                                 "Lab", 6, -42, Encryption::Wpa2});
    session.ingest(CapturedFrame{20u, FrameKind::Eapol, "aa:bb:cc:00:00:01", "", "", "", 6, -42,
                                 Encryption::Wpa2});
    assert(session.state().totalHandshakes == 1u);
    const WifiTarget* t = findTarget(session.state(), "aa:bb:cc:00:00:01");
    assert(t != nullptr && t->ssid == "Lab" && t->handshake);
}

void testAlertRingCapCounter() {
    SecState s;
    for (std::size_t i = 0; i < kMaxAlerts + 25u; ++i) {
        s = reduce(s, InjectionAttempt{static_cast<uint32_t>(1000u + i), "aa:bb:cc:00:00:01",
                                       "", 1u, AuthDecision::BlockedUnconfirmed});
    }
    assert(s.alerts.size() == kMaxAlerts);
    assert(s.totalAlertsEmitted == kMaxAlerts + 25u);
}

void testCollectionRingCapsAndWeakProbes() {
    SecState s;
    // Populate kMaxTargets + 10 distinct BSSIDs; oldest timestamp (bssid index 0) must be evicted.
    for (std::size_t i = 0; i < kMaxTargets + 10u; ++i) {
        char mac[24];
        std::snprintf(mac, sizeof(mac), "02:00:00:00:%02x:%02x",
                      static_cast<unsigned>((i >> 8) & 0xFFu),
                      static_cast<unsigned>(i & 0xFFu));
        s = reduce(s, ApObserved{static_cast<uint32_t>(100u + i), mac,
                                 "SSID_" + std::to_string(i), 6, -50, Encryption::Wpa2});
    }
    assert(s.targets.size() == kMaxTargets);
    assert(findTarget(s, "02:00:00:00:00:00") == nullptr);
    assert(findTarget(s, "02:00:00:00:00:0a") != nullptr);
    assert(s.bssidSsids.size() <= kMaxBssidSsids);

    // Weak/default probe pattern detection.
    Station cleanSt;
    cleanSt.mac = "02:11:22:33:44:55";
    cleanSt.probedSsids = {"CorpVpn_5G", "ZeroDayLab"};
    assert(!hasWeakOrDefaultProbe(cleanSt));

    Station weakSt = cleanSt;
    weakSt.probedSsids.push_back("Airport_FreeWiFi");
    assert(hasWeakOrDefaultProbe(weakSt));

    // SecSession live recorder & loadEvents replay.
    struct SpyRecorder : public ISessionRecorder {
        std::vector<std::string> lines;
        void recordEvent(const std::string& line) override { lines.push_back(line); }
    } rec;
    SecSession sess;
    sess.setRecorder(&rec);
    sess.ingest(CapturedFrame{50u, FrameKind::Beacon, "02:aa:bb:cc:dd:ee", "", "",
                              "TestLab", 11, -48, Encryption::Wpa3, true});
    assert(rec.lines.size() == 1u);
    assert(sess.events().size() == 1u);

    SecSession replayed;
    replayed.loadEvents(decodeSecEvents(rec.lines));
    const WifiTarget* rt = findTarget(replayed.state(), "02:aa:bb:cc:dd:ee");
    assert(rt != nullptr && rt->ssid == "TestLab" && rt->wps && rt->enc == Encryption::Wpa3);
}

void testStationZeroTimestampAndClockSkew() {
    SecState s;
    const std::string client = "12:22:33:44:55:66";
    s = reduce(s, ProbeRequestObserved{0u, client, "Home"});
    s = reduce(s, ProbeRequestObserved{5000u, client, "Work"});
    const Station* st = findStation(s, client);
    assert(st != nullptr);
    assert(st->firstSeenMs == 0u);
    assert(st->lastSeenMs == 5000u);

    // Out-of-order timestamps must not underflow unsigned window subtraction.
    s = reduce(s, ApObserved{2000u, "aa:bb:cc:00:00:01", "Lab", 6, -40, Encryption::Wpa2});
    s = reduce(s, ApObserved{2100u, "aa:bb:cc:00:00:02", "Lab", 6, -45, Encryption::Open});
    assert(deriveSecMood(s, 1500u) == SecMood::Alarmed);
}

void testHardeningInvariants() {
    // 1. Fail-closed audit sink refuses transmission when audit persistence fails.
    struct FailingAudit final : public IAuditLog {
        bool record(const std::string&) override { return false; }
    } badAudit;

    SecSession sess;
    SpyInjector inj;
    const std::string bssid = "02:aa:bb:cc:dd:01";
    sess.authorization().operatorConfirmed = true;
    assert(sess.authorization().allow(bssid));
    const InjectResult blocked = sess.requestDeauth(inj, bssid, "", 5u, 1000u, &badAudit);
    assert(blocked.decision == AuthDecision::BlockedAuditFailed);
    assert(!blocked.transmitted);
    assert(inj.sent == 0);
    assert(sess.state().blockedInjections == 1u);

    // 2. Multicast MACs never create phantom stations; roaming decrements prior AP clientCount.
    SecState s;
    const uint64_t rev0 = s.revision;
    s = reduce(std::move(s), ApObserved{100u, "02:00:00:00:00:01", "AP1\x1b[31m", 1, -40,
                                        Encryption::Wpa2});
    assert(s.revision == rev0 + 1u);
    assert(findTarget(s, "02:00:00:00:00:01")->ssid == "AP1[31m");  // ESC stripped
    s = reduce(std::move(s), ApObserved{110u, "02:00:00:00:00:02", "AP2", 6, -45,
                                        Encryption::Wpa2});
    s = reduce(std::move(s), ClientObserved{120u, "02:00:00:00:00:01", "01:00:5e:00:00:fb"});
    assert(findTarget(s, "02:00:00:00:00:01")->clientCount == 0u);  // multicast ignored
    s = reduce(std::move(s), ClientObserved{130u, "02:00:00:00:00:01", "02:11:22:33:44:55"});
    assert(findTarget(s, "02:00:00:00:00:01")->clientCount == 1u);
    s = reduce(std::move(s), ClientObserved{140u, "02:00:00:00:00:02", "02:11:22:33:44:55"});
    assert(findTarget(s, "02:00:00:00:00:01")->clientCount == 0u);  // decremented on roam
    assert(findTarget(s, "02:00:00:00:00:02")->clientCount == 1u);

    // 3. DeauthTracker recentMs is strictly bounded under high-rate flood.
    for (uint32_t i = 0; i < 200u; ++i) {
        s = reduce(std::move(s), DeauthObserved{2000u + i, "02:00:00:00:00:01", "", ""});
    }
    assert(!s.deauthTrackers.empty());
    assert(s.deauthTrackers[0].recentMs.size() <= kMaxDeauthTimestamps);

    // 4. Embedded zero-retention mode keeps events_ empty.
    sess.setMaxRecordedEvents(0u);
    sess.dispatch(DataFrameObserved{3000u, bssid});
    assert(sess.events().empty());

    // 5. Client target validator & beginDeauth reject multicast client MACs (empty/broadcast ok).
    assert(isValidClientTarget(""));
    assert(isValidClientTarget("ff:ff:ff:ff:ff:ff"));
    assert(isValidClientTarget("02:11:22:33:44:55"));
    assert(!isValidClientTarget("01:00:5e:00:00:01"));
    assert(!isValidClientTarget("not-a-mac"));
    const AuthDecision badSta = sess.beginDeauth(bssid, "01:00:5e:00:00:01", 4u, 3100u);
    assert(badSta == AuthDecision::BlockedNotAllowlisted);

    // 6. Strict EAPOL 4-way handshake M1+M2 pairing per (bssid, sta).
    SecSession hs;
    hs.dispatch(ApObserved{10u, bssid, "LabAP", 6, -42, Encryption::Wpa2});
    CapturedFrame m1{};
    m1.nowMs = 20u;
    m1.kind = FrameKind::Eapol;
    m1.bssid = bssid;
    m1.hasStation = true;
    m1.station = "02:11:22:33:44:01";
    m1.eapolMsg = 1u;
    hs.ingest(m1);
    assert(!findTarget(hs.state(), bssid)->handshake);

    CapturedFrame m2WrongSta = m1;
    m2WrongSta.nowMs = 25u;
    m2WrongSta.station = "02:11:22:33:44:99";
    m2WrongSta.eapolMsg = 2u;
    hs.ingest(m2WrongSta);
    assert(!findTarget(hs.state(), bssid)->handshake);  // mismatched station!

    CapturedFrame m2RightSta = m1;
    m2RightSta.nowMs = 30u;
    m2RightSta.eapolMsg = 2u;
    hs.ingest(m2RightSta);
    assert(findTarget(hs.state(), bssid)->handshake);

    // 7. Wrap-safe deriveSecMood across uint32_t rollover + O(1) index LRU eviction.
    SecState lru;
    char macBuf[24];
    for (uint32_t i = 0u; i < kMaxTargets + 10u; ++i) {
        std::snprintf(macBuf, sizeof(macBuf), "02:00:00:00:%02x:%02x", (i >> 8) & 0xff, i & 0xff);
        lru = reduce(std::move(lru), ApObserved{1000u + i, macBuf, "N", 6, -50, Encryption::Wpa2});
    }
    assert(lru.targets.size() == kMaxTargets);
    assert(findTarget(lru, "02:00:00:00:00:00") == nullptr);  // earliest evicted
    assert(findTarget(lru, "02:00:00:00:00:80") != nullptr);  // newer retained
}

void testBleAndSubGhzDefense() {
    SecState s;
    s = reduce(s, BleObserved{1000u, "7a:3c:91:04:88:12", "Tracker_Tag", -55, 0x004Cu, 0u, true});
    assert(hasAlert(s, AlertKind::BleTrackerDetected, "7a:3c:91:04:88:12"));
    assert(deriveSecMood(s, 1100u) == SecMood::Alarmed);  // RSSI >= -60 => Critical

    s = reduce(s, BleObserved{2000u, "00:80:e1:42:13:37", "SubGHz_Tool", -68, 0u, 0x3082u, false});
    assert(hasAlert(s, AlertKind::MultiToolDetected, "00:80:e1:42:13:37"));

    s = reduce(s, SubGhzObserved{3000u, 433920u, -50, "OOK", 6u, false});
    assert(hasAlert(s, AlertKind::SubGhzAnomaly));
    s = reduce(s, SubGhzObserved{4000u, 915000u, -42, "FSK", 12u, true});
    assert(countAlerts(s, AlertKind::SubGhzAnomaly) == 2u);

    // .zds round-trip serialization for BLE & SUBGHZ events
    const std::vector<SecEvent> evs = {
        BleObserved{100u, "7a:3c:91:04:88:12", "Tracker_Tag", -55, 0x004Cu, 0u, true},
        SubGhzObserved{200u, 433920u, -50, "OOK", 6u, false},
    };
    const auto encoded = encodeSecEvents(evs);
    const auto decoded = decodeSecEvents(encoded);
    assert(decoded.size() == 2u);
    const SecState replayed = replaySecEvents(decoded);
    assert(replayed.bleTargets.size() == 1u);
    assert(replayed.subGhzCaptures.size() == 1u);
    assert(hasAlert(replayed, AlertKind::BleTrackerDetected));
    assert(hasAlert(replayed, AlertKind::SubGhzAnomaly));
}

void testClientBeforeApEvictionTrustHopperAndReport() {
    // 1. Canonical lowercase normalizeMac fast path matches mixed-case path
    assert(normalizeMac("aa:bb:cc:dd:ee:ff") == "aa:bb:cc:dd:ee:ff");

    // 2. ClientObserved before ApObserved still counts toward clientCount once beacon arrives
    SecState s;
    s = reduce(std::move(s), ClientObserved{100u, "02:aa:bb:cc:dd:01", "02:11:22:33:44:01"});
    s = reduce(std::move(s), ClientObserved{110u, "02:aa:bb:cc:dd:01", "02:11:22:33:44:02"});
    s = reduce(std::move(s), ApObserved{120u, "02:aa:bb:cc:dd:01", "Office", 6, -42, Encryption::Wpa2});
    assert(findTarget(s, "02:aa:bb:cc:dd:01")->clientCount == 2u);

    // 3. Evicting oldest station (> kMaxStations) decrements AP clientCount
    char staBuf[24];
    for (uint32_t i = 0u; i < kMaxStations; ++i) {
        std::snprintf(staBuf, sizeof(staBuf), "02:77:00:00:%02x:%02x", (i >> 8) & 0xff, i & 0xff);
        s = reduce(std::move(s), ClientObserved{200u + i, "02:aa:bb:cc:dd:01", staBuf});
    }
    assert(s.stations.size() == kMaxStations);
    assert(findTarget(s, "02:aa:bb:cc:dd:01")->clientCount == kMaxStations);
    // Adding a station for another BSSID evicts one from 02:aa:bb:cc:dd:01 and decrements its count
    s = reduce(std::move(s), ApObserved{800u, "02:bb:bb:bb:bb:01", "Guest", 1, -60, Encryption::Open});
    s = reduce(std::move(s), ClientObserved{810u, "02:bb:bb:bb:bb:01", "02:88:00:00:00:01"});
    assert(findTarget(s, "02:aa:bb:cc:dd:01")->clientCount == kMaxStations - 1u);
    assert(findTarget(s, "02:bb:bb:bb:bb:01")->clientCount == 1u);

    // 4. Trusted BSSID memory: suppresses self evil-twin alerts & escalates impersonation to Critical
    SecState tr;
    assert(trustBssid(tr, "02:aa:bb:cc:dd:10"));
    assert(isTrustedBssid(tr, "02:AA:BB:CC:DD:10"));
    tr = reduce(std::move(tr), ApObserved{100u, "02:aa:bb:cc:dd:10", "HomeWiFi", 1, -40, Encryption::Wpa2});
    assert(trustBssid(tr, "02:aa:bb:cc:dd:11"));
    tr = reduce(std::move(tr), ApObserved{200u, "02:aa:bb:cc:dd:11", "HomeWiFi", 6, -44, Encryption::Wpa2});
    assert(!hasAlert(tr, AlertKind::EvilTwin));  // trusted mesh BSSID does not trigger alert
    tr = reduce(std::move(tr), ApObserved{300u, "02:aa:bb:cc:dd:99", "HomeWiFi", 11, -35, Encryption::Wpa2});
    assert(hasAlert(tr, AlertKind::EvilTwin, "02:aa:bb:cc:dd:99"));
    assert(tr.alerts.back().severity == Severity::Critical);
    assert(untrustBssid(tr, "02:aa:bb:cc:dd:11"));
    assert(!isTrustedBssid(tr, "02:aa:bb:cc:dd:11"));

    // 5. ChannelHopper 2.4/5GHz + 3s EAPOL handshake hold
    ChannelHopper hopper(ChannelHopper::Config{false, 350u, 3000u});
    assert(hopper.step(0u).value_or(-1) == 1);
    assert(!hopper.step(200u).has_value());
    assert(hopper.step(350u).value_or(-1) == 6);
    hopper.notifyEapolActivity(400u);
    assert(!hopper.step(2000u).has_value());
    assert(hopper.step(3400u).value_or(-1) == 11);
    hopper.setInclude5Ghz(true);
    assert(hopper.schedule().size() > 11u);

    // 6. M1 carrying PMKID + M2 records BOTH pmkid AND handshake
    SecSession pmSess;
    CapturedFrame m1p{};
    m1p.nowMs = 100u;
    m1p.kind = FrameKind::Pmkid;
    m1p.bssid = "02:aa:bb:cc:dd:ee";
    m1p.station = "02:11:22:33:44:55";
    m1p.hasStation = true;
    m1p.eapolMsg = 1u;
    m1p.hasPmkid = true;
    pmSess.ingest(m1p);
    CapturedFrame m2{};
    m2 = m1p;
    m2.nowMs = 120u;
    m2.kind = FrameKind::Eapol;
    m2.eapolMsg = 2u;
    m2.hasPmkid = false;
    pmSess.ingest(m2);
    const WifiTarget* pmTgt = findTarget(pmSess.state(), "02:aa:bb:cc:dd:ee");
    assert(pmTgt != nullptr && pmTgt->pmkid && pmTgt->handshake);

    // 7. Pure Report Exporter escaping (CSV formula injection + HTML XSS)
    SecState repState;
    repState = reduce(std::move(repState),
                      ApObserved{100u, "02:11:22:33:44:55", "=cmd|<script>alert(1)</script>",
                                 6, -50, Encryption::Open, true});
    const std::string csv = formatReport(repState, ReportFormat::Csv, 500u);
    assert(csv.find("\"'=cmd") != std::string::npos);
    const std::string html = formatReport(repState, ReportFormat::Html, 500u);
    assert(html.find("<script>") == std::string::npos);
    assert(html.find("&lt;script&gt;") != std::string::npos);
    assert(reportFormatFromPath("out.HTML") == ReportFormat::Html);
    assert(reportFormatFromPath("out.md") == ReportFormat::Markdown);
    assert(!reportFormatFromPath("out.txt").has_value());
}

}  // namespace

int main() {
    testMacNormalization();
    testMacValidation();
    testChannelBands();
    testAuthorizationGate();
    testApTrackingAndEvilTwin();
    testOpenDowngrade();
    testDeauthFloodDetection();
    testDeauthWindowExpiry();
    testKarmaBeacon();
    testWpsFlag();
    testStationProbeTracking();
    testProbedSsidCap();
    testSecMood();
    testSessionRecordReplay();
    testHandshakeAndPmkid();
    testSessionDeauthGate();
    testBeginDeauthMatchesRequestDeauth();
    testSessionIngest();
    testAlertRingCapCounter();
    testCollectionRingCapsAndWeakProbes();
    testStationZeroTimestampAndClockSkew();
    testHardeningInvariants();
    testBleAndSubGhzDefense();
    testClientBeforeApEvictionTrustHopperAndReport();
    std::cout << "[secops] all security-engine tests passed\n";
    return 0;
}
