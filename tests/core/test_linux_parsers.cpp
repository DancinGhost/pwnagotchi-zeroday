// Host unit tests for the Linux backend's pure parsers and the 802.11/radiotap decoder.
// No subprocesses, sockets, or root: validates text/byte parsing against fixed samples.

#include <cassert>
#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include "parsers.hpp"
#include "dot11.hpp"

namespace {

using namespace zd::linux_backend;

void testEncryptionFromText() {
    assert(encryptionFromText("WPA2") == zd::sec::Encryption::Wpa2);
    assert(encryptionFromText("WPA3 SAE") == zd::sec::Encryption::Wpa3);
    assert(encryptionFromText("WPA1 WPA2") == zd::sec::Encryption::Wpa2);
    assert(encryptionFromText("WEP") == zd::sec::Encryption::Wep);
    assert(encryptionFromText("--") == zd::sec::Encryption::Open);
    assert(encryptionFromText("") == zd::sec::Encryption::Open);
}

void testNmcliParse() {
    // `nmcli -t` escapes the colons inside a BSSID with backslashes.
    const std::string sample =
        "00\\:11\\:22\\:33\\:44\\:55:HomeNet:6:WPA2:82\n"
        "AA\\:BB\\:CC\\:DD\\:EE\\:FF:Cafe Guest:11:--:47\n"
        "66\\:77\\:88\\:99\\:AA\\:BB::1:WPA3:60\n";  // hidden SSID

    const std::vector<ScannedAp> aps = parseNmcliScanDetailed(sample);
    assert(aps.size() == 3);
    assert(aps[0].bssid == "00:11:22:33:44:55");
    assert(aps[0].ssid == "HomeNet");
    assert(aps[0].channel == 6);
    assert(aps[0].enc == zd::sec::Encryption::Wpa2);
    assert(aps[1].enc == zd::sec::Encryption::Open);
    assert(aps[1].ssid == "Cafe Guest");
    assert(aps[2].ssid.empty());
    assert(aps[2].enc == zd::sec::Encryption::Wpa3);

    const std::vector<zd::AccessPoint> legacy = parseNmcliScan(sample);
    assert(legacy.size() == 3);
    assert(legacy[0].secure);
    assert(!legacy[1].secure);
}

void testAirodumpCsv() {
    const std::string csv =
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
        "00:11:22:33:44:55, 2026-01-01 10:00:00, 2026-01-01 10:05:00, 6, 130, WPA2, CCMP, "
        "PSK, -42, 120, 0, 0.0.0.0, 7, HomeNet, \r\n"
        "AA:BB:CC:DD:EE:FF, 2026-01-01 10:00:00, 2026-01-01 10:05:00, 11, 54, OPN, , , -70, "
        "30, 0, 0.0.0.0, 10, Cafe Guest, \r\n"
        "\r\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n"
        "99:88:77:66:55:44, 2026-01-01 10:01:00, 2026-01-01 10:05:00, -50, 42, "
        "00:11:22:33:44:55, HomeNet, CorpWiFi\r\n"
        "11:22:33:44:55:66, 2026-01-01 10:02:00, 2026-01-01 10:05:00, -65, 10, "
        "(not associated), FreeCafe\r\n";

    const AirodumpDump dump = parseAirodumpCsv(csv);
    assert(dump.aps.size() == 2);
    assert(dump.aps[0].bssid == "00:11:22:33:44:55");
    assert(dump.aps[0].channel == 6);
    assert(dump.aps[0].enc == zd::sec::Encryption::Wpa2);
    assert(dump.aps[0].rssi == -42);
    assert(dump.aps[0].ssid == "HomeNet");
    assert(dump.aps[1].enc == zd::sec::Encryption::Open);
    assert(dump.stations.size() == 2);
    assert(dump.stations[0].mac == "99:88:77:66:55:44");
    assert(dump.stations[0].bssid == "00:11:22:33:44:55");
    assert(dump.stations[0].probedEssids.size() == 2);
    assert(dump.stations[0].probedEssids[0] == "HomeNet");
    assert(dump.stations[0].probedEssids[1] == "CorpWiFi");
    assert(dump.stations[1].mac == "11:22:33:44:55:66");
    assert(dump.stations[1].bssid.empty());
    assert(dump.stations[1].probedEssids.size() == 1);
    assert(dump.stations[1].probedEssids[0] == "FreeCafe");
}

std::vector<uint8_t> minimalRadiotap() {
    return {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};  // version0, len8, no fields
}

void append(std::vector<uint8_t>& v, std::initializer_list<uint8_t> b) {
    v.insert(v.end(), b);
}

void testDecodeBeacon() {
    std::vector<uint8_t> f = minimalRadiotap();
    const std::size_t rtEnd = f.size();
    // 802.11 beacon header
    append(f, {0x80, 0x00});              // FC: mgmt/beacon
    append(f, {0x00, 0x00});              // duration
    append(f, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff});  // addr1 dest (broadcast)
    append(f, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // addr2 bssid
    append(f, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // addr3 bssid
    append(f, {0x00, 0x00});              // seq
    // fixed params: timestamp(8), interval(2), caps(2 => privacy bit set 0x0010)
    append(f, {0, 0, 0, 0, 0, 0, 0, 0});
    append(f, {0x64, 0x00});
    append(f, {0x11, 0x00});              // caps: privacy bit (0x10) set
    // tags: SSID "Lab" (tag 0)
    append(f, {0x00, 0x03, 'L', 'a', 'b'});
    // DS param (tag 3): channel 6
    append(f, {0x03, 0x01, 0x06});
    // RSN (tag 48): WPA2-PSK
    append(f, {0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac,
               0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00});
    (void)rtEnd;

    const auto decoded = decodeRadiotapFrame(f.data(), f.size(), 1234u);
    assert(decoded.has_value());
    assert(decoded->kind == zd::sec::FrameKind::Beacon);
    assert(decoded->bssid == "00:11:22:33:44:55");
    assert(decoded->ssid == "Lab");
    assert(decoded->channel == 6);
    assert(decoded->enc == zd::sec::Encryption::Wpa2);
}

void testDecodeDeauth() {
    std::vector<uint8_t> f = minimalRadiotap();
    append(f, {0xC0, 0x00});              // FC: mgmt/deauth
    append(f, {0x00, 0x00});
    append(f, {0x99, 0x88, 0x77, 0x66, 0x55, 0x44});  // addr1 client
    append(f, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // addr2 bssid
    append(f, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});  // addr3 bssid
    append(f, {0x00, 0x00});
    append(f, {0x07, 0x00});              // reason code

    const auto decoded = decodeRadiotapFrame(f.data(), f.size(), 50u);
    assert(decoded.has_value());
    assert(decoded->kind == zd::sec::FrameKind::Deauth);
    assert(decoded->bssid == "00:11:22:33:44:55");
    assert(decoded->source == "00:11:22:33:44:55");
    assert(decoded->dest == "99:88:77:66:55:44");
}

void testDecodedFrameFeedsEngine() {
    std::vector<uint8_t> f = minimalRadiotap();
    append(f, {0x80, 0x00, 0x00, 0x00});
    append(f, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
    append(f, {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
    append(f, {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f});
    append(f, {0x00, 0x00});
    append(f, {0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x00, 0x00, 0x00});  // fixed, open caps
    append(f, {0x00, 0x04, 'O', 'p', 'e', 'n'});
    append(f, {0x03, 0x01, 0x01});
    // WPS vendor IE (tag 221, OUI 00:50:F2, type 04)
    append(f, {221, 0x06, 0x00, 0x50, 0xF2, 0x04, 0x10, 0x4a});

    const auto decoded = decodeRadiotapFrame(f.data(), f.size(), 10u);
    assert(decoded.has_value());
    assert(decoded->enc == zd::sec::Encryption::Open);
    assert(decoded->wps);

    zd::sec::SecSession session;
    session.ingest(*decoded);
    const auto* t = zd::sec::findTarget(session.state(), "0a:0b:0c:0d:0e:0f");
    assert(t != nullptr && t->ssid == "Open" && t->channel == 1 && t->wps);
}

void testMalformedAndTruncatedFrames() {
    // Empty or shorter than 8-byte radiotap header
    const uint8_t tiny[4] = {0x00, 0x00, 0x08, 0x00};
    assert(!decodeRadiotapFrame(tiny, sizeof(tiny), 1u).has_value());

    // Radiotap header claims length larger than packet buffer
    const uint8_t bogusLen[12] = {0x00, 0x00, 0x40, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
    assert(!decodeRadiotapFrame(bogusLen, sizeof(bogusLen), 1u).has_value());

    // Extended present bit (bit 31) chaining past rtLen without terminating
    const uint8_t endlessPresent[12] = {0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x80,
                                        0x00, 0x00, 0x00, 0x80};
    assert(!decodeRadiotapFrame(endlessPresent, sizeof(endlessPresent), 1u).has_value());

    // Present flags claim TSFT (8 bytes) + Channel (4 bytes) + Signal (1 byte), but rtLen is only 12
    std::vector<uint8_t> truncatedRt = {0x00, 0x00, 0x0c, 0x00, 0x29, 0x00, 0x00, 0x00,
                                        0x01, 0x02, 0x03, 0x04};
    append(truncatedRt, {0xC0, 0x00, 0x00, 0x00});
    append(truncatedRt, {0x99, 0x88, 0x77, 0x66, 0x55, 0x44});
    append(truncatedRt, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    append(truncatedRt, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    append(truncatedRt, {0x00, 0x00});
    const auto d = decodeRadiotapFrame(truncatedRt.data(), truncatedRt.size(), 10u);
    assert(d.has_value());
    assert(d->rssi == -100);  // Signal field was out-of-bounds of rtLen, safely defaulted

    // ANSI escape sequence in nmcli & airodump SSIDs is stripped
    const std::string dirtyNmcli = "00\\:11\\:22\\:33\\:44\\:55:Evil\x1b[31mNet:6:WPA2:80\n";
    const auto parsedNm = parseNmcliScanDetailed(dirtyNmcli);
    assert(parsedNm.size() == 1u);
    assert(parsedNm[0].ssid == "Evil[31mNet");

    // Malformed BSSID lines in nmcli / airodump are dropped
    assert(parseNmcliScanDetailed("not-a-mac:Fake:6:WPA2:80\n").empty());
    const std::string commaCsv =
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n"
        "00:11:22:33:44:55, 2026-01-01, 2026-01-01, 6, 130, WPA2, CCMP, PSK, -42, -5, 0, "
        "0.0.0.0, 12, Coffee, Tea, \r\n";
    const AirodumpDump cd = parseAirodumpCsv(commaCsv);
    assert(cd.aps.size() == 1u);
    assert(cd.aps[0].ssid == "Coffee, Tea");
    assert(cd.aps[0].beacons == 0u);
}

void testEapolPmkidAndRsnOui() {
    // 1. Non-IEEE AKM OUI with suite type 8 must NOT be misclassified as WPA3.
    const uint8_t vendorRsn[] = {
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,  // version + group
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,  // 1 pairwise
        0x01, 0x00, 0xAA, 0xBB, 0xCC, 0x08   // 1 AKM with non-IEEE OUI, type 8
    };
    assert(encryptionFromRsn(vendorRsn, sizeof(vendorRsn)) == zd::sec::Encryption::Wpa2);

    const uint8_t ieeeSaeRsn[] = {
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04,
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x08   // IEEE 00:0F:AC + SAE(8)
    };
    assert(encryptionFromRsn(ieeeSaeRsn, sizeof(ieeeSaeRsn)) == zd::sec::Encryption::Wpa3);

    // 2. EAPOL-Key M1 vs M2, station extraction, Protected/NullData rejection & extended Radiotap.
    std::vector<uint8_t> eapolNoPmkid = minimalRadiotap();
    append(eapolNoPmkid, {0x08, 0x02, 0x00, 0x00});                 // Data, FromDS
    append(eapolNoPmkid, {0x11, 0x22, 0x33, 0x44, 0x55, 0x66});     // addr1 DA (STA)
    append(eapolNoPmkid, {0x00, 0x0F, 0xAC, 0x04, 0xAA, 0xBB});     // addr2 BSSID has 00:0F:AC:04!
    append(eapolNoPmkid, {0x00, 0x0F, 0xAC, 0x04, 0xAA, 0xBB});     // addr3 SA
    append(eapolNoPmkid, {0x00, 0x00});
    append(eapolNoPmkid, {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E});  // LLC/SNAP EAPOL
    append(eapolNoPmkid, {0x02, 0x03, 0x00, 0x5F});                 // EAPOL v2, type=Key(3), len=95
    // 95-byte EAPOL-Key body: descType=2, keyInfo=0x008A (Ack+Pairwise -> M1!)
    eapolNoPmkid.push_back(0x02);
    eapolNoPmkid.push_back(0x00);
    eapolNoPmkid.push_back(0x8A);
    eapolNoPmkid.insert(eapolNoPmkid.end(), 92u, 0x00);
    const auto d1 = decodeRadiotapFrame(eapolNoPmkid.data(), eapolNoPmkid.size(), 100u);
    assert(d1.has_value());
    assert(d1->kind == zd::sec::FrameKind::Eapol);
    assert(d1->bssid == "00:0f:ac:04:aa:bb");
    assert(d1->hasStation && d1->station == "11:22:33:44:55:66");
    assert(d1->eapolMsg == 1u);

    // Protected bit (0x40) must NOT look like unencrypted LLC/SNAP EAPOL.
    std::vector<uint8_t> protectedData = eapolNoPmkid;
    protectedData[8u + 1u] = 0x42;  // FromDS + Protected
    const auto dProt = decodeRadiotapFrame(protectedData.data(), protectedData.size(), 110u);
    assert(dProt.has_value());
    assert(dProt->kind == zd::sec::FrameKind::Data);

    // Radiotap with extended-present bit31 skips 4-byte extended present word safely.
    std::vector<uint8_t> extRt = {0x00, 0x00, 12, 0, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00};
    append(extRt, {0xC0, 0x00, 0x00, 0x00});
    append(extRt, {0x99, 0x88, 0x77, 0x66, 0x55, 0x44});
    append(extRt, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    append(extRt, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
    append(extRt, {0x00, 0x00});
    const auto dExt = decodeRadiotapFrame(extRt.data(), extRt.size(), 120u);
    assert(dExt.has_value());
    assert(dExt->kind == zd::sec::FrameKind::Deauth);

    // 3. EAPOL-Key frame with a real non-zero PMKID KDE in Key Data triggers FrameKind::Pmkid.
    std::vector<uint8_t> eapolWithPmkid = eapolNoPmkid;
    // Set keyDataLen = 22 (bytes 93..94 of EAPOL-Key body)
    eapolWithPmkid[eapolWithPmkid.size() - 2u] = 0x00;
    eapolWithPmkid[eapolWithPmkid.size() - 1u] = 22u;
    // Append KDE: tag 0xDD, len 20, OUI 00:0F:AC, type 04, 16-byte non-zero PMKID
    append(eapolWithPmkid, {0xDD, 20u, 0x00, 0x0F, 0xAC, 0x04});
    for (uint8_t b = 1; b <= 16u; ++b) {
        eapolWithPmkid.push_back(b);
    }
    const auto d2 = decodeRadiotapFrame(eapolWithPmkid.data(), eapolWithPmkid.size(), 200u);
    assert(d2.has_value());
    assert(d2->kind == zd::sec::FrameKind::Pmkid);
    assert(d2->hasPmkid && d2->eapolMsg == 1u);
}

void testIwScanDetailedParser() {
    const std::string sample =
        "BSS aa:bb:cc:dd:ee:01(on wlan0)\n"
        "\tfreq: 5180\n"
        "\tsignal: -48.00 dBm\n"
        "\tSSID: Lab5G_WPS\n"
        "\tRSN:\n"
        "\t\t* Authentication suites: SAE\n"
        "\tWPS:\n"
        "BSS 00:11:22:33:44:55(on wlan0)\n"
        "\tfreq: 2437\n"
        "\tsignal: -71.00 dBm\n"
        "\tcapability: ESS Privacy (0x0411)\n"
        "\tSSID: LegacyWep\n"
        "BSS 00:11:22:33:44:66(on wlan0)\n"
        "\tfreq: 2412\n"
        "\tsignal: -80.00 dBm\n"
        "\tcapability: ESS (0x0401)\n"
        "\tSSID: FreeCafe\n";
    const auto aps = parseIwScanDetailed(sample);
    assert(aps.size() == 3u);
    assert(aps[0].bssid == "aa:bb:cc:dd:ee:01" && aps[0].channel == 36 && aps[0].wps);
    assert(aps[0].enc == zd::sec::Encryption::Wpa3);
    assert(aps[1].channel == 6 && aps[1].enc == zd::sec::Encryption::Wep && !aps[1].wps);
    assert(aps[2].channel == 1 && aps[2].enc == zd::sec::Encryption::Open);
}

void testBleAndSubGhzParsers() {
    const auto b1 = parseBluezBleLine("7A:3C:91:04:88:12|-54|Tracker_Tag|0x004C|0x0000|1");
    assert(b1.has_value());
    assert(b1->mac == "7a:3c:91:04:88:12");
    assert(b1->threat == zd::BleThreatKind::AirTagTracker);

    const auto b2 = parseBluezBleLine("Device 00:80:E1:11:22:33 MultiTool_Unit");
    assert(b2.has_value());
    assert(b2->threat == zd::BleThreatKind::MultiToolBle);

    const auto s1 = parseRtl433Line("SUBGHZ|433920|-52|OOK|6|0");
    assert(s1.has_value());
    assert(s1->freqKhz == 433920u && s1->burstCount == 6u && !s1->continuousCarrier);

    const auto s2 = parseRtl433Line("868.35MHz|-45|FSK|10|1");
    assert(s2.has_value());
    assert(s2->freqKhz == 868350u && s2->continuousCarrier);
}

}  // namespace

int main() {
    testEncryptionFromText();
    testNmcliParse();
    testAirodumpCsv();
    testDecodeBeacon();
    testDecodeDeauth();
    testDecodedFrameFeedsEngine();
    testMalformedAndTruncatedFrames();
    testEapolPmkidAndRsnOui();
    testIwScanDetailedParser();
    testBleAndSubGhzParsers();
    std::cout << "[linux-parsers] all backend parser/decoder tests passed\n";
    return 0;
}
