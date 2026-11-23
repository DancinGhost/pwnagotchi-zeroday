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
    // extractEapolKeyMaterial must lift the 16-byte PMKID and the raw EAPOL frame out.
    for (std::size_t i = 0u; i < 16u; ++i) {
        assert(d2->pmkid[i] == static_cast<uint8_t>(i + 1u));
    }
    assert(d2->eapolBody.size() >= 99u);

    // 4. EAPOL-Key M1 carrying a real non-zero ANonce + replay counter: material extracted.
    // The last 95 bytes of eapolNoPmkid are the EAPOL-Key body starting at the Descriptor Type
    // field (EAPOL-header offset 4), so within it: replay counter at +5..+12, nonce at +13..+44.
    std::vector<uint8_t> m1Nonce = eapolNoPmkid;
    const std::size_t body = m1Nonce.size() - 95u;
    m1Nonce[body + 12u] = 0x07;  // replay counter LSB (8-byte BE) -> rc = 7
    for (std::size_t i = 0u; i < 32u; ++i) {
        m1Nonce[body + 13u + i] = static_cast<uint8_t>(0xA0u + i);  // ANonce
    }
    const auto d3 = decodeRadiotapFrame(m1Nonce.data(), m1Nonce.size(), 300u);
    assert(d3.has_value() && d3->eapolMsg == 1u);
    assert(d3->hasEapolNonce);
    assert(d3->eapolReplayCounter == 7u);
    assert(d3->eapolNonce[0] == 0xA0u && d3->eapolNonce[31] == static_cast<uint8_t>(0xA0u + 31u));
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

    // JSON (`rtl_433 -F json`) parsing including Hz/kHz/MHz normalization & malformed inputs
    const auto sj1 = parseRtl433Line(
        "{\"time\":\"2026-11-22 12:00:00\",\"model\":\"Acurite-Tower\",\"freq\":433.92,"
        "\"rssi\":-49,\"burst_count\":4}");
    assert(sj1.has_value());
    assert(sj1->freqKhz == 433920u && sj1->rssi == -49 && sj1->protocol == "Acurite-Tower" &&
           sj1->burstCount == 4u);

    const auto sjHz = parseRtl433Line("{\"mod\":\"OOK\",\"frequency\":915000000,\"snr\":-35}");
    assert(sjHz.has_value() && sjHz->freqKhz == 915000u && sjHz->protocol == "OOK" &&
           sjHz->rssi == -35);

    assert(!parseRtl433Line("{\"unrelated\":\"field\"}").has_value());
    assert(!parseRtl433Line("{\"freq\":9999999999}").has_value());

    // ANSI escape stripping & BlueZ `bluetoothctl scan/devices/info` + `btmgmt find` parsers
    assert(stripAnsiEscapes("\x1b[0;94m[\x1b[0mbluetooth\x1b[0;94m]# Device AA:BB") ==
           "[bluetooth]# Device AA:BB");

    const std::string scanLog =
        "\x1b[0m[NEW] Device A4:5E:60:11:22:02 Earbuds Pro\r\n"
        "[CHG] Device 7A:3C:91:04:88:12 RSSI: 0xffffffc8 (-56)\n"
        "Device 44:12:AA:BB:10:01 SmartWatch\n"
        "[DEL] Device 11:22:33:44:55:66 Gone\n";
    const auto devs = parseBluezScanOutput(scanLog);
    assert(devs.size() == 3u);
    assert(devs[0].mac == "a4:5e:60:11:22:02" && devs[0].name == "Earbuds Pro");
    assert(devs[1].mac == "7a:3c:91:04:88:12" && devs[1].rssi == -56);
    assert(devs[2].mac == "44:12:aa:bb:10:01" && devs[2].name == "SmartWatch");

    ScannedBleDevice enriched{};
    enriched.mac = "7a:3c:91:04:88:12";
    const std::string btInfo =
        "Device 7A:3C:91:04:88:12 (random)\n"
        "\tName: AirTag Tracker\n"
        "\tAlias: AirTag Tracker\n"
        "\tRSSI: -52\n"
        "\tUUID: Apple Find My            (0000fd6f-0000-1000-8000-00805f9b34fb)\n"
        "\tManufacturerData Key: 0x004c\n"
        "\tManufacturerData Value:\n"
        "  12 19 00 01\n";
    assert(parseBluezDeviceInfo(btInfo, enriched));
    assert(enriched.rssi == -52 && enriched.companyId == 0x004Cu &&
           enriched.serviceUuid == 0xFD6Fu && enriched.trackerPayload);

    const std::string mgmtLog =
        "hci0 dev_found: 00:80:E1:42:13:37 type LE Random rssi -47 flags 0x0000\n"
        "name SubGHz_Tool\n";
    const auto mgmtDevs = parseBtmgmtFindOutput(mgmtLog);
    assert(mgmtDevs.size() == 1u);
    assert(mgmtDevs[0].mac == "00:80:e1:42:13:37" && mgmtDevs[0].rssi == -47 &&
           mgmtDevs[0].name == "SubGHz_Tool");
}

void testPmfCsa6GhzAndGpsd() {
    // 1. 802.11w PMF RSN capabilities parsing (MFPR = 0x0040, MFPC = 0x0080)
    const std::vector<uint8_t> rsnDisabled = {
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F,
        0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00
    };
    const std::vector<uint8_t> rsnOptional = {
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F,
        0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x80, 0x00
    };
    const std::vector<uint8_t> rsnRequired = {
        0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F,
        0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x08, 0xC0, 0x00
    };
    assert(pmfFromRsn(rsnDisabled.data(), rsnDisabled.size()) == zd::sec::PmfStatus::Disabled);
    assert(pmfFromRsn(rsnOptional.data(), rsnOptional.size()) == zd::sec::PmfStatus::Optional);
    assert(pmfFromRsn(rsnRequired.data(), rsnRequired.size()) == zd::sec::PmfStatus::Required);

    // 2. Beacon carrying RSN (PMF Required) + Tag 37 CSA (channel 149, count 2)
    std::vector<uint8_t> beacon(36, 0x00);
    beacon[0] = 0x80;  // Management Beacon
    // dst ff..ff, src/bssid 02:aa:bb:cc:dd:01
    for (int i = 4; i < 10; ++i) beacon[i] = 0xFF;
    const uint8_t bssid[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01};
    for (int i = 0; i < 6; ++i) {
        beacon[10 + i] = bssid[i];
        beacon[16 + i] = bssid[i];
    }
    beacon[34] = 0x11;  // Capability Privacy
    beacon.push_back(0u); beacon.push_back(3u); beacon.push_back('P'); beacon.push_back('M'); beacon.push_back('F');
    beacon.push_back(48u);
    beacon.push_back(static_cast<uint8_t>(rsnRequired.size()));
    beacon.insert(beacon.end(), rsnRequired.begin(), rsnRequired.end());
    beacon.push_back(37u); beacon.push_back(3u); beacon.push_back(1u); beacon.push_back(149u); beacon.push_back(2u);
    const auto bf = decodeDot11(beacon.data(), beacon.size(), 500u, -45);
    assert(bf.has_value());
    assert(bf->kind == zd::sec::FrameKind::Beacon);
    assert(bf->enc == zd::sec::Encryption::Wpa3);
    assert(bf->pmf == zd::sec::PmfStatus::Required);
    assert(bf->csaChannel == 149 && bf->csaCount == 2u);

    // 3. Action frame CSA (Category 0 Action 4, Tag 37 element targeting invalid channel 0)
    std::vector<uint8_t> csaAct(31, 0x00);
    csaAct[0] = 0xD0;  // Management Action (subtype 13)
    for (int i = 4; i < 10; ++i) csaAct[i] = 0xFF;
    for (int i = 0; i < 6; ++i) {
        csaAct[10 + i] = bssid[i];
        csaAct[16 + i] = bssid[i];
    }
    csaAct[24] = 0u;  // Spectrum Management
    csaAct[25] = 4u;  // CSA Action
    csaAct[26] = 37u;
    csaAct[27] = 3u;
    csaAct[28] = 1u;
    csaAct[29] = 0u;  // Invalid channel 0
    csaAct[30] = 1u;
    const auto af1 = decodeDot11(csaAct.data(), csaAct.size(), 600u, -42);
    assert(af1.has_value() && af1->kind == zd::sec::FrameKind::Csa);
    assert(af1->csaChannel == 0 && af1->csaCount == 1u);

    // Public Action ECSA (Category 4 Action 0)
    std::vector<uint8_t> ecsaAct(30, 0x00);
    ecsaAct[0] = 0xD0;
    for (int i = 0; i < 6; ++i) {
        ecsaAct[10 + i] = bssid[i];
        ecsaAct[16 + i] = bssid[i];
    }
    ecsaAct[24] = 4u;  // Public Action
    ecsaAct[25] = 0u;
    ecsaAct[26] = 1u;
    ecsaAct[27] = 81u;
    ecsaAct[28] = 36u;
    ecsaAct[29] = 4u;
    const auto af2 = decodeDot11(ecsaAct.data(), ecsaAct.size(), 700u, -50);
    assert(af2.has_value() && af2->kind == zd::sec::FrameKind::Csa);
    assert(af2->csaChannel == 36 && af2->csaCount == 4u);

    // 4. 6 GHz channel helper + `iw scan` PMF capabilities parsing
    assert(freqMhzToChannel(5955) == zd::k6GhzChannelBase + 1);
    assert(freqMhzToChannel(6115) == zd::k6GhzChannelBase + 33);
    const std::string iwSample =
        "BSS 02:11:22:33:44:55(on wlan0)\n"
        "\tfreq: 5955\n"
        "\tsignal: -58.00 dBm\n"
        "\tSSID: SixGigLab\n"
        "\tRSN:\n"
        "\t\t * Authentication suites: SAE\n"
        "\t\t * Capabilities: MFP-required MFP-capable\n"
        "BSS 02:11:22:33:44:66(on wlan0)\n"
        "\tfreq: 5180\n"
        "\tsignal: -65.00 dBm\n"
        "\tSSID: OptionalPmfAp\n"
        "\tRSN:\n"
        "\t\t * Authentication suites: PSK\n"
        "\t\t * Capabilities: MFP-capable\n";
    const auto iwAps = parseIwScanDetailed(iwSample);
    assert(iwAps.size() == 2u);
    assert(iwAps[0].channel == zd::k6GhzChannelBase + 1);
    assert(iwAps[0].enc == zd::sec::Encryption::Wpa3 &&
           iwAps[0].pmf == zd::sec::PmfStatus::Required);
    assert(iwAps[1].channel == 36);
    assert(iwAps[1].enc == zd::sec::Encryption::Wpa2 &&
           iwAps[1].pmf == zd::sec::PmfStatus::Optional);

    // 5. gpsd JSON TPV / SKY + NMEA sentence parser
    zd::esp32_common::GpsState gps{};
    assert(parseGpsdLine(
        R"({"class":"TPV","mode":3,"time":"2026-11-22T18:45:12.000Z","lat":37.7749,"lon":-122.4194})",
        gps, 1000u));
    assert(gps.hasFix);
    assert(gps.latitude > 37.7f && gps.latitude < 37.8f);
    assert(gps.longitude < -122.4f && gps.longitude > -122.5f);
    assert(std::string(gps.utcDate) == "2026-11-22");
    assert(std::string(gps.utcTime) == "18:45:12");
    assert(parseGpsdLine(R"({"class":"SKY","uSat":9,"hdop":0.9})", gps, 1100u));
    assert(gps.satellites == 9u);
    // No-fix TPV (mode=1) clears fix
    assert(parseGpsdLine(R"({"class":"TPV","mode":1})", gps, 1200u));
    assert(!gps.hasFix);
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
    testPmfCsa6GhzAndGpsd();
    std::cout << "[linux-parsers] all backend parser/decoder tests passed\n";
    return 0;
}
