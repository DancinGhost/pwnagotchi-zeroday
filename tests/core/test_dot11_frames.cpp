// Host unit tests for the pure 802.11 frame builders (platforms/common/dot11_frames.hpp).
// Hardware-free: validates MAC parsing and exact deauth/disassoc frame serialization. The
// bytes asserted here are what esp_wifi_80211_tx() puts on the air, so a regression in the
// builder is caught on the desktop before it ever reaches a radio.

#include <cassert>
#include <cstdint>
#include <cstddef>
#include <iostream>

#include "zd/dot11.hpp"

namespace {

using namespace zd::dot11;

void testParseMac() {
    uint8_t m[6];
    assert(parseMac("aa:bb:cc:dd:ee:ff", m));
    assert(m[0] == 0xAA && m[1] == 0xBB && m[2] == 0xCC && m[3] == 0xDD && m[4] == 0xEE &&
           m[5] == 0xFF);

    // Format-insensitive: no separators, dashes, mixed case, surrounding spaces.
    uint8_t n[6];
    assert(parseMac("AABBCCDDEEFF", n) && n[0] == 0xAA && n[5] == 0xFF);
    assert(parseMac("AA-BB-CC-DD-EE-FF", n) && n[2] == 0xCC);
    assert(parseMac("  00:11:22:33:44:55 ", n) && n[0] == 0x00 && n[5] == 0x55);

    // Rejections: too short, too long, stray non-hex (e.g. an injected CLI flag), null.
    assert(!parseMac("aa:bb:cc:dd:ee", n));         // 10 nibbles
    assert(!parseMac("aa:bb:cc:dd:ee:ff:00", n));   // 14 nibbles
    assert(!parseMac("--i-am-authorized", n));      // stray chars
    assert(!parseMac("", n));
    assert(!parseMac(nullptr, n));
}

void testBroadcast() {
    const uint8_t bc[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const uint8_t uc[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    assert(isBroadcast(bc));
    assert(!isBroadcast(uc));
}

void testBuildDeauthFrame() {
    const uint8_t ap[6]  = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const uint8_t sta[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t f[kMgmtDeauthFrameLen];

    const std::size_t len = buildDeauthFrame(f, sta, ap, ap);
    assert(len == kMgmtDeauthFrameLen);
    assert(len == 26u);

    // Frame Control: mgmt type, deauth subtype (0xC0), flags 0x00.
    assert(f[0] == 0xC0 && f[1] == 0x00);
    // Duration.
    assert(f[2] == 0x00 && f[3] == 0x00);
    // Addr1 = destination station.
    for (std::size_t i = 0; i < 6; ++i) assert(f[4 + i] == sta[i]);
    // Addr2 = source (AP).
    for (std::size_t i = 0; i < 6; ++i) assert(f[10 + i] == ap[i]);
    // Addr3 = BSSID (AP).
    for (std::size_t i = 0; i < 6; ++i) assert(f[16 + i] == ap[i]);
    // Sequence control.
    assert(f[22] == 0x00 && f[23] == 0x00);
    // Reason code 7, little-endian.
    assert(f[24] == 0x07 && f[25] == 0x00);

    // Disassoc variant flips the subtype to 0xA0 and can carry a different reason.
    const std::size_t len2 = buildDeauthFrame(f, sta, ap, ap, Reason::DisassocLeaving, true);
    assert(len2 == kMgmtDeauthFrameLen);
    assert(f[0] == 0xA0);
    assert(f[24] == 0x08 && f[25] == 0x00);
}

void testBuildAuthFrame() {
    const uint8_t ap[6]  = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const uint8_t sta[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t f[kAuthFrameLen];

    const std::size_t len = buildAuthFrame(f, ap, sta);
    assert(len == kAuthFrameLen && len == 30u);
    // FC: management type, Authentication subtype (0xB0).
    assert(f[0] == 0xB0 && f[1] == 0x00);
    assert(f[2] == 0x00 && f[3] == 0x00);  // Duration
    for (std::size_t i = 0; i < 6; ++i) assert(f[4 + i] == ap[i]);    // addr1 DA = AP
    for (std::size_t i = 0; i < 6; ++i) assert(f[10 + i] == sta[i]);  // addr2 SA = STA
    for (std::size_t i = 0; i < 6; ++i) assert(f[16 + i] == ap[i]);   // addr3 BSSID = AP
    assert(f[22] == 0x00 && f[23] == 0x00);  // sequence control
    // Auth body: Open System (0), transaction seq 1, status 0 (all little-endian).
    assert(f[24] == 0x00 && f[25] == 0x00);  // algorithm = Open
    assert(f[26] == 0x01 && f[27] == 0x00);  // transaction seq = 1
    assert(f[28] == 0x00 && f[29] == 0x00);  // status = 0
}

void testBuildAssocRequest() {
    const uint8_t ap[6]  = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    const uint8_t sta[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const char ssid[] = "Lab";
    uint8_t f[kMaxAssocReqLen];

    const std::size_t len = buildAssocRequest(f, ap, sta, ssid, 3u);
    // 24 hdr + 2 cap + 2 listen + (2+3) SSID + (2+4) rates + (2+20) RSN = 61
    assert(len == 61u);
    assert(f[0] == 0x00 && f[1] == 0x00);  // FC: Association Request
    for (std::size_t i = 0; i < 6; ++i) assert(f[4 + i] == ap[i]);    // addr1 = AP
    for (std::size_t i = 0; i < 6; ++i) assert(f[10 + i] == sta[i]);  // addr2 = STA
    // Capability info (ESS|Privacy) + listen interval.
    assert(f[24] == 0x11 && f[25] == 0x00);
    assert(f[26] == 0x0A && f[27] == 0x00);
    // SSID element: tag 0, len 3, "Lab".
    assert(f[28] == 0x00 && f[29] == 0x03);
    assert(f[30] == 'L' && f[31] == 'a' && f[32] == 'b');
    // Supported rates element: tag 1, len 4.
    assert(f[33] == 0x01 && f[34] == 0x04);
    // RSN element: tag 48, len 20, version 1, with the PSK AKM suite 00-0F-AC-02 at the end.
    assert(f[39] == 0x30 && f[40] == 0x14);
    assert(f[41] == 0x01 && f[42] == 0x00);           // RSN version 1
    assert(f[len - 6] == 0x00 && f[len - 5] == 0x0F && // AKM OUI 00-0F-AC
           f[len - 4] == 0xAC && f[len - 3] == 0x02);  // AKM type PSK
    assert(f[len - 2] == 0x00 && f[len - 1] == 0x00);  // RSN capabilities

    // SSID length is clamped to 32 so an over-long SSID can never overflow the element.
    char longSsid[40];
    for (char& c : longSsid) c = 'x';
    const std::size_t lenC = buildAssocRequest(f, ap, sta, longSsid, sizeof(longSsid));
    assert(f[29] == 32u);                 // SSID element length clamped
    assert(lenC == 24u + 4u + 2u + 32u + 6u + 22u);
}

void testRandomStaMac() {
    uint8_t a[6];
    uint8_t b[6];
    randomStaMac(a, 0u);
    randomStaMac(b, 0u);
    // Deterministic for a given seed.
    for (std::size_t i = 0; i < 6; ++i) assert(a[i] == b[i]);
    // Locally-administered (bit 0x02 set) and unicast (bit 0x01 clear) — never a real STA.
    assert((a[0] & 0x02u) == 0x02u);
    assert((a[0] & 0x01u) == 0x00u);
    // Different seeds yield different MACs.
    uint8_t c[6];
    randomStaMac(c, 0xABCD1234u);
    bool differs = false;
    for (std::size_t i = 0; i < 6; ++i) differs |= (c[i] != a[i]);
    assert(differs);
    // The LAA/unicast invariant holds regardless of seed.
    assert((c[0] & 0x03u) == 0x02u);
}

}  // namespace

int main() {
    testParseMac();
    testBroadcast();
    testBuildDeauthFrame();
    testBuildAuthFrame();
    testBuildAssocRequest();
    testRandomStaMac();
    std::cout << "dot11 frame-builder tests passed\n";
    return 0;
}
