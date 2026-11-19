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

}  // namespace

int main() {
    testParseMac();
    testBroadcast();
    testBuildDeauthFrame();
    std::cout << "dot11 frame-builder tests passed\n";
    return 0;
}
