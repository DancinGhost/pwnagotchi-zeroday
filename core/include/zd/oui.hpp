#pragma once

// Compact offline IEEE OUI 24-bit MAC vendor lookup (zero-dep C++17, -fno-exceptions/-fno-rtti safe).
// Covers major WiFi, BLE, and embedded hardware chipset vendors via constexpr binary search.

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace zd {

struct OuiEntry {
    uint32_t prefix24;
    const char* vendor;
};

// Sorted strictly ascending by 24-bit prefix for O(log N) std::lower_bound lookup.
inline constexpr std::array<OuiEntry, 68> kOuiCatalog = {{
    {0x00000Cu, "Cisco"},
    {0x00037Fu, "Atheros"},
    {0x000393u, "Apple"},
    {0x000A95u, "Apple"},
    {0x000B86u, "Aruba"},
    {0x000C42u, "MikroTik"},
    {0x000CE7u, "MediaTek"},
    {0x000F00u, "Legra"},
    {0x001122u, "Cimsysen"},
    {0x001310u, "Linksys"},
    {0x00146Cu, "Netgear"},
    {0x00156Du, "Ubiquiti"},
    {0x0017F2u, "Apple"},
    {0x0018E7u, "Cameo"},
    {0x001A11u, "Google"},
    {0x001B21u, "Intel"},
    {0x001B63u, "Apple"},
    {0x001D7Eu, "Linksys"},
    {0x0024A5u, "Buffalo"},
    {0x00259Cu, "Linksys"},
    {0x002722u, "Ubiquiti"},
    {0x005056u, "VMware"},
    {0x0050F2u, "Microsoft"},
    {0x0080E1u, "STMicro"},
    {0x00C0CAu, "Alfa"},
    {0x00E04Cu, "Realtek"},
    {0x0418D6u, "Ubiquiti"},
    {0x080027u, "VirtualBox"},
    {0x18E829u, "Ubiquiti"},
    {0x240AC4u, "Espressif"},
    {0x2462ABu, "Espressif"},
    {0x24A43Cu, "Ubiquiti"},
    {0x286DCDu, "WinnerMicro"},
    {0x2C3AE8u, "Espressif"},
    {0x30AEA4u, "Espressif"},
    {0x3C71BFu, "Espressif"},
    {0x44D9E7u, "Ubiquiti"},
    {0x50C7BFu, "TP-Link"},
    {0x58BF25u, "Espressif"},
    {0x600194u, "Espressif"},
    {0x68C63Au, "Espressif"},
    {0x704D7Bu, "Asus"},
    {0x74DA38u, "Edimax"},
    {0x788A20u, "Ubiquiti"},
    {0x802AA8u, "Ubiquiti"},
    {0x84F3EBu, "Espressif"},
    {0x94B97Eu, "Espressif"},
    {0x98DED0u, "TP-Link"},
    {0xA020A6u, "Espressif"},
    {0xA4CF12u, "Espressif"},
    {0xAC67B2u, "Espressif"},
    {0xB0B98Au, "Netgear"},
    {0xB4E62Du, "Espressif"},
    {0xB827EBu, "RaspberryPi"},
    {0xBCFF4Du, "Espressif"},
    {0xC05627u, "Belkin"},
    {0xC46E1Fu, "TP-Link"},
    {0xCC50E3u, "Espressif"},
    {0xD83ADDu, "RaspberryPi"},
    {0xDC4F22u, "Espressif"},
    {0xDCA632u, "RaspberryPi"},
    {0xE09806u, "Espressif"},
    {0xE45F01u, "RaspberryPi"},
    {0xECFA5Cu, "Espressif"},
    {0xF09FC2u, "Ubiquiti"},
    {0xF4CFA2u, "Espressif"},
    {0xF8E903u, "Apple"},
    {0xFCECDAu, "Ubiquiti"},
}};

namespace detail {
constexpr bool isOuiCatalogSorted() {
    for (std::size_t i = 1u; i < kOuiCatalog.size(); ++i) {
        if (kOuiCatalog[i - 1u].prefix24 >= kOuiCatalog[i].prefix24) {
            return false;
        }
    }
    return true;
}
static_assert(isOuiCatalogSorted(), "kOuiCatalog must be strictly sorted ascending by prefix24");
}  // namespace detail

// Extract the first 6 hex nibbles from a MAC string (ignoring ':', '-', spaces) into a 24-bit OUI.
inline std::optional<uint32_t> parseOui24(std::string_view mac) {
    uint32_t prefix = 0u;
    std::size_t nibbles = 0u;
    for (char ch : mac) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (c == ':' || c == '-' || c == ' ' || c == '\t') {
            continue;
        }
        uint32_t nib = 0u;
        if (c >= '0' && c <= '9') {
            nib = static_cast<uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            nib = static_cast<uint32_t>(10 + (c - 'a'));
        } else if (c >= 'A' && c <= 'F') {
            nib = static_cast<uint32_t>(10 + (c - 'A'));
        } else {
            return std::nullopt;
        }
        prefix = (prefix << 4u) | nib;
        ++nibbles;
        if (nibbles == 6u) {
            return prefix;
        }
    }
    return std::nullopt;
}

inline const char* lookupOuiVendor(std::string_view mac) {
    const std::optional<uint32_t> oui = parseOui24(mac);
    if (!oui.has_value()) {
        return "";
    }
    const auto it = std::lower_bound(
        kOuiCatalog.begin(), kOuiCatalog.end(), *oui,
        [](const OuiEntry& entry, uint32_t target) { return entry.prefix24 < target; });
    if (it != kOuiCatalog.end() && it->prefix24 == *oui) {
        return it->vendor;
    }
    return "";
}

// True if the first octet's locally-administered bit (0x02) is set: a randomized /
// locally-administered MAC (iOS/Android privacy MACs, most BLE-spam adverts). These have no
// real IEEE vendor assignment, so flagging them declutters the Stations/Probes view and is a
// rogue-AP signal when such a MAC impersonates a real access point.
inline bool isLocallyAdministeredMac(std::string_view mac) {
    const std::optional<uint32_t> oui = parseOui24(mac);
    if (!oui.has_value()) {
        return false;
    }
    return ((((*oui) >> 16u) & 0xFFu) & 0x02u) != 0u;
}

// True when both MACs resolve to the SAME known IEEE vendor. Correctly treats a vendor's
// many OUIs as one (e.g. two different Ubiquiti prefixes match). False if either side is
// unknown or randomized — callers must not infer "different vendor" from a false return.
inline bool sameOuiVendor(std::string_view a, std::string_view b) {
    const char* va = lookupOuiVendor(a);
    const char* vb = lookupOuiVendor(b);
    if (va[0] == '\0' || vb[0] == '\0') {
        return false;
    }
    return std::string_view(va) == std::string_view(vb);
}

// True only when both MACs resolve to known vendors AND those vendors differ — a positive
// rogue/evil-twin signal (unlike sameOuiVendor's conservative negatives).
inline bool differentKnownOuiVendor(std::string_view a, std::string_view b) {
    const char* va = lookupOuiVendor(a);
    const char* vb = lookupOuiVendor(b);
    return va[0] != '\0' && vb[0] != '\0' && std::string_view(va) != std::string_view(vb);
}

inline std::string ouiVendorLabel(std::string_view mac, const char* fallback = "-") {
    const char* v = lookupOuiVendor(mac);
    if (v != nullptr && v[0] != '\0') {
        return std::string(v);
    }
    if (isLocallyAdministeredMac(mac)) {
        return "random";  // randomized/private MAC: no IEEE vendor to resolve
    }
    return std::string(fallback != nullptr ? fallback : "-");
}

}  // namespace zd
