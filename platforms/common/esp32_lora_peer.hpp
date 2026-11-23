#pragma once

// Opt-in, compile-gated SX1262 LoRa peer transceiver for the LILYGO T-Deck.
//
// Periodically broadcasts THIS unit's advert as a ZeroDay LoRa packet
// (zd::peer::buildZeroDayLoraPacket) and non-blocking-receives packets from other ZeroDay units
// up to km away, feeding them into the shared PeerRegistry and giving the pet a PeerSpotted
// social moment. This is the long-range transport for team WIDS alert sharing
// (zd::peer::kFlagWidsAlert).
//
// COMPILED OFF BY DEFAULT: the whole radio driver is behind ZD_WITH_LORA (set only by the
// dedicated `t-deck-lora` PlatformIO env), mirroring the compiled-off-by-default pattern of the
// ESP32 offensive path. Reasons: (1) the SX1262 shares the T-Deck's SPI bus with the ST7789 LCD
// and the MicroSD card, so enabling it needs careful bus arbitration that must be validated on
// real hardware; (2) LoRa duty-cycle / frequency rules are region-specific (set kLoraFreqMHz for
// your locale). When the flag is off, Esp32LoraPeer is an inert no-op stub so the default
// firmware is byte-for-byte unchanged.
//
// NOTE: untested on hardware in this tree — the pure packet codec (zd::peer::*LoraPacket) is
// host-unit-tested; the RadioLib glue below is compile-verified only.

#include <cstdint>

#ifdef ZD_WITH_LORA
#include <RadioLib.h>
#include <SPI.h>
#endif

#include "zd/domain.hpp"
#include "zd/hal.hpp"
#include "zd/peering.hpp"

namespace zd {
namespace esp32_common {

#ifdef ZD_WITH_LORA

// T-Deck SX1262 wiring (shared VSPI/SPI2 bus with LCD + SD).
#ifndef ZD_LORA_PIN_SCK
#define ZD_LORA_PIN_SCK 40
#endif
#ifndef ZD_LORA_PIN_MISO
#define ZD_LORA_PIN_MISO 38
#endif
#ifndef ZD_LORA_PIN_MOSI
#define ZD_LORA_PIN_MOSI 41
#endif
#ifndef ZD_LORA_PIN_CS
#define ZD_LORA_PIN_CS 9
#endif
#ifndef ZD_LORA_PIN_DIO1
#define ZD_LORA_PIN_DIO1 45
#endif
#ifndef ZD_LORA_PIN_RST
#define ZD_LORA_PIN_RST 17
#endif
#ifndef ZD_LORA_PIN_BUSY
#define ZD_LORA_PIN_BUSY 13
#endif

class Esp32LoraPeer {
public:
    // Region-specific; override at build time (-DZD_LORA_FREQ=868.0 etc.).
#ifdef ZD_LORA_FREQ
    static constexpr float kLoraFreqMHz = ZD_LORA_FREQ;
#else
    static constexpr float kLoraFreqMHz = 915.0f;  // US ISM default
#endif
    static constexpr uint32_t kTxIntervalMs = 20000u;

    bool begin() {
        spi_.begin(ZD_LORA_PIN_SCK, ZD_LORA_PIN_MISO, ZD_LORA_PIN_MOSI, ZD_LORA_PIN_CS);
        const int st = radio_.begin(kLoraFreqMHz);
        if (st != RADIOLIB_ERR_NONE) {
            ready_ = false;
            return false;
        }
        radio_.setDio1Action(onDio1);
        ready_ = (radio_.startReceive() == RADIOLIB_ERR_NONE);
        return ready_;
    }

    void setEnabled(bool on) {
        enabled_ = on;
        if (on && !ready_) {
            begin();
        }
    }
    bool enabled() const { return enabled_ && ready_; }
    bool available() const { return ready_; }

    // Drain any received peer packets, then transmit our advert if the interval elapsed.
    void step(uint32_t nowMs, const zd::peer::PeerAdvert& advert, zd::peer::PeerRegistry& registry,
              zd::hal::PlatformSession* pet, zd::hal::IThemeStore* themeStore) {
        if (!enabled_ || !ready_) {
            return;
        }
        // --- RX: a DIO1 interrupt flagged a received packet ---
        if (rxFlag_) {
            rxFlag_ = false;
            uint8_t buf[64];
            const int len = radio_.readData(buf, sizeof(buf));
            if (len > 0) {
                const float rssi = radio_.getRSSI();
                if (const auto adv =
                        zd::peer::parseZeroDayLoraPacket(buf, static_cast<std::size_t>(len))) {
                    // LoRa packets carry no MAC; key the peer by advertised name (fallback below).
                    std::string id = adv->name.empty() ? std::string("lora-peer") : adv->name;
                    const bool firstGreeting =
                        registry.observe(id, zd::peer::PeerKind::ZeroDay,
                                         zd::peer::PeerTransport::Lora, static_cast<int32_t>(rssi),
                                         adv->name, adv->pwned,
                                         (adv->flags & zd::peer::kFlagWidsAlert) != 0u, nowMs);
                    if (firstGreeting && pet != nullptr) {
                        pet->dispatch(zd::PeerSpottedEvent{nowMs, adv->name,
                                                           static_cast<int32_t>(rssi)},
                                      themeStore);
                    }
                }
            }
            radio_.startReceive();  // re-arm RX
        }
        // --- TX: periodic greeting ---
        if (lastTxMs_ == 0u || (nowMs - lastTxMs_) >= kTxIntervalMs) {
            lastTxMs_ = (nowMs == 0u) ? 1u : nowMs;
            const std::vector<uint8_t> pkt = zd::peer::buildZeroDayLoraPacket(advert);
            radio_.transmit(const_cast<uint8_t*>(pkt.data()), pkt.size());
            radio_.startReceive();  // return to RX after the blocking transmit
        }
    }

private:
    // Flag-only DIO1 handler. Deliberately NOT IRAM_ATTR: it touches no flash and placing a
    // header-inline ISR in IRAM triggers an l32r "literal placed after use" link error on
    // Arduino-ESP32; the GPIO ISR dispatcher runs this fine from flash.
    static void onDio1() { rxFlag_ = true; }

    SPIClass spi_{HSPI};
    SX1262 radio_ = new Module(ZD_LORA_PIN_CS, ZD_LORA_PIN_DIO1, ZD_LORA_PIN_RST,
                               ZD_LORA_PIN_BUSY, spi_);
    bool enabled_ = false;
    bool ready_ = false;
    uint32_t lastTxMs_ = 0u;
    static volatile bool rxFlag_;
};

inline volatile bool Esp32LoraPeer::rxFlag_ = false;

#else  // !ZD_WITH_LORA — inert no-op stub

class Esp32LoraPeer {
public:
    bool begin() { return false; }
    void setEnabled(bool) {}
    bool enabled() const { return false; }
    bool available() const { return false; }
    void step(uint32_t, const zd::peer::PeerAdvert&, zd::peer::PeerRegistry&,
              zd::hal::PlatformSession*, zd::hal::IThemeStore*) {}
};

#endif  // ZD_WITH_LORA

}  // namespace zd::esp32_common
}  // namespace zd
