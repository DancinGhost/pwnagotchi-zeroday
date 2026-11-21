#pragma once

// Shared Arduino-ESP32 Hardware Adapters for `zd::hal` contracts.
//
// Used across all ESP32 / ESP32-S3 targets (M5StickC, M5StickC Plus/Plus2, M5Stack Core2,
// LILYGO T-Deck / T-Deck Plus, CYD ESP32-2432S028) so radio scanning and NVS flash
// persistence live in one place.

#include <Arduino.h>
#include <Preferences.h>
#include <SPI.h>
#include <WiFi.h>

#if defined(__has_include)
#if __has_include(<BLEDevice.h>) && !defined(ZD_NO_ESP32_BLE)
#include <BLEDevice.h>
#include <BLEScan.h>
#define ZD_HAS_ESP32_BLE 1
#endif
#endif

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "zd/hal.hpp"
#include "zd/wifi_analysis.hpp"

namespace zd {
namespace esp32_common {

class Esp32WifiScanner final : public zd::hal::IRadioScanner {
public:
    void init() {
        WiFi.mode(WIFI_STA);
        WiFi.disconnect(true, true);
    }

    bool startAsyncScan() override {
        // Strictly passive listen-only scan (no 802.11 probe requests transmitted).
        const int16_t rc = WiFi.scanNetworks(
            /*async=*/true, /*show_hidden=*/true, /*passive=*/true, /*max_ms_per_chan=*/360);
        return (rc == WIFI_SCAN_RUNNING || rc >= 0);
    }

    zd::hal::ScanPollResult pollScan() override {
        const int16_t status = WiFi.scanComplete();
        if (status == WIFI_SCAN_RUNNING) {
            return {zd::hal::ScanPollState::Running, {}};
        }
        if (status < 0) {
            return {zd::hal::ScanPollState::Failed, {}};
        }
        std::vector<zd::AccessPoint> networks;
        networks.reserve(static_cast<std::size_t>(status));
        for (int16_t i = 0; i < status; ++i) {
            networks.push_back(zd::AccessPoint{
                std::string(WiFi.SSID(i).c_str()),
                static_cast<int32_t>(WiFi.RSSI(i)),
                static_cast<int32_t>(WiFi.channel(i)),
                WiFi.encryptionType(i) != WIFI_AUTH_OPEN
            });
        }
        return {zd::hal::ScanPollState::Completed, std::move(networks)};
    }

    void clearScan() override {
        WiFi.scanDelete();
    }
};

class NvsThemeStore final : public zd::hal::IThemeStore {
public:
    void init() {
        ready_ = prefs_.begin("zeroday", /*readOnly=*/false);
    }

    std::string loadThemeKey() override {
        if (!ready_) {
            return {};
        }
        return std::string(prefs_.getString("theme", "").c_str());
    }

    void saveThemeKey(std::string_view key) override {
        if (!ready_) {
            return;
        }
        const std::string owned(key);
        prefs_.putString("theme", owned.c_str());
    }

    uint32_t loadHighScore() override {
        if (!ready_) {
            return 0u;
        }
        return static_cast<uint32_t>(prefs_.getULong("hiscore", 0u));
    }

    void saveHighScore(uint32_t score) override {
        if (!ready_) {
            return;
        }
        prefs_.putULong("hiscore", static_cast<unsigned long>(score));
    }

private:
    Preferences prefs_;
    bool ready_ = false;
};

// Optional CC1101 Sub-GHz transceiver over SPI (315 / 433.92 / 868.35 / 915 MHz).
class Esp32Cc1101SubGhz final : public zd::hal::ISubGhzRadio {
public:
    bool init(int8_t sckPin = -1, int8_t misoPin = -1, int8_t mosiPin = -1, int8_t csPin = -1,
              int8_t gdo0Pin = -1) {
        if (csPin < 0) {
            detected_ = false;
            return false;
        }
        csPin_ = csPin;
        gdo0Pin_ = gdo0Pin;
        pinMode(csPin_, OUTPUT);
        digitalWrite(csPin_, HIGH);
        if (gdo0Pin_ >= 0) {
            pinMode(gdo0Pin_, INPUT);
        }
        if (sckPin >= 0 && misoPin >= 0 && mosiPin >= 0) {
            SPI.begin(sckPin, misoPin, mosiPin, csPin_);
        } else {
            SPI.begin();
        }
        // Reset CC1101 strobe (0x30) and probe PARTNUM/VERSION (0x31 | 0xC0)
        strobe(0x30u);
        delay(2);
        const uint8_t ver = readReg(0x31u | 0xC0u);
        detected_ = (ver == 0x14u || ver == 0x04u);
        if (detected_) {
            tuneFrequency(freqKhz_);
        }
        return detected_;
    }

    bool available() const override { return detected_; }

    bool tuneFrequency(uint32_t freqKhz) override {
        freqKhz_ = freqKhz;
        if (!detected_) {
            return false;
        }
        // 26 MHz crystal tuning word: freqWord = (freqHz * 65536) / 26000000
        const uint64_t word = (static_cast<uint64_t>(freqKhz) * 1000ull * 65536ull) / 26000000ull;
        writeReg(0x0Du, static_cast<uint8_t>((word >> 16u) & 0xFFu));
        writeReg(0x0Eu, static_cast<uint8_t>((word >> 8u) & 0xFFu));
        writeReg(0x0Fu, static_cast<uint8_t>(word & 0xFFu));
        strobe(0x34u);  // SRX
        return true;
    }

    uint32_t frequencyKhz() const override { return freqKhz_; }

    std::optional<zd::SubGhzSignal> pollSignal(uint32_t nowMs) override {
        if (!detected_ || (nowMs - lastPollMs_) < 250u) {
            return std::nullopt;
        }
        lastPollMs_ = nowMs;
        const uint8_t rawRssi = readReg(0x34u | 0xC0u);
        const int16_t signedRssi = (rawRssi >= 128u) ? (static_cast<int16_t>(rawRssi) - 256)
                                                     : static_cast<int16_t>(rawRssi);
        const int32_t rssiDbm = (signedRssi / 2) - 74;
        if (rssiDbm < -75) {
            streak_ = 0u;
            return std::nullopt;
        }
        ++streak_;
        zd::SubGhzSignal sig{};
        sig.freqKhz = freqKhz_;
        sig.rssi = rssiDbm;
        sig.protocol = "OOK/FSK";
        sig.burstCount = streak_;
        if (streak_ >= 12u) {
            sig.anomaly = zd::SubGhzAnomaly::JammingCarrier;
        } else if (streak_ >= 5u) {
            sig.anomaly = zd::SubGhzAnomaly::ReplayBurst;
        }
        return sig;
    }

private:
    void strobe(uint8_t cmd) {
        SPI.beginTransaction(SPISettings(4000000u, MSBFIRST, SPI_MODE0));
        digitalWrite(csPin_, LOW);
        SPI.transfer(cmd);
        digitalWrite(csPin_, HIGH);
        SPI.endTransaction();
    }

    uint8_t readReg(uint8_t addr) {
        SPI.beginTransaction(SPISettings(4000000u, MSBFIRST, SPI_MODE0));
        digitalWrite(csPin_, LOW);
        SPI.transfer(addr);
        const uint8_t v = SPI.transfer(0x00u);
        digitalWrite(csPin_, HIGH);
        SPI.endTransaction();
        return v;
    }

    void writeReg(uint8_t addr, uint8_t val) {
        SPI.beginTransaction(SPISettings(4000000u, MSBFIRST, SPI_MODE0));
        digitalWrite(csPin_, LOW);
        SPI.transfer(addr);
        SPI.transfer(val);
        digitalWrite(csPin_, HIGH);
        SPI.endTransaction();
    }

    int8_t csPin_ = -1;
    int8_t gdo0Pin_ = -1;
    bool detected_ = false;
    uint32_t freqKhz_ = 433920u;
    uint32_t lastPollMs_ = 0u;
    uint32_t streak_ = 0u;
};

// Optional ESP32 BLE advertisement scanner (detects FindMy/AirTag/Tile & multi-tool beacons).
class Esp32BleScanner final : public zd::hal::IBleScanner {
public:
    bool init() {
#ifdef ZD_HAS_ESP32_BLE
        BLEDevice::init("");
        scan_ = BLEDevice::getScan();
        if (scan_ != nullptr) {
            scan_->setActiveScan(false);  // passive listen-only BLE scan
            scan_->setInterval(120);
            scan_->setWindow(60);
            ready_ = true;
        }
#endif
        return ready_;
    }

    bool available() const override { return ready_; }

    std::vector<zd::BleDevice> pollBleDevices(uint32_t nowMs) override {
        std::vector<zd::BleDevice> out;
#ifdef ZD_HAS_ESP32_BLE
        if (!ready_ || scan_ == nullptr || (nowMs - lastScanMs_) < 8000u) {
            return out;
        }
        lastScanMs_ = nowMs;
        BLEScanResults results = scan_->start(1, false);
        const int n = results.getCount();
        for (int i = 0; i < n; ++i) {
            BLEAdvertisedDevice dev = results.getDevice(i);
            const std::string mac = dev.getAddress().toString();
            const std::string name = dev.haveName() ? dev.getName() : std::string{};
            const int32_t rssi = dev.getRSSI();
            uint16_t companyId = 0u;
            bool trackerPayload = false;
            if (dev.haveManufacturerData()) {
                const std::string mfg = dev.getManufacturerData();
                if (mfg.size() >= 2u) {
                    companyId = static_cast<uint16_t>(
                        static_cast<uint8_t>(mfg[0]) |
                        (static_cast<uint16_t>(static_cast<uint8_t>(mfg[1])) << 8u));
                    if (companyId == 0x004Cu && mfg.size() >= 4u &&
                        static_cast<uint8_t>(mfg[2]) == 0x12u) {
                        trackerPayload = true;
                    }
                    if (companyId == 0x0075u && mfg.size() >= 4u) {
                        trackerPayload = true;
                    }
                }
            }
            const zd::BleThreatKind threat =
                zd::classifyBleDevice(mac, name, companyId, 0u, trackerPayload);
            out.push_back(zd::BleDevice{mac, name, rssi, companyId, 0u, trackerPayload, threat});
        }
        scan_->clearResults();
#else
        (void)nowMs;
#endif
        return out;
    }

private:
#ifdef ZD_HAS_ESP32_BLE
    BLEScan* scan_ = nullptr;
    uint32_t lastScanMs_ = 0u;
#endif
    bool ready_ = false;
};

}  // namespace esp32_common
}  // namespace zd
