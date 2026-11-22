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
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>

#if defined(__has_include)
#if __has_include(<BLEDevice.h>) && !defined(ZD_NO_ESP32_BLE)
#include <BLEDevice.h>
#include <BLEScan.h>
#define ZD_HAS_ESP32_BLE 1
#endif
#endif

#include <atomic>
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
        lastBssids_.clear();
        lastBssids_.reserve(static_cast<std::size_t>(status));
        for (int16_t i = 0; i < status; ++i) {
            networks.push_back(zd::AccessPoint{
                std::string(WiFi.SSID(i).c_str()),
                static_cast<int32_t>(WiFi.RSSI(i)),
                static_cast<int32_t>(WiFi.channel(i)),
                WiFi.encryptionType(i) != WIFI_AUTH_OPEN
            });
            lastBssids_.push_back(std::string(WiFi.BSSIDstr(i).c_str()));
        }
        lastNetworks_ = networks;
        return {zd::hal::ScanPollState::Completed, std::move(networks)};
    }

    const std::vector<zd::AccessPoint>& lastNetworks() const { return lastNetworks_; }
    const std::vector<std::string>& lastBssids() const { return lastBssids_; }

    void clearScan() override {
        WiFi.scanDelete();
    }

private:
    std::vector<zd::AccessPoint> lastNetworks_{};
    std::vector<std::string> lastBssids_{};
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

    bool loadAudioMuted() override {
        return ready_ ? prefs_.getBool("muted", false) : false;
    }

    void saveAudioMuted(bool muted) override {
        if (!ready_) {
            return;
        }
        prefs_.putBool("muted", muted);
    }

    std::vector<std::string> loadTrustedBssids() override {
        std::vector<std::string> out;
        if (!ready_) {
            return out;
        }
        const std::string raw(prefs_.getString("trusted", "").c_str());
        std::size_t start = 0u;
        while (start < raw.size()) {
            const std::size_t sep = raw.find(',', start);
            const std::string item =
                (sep == std::string::npos) ? raw.substr(start) : raw.substr(start, sep - start);
            if (!item.empty()) {
                out.push_back(item);
            }
            if (sep == std::string::npos) {
                break;
            }
            start = sep + 1u;
        }
        return out;
    }

    void saveTrustedBssids(const std::vector<std::string>& bssids) override {
        if (!ready_) {
            return;
        }
        std::string joined;
        for (std::size_t i = 0u; i < bssids.size(); ++i) {
            if (i > 0u) joined.push_back(',');
            joined += bssids[i];
        }
        prefs_.putString("trusted", joined.c_str());
    }

private:
    Preferences prefs_;
    bool ready_ = false;
};

// Optional CC1101 Sub-GHz transceiver over SPI (315 / 433.92 / 868.35 / 915 MHz).
class Esp32Cc1101SubGhz final : public zd::hal::ISubGhzRadio {
public:
    bool init(int8_t sckPin = -1, int8_t misoPin = -1, int8_t mosiPin = -1, int8_t csPin = -1,
              int8_t gdo0Pin = -1, SPIClass* spi = &SPI) {
        if (csPin < 0 || spi == nullptr) {
            detected_ = false;
            return false;
        }
        spi_ = spi;
        csPin_ = csPin;
        gdo0Pin_ = gdo0Pin;
        pinMode(csPin_, OUTPUT);
        digitalWrite(csPin_, HIGH);
        if (gdo0Pin_ >= 0) {
            pinMode(gdo0Pin_, INPUT);
        }
        if (sckPin >= 0 && misoPin >= 0 && mosiPin >= 0) {
            spi_->begin(sckPin, misoPin, mosiPin, csPin_);
        } else {
            spi_->begin();
        }
        // Reset CC1101 strobe (0x30) and probe PARTNUM/VERSION (0x31 | 0xC0)
        strobe(0x30u);
        delay(2);
        const uint8_t ver = readReg(0x31u | 0xC0u);
        detected_ = (ver == 0x14u || ver == 0x04u);
        if (detected_) {
            configureRxModem();
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
        strobe(0x36u);  // SIDLE before synthesizer retune
        // 26 MHz crystal tuning word: freqWord = (freqHz * 65536) / 26000000
        const uint64_t word = (static_cast<uint64_t>(freqKhz) * 1000ull * 65536ull) / 26000000ull;
        writeReg(0x0Du, static_cast<uint8_t>((word >> 16u) & 0xFFu));
        writeReg(0x0Eu, static_cast<uint8_t>((word >> 8u) & 0xFFu));
        writeReg(0x0Fu, static_cast<uint8_t>(word & 0xFFu));
        strobe(0x33u);  // SCAL manual synth calibration
        delay(1);
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
    void configureRxModem() {
        writeReg(0x02u, 0x0Du);  // IOCFG0: asynchronous serial data output on GDO0
        writeReg(0x08u, 0x32u);  // PKTCTRL0: async serial RX, infinite packet length
        writeReg(0x0Bu, 0x06u);  // FSCTRL1: IF = 152.34 kHz
        writeReg(0x10u, 0x67u);  // MDMCFG4: ~270 kHz RX filter BW, ~4.8 kBaud
        writeReg(0x11u, 0x83u);  // MDMCFG3: data rate mantissa
        writeReg(0x12u, 0x30u);  // MDMCFG2: ASK/OOK modulation, no preamble/sync gate
        writeReg(0x18u, 0x18u);  // MCSM0: auto-calibrate on IDLE->RX/TX transitions
        writeReg(0x1Bu, 0x07u);  // AGCCTRL2
        writeReg(0x1Cu, 0x00u);  // AGCCTRL1
        writeReg(0x1Du, 0x91u);  // AGCCTRL0
    }

    void strobe(uint8_t cmd) {
        spi_->beginTransaction(SPISettings(4000000u, MSBFIRST, SPI_MODE0));
        digitalWrite(csPin_, LOW);
        spi_->transfer(cmd);
        digitalWrite(csPin_, HIGH);
        spi_->endTransaction();
    }

    uint8_t readReg(uint8_t addr) {
        spi_->beginTransaction(SPISettings(4000000u, MSBFIRST, SPI_MODE0));
        digitalWrite(csPin_, LOW);
        spi_->transfer(addr);
        const uint8_t v = spi_->transfer(0x00u);
        digitalWrite(csPin_, HIGH);
        spi_->endTransaction();
        return v;
    }

    void writeReg(uint8_t addr, uint8_t val) {
        spi_->beginTransaction(SPISettings(4000000u, MSBFIRST, SPI_MODE0));
        digitalWrite(csPin_, LOW);
        spi_->transfer(addr);
        spi_->transfer(val);
        digitalWrite(csPin_, HIGH);
        spi_->endTransaction();
    }

    SPIClass* spi_ = &SPI;
    int8_t csPin_ = -1;
    int8_t gdo0Pin_ = -1;
    bool detected_ = false;
    uint32_t freqKhz_ = 433920u;
    uint32_t lastPollMs_ = 0u;
    uint32_t streak_ = 0u;
};

// Optional non-blocking ESP32 BLE advertisement scanner (FindMy/AirTag/SmartTag/Tile & multi-tool).
class Esp32BleScanner final : public zd::hal::IBleScanner {
public:
    static constexpr uint32_t kMinFreeHeapBytes = 90000u;

    Esp32BleScanner() = default;
    Esp32BleScanner(const Esp32BleScanner&) = delete;
    Esp32BleScanner& operator=(const Esp32BleScanner&) = delete;

    bool init() {
#ifdef ZD_HAS_ESP32_BLE
        if (mutex_ == nullptr) {
            mutex_ = xSemaphoreCreateMutex();
        }
        if (esp_get_free_heap_size() <= kMinFreeHeapBytes) {
            ready_ = false;
            return false;
        }
        BLEDevice::init("");
        scan_ = BLEDevice::getScan();
        if (scan_ != nullptr && mutex_ != nullptr) {
            scan_->setActiveScan(false);  // passive listen-only BLE scan
            scan_->setInterval(120);
            scan_->setWindow(60);
            ready_ = true;
        }
#endif
        return ready_;
    }

    void setEnabled(bool enabled) { enabled_.store(enabled, std::memory_order_release); }
    bool isEnabled() const { return enabled_.load(std::memory_order_acquire); }
    bool available() const override { return ready_ && enabled_.load(std::memory_order_acquire); }

    std::vector<zd::BleDevice> pollBleDevices(uint32_t nowMs) override {
        std::vector<zd::BleDevice> out;
#ifdef ZD_HAS_ESP32_BLE
        if (!ready_ || !enabled_.load(std::memory_order_acquire) || scan_ == nullptr ||
            mutex_ == nullptr) {
            return out;
        }
        bool busy = false;
        if (xSemaphoreTake(mutex_, 0) == pdTRUE) {
            if (hasPending_) {
                out.swap(pending_);
                hasPending_ = false;
            }
            busy = workerRunning_;
            xSemaphoreGive(mutex_);
        } else {
            return out;
        }
        if (!busy && (nowMs - lastScanMs_) >= 8000u &&
            esp_get_free_heap_size() > kMinFreeHeapBytes) {
            lastScanMs_ = nowMs;
            if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(5)) == pdTRUE) {
                workerRunning_ = true;
                xSemaphoreGive(mutex_);
                if (xTaskCreate(&Esp32BleScanner::scanTaskEntry, "zd_ble", 4096u, this, 1,
                                nullptr) != pdPASS) {
                    if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(5)) == pdTRUE) {
                        workerRunning_ = false;
                        xSemaphoreGive(mutex_);
                    }
                }
            }
        }
#else
        (void)nowMs;
#endif
        return out;
    }

private:
#ifdef ZD_HAS_ESP32_BLE
    static void scanTaskEntry(void* arg) {
        auto* self = static_cast<Esp32BleScanner*>(arg);
        if (self != nullptr) {
            self->runWorkerScan();
        }
        vTaskDelete(nullptr);
    }

    void runWorkerScan() {
        std::vector<zd::BleDevice> batch;
        if (scan_ != nullptr && enabled_.load(std::memory_order_acquire) &&
            esp_get_free_heap_size() > kMinFreeHeapBytes) {
            BLEScanResults results = scan_->start(1, false);
            const int n = results.getCount();
            batch.reserve(static_cast<std::size_t>(n > 0 ? n : 0));
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
                const uint16_t svcUuid = zd::extractBle16ServiceUuid(
                    dev.getPayload(), static_cast<std::size_t>(dev.getPayloadLength()));
                const zd::BleThreatKind threat =
                    zd::classifyBleDevice(mac, name, companyId, svcUuid, trackerPayload);
                batch.push_back(
                    zd::BleDevice{mac, name, rssi, companyId, svcUuid, trackerPayload, threat});
            }
            scan_->clearResults();
        }
        if (mutex_ != nullptr && xSemaphoreTake(mutex_, pdMS_TO_TICKS(50)) == pdTRUE) {
            if (!batch.empty()) {
                pending_ = std::move(batch);
                hasPending_ = true;
            }
            workerRunning_ = false;
            xSemaphoreGive(mutex_);
        }
    }

    BLEScan* scan_ = nullptr;
    SemaphoreHandle_t mutex_ = nullptr;
    std::vector<zd::BleDevice> pending_{};
    bool hasPending_ = false;
    bool workerRunning_ = false;
    uint32_t lastScanMs_ = 0u;
#endif
    std::atomic<bool> enabled_{true};
    bool ready_ = false;
};

}  // namespace esp32_common
}  // namespace zd
