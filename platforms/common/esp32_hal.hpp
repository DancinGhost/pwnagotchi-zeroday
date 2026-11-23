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
#include <esp_wifi.h>
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
#include "zd/peering.hpp"
#include "zd/wifi_analysis.hpp"
#include "esp32_defensive.hpp"

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
            inBurst_ = false;
            return std::nullopt;
        }
        ++streak_;
        const bool risingEdge = !inBurst_;
        const bool escalated = (streak_ == 5u || streak_ == 12u);
        const bool periodicRefresh = (nowMs - lastReportMs_) >= 2000u;
        if (!risingEdge && !escalated && !periodicRefresh) {
            return std::nullopt;
        }
        inBurst_ = true;
        lastReportMs_ = nowMs;
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
    uint32_t lastReportMs_ = 0u;
    uint32_t streak_ = 0u;
    bool inBurst_ = false;
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
        if (triggerSem_ == nullptr) {
            triggerSem_ = xSemaphoreCreateBinary();
        }
        if (esp_get_free_heap_size() <= kMinFreeHeapBytes) {
            ready_ = false;
            return false;
        }
        BLEDevice::init("");
        scan_ = BLEDevice::getScan();
        if (scan_ != nullptr && mutex_ != nullptr && triggerSem_ != nullptr) {
            scan_->setActiveScan(false);  // passive listen-only BLE scan
            scan_->setInterval(120);
            scan_->setWindow(60);
            if (workerTask_ == nullptr) {
                if (xTaskCreate(&Esp32BleScanner::scanTaskLoop, "zd_ble", 4096u, this, 1,
                                &workerTask_) != pdPASS) {
                    workerTask_ = nullptr;
                }
            }
            ready_ = (workerTask_ != nullptr);
        }
#endif
        return ready_;
    }

    void setEnabled(bool enabled) { enabled_.store(enabled, std::memory_order_release); }
    bool isEnabled() const { return enabled_.load(std::memory_order_acquire); }
    bool available() const override { return ready_ && enabled_.load(std::memory_order_acquire); }

    void requestScanNow() {
        forceScan_.store(true, std::memory_order_release);
#ifdef ZD_HAS_ESP32_BLE
        if (!ready_ || !enabled_.load(std::memory_order_acquire) || scan_ == nullptr ||
            mutex_ == nullptr || triggerSem_ == nullptr ||
            esp_get_free_heap_size() <= kMinFreeHeapBytes) {
            return;
        }
        bool triggered = false;
        if (xSemaphoreTake(mutex_, 0) == pdTRUE) {
            if (!workerRunning_) {
                workerRunning_ = true;
                forceScan_.store(false, std::memory_order_release);
                triggered = true;
            }
            xSemaphoreGive(mutex_);
        }
        if (triggered) {
            xSemaphoreGive(triggerSem_);
        }
#endif
    }

    std::vector<zd::BleDevice> pollBleDevices(uint32_t nowMs) override {
        std::vector<zd::BleDevice> out;
#ifdef ZD_HAS_ESP32_BLE
        if (!ready_ || !enabled_.load(std::memory_order_acquire) || scan_ == nullptr ||
            mutex_ == nullptr || triggerSem_ == nullptr) {
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
        const bool due = forceScan_.load(std::memory_order_acquire) ||
                         ((nowMs - lastScanMs_) >= 8000u);
        if (!busy && due && esp_get_free_heap_size() > kMinFreeHeapBytes) {
            bool triggered = false;
            if (xSemaphoreTake(mutex_, pdMS_TO_TICKS(5)) == pdTRUE) {
                if (!workerRunning_) {
                    workerRunning_ = true;
                    forceScan_.store(false, std::memory_order_release);
                    lastScanMs_ = nowMs;
                    triggered = true;
                }
                xSemaphoreGive(mutex_);
            }
            if (triggered) {
                xSemaphoreGive(triggerSem_);
            }
        }
#else
        (void)nowMs;
#endif
        return out;
    }

private:
#ifdef ZD_HAS_ESP32_BLE
    static void scanTaskLoop(void* arg) {
        auto* self = static_cast<Esp32BleScanner*>(arg);
        if (self == nullptr) {
            vTaskDelete(nullptr);
            return;
        }
        for (;;) {
            if (xSemaphoreTake(self->triggerSem_, portMAX_DELAY) == pdTRUE) {
                self->runWorkerScan();
            }
        }
    }

    void runWorkerScan() {
        std::vector<zd::BleDevice> batch;
        if (scan_ != nullptr && enabled_.load(std::memory_order_acquire) &&
            esp_get_free_heap_size() > kMinFreeHeapBytes) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
            BLEScanResults* resultsPtr = scan_->start(1, false);
            const int n = (resultsPtr != nullptr) ? resultsPtr->getCount() : 0;
#else
            BLEScanResults results = scan_->start(1, false);
            BLEScanResults* resultsPtr = &results;
            const int n = resultsPtr->getCount();
#endif
            batch.reserve(static_cast<std::size_t>(n > 0 ? n : 0));
            for (int i = 0; i < n; ++i) {
                BLEAdvertisedDevice dev = resultsPtr->getDevice(i);
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
                const auto addrVal = dev.getAddress().toString();
                const std::string mac(addrVal.c_str(), addrVal.length());
                std::string name;
                if (dev.haveName()) {
                    const auto nameVal = dev.getName();
                    name.assign(nameVal.c_str(), nameVal.length());
                }
#else
                const std::string mac = dev.getAddress().toString();
                const std::string name = dev.haveName() ? dev.getName() : std::string{};
#endif
                const int32_t rssi = dev.getRSSI();
                uint16_t companyId = 0u;
                bool trackerPayload = false;
                if (dev.haveManufacturerData()) {
#if defined(ESP_ARDUINO_VERSION_MAJOR) && ESP_ARDUINO_VERSION_MAJOR >= 3
                    const auto mfgVal = dev.getManufacturerData();
                    const std::string mfg(mfgVal.c_str(), mfgVal.length());
#else
                    const std::string mfg = dev.getManufacturerData();
#endif
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
    SemaphoreHandle_t triggerSem_ = nullptr;
    TaskHandle_t workerTask_ = nullptr;
    std::vector<zd::BleDevice> pending_{};
    bool hasPending_ = false;
    bool workerRunning_ = false;
    uint32_t lastScanMs_ = 0u;
#endif
    std::atomic<bool> forceScan_{false};
    std::atomic<bool> enabled_{true};
    bool ready_ = false;
};

// Opt-in BLE peer greeting: advertises THIS unit's presence as BLE manufacturer-specific data
// (zd::peer::buildZeroDayBleManufacturerData) so nearby ZeroDay units greet it over BLE.
// DISABLED by default. CRITICAL: it NEVER transmits while the pet is in Offensive ops mode —
// when offensive, advertising is force-stopped and refused (you do not beacon your presence
// while actively attacking). Coexists with the passive BLE scanner (both use BLEDevice).
class Esp32PeerBleAdvertiser {
public:
    void setEnabled(bool on) { enabled_ = on; }
    bool enabled() const { return enabled_; }
    // True only when the radio is currently advertising (enabled, not offensive, started OK).
    bool advertising() const { return advertising_; }

    // Reconcile advertising state against the desired advert and the current ops mode.
    // `offensiveMode` true => stop and refuse to transmit, regardless of `enabled()`.
    void sync(const zd::peer::PeerAdvert& advert, bool offensiveMode) {
#ifdef ZD_HAS_ESP32_BLE
        if (offensiveMode || !enabled_) {
            stop();
            return;
        }
        const std::vector<uint8_t> mfg = zd::peer::buildZeroDayBleManufacturerData(advert);
        const uint32_t h = fnv1a(mfg);
        if (advertising_ && h == lastHash_) {
            return;  // already advertising the current advert; nothing to do
        }
        if (!ensureInit()) {
            return;
        }
        BLEAdvertising* adv = BLEDevice::getAdvertising();
        if (adv == nullptr) {
            return;
        }
        if (advertising_) {
            adv->stop();
        }
        BLEAdvertisementData data;
        data.setFlags(0x06);  // LE General Discoverable + BR/EDR not supported
        data.setManufacturerData(std::string(reinterpret_cast<const char*>(mfg.data()), mfg.size()));
        adv->setAdvertisementData(data);
        adv->start();
        advertising_ = true;
        lastHash_ = h;
#else
        (void)advert;
        (void)offensiveMode;
#endif
    }

    void stop() {
#ifdef ZD_HAS_ESP32_BLE
        if (advertising_) {
            BLEAdvertising* adv = BLEDevice::getAdvertising();
            if (adv != nullptr) {
                adv->stop();
            }
            advertising_ = false;
        }
#endif
    }

private:
#ifdef ZD_HAS_ESP32_BLE
    bool ensureInit() {
        if (!inited_) {
            BLEDevice::init("");  // idempotent; the scanner may already have initialized BLE
            inited_ = true;
        }
        return true;
    }
    static uint32_t fnv1a(const std::vector<uint8_t>& b) {
        uint32_t h = 0x811C9DC5u;
        for (uint8_t x : b) {
            h ^= x;
            h *= 0x01000193u;
        }
        return h;
    }
    bool inited_ = false;
#endif
    bool enabled_ = false;
    bool advertising_ = false;
    uint32_t lastHash_ = 0u;
};

// Promiscuous 802.11 defensive monitor adapter for ESP32 / ESP32-S3.
// Captures management (beacons, deauth/disassoc, action CSA) and unencrypted data (EAPOL M1..M4)
// frames in real time via `esp_wifi_set_promiscuous_rx_cb` and drains them on the main loop.
class Esp32PromiscuousMonitor {
public:
    void init(uint8_t startChannel = 1u) {
        instance_ = this;
        channel_ = (startChannel >= 1u && startChannel <= 13u) ? startChannel : 1u;
        setEnabled(true);
    }

    bool setEnabled(bool on) {
        core_.setEnabled(on);
        if (on) {
            instance_ = this;
            wifi_promiscuous_filter_t filter{};
            filter.filter_mask =
                WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
            esp_wifi_set_promiscuous_filter(&filter);
            esp_wifi_set_promiscuous_rx_cb(&Esp32PromiscuousMonitor::onPromiscuousRx);
            return esp_wifi_set_promiscuous(true) == ESP_OK;
        }
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(nullptr);
        return true;
    }

    bool isEnabled() const { return core_.enabled(); }

    void setAutoHop(bool on) { autoHop_ = on; }
    bool autoHop() const { return autoHop_; }
    uint8_t currentChannel() const { return channel_; }

    uint32_t step(uint32_t nowMs,
                  zd::sec::SecSession& sec,
                  zd::hal::PlatformSession* pet = nullptr,
                  zd::hal::IThemeStore* themeStore = nullptr) {
        const uint32_t decoded = core_.step(sec, nowMs, pet, themeStore);
        // Optionally sweep 2.4 GHz channels slowly while idle (never mid-scan).
        if (autoHop_ && core_.enabled() && WiFi.scanComplete() != WIFI_SCAN_RUNNING &&
            (nowMs - lastHopMs_) >= 350u) {
            // Full 2.4 GHz coverage (1-13): primaries 1/6/11 first so they're
            // over-sampled, then every remaining channel so APs parked on 4/5/9/10
            // (previously skipped entirely) are still swept.
            static constexpr uint8_t kHopChans[] = {1u, 6u,  11u, 2u, 7u, 12u, 3u,
                                                    8u, 13u, 4u,  9u, 5u, 10u};
            hopIdx_ = (hopIdx_ + 1u) % (sizeof(kHopChans) / sizeof(kHopChans[0]));
            channel_ = kHopChans[hopIdx_];
            esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
            lastHopMs_ = nowMs;
        }
        return decoded;
    }

    // Handle `defmon [on|off]` serial command; returns empty string if unrelated.
    std::string handleCommand(const std::string& line, const zd::sec::SecState& st) {
        if (line == "defmon on") {
            setEnabled(true);
            return "Defensive monitor: ON (promiscuous MGMT+DATA active)\n";
        }
        if (line == "defmon off") {
            setEnabled(false);
            return "Defensive monitor: OFF\n";
        }
        if (line == "defmon hop on") {
            autoHop_ = true;
            return "Defensive monitor channel-hop: ON\n";
        }
        if (line == "defmon hop off") {
            autoHop_ = false;
            return "Defensive monitor channel-hop: OFF\n";
        }
        if (line == "defmon") {
            return core_.formatStatus(st);
        }
        return {};
    }

    Esp32DefensiveMonitorCore& core() { return core_; }
    const Esp32DefensiveMonitorCore& core() const { return core_; }

private:
    static void onPromiscuousRx(void* buf, wifi_promiscuous_pkt_type_t type) {
        Esp32PromiscuousMonitor* self = instance_;
        if (self == nullptr || buf == nullptr) {
            return;
        }
        if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
            return;
        }
        const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
        const std::size_t rawLen = static_cast<std::size_t>(pkt->rx_ctrl.sig_len);
        const std::size_t frameLen = (rawLen >= 28u) ? (rawLen - 4u) : rawLen;
        self->core_.enqueueFromIsr(pkt->payload, frameLen, pkt->rx_ctrl.rssi,
                                   static_cast<uint32_t>(millis()));
    }

    inline static Esp32PromiscuousMonitor* instance_ = nullptr;
    Esp32DefensiveMonitorCore core_{};
    // Default ON: a defensive monitor parked on channel 1 misses APs/attacks on all
    // other channels. step() still never hops mid-scan. Toggle via `defmon hop off`.
    bool autoHop_ = true;
    uint8_t channel_ = 1u;
    std::size_t hopIdx_ = 0u;
    uint32_t lastHopMs_ = 0u;
};

}  // namespace esp32_common
}  // namespace zd
