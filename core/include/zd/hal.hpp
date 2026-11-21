#pragma once

// Portable Hardware Abstraction Layer (HAL) & Session Coordinator.
//
// Zero OS or SDK headers live here. A new hardware target (ESP32 board, RP2040 Pico W,
// Linux SBC + e-Paper HAT, desktop app) implements the tiny adapter interfaces below —
// or uses the standalone value types directly — while `PlatformSession` handles boot
// theme restoration, flash-wear-safe theme persistence, async scan scheduling/timeouts,
// CLI command parsing, and frame projection.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "domain.hpp"
#include "pet_logic.hpp"
#include "theme.hpp"
#include "ui_model.hpp"

namespace zd {
namespace hal {

struct PowerStatus {
    int32_t batteryPercent = 100;
    bool isCharging = false;
};

enum class ScanPollState : uint8_t {
    Running = 0,
    Completed,
    Failed
};

struct ScanPollResult {
    ScanPollState state = ScanPollState::Running;
    std::vector<AccessPoint> networks{};
};

// --- Optional abstract adapter contracts for multi-device ports ----------------------

class IRadioScanner {
public:
    virtual ~IRadioScanner() = default;
    // Kick off a non-blocking 2.4 GHz scan. Return true if accepted/started.
    virtual bool startAsyncScan() = 0;
    // Poll an active scan without blocking the UI loop.
    virtual ScanPollResult pollScan() = 0;
    // Release any driver-held scan buffers after completion/timeout.
    virtual void clearScan() {}
};

// Optional BLE advertisement scanner interface (AirTag/FindMy/Tile/Multi-Tool Guard).
class IBleScanner {
public:
    virtual ~IBleScanner() = default;
    virtual bool available() const { return false; }
    virtual std::vector<BleDevice> pollBleDevices(uint32_t nowMs) = 0;
};

// Optional Sub-GHz transceiver interface (e.g. CC1101 on 315/433.92/868.35/915 MHz).
class ISubGhzRadio {
public:
    virtual ~ISubGhzRadio() = default;
    virtual bool available() const { return false; }
    virtual bool tuneFrequency(uint32_t freqKhz) = 0;
    virtual uint32_t frequencyKhz() const = 0;
    virtual std::optional<SubGhzSignal> pollSignal(uint32_t nowMs) = 0;
};

class NullBleScanner final : public IBleScanner {
public:
    std::vector<BleDevice> pollBleDevices(uint32_t) override { return {}; }
};

class NullSubGhzRadio final : public ISubGhzRadio {
public:
    bool tuneFrequency(uint32_t freqKhz) override {
        freqKhz_ = freqKhz;
        return false;
    }
    uint32_t frequencyKhz() const override { return freqKhz_; }
    std::optional<SubGhzSignal> pollSignal(uint32_t) override { return std::nullopt; }

private:
    uint32_t freqKhz_ = 433920u;
};

class IPowerSensor {
public:
    virtual ~IPowerSensor() = default;
    virtual PowerStatus readPower() = 0;
};

class IThemeStore {
public:
    virtual ~IThemeStore() = default;
    // Return persisted theme slug (e.g. "cyan") or empty string if unset.
    virtual std::string loadThemeKey() = 0;
    // Persist stable theme slug (e.g. "blueteam") to NVS / file / EEPROM.
    virtual void saveThemeKey(std::string_view key) = 0;
    // Optional highscore persistence (defaults to no-op for minimal stores).
    virtual uint32_t loadHighScore() { return 0u; }
    virtual void saveHighScore(uint32_t) {}
};

class IDisplaySink {
public:
    virtual ~IDisplaySink() = default;
    virtual ScreenDimensions dimensions() const = 0;
    virtual void present(const UiFrame& frame) = 0;
};

// Null object defaults for targets without battery telemetry or persistent storage.
class FixedPowerSensor final : public IPowerSensor {
public:
    explicit FixedPowerSensor(int32_t pct = 100, bool charging = false)
        : status_{pct, charging} {}
    PowerStatus readPower() override { return status_; }

private:
    PowerStatus status_;
};

class MemoryThemeStore final : public IThemeStore {
public:
    explicit MemoryThemeStore(std::string initialKey = {}, uint32_t initialHi = 0u)
        : key_(std::move(initialKey)), highScore_(initialHi) {}
    std::string loadThemeKey() override { return key_; }
    void saveThemeKey(std::string_view key) override { key_.assign(key.data(), key.size()); }
    uint32_t loadHighScore() override { return highScore_; }
    void saveHighScore(uint32_t score) override { highScore_ = score; }
    const std::string& storedKey() const { return key_; }
    uint32_t storedHighScore() const { return highScore_; }

private:
    std::string key_;
    uint32_t highScore_ = 0u;
};

// --- Shared portable text CLI (Serial Monitor, desktop terminal, SSH, USB CDC) -------

struct CliOutcome {
    std::optional<AppEvent> event{};
    std::string output{};
    bool requestQuit = false;
};

inline std::string_view trimAscii(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
        s.remove_suffix(1);
    }
    return s;
}

inline std::string formatThemeTable(ThemeId active) {
    std::string out = "Available themes (theme <key|next|prev>):\n";
    for (const ThemeSpec& t : kThemeCatalog) {
        const std::string keyCol(t.key);
        const std::string nameCol(t.name);
        out += (t.id == active) ? " * " : "   ";
        out += keyCol + std::string(keyCol.size() < 10u ? 10u - keyCol.size() : 1u, ' ');
        out += nameCol + std::string(nameCol.size() < 13u ? 13u - nameCol.size() : 1u, ' ');
        out += t.blurb;
        out += "\n";
    }
    return out;
}

// Pure command interpreter usable across Serial, stdin, WebSocket, or keyboard consoles.
inline CliOutcome interpretCliLine(std::string_view rawLine,
                                   const AppState& state,
                                   ScreenDimensions dims,
                                   uint32_t nowMs) {
    CliOutcome out{};
    const std::string_view line = trimAscii(rawLine);
    if (line.empty()) {
        return out;
    }

    const std::size_t sp = line.find(' ');
    const std::string_view cmd = line.substr(0, sp);
    const std::string_view arg =
        (sp == std::string_view::npos) ? std::string_view{} : trimAscii(line.substr(sp + 1));

    if (cmd == "q" || cmd == "quit" || cmd == "exit") {
        out.requestQuit = true;
    } else if (cmd == "help" || cmd == "?") {
        out.output =
            "Commands: theme [next|prev|<key>] | themes | view [next|prev|1-4] | mode [recon|def|off] | subghz [next|315|433|868|915] | ble | score | scan | ascii | status\n";
    } else if (cmd == "themes") {
        out.output = formatThemeTable(state.theme);
    } else if (cmd == "t") {
        out.event = CycleThemeEvent{nowMs, +1};
    } else if (cmd == "T") {
        out.event = CycleThemeEvent{nowMs, -1};
    } else if (cmd == "theme") {
        if (arg.empty() || arg == "next" || arg == "+") {
            out.event = CycleThemeEvent{nowMs, +1};
        } else if (arg == "prev" || arg == "back" || arg == "-") {
            out.event = CycleThemeEvent{nowMs, -1};
        } else if (const auto theme = themeFromKey(arg)) {
            out.event = SetThemeEvent{nowMs, *theme, true};
        } else {
            out.output = "Unknown theme '" + std::string(arg) + "'.\n" + formatThemeTable(state.theme);
        }
    } else if (cmd == "1") {
        out.event = SetPageEvent{nowMs, ScreenPage::PetFace};
    } else if (cmd == "2") {
        out.event = SetPageEvent{nowMs, ScreenPage::NearbyRadar};
    } else if (cmd == "3") {
        out.event = SetPageEvent{nowMs, ScreenPage::ChannelSpectrum};
    } else if (cmd == "4") {
        out.event = SetPageEvent{nowMs, ScreenPage::RfGuard};
    } else if (cmd == "a" || cmd == "view" || cmd == "page") {
        if (arg == "prev" || arg == "back" || arg == "-") {
            out.event = CyclePageEvent{nowMs, -1};
        } else if (arg == "1" || arg == "face") {
            out.event = SetPageEvent{nowMs, ScreenPage::PetFace};
        } else if (arg == "2" || arg == "radar") {
            out.event = SetPageEvent{nowMs, ScreenPage::NearbyRadar};
        } else if (arg == "3" || arg == "spectrum") {
            out.event = SetPageEvent{nowMs, ScreenPage::ChannelSpectrum};
        } else if (arg == "4" || arg == "guard" || arg == "rf") {
            out.event = SetPageEvent{nowMs, ScreenPage::RfGuard};
        } else {
            out.event = CyclePageEvent{nowMs, +1};
        }
    } else if (cmd == "b" || cmd == "scan") {
        out.event = ButtonBPressedEvent{nowMs};
    } else if (cmd == "m" || cmd == "mode") {
        if (arg.empty() || arg == "next" || arg == "cycle") {
            out.event = CycleOpsModeEvent{nowMs};
        } else if (arg == "recon" || arg == "rcn") {
            out.event = SetOpsModeEvent{nowMs, OpsMode::Recon};
        } else if (arg == "def" || arg == "defense" || arg == "defensive") {
            out.event = SetOpsModeEvent{nowMs, OpsMode::Defensive};
        } else if (arg == "off" || arg == "offense" || arg == "offensive") {
            out.event = SetOpsModeEvent{nowMs, OpsMode::Offensive};
        } else {
            out.output = "Usage: mode [next|recon|defense|offense]\n";
        }
    } else if (cmd == "subghz") {
        if (arg == "315") {
            out.event = SetSubGhzFreqEvent{nowMs, 315000u};
        } else if (arg == "433" || arg == "433.92") {
            out.event = SetSubGhzFreqEvent{nowMs, 433920u};
        } else if (arg == "868" || arg == "868.35") {
            out.event = SetSubGhzFreqEvent{nowMs, 868350u};
        } else if (arg == "915") {
            out.event = SetSubGhzFreqEvent{nowMs, 915000u};
        } else if (arg == "next" || arg == "cycle") {
            uint32_t nextFreq = 315000u;
            if (state.subGhzFreqKhz == 315000u) nextFreq = 433920u;
            else if (state.subGhzFreqKhz == 433920u) nextFreq = 868350u;
            else if (state.subGhzFreqKhz == 868350u) nextFreq = 915000u;
            out.event = SetSubGhzFreqEvent{nowMs, nextFreq};
        } else {
            out.output = "Sub-GHz tuned: " + formatFreqMhz(state.subGhzFreqKhz) +
                         " | Captures: " + std::to_string(state.subGhzSignals.size()) + "\n";
        }
    } else if (cmd == "ble") {
        out.output = "BLE Devices: " + std::to_string(state.bleDevices.size()) +
                     " | Threats: " + std::to_string(state.threatsDetected) + "\n";
    } else if (cmd == "score" || cmd == "level") {
        const LevelInfo lvl = deriveLevelInfo(state.xp);
        out.output = "Lv." + std::to_string(lvl.level) + " " + lvl.title +
                     " | XP:" + std::to_string(lvl.xp) +
                     " | HighScore:" + std::to_string(state.highScore) + "\n";
    } else if (cmd == "ascii") {
        out.output = renderAsciiPreview(buildUiFrame(state, dims));
    } else if (cmd == "status") {
        const FaceDescriptor f = faceForMood(state.mood);
        out.output = std::string(f.asciiFace) + " " + state.petName + "> \"" + state.phrase +
                     "\" | Mode:" + opsModeLabel(state.opsMode) +
                     " | Lv." + std::to_string(state.level) + " HI:" + std::to_string(state.highScore) +
                     " | APs:" + std::to_string(state.latestScan.totalAps) +
                     " | BLE:" + std::to_string(state.bleDevices.size()) +
                     " | SubGHz:" + formatFreqMhz(state.subGhzFreqKhz) +
                     " | Theme:" + themeSpec(state.theme).key + "\n";
    } else {
        out.output =
            "Commands: theme [next|prev|<key>] | themes | view [next|prev] | mode [recon|def|off] | subghz [315|433|868|915] | ble | score | scan | ascii | status\n";
    }
    return out;
}

// --- Reusable imperative-boundary coordinator ----------------------------------------

class PlatformSession {
public:
    static constexpr uint32_t kDefaultScanTimeoutMs = 15000u;

    void boot(uint32_t bootSeed, uint32_t nowMs, IThemeStore* store = nullptr) {
        state_ = initialState(bootSeed);
        if (store != nullptr) {
            const std::string saved = store->loadThemeKey();
            if (const auto theme = themeFromKey(saved)) {
                state_ = reduce(state_, SetThemeEvent{nowMs, *theme, /*announce=*/false});
            }
            const uint32_t hi = store->loadHighScore();
            if (hi > 0u) {
                state_ = reduce(state_, SetHighScoreEvent{nowMs, hi, 0u});
            }
        }
        persistedTheme_ = state_.theme;
        persistedHighScore_ = state_.highScore;
    }

    void dispatch(const AppEvent& ev, IThemeStore* store = nullptr) {
        state_ = reduce(state_, ev);
        syncThemeStore(store);
    }

    // Drives non-blocking scan start, completion, and timeout recovery.
    // Returns a diagnostic tag ("SCAN_START", "SCAN_DONE", "SCAN_EMPTY") when a transition occurs.
    const char* stepRadio(uint32_t nowMs,
                          IRadioScanner& radio,
                          uint32_t scanTimeoutMs = kDefaultScanTimeoutMs,
                          IThemeStore* store = nullptr) {
        const char* tag = nullptr;
        if (state_.isScanning) {
            const ScanPollResult poll = radio.pollScan();
            if (poll.state == ScanPollState::Completed) {
                radio.clearScan();
                state_ = reduce(state_, ScanCompletedEvent{nowMs, poll.networks});
                syncThemeStore(store);
                tag = "SCAN_DONE";
            } else if (poll.state == ScanPollState::Failed ||
                       (nowMs - state_.lastScanStartMs) > scanTimeoutMs) {
                radio.clearScan();
                state_ = reduce(state_, ScanCompletedEvent{nowMs, {}});
                syncThemeStore(store);
                tag = "SCAN_EMPTY";
            }
        }

        if (shouldTriggerScan(state_, nowMs)) {
            radio.clearScan();
            if (radio.startAsyncScan()) {
                state_ = reduce(state_, ScanStartedEvent{nowMs});
                if (tag == nullptr) {
                    tag = "SCAN_START";
                }
            }
        }
        return tag;
    }

    const char* stepMultiRadio(uint32_t nowMs,
                               IRadioScanner& wifi,
                               IBleScanner* ble = nullptr,
                               ISubGhzRadio* subghz = nullptr,
                               IThemeStore* store = nullptr,
                               uint32_t scanTimeoutMs = kDefaultScanTimeoutMs) {
        const char* tag = stepRadio(nowMs, wifi, scanTimeoutMs, store);
        if (ble != nullptr && ble->available()) {
            auto devs = ble->pollBleDevices(nowMs);
            if (!devs.empty()) {
                state_ = reduce(state_, BleScanCompletedEvent{nowMs, std::move(devs)});
            }
        }
        if (subghz != nullptr && subghz->available()) {
            if (subghz->frequencyKhz() != state_.subGhzFreqKhz) {
                subghz->tuneFrequency(state_.subGhzFreqKhz);
            }
            if (auto sig = subghz->pollSignal(nowMs)) {
                state_ = reduce(state_, SubGhzObservedEvent{nowMs, *sig});
            }
        }
        syncThemeStore(store);
        return tag;
    }

    void stepTick(uint32_t nowMs, IPowerSensor& power) {
        const PowerStatus p = power.readPower();
        state_ = reduce(state_, TickEvent{nowMs, p.batteryPercent, p.isCharging});
    }

    UiFrame buildFrame(ScreenDimensions dims) const {
        return buildUiFrame(state_, dims);
    }

    void renderTo(IDisplaySink& sink) const {
        sink.present(buildFrame(sink.dimensions()));
    }

    const AppState& state() const { return state_; }

private:
    void syncThemeStore(IThemeStore* store) {
        if (store == nullptr) {
            return;
        }
        if (state_.theme != persistedTheme_) {
            store->saveThemeKey(themeSpec(state_.theme).key);
            persistedTheme_ = state_.theme;
        }
        if (state_.highScore > persistedHighScore_) {
            store->saveHighScore(state_.highScore);
            persistedHighScore_ = state_.highScore;
        }
    }

    AppState state_ = initialState();
    ThemeId persistedTheme_ = ThemeId::PaperInk;
    uint32_t persistedHighScore_ = 0u;
};

}  // namespace hal
}  // namespace zd
