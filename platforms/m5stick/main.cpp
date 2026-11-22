// Imperative Hardware Shell for pwnagotchi-zeroday (M5StickC / Plus / Plus2, and other
// M5Unified-supported ESP32 boards such as M5Stack Core / Core2 / Cardputer).
//
// All domain logic, state transitions, WiFi aggregation, theming, layout, and session
// coordination live in `core/include/zd/`. Pixel drawing lives in `render/include/zd/render/`.
// This file implements thin M5Unified + Arduino ESP32 HAL adapters at the boundary.

#include "zd/hal.hpp"
#include "zd/render/painter.hpp"
#include "buzzer_melodies.hpp"
#include "esp32_cli.hpp"
#include "esp32_hal.hpp"
#include "esp32_offensive.hpp"

#include <Arduino.h>
#include <M5Unified.h>
#include <esp_system.h>

namespace {

using zd::esp32_common::Esp32BleScanner;
using zd::esp32_common::Esp32WifiScanner;
using zd::esp32_common::NvsThemeStore;

// --- Thin Hardware Adapters Implementing `zd::hal` Contracts ---

class M5PowerSensor final : public zd::hal::IPowerSensor {
public:
    zd::hal::PowerStatus readPower() override {
        return zd::hal::PowerStatus{
            M5.Power.getBatteryLevel(),
            M5.Power.isCharging() == m5::Power_Class::is_charging
        };
    }
};

class M5DisplaySink final : public zd::hal::IDisplaySink {
public:
    void init() {
        M5.Display.setRotation(1);
        M5.Display.setBrightness(180);
        canvas_.setColorDepth(16);
        canvasReady_ = canvas_.createSprite(M5.Display.width(), M5.Display.height());
        if (!canvasReady_) {
            Serial.println("[DISPLAY] ERROR: createSprite failed; screen output disabled");
        }
    }

    zd::ScreenDimensions dimensions() const override {
        return zd::ScreenDimensions{
            static_cast<int16_t>(M5.Display.width()),
            static_cast<int16_t>(M5.Display.height())
        };
    }

    void present(const zd::UiFrame& frame) override {
        // Sprite-only by design: `paintUiFrame<Gfx>` is a template, so a direct-to-display
        // fallback branch would instantiate the entire render pipeline a second time (one
        // full copy per Gfx type), just to cover an allocation failure that essentially
        // never happens in practice (the sprite is at most 320x240x2 = 150KB against
        // ~320KB of usable RAM). If it ever does fail, skip the frame rather than pay for
        // that duplication permanently in flash.
        if (!canvasReady_) {
            return;
        }
        canvas_.setFont(&fonts::Font0);
        canvas_.setTextSize(1);
        zd::render::paintUiFrame(canvas_, frame);
        canvas_.pushSprite(0, 0);
    }

private:
    M5Canvas canvas_{&M5.Display};
    bool canvasReady_ = false;
};

class M5BuzzerPlayer {
public:
    void init(zd::hal::IThemeStore& store, uint32_t nowMs) {
        if (M5.Speaker.isEnabled()) {
            M5.Speaker.setVolume(110);
        }
        player_.setMuted(store.loadAudioMuted());
        if (!player_.isMuted()) {
            player_.trigger(zd::MelodyId::Boot, nowMs);
        }
    }

    void trigger(zd::MelodyId id, uint32_t nowMs) {
        if (M5.Speaker.isEnabled()) {
            player_.trigger(id, nowMs);
        }
    }

    void setMuted(bool muted, zd::hal::IThemeStore& store) {
        player_.setMuted(muted);
        store.saveAudioMuted(muted);
        if (muted && M5.Speaker.isEnabled()) {
            M5.Speaker.stop();
        }
    }

    bool isMuted() const { return player_.isMuted(); }

    void step(uint32_t nowMs) {
        if (!M5.Speaker.isEnabled()) {
            return;
        }
        if (const auto cmd = player_.step(nowMs)) {
            if (cmd->active) {
                M5.Speaker.tone(static_cast<float>(cmd->freqHz), cmd->durationMs);
            } else {
                M5.Speaker.stop();
            }
        }
    }

private:
    zd::MelodyPlayer player_;
};

// --- Runtime State ---

Esp32WifiScanner gRadio;
Esp32BleScanner gBle;
M5PowerSensor gPower;
NvsThemeStore gThemeStore;
M5DisplaySink gDisplay;
M5BuzzerPlayer gBuzzer;
zd::hal::PlatformSession gSession;

// Active-offense console (deauth injection). Inert until explicitly armed + allow-listed at
// the serial `sec` console; runtime-gated only. See docs/OFFENSIVE.md.
zd::esp32_common::OffensiveConsole gOffensive;

bool gBtnALongHandled = false;
bool gBtnBLongHandled = false;
zd::esp32_common::DirtyFramePacer gFramePacer;
std::string gSerialLine;
uint32_t gLastActivityMs = 0u;
uint8_t gDisplayBrightness = 180u;

void wakeDisplay(uint32_t nowMs) {
    gLastActivityMs = nowMs;
    if (gDisplayBrightness != 180u) {
        gDisplayBrightness = 180u;
        M5.Display.setBrightness(gDisplayBrightness);
    }
}

void logSerialStatus(const char* eventTag) {
    zd::esp32_common::printSerialStatus(gSession, eventTag);
}

void pollSerialCli(uint32_t nowMs) {
    zd::esp32_common::pollSerialLines(gSerialLine, [&](const std::string& line) {
        wakeDisplay(nowMs);
        if (line == "sec" || line.rfind("sec ", 0) == 0) {
            Serial.print(gOffensive.handleLine(line, nowMs, &gSession).c_str());
            return;
        }
        if (line == "sfx on") {
            gBuzzer.setMuted(false, gThemeStore);
            gBuzzer.trigger(zd::MelodyId::ButtonClick, nowMs);
            Serial.println("SFX: enabled");
            return;
        }
        if (line == "sfx off") {
            gBuzzer.setMuted(true, gThemeStore);
            Serial.println("SFX: muted");
            return;
        }
        if (line == "sfx") {
            Serial.printf("SFX: %s (use 'sfx on|off')\n", gBuzzer.isMuted() ? "muted" : "on");
            return;
        }
        if (line == "ble on") {
            gBle.setEnabled(true);
            Serial.println("BLE scanner: enabled");
            return;
        }
        if (line == "ble off") {
            gBle.setEnabled(false);
            Serial.println("BLE scanner: disabled");
            return;
        }
        const zd::hal::CliOutcome res = zd::hal::interpretCliLine(
            line, gSession.state(), gDisplay.dimensions(), nowMs);
        if (!res.output.empty()) {
            Serial.print(res.output.c_str());
        }
        if (res.event.has_value()) {
            gSession.dispatch(*res.event, &gThemeStore);
            gBuzzer.trigger(zd::MelodyId::ButtonClick, nowMs);
            logSerialStatus("SERIAL");
        }
    });
}

}  // namespace

void setup() {
    auto cfg = M5.config();
    M5.begin(cfg);
    Serial.begin(115200);

    gDisplay.init();
    gRadio.init();
    gBle.init();
    gThemeStore.init();
    gOffensive.begin();

    const uint32_t bootMs = millis();
    gLastActivityMs = bootMs;
    gBuzzer.init(gThemeStore, bootMs);

    // Seed pure functional PRNG with hardware entropy & restore saved theme from NVS
    gSession.boot(esp_random(), bootMs, &gThemeStore);
    gSession.renderTo(gDisplay);
    logSerialStatus("BOOT");
}

void loop() {
    M5.update();
    const uint32_t nowMs = millis();

    // 1. Button A -> short press cycles screen view, 700ms hold cycles OpsMode
    if (M5.BtnA.wasPressed()) {
        gBtnALongHandled = false;
        wakeDisplay(nowMs);
    }
    if (M5.BtnA.isPressed() && !gBtnALongHandled && M5.BtnA.pressedFor(700)) {
        gBtnALongHandled = true;
        gSession.dispatch(zd::CycleOpsModeEvent{nowMs}, &gThemeStore);
        gBuzzer.trigger(zd::MelodyId::ModeSwitch, nowMs);
        logSerialStatus("MODE");
    }
    if (M5.BtnA.wasReleased() && !gBtnALongHandled) {
        gSession.dispatch(zd::ButtonAPressedEvent{nowMs}, &gThemeStore);
        gBuzzer.trigger(zd::MelodyId::ButtonClick, nowMs);
        logSerialStatus("BTN_A");
    }

    // 2. Button B -> short press triggers scan, 700ms hold cycles to next theme
    if (M5.BtnB.wasPressed()) {
        gBtnBLongHandled = false;
        wakeDisplay(nowMs);
    }
    if (M5.BtnB.isPressed() && !gBtnBLongHandled && M5.BtnB.pressedFor(700)) {
        gBtnBLongHandled = true;
        gSession.dispatch(zd::CycleThemeEvent{nowMs, +1}, &gThemeStore);
        gBuzzer.trigger(zd::MelodyId::ThemeSwitch, nowMs);
        logSerialStatus("THEME");
    }
    if (M5.BtnB.wasReleased() && !gBtnBLongHandled) {
        gSession.dispatch(zd::ButtonBPressedEvent{nowMs}, &gThemeStore);
        gBuzzer.trigger(zd::MelodyId::ButtonClick, nowMs);
        logSerialStatus("BTN_B");
    }

    // 3. Extra hardware buttons -> previous theme
    if (M5.BtnPWR.wasClicked() || M5.BtnC.wasPressed()) {
        wakeDisplay(nowMs);
        gSession.dispatch(zd::CycleThemeEvent{nowMs, -1}, &gThemeStore);
        gBuzzer.trigger(zd::MelodyId::ThemeSwitch, nowMs);
        logSerialStatus("THEME");
    }

    // 4. Interactive Serial CLI
    pollSerialCli(nowMs);

    // 5. Step non-blocking multi-radio scanner & periodic telemetry tick
    const uint8_t prevLevel = gSession.state().level;
    const uint32_t prevThreats = gSession.state().threatsDetected;
    if (const char* scanTag = gSession.stepMultiRadio(
            nowMs, gRadio, &gBle, nullptr, &gThemeStore)) {
        if (gSession.state().level > prevLevel) {
            gBuzzer.trigger(zd::MelodyId::LevelUp, nowMs);
        } else if (gSession.state().threatsDetected > prevThreats) {
            gBuzzer.trigger(zd::MelodyId::ThreatAlert, nowMs);
        } else if (std::string(scanTag) == "SCAN_DONE") {
            gBuzzer.trigger(zd::MelodyId::ScanDone, nowMs);
        }
        logSerialStatus(scanTag);
    } else if (gSession.state().threatsDetected > prevThreats) {
        gBuzzer.trigger(zd::MelodyId::ThreatAlert, nowMs);
    }
    gSession.stepTick(nowMs, gPower);
    gBuzzer.step(nowMs);

    // Dim backlight on battery after 30s of idle
    const uint8_t targetBright =
        (!gSession.state().isCharging && (nowMs - gLastActivityMs) >= 30000u) ? 48u : 180u;
    if (targetBright != gDisplayBrightness) {
        gDisplayBrightness = targetBright;
        M5.Display.setBrightness(gDisplayBrightness);
    }

    // 6. Refresh display only when state changed, animating, or on 1 Hz uptime tick
    if (gFramePacer.shouldRender(gSession.state(), nowMs)) {
        gSession.renderTo(gDisplay);
    }

    delay(15);
}
