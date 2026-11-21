// Imperative Hardware Shell for pwnagotchi-zeroday on ESP32-2432S028 ("CYD" — Cheap Yellow Display).
//
// Hardware Features (Sunton ESP32-2432S028R):
// - ESP32-WROOM-32 (Dual-core Xtensa LX6 @ 240MHz, 4MB Flash, 520KB SRAM, no PSRAM)
// - 2.8" 320x240 TFT LCD on HSPI (ILI9341 single-USB default; ST7789 dual-USB via ZD_CYD_PANEL_ST7789=1)
// - XPT2046 Resistive Touchscreen on dedicated pins (Software SPI: CLK=25, MOSI=32, MISO=39, CS=33)
// - PWM Backlight Control (GPIO 21)
// - On-board BOOT Physical Button (GPIO 0, active LOW)
// - On-board RGB LED (R=4, G=16, B=17, active LOW — driven OFF at boot)
// - Ambient Light Photoresistor / LDR (GPIO 34, ADC)
// - MicroSD Card Slot CS isolation (GPIO 5 pulled HIGH)
//
// All domain logic, state transitions, WiFi aggregation, theming, layout, and session
// coordination live in `core/include/zd/`. Pixel drawing lives in `render/include/zd/render/`.

#include "zd/hal.hpp"
#include "zd/render/painter.hpp"
#include "esp32_cli.hpp"
#include "esp32_hal.hpp"
#include "esp32_offensive.hpp"

#include <Arduino.h>
#define LGFX_USE_V1
#include <LovyanGFX.hpp>
#include <algorithm>
#include <cstdlib>
#include <esp_system.h>
#include <string>

#ifndef ZD_CYD_PANEL_ST7789
#define ZD_CYD_PANEL_ST7789 0
#endif

#ifndef ZD_CYD_INVERT_COLORS
#define ZD_CYD_INVERT_COLORS 0
#endif

#ifndef ZD_CYD_RGB_ORDER
#define ZD_CYD_RGB_ORDER 0
#endif

#ifndef ZD_CYD_ROTATION
#define ZD_CYD_ROTATION 1
#endif

namespace {

using zd::esp32_common::Esp32WifiScanner;
using zd::esp32_common::NvsThemeStore;

// --- Pinout & Hardware Constants for Sunton ESP32-2432S028R (CYD) ---

// Display SPI pins (HSPI / SPI2)
constexpr uint8_t PIN_LCD_SCLK   = 14;
constexpr uint8_t PIN_LCD_MOSI   = 13;
constexpr uint8_t PIN_LCD_MISO   = 12;
constexpr uint8_t PIN_LCD_DC     = 2;
constexpr uint8_t PIN_LCD_CS     = 15;
constexpr uint8_t PIN_LCD_BL     = 21;

// XPT2046 Resistive Touch pins (separate from HSPI display & VSPI SD)
constexpr uint8_t PIN_TOUCH_SCLK = 25;
constexpr uint8_t PIN_TOUCH_MOSI = 32;
constexpr uint8_t PIN_TOUCH_MISO = 39; // Input-only pin
constexpr uint8_t PIN_TOUCH_CS   = 33;

// MicroSD CS (VSPI) — driven HIGH at boot to prevent bus contention
constexpr uint8_t PIN_SD_CS      = 5;

// On-board RGB LED (common anode: active LOW)
constexpr uint8_t PIN_LED_R      = 4;
constexpr uint8_t PIN_LED_G      = 16;
constexpr uint8_t PIN_LED_B      = 17;

// On-board physical BOOT button (active LOW) & ambient light sensor (LDR)
constexpr uint8_t PIN_BTN_BOOT   = 0;
constexpr uint8_t PIN_LDR_ADC    = 34; // Input-only ADC1 pin

// --- LovyanGFX Hardware Device Driver for CYD ESP32-2432S028 ---

class LGFX_CYD : public lgfx::LGFX_Device {
    lgfx::Bus_SPI     bus_instance_;
    lgfx::Light_PWM   light_instance_;
#if ZD_CYD_PANEL_ST7789
    lgfx::Panel_ST7789  panel_instance_;
#else
    lgfx::Panel_ILI9341 panel_instance_;
#endif
    lgfx::Touch_XPT2046 touch_instance_;

public:
    LGFX_CYD() {
        // 1. HSPI Bus configuration (Display)
        {
            auto cfg = bus_instance_.config();
            cfg.spi_host    = HSPI_HOST;
            cfg.spi_mode    = 0;
            cfg.freq_write  = 40000000;
            cfg.freq_read   = 16000000;
            cfg.spi_3wire   = false;
            cfg.use_lock    = true;
            cfg.dma_channel = SPI_DMA_CH_AUTO;
            cfg.pin_sclk    = PIN_LCD_SCLK;
            cfg.pin_mosi    = PIN_LCD_MOSI;
            cfg.pin_miso    = PIN_LCD_MISO;
            cfg.pin_dc      = PIN_LCD_DC;
            bus_instance_.config(cfg);
            panel_instance_.setBus(&bus_instance_);
        }

        // 2. Backlight PWM configuration (GPIO 21)
        {
            auto cfg = light_instance_.config();
            cfg.pin_bl      = PIN_LCD_BL;
            cfg.invert      = false;
            cfg.freq        = 44100;
            cfg.pwm_channel = 7;
            light_instance_.config(cfg);
            panel_instance_.setLight(&light_instance_);
        }

        // 3. TFT Panel configuration (matches LovyanGFX Sunton_ESP32_2432S028 profile)
        {
            auto cfg = panel_instance_.config();
            cfg.pin_cs          = PIN_LCD_CS;
            cfg.pin_rst         = -1; // Tied to ESP32 EN/RST
            cfg.pin_busy        = -1;
            cfg.panel_width     = 240;
            cfg.panel_height    = 320;
            cfg.offset_x        = 0;
            cfg.offset_y        = 0;
#if ZD_CYD_PANEL_ST7789
            cfg.offset_rotation = 0;
#else
            cfg.offset_rotation = 2;
#endif
            cfg.invert          = (ZD_CYD_INVERT_COLORS != 0);
            cfg.rgb_order       = (ZD_CYD_RGB_ORDER != 0);
            cfg.dlen_16bit      = false;
            cfg.bus_shared      = false;
            panel_instance_.config(cfg);
        }

        // 4. XPT2046 Resistive Touch configuration (Software SPI to avoid bus conflicts)
        {
            auto cfg = touch_instance_.config();
            cfg.x_min           = 300;
            cfg.x_max           = 3900;
            cfg.y_min           = 3700; // Y axis is inverted on ESP32-2432S028R panels
            cfg.y_max           = 200;
            cfg.pin_int         = -1;
            cfg.bus_shared      = false;
#if ZD_CYD_PANEL_ST7789
            cfg.offset_rotation = 2;
#else
            cfg.offset_rotation = 0;
#endif
            cfg.spi_host        = -1; // Software SPI on dedicated CYD touch GPIOs
            cfg.pin_sclk        = PIN_TOUCH_SCLK;
            cfg.pin_mosi        = PIN_TOUCH_MOSI;
            cfg.pin_miso        = PIN_TOUCH_MISO;
            cfg.pin_cs          = PIN_TOUCH_CS;
            touch_instance_.config(cfg);
            panel_instance_.setTouch(&touch_instance_);
        }

        setPanel(&panel_instance_);
    }
};

// --- Banded RGB565 Sprite Adapter (No-PSRAM Safe Double Buffering) ---
//
// Classic ESP32-WROOM-32 lacks PSRAM, so allocating a full 320x240x2 (150 KB) contiguous
// RGB565 sprite alongside WiFi STA buffers fails or fragments DRAM. Rendering in 4 horizontal
// strips of 320x60 (37.5 KB) preserves lossless 16-bit RGB565 fidelity, zero flicker, and a
// single template instantiation of `zd::render::paintUiFrame<BandedSpriteGfx>`.

class BandedSpriteGfx {
public:
    BandedSpriteGfx(lgfx::LGFX_Sprite& sprite, int32_t yOffset, int32_t bandHeight)
        : sprite_(sprite), yOffset_(yOffset), bandHeight_(bandHeight) {}

    void fillScreen(uint16_t color) {
        sprite_.fillScreen(color);
    }

    void fillRect(int32_t x, int32_t y, int32_t w, int32_t h, uint16_t color) {
        if ((y + h) <= yOffset_ || y >= (yOffset_ + bandHeight_)) {
            return;
        }
        sprite_.fillRect(x, y - yOffset_, w, h, color);
    }

    void fillRoundRect(int32_t x, int32_t y, int32_t w, int32_t h, int32_t r, uint16_t color) {
        if ((y + h) <= yOffset_ || y >= (yOffset_ + bandHeight_)) {
            return;
        }
        sprite_.fillRoundRect(x, y - yOffset_, w, h, r, color);
    }

    void fillCircle(int32_t x, int32_t y, int32_t r, uint16_t color) {
        if ((y + r) < yOffset_ || (y - r) >= (yOffset_ + bandHeight_)) {
            return;
        }
        sprite_.fillCircle(x, y - yOffset_, r, color);
    }

    void fillArc(int32_t x, int32_t y, int32_t r0, int32_t r1, float a0, float a1, uint16_t color) {
        const int32_t maxR = (std::max)(r0, r1);
        if ((y + maxR) < yOffset_ || (y - maxR) >= (yOffset_ + bandHeight_)) {
            return;
        }
        sprite_.fillArc(x, y - yOffset_, r0, r1, a0, a1, color);
    }

    void drawLine(int32_t x0, int32_t y0, int32_t x1, int32_t y1, uint16_t color) {
        const int32_t minY = (std::min)(y0, y1);
        const int32_t maxY = (std::max)(y0, y1);
        if (maxY < yOffset_ || minY >= (yOffset_ + bandHeight_)) {
            return;
        }
        sprite_.drawLine(x0, y0 - yOffset_, x1, y1 - yOffset_, color);
    }

    void setTextColor(uint16_t fg, uint16_t bg) {
        sprite_.setTextColor(fg, bg);
    }

    void drawString(const char* text, int32_t x, int32_t y) {
        // Font0 at textSize(1) is 8 px tall.
        if ((y + 8) <= yOffset_ || y >= (yOffset_ + bandHeight_)) {
            return;
        }
        sprite_.drawString(text, x, y - yOffset_);
    }

private:
    lgfx::LGFX_Sprite& sprite_;
    int32_t yOffset_;
    int32_t bandHeight_;
};

// --- Thin Hardware Adapters Implementing `zd::hal` Contracts ---

class CydDisplaySink final : public zd::hal::IDisplaySink {
public:
    static constexpr int16_t kBandHeight = 60; // 320 x 60 x 2 = 38.4 KB (4 strips cover 240 px)

    void init() {
        // 1. Keep MicroSD CS idle HIGH and turn off the active-LOW rear RGB LED
        pinMode(PIN_SD_CS, OUTPUT);
        digitalWrite(PIN_SD_CS, HIGH);

        pinMode(PIN_LED_R, OUTPUT);
        pinMode(PIN_LED_G, OUTPUT);
        pinMode(PIN_LED_B, OUTPUT);
        digitalWrite(PIN_LED_R, HIGH);
        digitalWrite(PIN_LED_G, HIGH);
        digitalWrite(PIN_LED_B, HIGH);

        // 2. Initialize LCD in landscape (320x240 QVGA)
        lcd_.init();
        lcd_.setRotation(ZD_CYD_ROTATION);
        lcd_.setBrightness(brightness_);

        // 3. Allocate banded RGB565 sprite in internal DRAM
        band_.setColorDepth(16);
        bandReady_ = band_.createSprite(lcd_.width(), kBandHeight);
        if (!bandReady_) {
            Serial.println("[DISPLAY] ERROR: band createSprite failed; screen output disabled");
        }
    }

    void setBrightness(uint8_t level) {
        brightness_ = level;
        lcd_.setBrightness(brightness_);
    }

    uint8_t brightness() const { return brightness_; }

    void setLandscapeRotation(uint8_t rot) {
        const uint8_t r = (rot == 3) ? 3 : 1;
        lcd_.setRotation(r);
    }

    zd::ScreenDimensions dimensions() const override {
        return zd::ScreenDimensions{
            static_cast<int16_t>(lcd_.width()),
            static_cast<int16_t>(lcd_.height())
        };
    }

    void present(const zd::UiFrame& frame) override {
        if (!bandReady_) {
            return;
        }
        band_.setFont(&fonts::Font0);
        band_.setTextSize(1);

        const int32_t totalH = lcd_.height();
        lcd_.startWrite();
        for (int32_t yOff = 0; yOff < totalH; yOff += kBandHeight) {
            const int32_t stripH = (std::min)(static_cast<int32_t>(kBandHeight), totalH - yOff);
            BandedSpriteGfx gfx(band_, yOff, stripH);
            zd::render::paintUiFrame(gfx, frame);
            band_.pushSprite(0, yOff);
        }
        lcd_.endWrite();
    }

    LGFX_CYD& lcd() { return lcd_; }

private:
    LGFX_CYD lcd_;
    lgfx::LGFX_Sprite band_{&lcd_};
    bool bandReady_ = false;
    uint8_t brightness_ = 200;
};

// --- Runtime State & Adapters ---

Esp32WifiScanner gRadio;
zd::hal::FixedPowerSensor gPower{100, /*charging=*/true}; // CYD is USB-powered
NvsThemeStore gThemeStore;
CydDisplaySink gDisplay;
zd::hal::PlatformSession gSession;

// Active-offense console (deauth injection). Inert until explicitly armed + allow-listed at
// the serial `sec` console; runtime-gated only. See docs/OFFENSIVE.md.
zd::esp32_common::OffensiveConsole gOffensive;

zd::esp32_common::DirtyFramePacer gFramePacer;
std::string gSerialLine;

// BOOT button (GPIO 0) state
bool gBootActive = false;
bool gBootLongHandled = false;
uint32_t gBootStartMs = 0;

// XPT2046 resistive touchscreen gesture state
zd::esp32_common::TouchZoneGesture gTouchGesture;

void logSerialStatus(const char* eventTag) {
    zd::esp32_common::printSerialStatus(gSession, eventTag);
}

bool parseStrictRangeInt(const char* raw, int minVal, int maxVal, int& out) {
    if (raw == nullptr || *raw == '\0') {
        return false;
    }
    char* end = nullptr;
    const long v = std::strtol(raw, &end, 10);
    if (end == raw || *end != '\0' || v < minVal || v > maxVal) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

void pollSerialCli(uint32_t nowMs) {
    zd::esp32_common::pollSerialLines(gSerialLine, [&](const std::string& line) {
        if (line == "sec" || line.rfind("sec ", 0) == 0) {
            Serial.print(gOffensive.handleLine(line, nowMs, &gSession).c_str());
            return;
        }
        if (line == "ldr") {
            const int raw = analogRead(PIN_LDR_ADC);
            const uint32_t mv = analogReadMilliVolts(PIN_LDR_ADC);
            Serial.printf("LDR (GPIO %u): raw=%d | %lu mV\n",
                          static_cast<unsigned>(PIN_LDR_ADC),
                          raw,
                          static_cast<unsigned long>(mv));
        } else if (line.rfind("bl ", 0) == 0) {
            int val = 0;
            if (!parseStrictRangeInt(line.c_str() + 3, 10, 255, val)) {
                Serial.println("Invalid backlight value (expected integer 10..255)");
                return;
            }
            gDisplay.setBrightness(static_cast<uint8_t>(val));
            Serial.printf("Backlight set to %u/255\n", static_cast<unsigned>(val));
        } else if (line == "bl") {
            Serial.printf("Backlight: %u/255 (use 'bl <10-255>')\n",
                          static_cast<unsigned>(gDisplay.brightness()));
        } else if (line.rfind("rot ", 0) == 0) {
            int val = 0;
            if (!parseStrictRangeInt(line.c_str() + 4, 1, 3, val) || (val != 1 && val != 3)) {
                Serial.println("Invalid rotation (expected 1 or 3)");
                return;
            }
            const uint8_t r = static_cast<uint8_t>(val);
            gDisplay.setLandscapeRotation(r);
            gSession.renderTo(gDisplay);
            gFramePacer.markRendered(nowMs);
            Serial.printf("Landscape rotation set to %u\n", static_cast<unsigned>(r));
        } else {
            const zd::hal::CliOutcome res = zd::hal::interpretCliLine(
                line, gSession.state(), gDisplay.dimensions(), nowMs);
            if (!res.output.empty()) {
                Serial.print(res.output.c_str());
            }
            if (res.event.has_value()) {
                gSession.dispatch(*res.event, &gThemeStore);
                logSerialStatus("SERIAL");
            }
        }
    });
}

void pollBootButton(uint32_t nowMs) {
    const bool pressed = (digitalRead(PIN_BTN_BOOT) == LOW);
    if (pressed && !gBootActive) {
        gBootActive = true;
        gBootStartMs = nowMs;
        gBootLongHandled = false;
    } else if (pressed && gBootActive && !gBootLongHandled) {
        // Hold BOOT for 600ms -> trigger immediate WiFi scan
        if ((nowMs - gBootStartMs) >= 600u) {
            gBootLongHandled = true;
            gSession.dispatch(zd::ButtonBPressedEvent{nowMs}, &gThemeStore);
            logSerialStatus("BOOT_HOLD_SCAN");
        }
    } else if (!pressed && gBootActive) {
        gBootActive = false;
        const uint32_t duration = nowMs - gBootStartMs;
        if (!gBootLongHandled && duration >= 25u) {
            // Short BOOT click -> cycle screen view / wake pet
            gSession.dispatch(zd::ButtonAPressedEvent{nowMs}, &gThemeStore);
            logSerialStatus("BOOT_CLICK_VIEW");
        }
    }
}

void pollTouch(uint32_t nowMs, LGFX_CYD& lcd) {
    uint16_t tx = 0;
    uint16_t ty = 0;
    const bool isTouched = lcd.getTouch(&tx, &ty);
    using Act = zd::esp32_common::TouchZoneGesture::Action;
    switch (gTouchGesture.update(isTouched, tx, ty, nowMs, 35u)) {
        case Act::PrevTheme:
            gSession.dispatch(zd::CycleThemeEvent{nowMs, -1}, &gThemeStore);
            logSerialStatus("TOUCH_THEME_PREV");
            break;
        case Act::NextTheme:
            gSession.dispatch(zd::CycleThemeEvent{nowMs, +1}, &gThemeStore);
            logSerialStatus("TOUCH_THEME");
            break;
        case Act::PrevView:
            gSession.dispatch(zd::CyclePageEvent{nowMs, -1}, &gThemeStore);
            logSerialStatus("TOUCH_VIEW_PREV");
            break;
        case Act::NextView:
            gSession.dispatch(zd::CyclePageEvent{nowMs, +1}, &gThemeStore);
            logSerialStatus("TOUCH_VIEW_NEXT");
            break;
        case Act::Scan:
            gSession.dispatch(zd::ButtonBPressedEvent{nowMs}, &gThemeStore);
            logSerialStatus("TOUCH_SCAN");
            break;
        case Act::CycleMode:
            gSession.dispatch(zd::CycleOpsModeEvent{nowMs}, &gThemeStore);
            logSerialStatus("TOUCH_MODE");
            break;
        case Act::None:
            break;
    }
}

}  // namespace

void setup() {
    Serial.begin(115200);

    pinMode(PIN_BTN_BOOT, INPUT_PULLUP);
    pinMode(PIN_LDR_ADC, INPUT);
    analogSetAttenuation(ADC_11db);

    gDisplay.init();
    gRadio.init();
    gThemeStore.init();
    gOffensive.begin();

    // Seed pure functional PRNG with hardware entropy & restore theme from NVS
    gSession.boot(esp_random(), millis(), &gThemeStore);
    gSession.renderTo(gDisplay);
    logSerialStatus("BOOT");
}

void loop() {
    const uint32_t nowMs = millis();

    // 1. Poll physical inputs: resistive touchscreen, BOOT button, serial CLI
    pollTouch(nowMs, gDisplay.lcd());
    pollBootButton(nowMs);
    pollSerialCli(nowMs);

    // 2. Step non-blocking radio scanner & periodic telemetry tick
    if (const char* scanTag = gSession.stepRadio(
            nowMs, gRadio, zd::hal::PlatformSession::kDefaultScanTimeoutMs, &gThemeStore)) {
        logSerialStatus(scanTag);
    }
    gSession.stepTick(nowMs, gPower);

    // 3. Refresh display only when state changed, animating, or on 1 Hz uptime tick
    if (gFramePacer.shouldRender(gSession.state(), nowMs)) {
        gSession.renderTo(gDisplay);
    }

    delay(10);
}
