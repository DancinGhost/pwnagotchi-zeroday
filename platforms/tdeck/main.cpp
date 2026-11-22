// Imperative Hardware Shell for pwnagotchi-zeroday on LILYGO T-Deck / T-Deck Plus.
//
// Hardware Features:
// - ESP32-S3FN16R8 (Dual-core LX7 @ 240MHz, 16MB Flash, 8MB OPI PSRAM)
// - 2.8" IPS ST7789 Display (320x240, Landscape QVGA wide layout)
// - GT911 Capacitive Touchscreen (T-Deck Plus)
// - Trackball Navigation (Up/Down/Left/Right/Center Click on GPIO 0/BOOT)
// - ESP32-C3 QWERTY Keyboard Coprocessor (I2C 0x55, INT GPIO 46)
// - Battery ADC Voltage Divider (GPIO 4 with 2:1 divider)
// - Peripheral Power Rail Gate (GPIO 10, required for battery operation)
// - MIA-M10Q GNSS / GPS Module (T-Deck Plus, RX 44, TX 43)
// - SX1262 LoRa (CS GPIO 9) & MicroSD (CS GPIO 39) SPI bus isolation
//
// All domain logic, state transitions, WiFi aggregation, theming, layout, and session
// coordination live in `core/include/zd/`. Pixel drawing lives in `render/include/zd/render/`.

#include "zd/hal.hpp"
#include "zd/render/painter.hpp"
#include "esp32_cli.hpp"
#include "esp32_hal.hpp"
#include "esp32_offensive.hpp"
#include "nmea.hpp"
#include "wigle.hpp"

#include <Arduino.h>
#define LGFX_USE_V1
#include <LovyanGFX.hpp>
#include <SPI.h>
#include <Wire.h>
#if defined(__has_include)
#if __has_include(<SD.h>) && !defined(ZD_NO_ESP32_SD)
#include <SD.h>
#define ZD_HAS_ESP32_SD 1
#endif
#endif
#include <algorithm>
#include <array>
#include <cstring>
#include <esp_random.h>
#include <string_view>

namespace {

using zd::esp32_common::Esp32BleScanner;
using zd::esp32_common::Esp32WifiScanner;
using zd::esp32_common::NvsThemeStore;

// --- Pinout & Hardware Constants for LILYGO T-Deck / T-Deck Plus ---

constexpr uint8_t PIN_POWER_ON   = 10; // High enables peripheral power rail on battery
constexpr uint8_t PIN_LORA_CS    = 9;  // Shared SPI CS: pull HIGH to avoid bus contention
constexpr uint8_t PIN_SD_CS      = 39; // Shared SPI CS: pull HIGH to avoid bus contention
constexpr uint8_t PIN_BAT_ADC    = 4;  // Battery voltage divider (2:1 ratio)

// Trackball pins
constexpr uint8_t PIN_TB_CLICK   = 0;  // Center click / ESP32-S3 BOOT button (active LOW)
constexpr uint8_t PIN_TB_UP      = 3;  // Trackball Up
constexpr uint8_t PIN_TB_DOWN    = 15; // Trackball Down
constexpr uint8_t PIN_TB_LEFT    = 1;  // Trackball Left
constexpr uint8_t PIN_TB_RIGHT   = 2;  // Trackball Right

// I2C bus pins (shared by ESP32-C3 keyboard coprocessor & GT911 touchscreen)
constexpr uint8_t PIN_I2C_SDA    = 18;
constexpr uint8_t PIN_I2C_SCL    = 8;
constexpr uint8_t PIN_KB_INT     = 46; // Active LOW when keyboard key is ready
constexpr uint8_t KB_I2C_ADDR    = 0x55;

// ST7789 Display SPI pins
constexpr uint8_t PIN_LCD_SCLK   = 40;
constexpr uint8_t PIN_LCD_MOSI   = 41;
constexpr uint8_t PIN_LCD_MISO   = 38;
constexpr uint8_t PIN_LCD_DC     = 11;
constexpr uint8_t PIN_LCD_CS     = 12;
constexpr uint8_t PIN_LCD_BL     = 42;

// GT911 Touchscreen pins (T-Deck Plus)
constexpr uint8_t PIN_TOUCH_INT  = 16;
constexpr uint8_t TOUCH_I2C_ADDR = 0x5D;

// MIA-M10Q GNSS / GPS UART pins (T-Deck Plus)
constexpr uint8_t PIN_GPS_RX     = 44; // ESP32 RX <- GPS TX
constexpr uint8_t PIN_GPS_TX     = 43; // ESP32 TX -> GPS RX

// --- LovyanGFX Hardware Device Driver for T-Deck / T-Deck Plus ---

class LGFX_TDeck : public lgfx::LGFX_Device {
    lgfx::Bus_SPI     bus_instance_;
    lgfx::Light_PWM   light_instance_;
    lgfx::Panel_ST7789 panel_instance_;
    lgfx::Touch_GT911  touch_instance_;

public:
    LGFX_TDeck() {
        // SPI Bus configuration
        {
            auto cfg = bus_instance_.config();
            cfg.spi_host   = SPI2_HOST;
            cfg.spi_3wire  = true;
            cfg.spi_mode   = 0;
            cfg.freq_write = 40000000;
            cfg.freq_read  = 16000000;
            cfg.pin_sclk   = PIN_LCD_SCLK;
            cfg.pin_mosi   = PIN_LCD_MOSI;
            cfg.pin_miso   = PIN_LCD_MISO;
            cfg.pin_dc     = PIN_LCD_DC;
            bus_instance_.config(cfg);
            panel_instance_.setBus(&bus_instance_);
        }

        // Backlight PWM configuration
        {
            auto cfg = light_instance_.config();
            cfg.pin_bl      = PIN_LCD_BL;
            cfg.freq        = 12000;
            cfg.pwm_channel = 7;
            cfg.invert      = false;
            light_instance_.config(cfg);
            panel_instance_.light(&light_instance_);
        }

        // ST7789 Panel configuration
        {
            auto cfg = panel_instance_.config();
            cfg.pin_cs       = PIN_LCD_CS;
            cfg.pin_rst      = -1;
            cfg.panel_width  = 240;
            cfg.panel_height = 320;
            cfg.offset_x     = 0;
            cfg.offset_y     = 0;
            cfg.invert       = true;
            cfg.rgb_order    = false;
            cfg.dlen_16bit   = false;
            cfg.bus_shared   = true;
            panel_instance_.config(cfg);
        }

        // GT911 Capacitive Touch configuration (T-Deck Plus)
        {
            auto cfg = touch_instance_.config();
            cfg.x_min      = 0;
            cfg.x_max      = 319;
            cfg.y_min      = 0;
            cfg.y_max      = 239;
            cfg.pin_int    = PIN_TOUCH_INT;
            cfg.pin_rst    = -1;
            cfg.bus_shared = true;
            cfg.i2c_port   = 0;
            cfg.i2c_addr   = TOUCH_I2C_ADDR;
            cfg.pin_sda    = PIN_I2C_SDA;
            cfg.pin_scl    = PIN_I2C_SCL;
            cfg.freq       = 400000;
            touch_instance_.config(cfg);
            panel_instance_.setTouch(&touch_instance_);
        }

        setPanel(&panel_instance_);
    }
};

// --- Thin Hardware Adapters Implementing `zd::hal` Contracts ---

class TDeckPowerSensor final : public zd::hal::IPowerSensor {
public:
    void init() {
        pinMode(PIN_BAT_ADC, INPUT);
        analogSetAttenuation(ADC_11db);
    }

    zd::hal::PowerStatus readPower() override {
        const uint32_t nowMs = millis();
        if (hasCache_ && (nowMs - lastReadMs_) < 2000u) {
            return cached_;
        }
        lastReadMs_ = nowMs;
        hasCache_ = true;

        // Sample ADC with 4-reading moving average
        uint32_t sumMv = 0;
        for (int i = 0; i < 4; ++i) {
            sumMv += analogReadMilliVolts(PIN_BAT_ADC);
        }
        const uint32_t rawMv = sumMv / 4;
        // Hardware features a 2:1 resistor divider (two 100k resistors)
        const uint32_t batMv = rawMv * 2;

        // LiPo curve: 4200 mV (100%), 3300 mV (0%)
        int32_t pct = 0;
        if (batMv >= 4200) {
            pct = 100;
        } else if (batMv <= 3300) {
            pct = 0;
        } else {
            pct = static_cast<int32_t>((batMv - 3300) * 100 / 900);
        }

        // Elevated voltage when USB charging (>4.25V)
        const bool charging = (batMv > 4250);
        cached_ = zd::hal::PowerStatus{pct, charging};
        return cached_;
    }

private:
    zd::hal::PowerStatus cached_{100, true};
    uint32_t lastReadMs_ = 0u;
    bool hasCache_ = false;
};

class TDeckDisplaySink final : public zd::hal::IDisplaySink {
public:
    void init() {
        // 1. Enable peripheral power rail (critical for display & peripherals on battery)
        pinMode(PIN_POWER_ON, OUTPUT);
        digitalWrite(PIN_POWER_ON, HIGH);

        // 2. Isolate shared SPI CS pins HIGH and initialize SPI bus before display init
        pinMode(PIN_LORA_CS, OUTPUT);
        digitalWrite(PIN_LORA_CS, HIGH);
        pinMode(PIN_SD_CS, OUTPUT);
        digitalWrite(PIN_SD_CS, HIGH);
        pinMode(PIN_LCD_CS, OUTPUT);
        digitalWrite(PIN_LCD_CS, HIGH);
        SPI.begin(PIN_LCD_SCLK, PIN_LCD_MISO, PIN_LCD_MOSI);

        // 3. Initialize LCD in landscape (320x240 QVGA)
        lcd_.init();
        lcd_.setRotation(1);
        lcd_.setBrightness(brightness_);

        // 4. Create RGB565 double-buffered sprite
        canvas_.setColorDepth(16);
        canvasReady_ = canvas_.createSprite(lcd_.width(), lcd_.height());
        if (!canvasReady_) {
            Serial.println("[DISPLAY] ERROR: createSprite failed; screen output disabled");
        }
    }

    void setOverlay(std::string text) { overlay_ = std::move(text); }
    void setGpsStatus(bool hasFix, uint8_t sats) {
        gpsFix_ = hasFix;
        gpsSats_ = sats;
    }

    void setBrightness(uint8_t level) {
        if (brightness_ != level) {
            brightness_ = level;
            lcd_.setBrightness(brightness_);
        }
    }

    zd::ScreenDimensions dimensions() const override {
        return zd::ScreenDimensions{
            static_cast<int16_t>(lcd_.width()),
            static_cast<int16_t>(lcd_.height())
        };
    }

    void present(const zd::UiFrame& frame) override {
        if (!canvasReady_) {
            return;
        }
        canvas_.setFont(&fonts::Font0);
        canvas_.setTextSize(1);
        zd::render::paintUiFrame(canvas_, frame);

        const int32_t w = lcd_.width();
        const int32_t h = lcd_.height();
        if (gpsFix_ || gpsSats_ > 0u) {
            char gpsTag[16];
            if (gpsFix_) {
                snprintf(gpsTag, sizeof(gpsTag), "GPS:%u", static_cast<unsigned>(gpsSats_));
            } else {
                snprintf(gpsTag, sizeof(gpsTag), "GPS..");
            }
            const uint16_t fg = gpsFix_ ? frame.palette.accent : frame.palette.muted;
            canvas_.setTextColor(fg, frame.palette.bg);
            canvas_.drawString(gpsTag, w - 42, frame.footerDividerY - 10);
        }

        if (!overlay_.empty()) {
            canvas_.fillRect(0, h - 12, w, 12, frame.palette.bg);
            canvas_.drawFastHLine(0, h - 12, w, frame.palette.accent);
            canvas_.setTextColor(frame.palette.fg, frame.palette.bg);
            canvas_.setCursor(3, h - 10);
            canvas_.print(overlay_.c_str());
        }
        canvas_.pushSprite(0, 0);
    }

    LGFX_TDeck& lcd() { return lcd_; }

private:
    LGFX_TDeck lcd_;
    lgfx::LGFX_Sprite canvas_{&lcd_};
    bool canvasReady_ = false;
    std::string overlay_;
    bool gpsFix_ = false;
    uint8_t gpsSats_ = 0u;
    uint8_t brightness_ = 180u;
};

// --- Optional MIA-M10Q GNSS / GPS Telemetry (T-Deck Plus) ---

HardwareSerial gGpsSerial(1);
zd::esp32_common::GpsState gGps;
std::string gGpsNmeaLine;

void initGps() {
    gGpsSerial.begin(9600, SERIAL_8N1, PIN_GPS_RX, PIN_GPS_TX);
}

void pollGps(uint32_t nowMs) {
    zd::esp32_common::expireStaleGpsFix(gGps, nowMs);
    while (gGpsSerial.available() > 0) {
        const char c = static_cast<char>(gGpsSerial.read());
        if (c == '\n' || c == '\r') {
            if (!gGpsNmeaLine.empty()) {
                (void)zd::esp32_common::processNmeaSentence(gGps, gGpsNmeaLine, nowMs);
                gGpsNmeaLine.clear();
            }
        } else if (gGpsNmeaLine.size() < 120u) {
            gGpsNmeaLine.push_back(c);
        }
    }
}

// --- Runtime State & Adapters ---

Esp32WifiScanner gRadio;
Esp32BleScanner gBle;
TDeckPowerSensor gPower;
NvsThemeStore gThemeStore;
TDeckDisplaySink gDisplay;
zd::hal::PlatformSession gSession;

// Active-offense console (deauth injection). Inert until explicitly armed + allow-listed at
// the serial `sec` console; runtime-gated only. See docs/OFFENSIVE.md.
zd::esp32_common::OffensiveConsole gOffensive;

zd::esp32_common::DirtyFramePacer gFramePacer;
zd::WigleLogger gWigle;
bool gSdReady = false;
bool gWardriveEnabled = false;
std::string gSerialLine;
std::string gKeyboardLine;
std::string gKbFeedback;
uint32_t gKbFeedbackUntilMs = 0;
std::string gLastKbOverlay;
uint32_t gLastActivityMs = 0;

// Trackball button state & touch gesture state
zd::esp32_common::ShortLongButton gTbBtn;
uint32_t gLastTbRollMs = 0;
zd::esp32_common::TouchZoneGesture gTouchGesture;

void wakeDisplay(uint32_t nowMs) {
    gLastActivityMs = nowMs;
    gDisplay.setBrightness(180u);
}

void logSerialStatus(const char* eventTag) {
    char gpsBuf[64] = "";
    if (gGps.hasFix) {
        snprintf(gpsBuf, sizeof(gpsBuf), " | GPS: %.4f,%.4f (%u sats)",
                 gGps.latitude, gGps.longitude, static_cast<unsigned>(gGps.satellites));
    }
    zd::esp32_common::printSerialStatus(gSession, eventTag, gpsBuf);
}

void setKbFeedback(const std::string& msg, uint32_t nowMs) {
    std::string line = msg;
    const std::size_t nl = line.find('\n');
    if (nl != std::string::npos) {
        line.resize(nl);
    }
    if (line.size() > 50u) {
        line.resize(50u);
    }
    gKbFeedback = std::move(line);
    gKbFeedbackUntilMs = nowMs + 3000u;
}

void flushWigleToSd() {
#ifdef ZD_HAS_ESP32_SD
    if (!gWardriveEnabled || !gSdReady || !gGps.hasFix) {
        return;
    }
    const auto lines = gWigle.recordScan(gRadio.lastNetworks(), gRadio.lastBssids(), gGps);
    if (lines.empty()) {
        return;
    }
    const bool needsHeader = !SD.exists("/wigle_zd.csv");
    File f = SD.open("/wigle_zd.csv", FILE_APPEND);
    if (!f) {
        return;
    }
    if (needsHeader) {
        f.print(zd::formatWigleHeader().c_str());
    }
    for (const std::string& ln : lines) {
        f.print(ln.c_str());
    }
    f.close();
#endif
}

std::string executeConsoleLine(const std::string& line, uint32_t nowMs, const char* srcTag) {
    if (line == "sec" || line.rfind("sec ", 0) == 0) {
        return gOffensive.handleLine(line, nowMs, &gSession);
    }
    if (line == "ble on") {
        gBle.setEnabled(true);
        return "BLE scanner: enabled\n";
    }
    if (line == "ble off") {
        gBle.setEnabled(false);
        return "BLE scanner: disabled\n";
    }
    if (line == "wardrive on") {
#ifdef ZD_HAS_ESP32_SD
        if (!gSdReady) {
            gSdReady = SD.begin(PIN_SD_CS);
        }
        gWardriveEnabled = gSdReady;
        return gSdReady ? "WiGLE SD logging enabled (/wigle_zd.csv)\n"
                        : "SD card not detected; wardriving unavailable\n";
#else
        return "SD support disabled in build\n";
#endif
    }
    if (line == "wardrive off") {
        gWardriveEnabled = false;
        return "WiGLE SD logging disabled\n";
    }
    if (line == "wardrive") {
        char buf[80];
        snprintf(buf, sizeof(buf), "Wardrive: %s | SD:%s | Logged:%lu\n",
                 gWardriveEnabled ? "ON" : "OFF", gSdReady ? "OK" : "NO",
                 static_cast<unsigned long>(gWigle.loggedCount()));
        return std::string(buf);
    }
    if (line == "gps") {
        if (gGps.hasFix) {
            char buf[96];
            snprintf(buf, sizeof(buf), "GPS: FIX OK | Lat: %.5f Lon: %.5f | Sats: %u | %s UTC\n",
                     gGps.latitude, gGps.longitude, static_cast<unsigned>(gGps.satellites),
                     gGps.utcTime);
            return std::string(buf);
        }
        return "GPS: Searching for satellites...\n";
    }
    const zd::hal::CliOutcome res = zd::hal::interpretCliLine(
        line, gSession.state(), gDisplay.dimensions(), nowMs);
    if (res.event.has_value()) {
        gSession.dispatch(*res.event, &gThemeStore);
        logSerialStatus(srcTag);
    }
    return res.output;
}

void pollSerialCli(uint32_t nowMs) {
    zd::esp32_common::pollSerialLines(gSerialLine, [&](const std::string& line) {
        wakeDisplay(nowMs);
        const std::string out = executeConsoleLine(line, nowMs, "SERIAL");
        if (!out.empty()) {
            Serial.print(out.c_str());
        }
    });
}

void initTrackball() {
    pinMode(PIN_TB_CLICK, INPUT_PULLUP);
    pinMode(PIN_TB_UP, INPUT_PULLUP);
    pinMode(PIN_TB_DOWN, INPUT_PULLUP);
    pinMode(PIN_TB_LEFT, INPUT_PULLUP);
    pinMode(PIN_TB_RIGHT, INPUT_PULLUP);
}

void pollTrackball(uint32_t nowMs) {
    // 1. Center Click / BOOT button (GPIO 0)
    using Ev = zd::esp32_common::ShortLongButton::Event;
    switch (gTbBtn.update(digitalRead(PIN_TB_CLICK) == LOW, nowMs, 600u, 25u)) {
        case Ev::LongHold:
            wakeDisplay(nowMs);
            gSession.dispatch(zd::ButtonBPressedEvent{nowMs}, &gThemeStore);
            logSerialStatus("TB_HOLD_SCAN");
            break;
        case Ev::ShortClick:
            wakeDisplay(nowMs);
            gSession.dispatch(zd::ButtonAPressedEvent{nowMs}, &gThemeStore);
            logSerialStatus("TB_CLICK_VIEW");
            break;
        case Ev::None:
            break;
    }

    // 2. Directional roll (active LOW pulses with debouncing)
    constexpr uint32_t kRollDebounceMs = 140u;
    if ((nowMs - gLastTbRollMs) >= kRollDebounceMs) {
        if (digitalRead(PIN_TB_LEFT) == LOW) {
            gLastTbRollMs = nowMs;
            wakeDisplay(nowMs);
            gSession.dispatch(zd::CycleThemeEvent{nowMs, -1}, &gThemeStore);
            logSerialStatus("TB_LEFT_THEME");
        } else if (digitalRead(PIN_TB_RIGHT) == LOW) {
            gLastTbRollMs = nowMs;
            wakeDisplay(nowMs);
            gSession.dispatch(zd::CycleThemeEvent{nowMs, +1}, &gThemeStore);
            logSerialStatus("TB_RIGHT_THEME");
        } else if (digitalRead(PIN_TB_UP) == LOW) {
            gLastTbRollMs = nowMs;
            wakeDisplay(nowMs);
            gSession.dispatch(zd::CyclePageEvent{nowMs, -1}, &gThemeStore);
            logSerialStatus("TB_UP_VIEW");
        } else if (digitalRead(PIN_TB_DOWN) == LOW) {
            gLastTbRollMs = nowMs;
            wakeDisplay(nowMs);
            gSession.dispatch(zd::CyclePageEvent{nowMs, +1}, &gThemeStore);
            logSerialStatus("TB_DOWN_VIEW");
        }
    }
}

uint32_t gLastKbPollMs = 0;

void initKeyboard() {
    pinMode(PIN_KB_INT, INPUT_PULLUP);
}

void pollKeyboard(uint32_t nowMs) {
    // Stock LILYGO T-Deck ESP32-C3 keyboard firmware requires periodic I2C polling (returns
    // 0x00 when idle) and does not always assert PIN_KB_INT; custom C3 firmware asserts
    // PIN_KB_INT LOW. Supporting both ensures keys work across all T-Deck board revisions.
    const bool intLow = (digitalRead(PIN_KB_INT) == LOW);
    if (!intLow && (nowMs - gLastKbPollMs) < 40u) {
        return;
    }
    gLastKbPollMs = nowMs;

    Wire.requestFrom(static_cast<uint8_t>(KB_I2C_ADDR), static_cast<uint8_t>(1));
    if (Wire.available() > 0) {
        const char c = static_cast<char>(Wire.read());
        if (c == 0) {
            return;
        }
        wakeDisplay(nowMs);

        if (c == '\r' || c == '\n') {
            if (gKeyboardLine.empty()) {
                // Empty Enter key: quick shortcut triggers a WiFi scan
                gSession.dispatch(zd::ButtonBPressedEvent{nowMs}, &gThemeStore);
                setKbFeedback("Scan requested", nowMs);
                logSerialStatus("KB_SCAN");
            } else {
                const std::string out = executeConsoleLine(gKeyboardLine, nowMs, "KB_CLI");
                if (!out.empty()) {
                    Serial.print(out.c_str());
                    setKbFeedback(out, nowMs);
                }
                gKeyboardLine.clear();
            }
        } else if (c == 0x08 || c == 127) { // Backspace
            if (!gKeyboardLine.empty()) {
                gKeyboardLine.pop_back();
            }
        } else if (c == 0x1B) { // Escape
            gKeyboardLine.clear();
            gKbFeedbackUntilMs = 0u;
        } else if (gKeyboardLine.empty() && (c == ' ' || c == '\t')) {
            gSession.dispatch(zd::CyclePageEvent{nowMs, +1}, &gThemeStore);
            logSerialStatus("KB_VIEW");
        } else if (gKeyboardLine.empty() && c == 'm') {
            gSession.dispatch(zd::CycleOpsModeEvent{nowMs}, &gThemeStore);
            logSerialStatus("KB_MODE");
        } else if (gKeyboardLine.empty() && c == '1') {
            gSession.dispatch(zd::SetPageEvent{nowMs, zd::ScreenPage::PetFace}, &gThemeStore);
            logSerialStatus("KB_PAGE_FACE");
        } else if (gKeyboardLine.empty() && c == '2') {
            gSession.dispatch(zd::SetPageEvent{nowMs, zd::ScreenPage::NearbyRadar}, &gThemeStore);
            logSerialStatus("KB_PAGE_RADAR");
        } else if (gKeyboardLine.empty() && c == '3') {
            gSession.dispatch(zd::SetPageEvent{nowMs, zd::ScreenPage::ChannelSpectrum}, &gThemeStore);
            logSerialStatus("KB_PAGE_SPECTRUM");
        } else if (gKeyboardLine.empty() && c == '4') {
            gSession.dispatch(zd::SetPageEvent{nowMs, zd::ScreenPage::RfGuard}, &gThemeStore);
            logSerialStatus("KB_PAGE_RFGUARD");
        } else if (gKeyboardLine.empty() && c == '[') {
            gSession.dispatch(zd::CycleThemeEvent{nowMs, -1}, &gThemeStore);
            logSerialStatus("KB_THEME_PREV");
        } else if (gKeyboardLine.empty() && c == ']') {
            gSession.dispatch(zd::CycleThemeEvent{nowMs, +1}, &gThemeStore);
            logSerialStatus("KB_THEME_NEXT");
        } else if (gKeyboardLine.size() < 64u && c >= 32 && c <= 126) {
            gKeyboardLine.push_back(c);
        }
    }
}

void pollTouch(uint32_t nowMs, LGFX_TDeck& lcd) {
    uint16_t tx = 0;
    uint16_t ty = 0;
    const bool isTouched = lcd.getTouch(&tx, &ty);
    if (const char* tag = zd::esp32_common::dispatchTouchAction(
            gTouchGesture.update(isTouched, tx, ty, nowMs, 0u, gDisplay.dimensions()),
            nowMs, gSession, &gThemeStore)) {
        wakeDisplay(nowMs);
        logSerialStatus(tag);
    }
}

} // namespace

void setup() {
    Serial.begin(115200);

    // Initialize shared 400 kHz I2C bus before GT911 touch init inside gDisplay.init().
    Wire.begin(PIN_I2C_SDA, PIN_I2C_SCL, 400000u);

    // Initialize display & peripheral power rails
    gDisplay.init();
    initTrackball();
    initKeyboard();
    initGps();

    gRadio.init();
    gBle.init();
    gPower.init();
    gThemeStore.init();
    gOffensive.begin();
#ifdef ZD_HAS_ESP32_SD
    gSdReady = SD.begin(PIN_SD_CS);
    gWardriveEnabled = gSdReady;
#endif

    const uint32_t bootMs = millis();
    gLastActivityMs = bootMs;

    // Seed pure functional PRNG with hardware entropy & restore theme from NVS
    gSession.boot(esp_random(), bootMs, &gThemeStore);
    gSession.renderTo(gDisplay);
    logSerialStatus("BOOT");
}

void loop() {
    const uint32_t nowMs = millis();

    // 1. Poll physical inputs: trackball, keyboard coprocessor, touchscreen, serial CLI
    pollTrackball(nowMs);
    pollKeyboard(nowMs);
    pollTouch(nowMs, gDisplay.lcd());
    pollSerialCli(nowMs);
    pollGps(nowMs);
    gDisplay.setGpsStatus(gGps.hasFix, gGps.satellites);

    // 2. Step non-blocking multi-radio scanner & periodic telemetry tick
    if (const char* scanTag = gSession.stepMultiRadio(
            nowMs, gRadio, &gBle, nullptr, &gThemeStore)) {
        if (std::string(scanTag) == "SCAN_DONE") {
            flushWigleToSd();
        }
        logSerialStatus(scanTag);
    }
    gSession.stepTick(nowMs, gPower);

    // Dim backlight after 45s of idle while running on battery
    if (!gSession.state().isCharging && (nowMs - gLastActivityMs) >= 45000u) {
        gDisplay.setBrightness(48u);
    }

    // 3. Synchronize keyboard overlay & refresh display when dirty
    std::string kbOverlay;
    if (!gKeyboardLine.empty()) {
        kbOverlay = "> " + gKeyboardLine + "_";
    } else if (gKbFeedbackUntilMs != 0u &&
               static_cast<int32_t>(gKbFeedbackUntilMs - nowMs) > 0 &&
               !gKbFeedback.empty()) {
        kbOverlay = gKbFeedback;
    } else {
        gKbFeedbackUntilMs = 0u;
    }
    const bool kbChanged = (kbOverlay != gLastKbOverlay);
    if (kbChanged) {
        gLastKbOverlay = kbOverlay;
        gDisplay.setOverlay(std::move(kbOverlay));
    }
    if (kbChanged || gFramePacer.shouldRender(gSession.state(), nowMs)) {
        gSession.renderTo(gDisplay);
        gFramePacer.markRendered(nowMs);
    }

    delay(10);
}
