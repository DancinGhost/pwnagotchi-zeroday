#pragma once

// Shared ESP32 serial console & dirty-checked frame pacing helpers.
// Used across M5Stick/Core2, CYD, and T-Deck shells to eliminate duplication,
// properly handle backspace / control chars in serial input, and avoid redundant
// 20 FPS full-screen SPI redraws on static themes.

#include <Arduino.h>

#include <cstdint>
#include <string>

#include "zd/hal.hpp"
#include "zd/theme.hpp"

namespace zd {
namespace esp32_common {

// Feeds incoming Serial bytes into `lineBuf` with backspace (0x08/0x7F) and printable-ASCII
// filtering; invokes `onLine(const std::string&)` on CR/LF.
template <typename OnLineFn>
inline void pollSerialLines(std::string& lineBuf, OnLineFn&& onLine, std::size_t maxLen = 64u) {
    while (Serial.available() > 0) {
        const char c = static_cast<char>(Serial.read());
        if (c == '\n' || c == '\r') {
            if (!lineBuf.empty()) {
                onLine(lineBuf);
                lineBuf.clear();
            }
        } else if (c == 0x08 || c == 0x7F) {
            if (!lineBuf.empty()) {
                lineBuf.pop_back();
            }
        } else if (lineBuf.size() < maxLen && c >= 32 && c <= 126) {
            lineBuf.push_back(c);
        }
    }
}

// Tracks whether the display actually needs an SPI push this tick:
// - 20 FPS (50 ms) while scanning, while a theme toast is visible, or on animated themes.
// - Immediate redraw when state changes (page, theme, mood, phrase, scan count, battery).
// - 1 Hz (1000 ms) fallback for the uptime clock when idle on static themes.
class DirtyFramePacer {
public:
    bool shouldRender(const zd::AppState& st, uint32_t nowMs) {
        const bool animated = st.isScanning ||
                              zd::isThemeToastVisible(st.themeToastUntilMs, nowMs) ||
                              zd::themeSpec(st.theme).effect != zd::ThemeEffect::None;
        const bool stateChanged =
            !initialized_ || st.page != lastPage_ || st.theme != lastTheme_ ||
            st.mood != lastMood_ || st.completedScans != lastScans_ ||
            st.batteryPercent != lastBat_ || st.isCharging != lastCharging_ ||
            st.phrase != lastPhrase_;

        const uint32_t minInterval = animated ? 50u : 1000u;
        if (!stateChanged && (nowMs - lastRenderMs_) < minInterval) {
            return false;
        }
        if (stateChanged && (nowMs - lastRenderMs_) < 25u && initialized_) {
            return false;
        }

        initialized_ = true;
        lastRenderMs_ = nowMs;
        lastPage_ = st.page;
        lastTheme_ = st.theme;
        lastMood_ = st.mood;
        lastScans_ = st.completedScans;
        lastBat_ = st.batteryPercent;
        lastCharging_ = st.isCharging;
        lastPhrase_ = st.phrase;
        return true;
    }

    void markRendered(uint32_t nowMs) { lastRenderMs_ = nowMs; }

private:
    bool initialized_ = false;
    uint32_t lastRenderMs_ = 0;
    zd::ScreenPage lastPage_ = zd::ScreenPage::PetFace;
    zd::ThemeId lastTheme_ = zd::ThemeId::PaperInk;
    zd::Mood lastMood_ = zd::Mood::Awake;
    uint32_t lastScans_ = 0;
    int32_t lastBat_ = -1;
    bool lastCharging_ = false;
    std::string lastPhrase_;
};

}  // namespace esp32_common
}  // namespace zd
