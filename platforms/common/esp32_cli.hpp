#pragma once

// Shared ESP32 serial console & dirty-checked frame pacing helpers.
// Used across M5Stick/Core2, CYD, and T-Deck shells to eliminate duplication,
// properly handle backspace / control chars in serial input, and avoid redundant
// 20 FPS full-screen SPI redraws on static themes.

#include <Arduino.h>

#include <algorithm>
#include <cstdint>
#include <string>

#include "frame_pacer.hpp"
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

inline void printSerialStatus(const zd::hal::PlatformSession& session,
                              const char* eventTag,
                              const char* extraSuffix = nullptr) {
    const zd::AppState& st = session.state();
    const zd::FaceDescriptor face = zd::faceForMood(st.mood);
    Serial.printf("[%s] %s %s> \"%s\" | APs:%u | BusiestCh:%d | Theme:%s%s\n",
                  eventTag,
                  face.asciiFace,
                  st.petName.c_str(),
                  st.phrase.c_str(),
                  static_cast<unsigned>(st.latestScan.totalAps),
                  static_cast<int>(st.latestScan.busiestChannel),
                  zd::themeSpec(st.theme).key,
                  extraSuffix != nullptr ? extraSuffix : "");
}

// Reusable short-click / long-hold debounced physical button state machine.
struct ShortLongButton {
    enum class Event : uint8_t {
        None = 0,
        ShortClick,
        LongHold
    };

    Event update(bool pressed, uint32_t nowMs, uint32_t longMs = 600u, uint32_t debounceMs = 25u) {
        if (pressed && !active_) {
            active_ = true;
            longHandled_ = false;
            startMs_ = nowMs;
            return Event::None;
        }
        if (pressed && active_ && !longHandled_) {
            const uint32_t held = nowMs - startMs_;
            if (held < 0x80000000u && held >= longMs) {
                longHandled_ = true;
                return Event::LongHold;
            }
            return Event::None;
        }
        if (!pressed && active_) {
            active_ = false;
            const uint32_t held = nowMs - startMs_;
            if (!longHandled_ && held < 0x80000000u && held >= debounceMs) {
                return Event::ShortClick;
            }
        }
        return Event::None;
    }

private:
    bool active_ = false;
    bool longHandled_ = false;
    uint32_t startMs_ = 0u;
};

// Shared resistive/capacitive touch zone gesture recognizer with release debounce & cooldown.
struct TouchZoneGesture {
    enum class Action : uint8_t {
        None = 0,
        PrevTheme,
        NextTheme,
        PrevView,
        NextView,
        Scan,
        CycleMode
    };

    Action update(bool isTouched,
                  uint16_t tx,
                  uint16_t ty,
                  uint32_t nowMs,
                  uint32_t releaseDebounceMs,
                  zd::ScreenDimensions dims = zd::ScreenDimensions{320, 240}) {
        if (cooldownUntilMs_ != 0u && static_cast<int32_t>(cooldownUntilMs_ - nowMs) > 0) {
            return Action::None;
        }
        const int32_t w = (dims.width > 0) ? dims.width : 320;
        const int32_t h = (dims.height > 0) ? dims.height : 240;
        const uint16_t topBandY = static_cast<uint16_t>((std::max)(int32_t{20}, (h * 42) / 240));
        const uint16_t leftMaxX = static_cast<uint16_t>((w * 100) / 320);
        const uint16_t rightMinX = static_cast<uint16_t>((w * 220) / 320);
        const uint16_t modeMinX = static_cast<uint16_t>((w * 250) / 320);

        if (isTouched) {
            lastSeenMs_ = nowMs;
            if (!active_) {
                active_ = true;
                longHandled_ = false;
                startMs_ = nowMs;
                startX_ = tx;
                startY_ = ty;
            } else if (!longHandled_ && (nowMs - startMs_) >= 600u) {
                if (startY_ < topBandY) {
                    longHandled_ = true;
                    cooldownUntilMs_ = nowMs + 250u;
                    return Action::PrevTheme;
                }
                if (startX_ >= leftMaxX && startX_ <= rightMinX) {
                    longHandled_ = true;
                    cooldownUntilMs_ = nowMs + 250u;
                    return Action::CycleMode;
                }
            }
            return Action::None;
        }
        if (active_ && (nowMs - lastSeenMs_) >= releaseDebounceMs) {
            active_ = false;
            if (longHandled_) {
                return Action::None;
            }
            const uint32_t duration = lastSeenMs_ - startMs_;
            if (duration < 600u) {
                cooldownUntilMs_ = nowMs + 150u;
                if (startY_ < topBandY) {
                    return (startX_ >= modeMinX) ? Action::CycleMode : Action::NextTheme;
                }
                if (startX_ < leftMaxX) {
                    return Action::PrevView;
                }
                if (startX_ > rightMinX) {
                    return Action::NextView;
                }
                return Action::Scan;
            }
        }
        return Action::None;
    }

private:
    bool active_ = false;
    bool longHandled_ = false;
    uint32_t startMs_ = 0;
    uint32_t lastSeenMs_ = 0;
    uint32_t cooldownUntilMs_ = 0;
    uint16_t startX_ = 0;
    uint16_t startY_ = 0;
};

inline const char* dispatchTouchAction(TouchZoneGesture::Action act,
                                       uint32_t nowMs,
                                       zd::hal::PlatformSession& session,
                                       zd::hal::IThemeStore* store) {
    using Act = TouchZoneGesture::Action;
    switch (act) {
        case Act::PrevTheme:
            session.dispatch(zd::CycleThemeEvent{nowMs, -1}, store);
            return "TOUCH_THEME_PREV";
        case Act::NextTheme:
            session.dispatch(zd::CycleThemeEvent{nowMs, +1}, store);
            return "TOUCH_THEME";
        case Act::PrevView:
            session.dispatch(zd::CyclePageEvent{nowMs, -1}, store);
            return "TOUCH_VIEW_PREV";
        case Act::NextView:
            session.dispatch(zd::CyclePageEvent{nowMs, +1}, store);
            return "TOUCH_VIEW_NEXT";
        case Act::Scan:
            session.dispatch(zd::ButtonBPressedEvent{nowMs}, store);
            return "TOUCH_SCAN";
        case Act::CycleMode:
            session.dispatch(zd::CycleOpsModeEvent{nowMs}, store);
            return "TOUCH_MODE";
        case Act::None:
            break;
    }
    return nullptr;
}

}  // namespace esp32_common
}  // namespace zd
