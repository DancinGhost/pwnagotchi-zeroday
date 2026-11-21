#pragma once

// Shared ESP32 serial console & dirty-checked frame pacing helpers.
// Used across M5Stick/Core2, CYD, and T-Deck shells to eliminate duplication,
// properly handle backspace / control chars in serial input, and avoid redundant
// 20 FPS full-screen SPI redraws on static themes.

#include <Arduino.h>

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

    Action update(bool isTouched, uint16_t tx, uint16_t ty, uint32_t nowMs, uint32_t releaseDebounceMs) {
        if (cooldownUntilMs_ != 0u && static_cast<int32_t>(cooldownUntilMs_ - nowMs) > 0) {
            return Action::None;
        }
        if (isTouched) {
            lastSeenMs_ = nowMs;
            if (!active_) {
                active_ = true;
                longHandled_ = false;
                startMs_ = nowMs;
                startX_ = tx;
                startY_ = ty;
            } else if (!longHandled_ && (nowMs - startMs_) >= 600u) {
                if (startY_ < 42) {
                    longHandled_ = true;
                    cooldownUntilMs_ = nowMs + 250u;
                    return Action::PrevTheme;
                }
                if (startX_ >= 100 && startX_ <= 220) {
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
                if (startY_ < 42) {
                    return (startX_ >= 250) ? Action::CycleMode : Action::NextTheme;
                }
                if (startX_ < 100) {
                    return Action::PrevView;
                }
                if (startX_ > 220) {
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

}  // namespace esp32_common
}  // namespace zd
