#pragma once

// Dirty-checked display frame pacer (portable, zero Arduino/OS headers).
//
// - Immediate redraw when UI state changes (page, theme, mood, phrase, scan count, battery,
//   offensive arming badge, or theme toast visibility).
// - Advances animated backdrop themes on actual `animTick` transitions (every 140 ms, ~7.1 Hz)
//   and passive scan eye sweeps on `scanAnimTick` transitions (every 450 ms) instead of burning
//   20 FPS SPI traffic.
// - 1 Hz (1000 ms) fallback for the uptime clock when idle on static themes.

#include <cstdint>
#include <string>

#include "zd/domain.hpp"
#include "zd/theme.hpp"

namespace zd {
namespace esp32_common {

class DirtyFramePacer {
public:
    bool shouldRender(const zd::AppState& st, uint32_t nowMs) {
        const bool toastVisible = zd::isThemeToastVisible(st.themeToastUntilMs, nowMs);
        const bool hasEffect = zd::themeSpec(st.theme).effect != zd::ThemeEffect::None;
        const uint32_t animTick = nowMs / 140u;

        const bool stateChanged =
            !initialized_ || st.page != lastPage_ || st.theme != lastTheme_ ||
            st.mood != lastMood_ || st.completedScans != lastScans_ ||
            st.batteryPercent != lastBat_ || st.isCharging != lastCharging_ ||
            st.phrase != lastPhrase_ || st.offensiveArmed != lastArmed_ ||
            st.opsMode != lastOpsMode_ || st.xp != lastXp_ ||
            st.highScore != lastHighScore_ || st.threatsDetected != lastThreats_ ||
            st.lastThreatLabel != lastThreatLabel_ || st.subGhzFreqKhz != lastSubGhzFreq_ ||
            st.bleDevices.size() != lastBleCount_ ||
            st.subGhzSignals.size() != lastSubGhzCount_ || toastVisible != lastToastVisible_;

        const bool hasPetIdleAnim = (st.page == zd::ScreenPage::PetFace);
        const bool hasSceneAnim = st.isScanning || st.offensiveArmed ||
                                  st.opsMode != zd::OpsMode::Recon ||
                                  st.mood == zd::Mood::ThreatAlert ||
                                  st.mood == zd::Mood::CyberAttack ||
                                  hasPetIdleAnim;

        const bool animChanged =
            ((hasEffect || hasSceneAnim) && animTick != lastAnimTick_) ||
            (st.isScanning && st.scanAnimTick != lastScanAnimTick_);

        if (!stateChanged && !animChanged) {
            if ((nowMs - lastRenderMs_) < 1000u) {
                return false;
            }
        } else if (initialized_ && (nowMs - lastRenderMs_) < 25u) {
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
        lastArmed_ = st.offensiveArmed;
        lastOpsMode_ = st.opsMode;
        lastXp_ = st.xp;
        lastHighScore_ = st.highScore;
        lastThreats_ = st.threatsDetected;
        lastThreatLabel_ = st.lastThreatLabel;
        lastSubGhzFreq_ = st.subGhzFreqKhz;
        lastBleCount_ = st.bleDevices.size();
        lastSubGhzCount_ = st.subGhzSignals.size();
        lastToastVisible_ = toastVisible;
        lastAnimTick_ = animTick;
        lastScanAnimTick_ = st.scanAnimTick;
        return true;
    }

    void markRendered(uint32_t nowMs) { lastRenderMs_ = nowMs; }

private:
    bool initialized_ = false;
    uint32_t lastRenderMs_ = 0;
    zd::ScreenPage lastPage_ = zd::ScreenPage::PetFace;
    zd::ThemeId lastTheme_ = zd::ThemeId::PaperInk;
    zd::Mood lastMood_ = zd::Mood::Awake;
    zd::OpsMode lastOpsMode_ = zd::OpsMode::Recon;
    uint32_t lastScans_ = 0;
    uint32_t lastXp_ = 0;
    uint32_t lastHighScore_ = 0;
    uint32_t lastThreats_ = 0;
    uint32_t lastSubGhzFreq_ = 433920u;
    std::size_t lastBleCount_ = 0;
    std::size_t lastSubGhzCount_ = 0;
    int32_t lastBat_ = -1;
    bool lastCharging_ = false;
    bool lastArmed_ = false;
    bool lastToastVisible_ = false;
    uint32_t lastAnimTick_ = 0;
    uint8_t lastScanAnimTick_ = 0;
    std::string lastPhrase_;
    std::string lastThreatLabel_;
};

}  // namespace esp32_common
}  // namespace zd
