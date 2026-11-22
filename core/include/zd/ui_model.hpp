#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "domain.hpp"
#include "fp.hpp"
#include "pet_logic.hpp"
#include "theme.hpp"
#include "wifi_analysis.hpp"

namespace zd {

struct ScreenDimensions {
    int16_t width = 240;
    int16_t height = 135;
};

struct ScreenProfile {
    const char* key;
    const char* label;
    ScreenDimensions dims;
    bool monochrome;
};

// Common hardware display profiles across target form factors.
// `buildUiFrame` works with *any* arbitrary ScreenDimensions, not just these presets.
inline constexpr std::array<ScreenProfile, 5> kScreenProfiles = {{
    {"micro",   "128x64 OLED (SSD1306 / SH1106)",            {128, 64},  true},
    {"compact", "160x80 TFT (M5StickC / 0.96\" IPS)",        {160, 80},  false},
    {"plus",    "240x135 TFT (StickC Plus2 / Cardputer)",    {240, 135}, false},
    {"epaper",  "250x122 e-Paper (2.13\" HAT)",              {250, 122}, true},
    {"wide",    "320x240 QVGA (Core2 / CYD / T-Deck)",       {320, 240}, false},
}};

inline std::optional<ScreenProfile> screenProfileFromKey(std::string_view key) {
    for (const ScreenProfile& p : kScreenProfiles) {
        if (key == p.key) {
            return p;
        }
    }
    return std::nullopt;
}

// Device-ready RGB565 palette (native format of the ST7789/ILI9341 TFTs used by
// M5Stack/M5Stick and most ESP32 boards). Backends needing other color formats can
// read the platform-neutral `ThemePalette` via `themeSpec(frame.theme).palette`.
struct ColorPalette {
    uint16_t bg;
    uint16_t fg;
    uint16_t accent;
    uint16_t muted;
    uint16_t highlight;
};

constexpr ColorPalette toColorPalette(const ThemePalette& p) {
    return ColorPalette{
        toRgb565(p.bg),
        toRgb565(p.fg),
        toRgb565(p.accent),
        toRgb565(p.muted),
        toRgb565(p.highlight)
    };
}

// Pure theme -> RGB565 palette mapping (driven by the data catalog in theme.hpp).
constexpr ColorPalette resolvePalette(ThemeId theme) {
    return toColorPalette(themeSpec(theme).palette);
}

// Pure zero-padded 2-digit number formatter.
inline std::string twoDigit(uint32_t val) {
    const uint32_t clamped = val % 100u;
    std::string out(2, '0');
    out[0] = static_cast<char>('0' + (clamped / 10u));
    out[1] = static_cast<char>('0' + (clamped % 10u));
    return out;
}

// Pure uptime formatter: "HH:MM:SS" (full) or "MM:SS" / "HHhMM" (compact 160x80).
inline std::string formatUptime(uint32_t uptimeMs, bool compact = false) {
    const uint32_t totalSec = uptimeMs / 1000u;
    const uint32_t secs = totalSec % 60u;
    const uint32_t mins = (totalSec / 60u) % 60u;
    const uint32_t hours = (totalSec / 3600u) % 100u;

    if (compact) {
        if (hours > 0u) {
            return twoDigit(hours) + "h" + twoDigit(mins);
        }
        return twoDigit(mins) + ":" + twoDigit(secs);
    }
    return twoDigit(hours) + ":" + twoDigit(mins) + ":" + twoDigit(secs);
}

// Pure text truncator that fits `maxChars` columns cleanly.
inline std::string truncateText(const std::string& text, std::size_t maxChars) {
    if (maxChars == 0u) {
        return {};
    }
    if (text.size() <= maxChars) {
        return text;
    }
    if (maxChars <= 2u) {
        return text.substr(0u, maxChars);
    }
    return text.substr(0u, maxChars - 2u) + "..";
}

// Pure word-wrapper splitting `text` into at most `maxLines` lines of <= `maxCols` chars.
inline std::vector<std::string> wrapWords(const std::string& text,
                                          std::size_t maxCols,
                                          std::size_t maxLines) {
    if (maxCols == 0u || maxLines == 0u || text.empty()) {
        return {};
    }

    // Tokenize words purely
    std::vector<std::string> words;
    std::string currentWord;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\n') {
            if (!currentWord.empty()) {
                words.push_back(currentWord);
                currentWord.clear();
            }
        } else {
            currentWord.push_back(c);
        }
    }
    if (!currentWord.empty()) {
        words.push_back(currentWord);
    }

    std::vector<std::string> lines;
    std::string currentLine;

    for (const std::string& word : words) {
        const std::string clippedWord =
            (word.size() > maxCols) ? truncateText(word, maxCols) : word;

        if (currentLine.empty()) {
            currentLine = clippedWord;
        } else if (currentLine.size() + 1u + clippedWord.size() <= maxCols) {
            currentLine += " " + clippedWord;
        } else {
            lines.push_back(currentLine);
            if (lines.size() >= maxLines) {
                currentLine.clear();
                break;
            }
            currentLine = clippedWord;
        }
    }

    if (!currentLine.empty() && lines.size() < maxLines) {
        lines.push_back(currentLine);
    }

    return lines;
}

struct FaceGeometry {
    int16_t centerX;
    int16_t centerY;
    int16_t eyeOffsetX;
    int16_t eyeY;
    int16_t eyeRadius;
    int16_t mouthY;
    int16_t mouthRadius;
    int16_t bracketOffsetX;
    int16_t bracketHalfHeight;
    int16_t moodBadgeY;
};

struct RadarRowView {
    std::string ssid;
    std::string details;
    int bars;
    bool secure;
};

struct ChannelBarView {
    int32_t channel;
    uint16_t count;
    int16_t heightPx;
};

enum class ActivityScene : uint8_t {
    None = 0,
    RadarDish,
    SatelliteBeam,
    ThreatShield
};

// Transient overlay announcing the active theme after a switch.
struct ToastView {
    bool visible = false;
    std::string text{};
    int16_t x = 0;
    int16_t y = 0;
    int16_t w = 0;
    int16_t h = 0;
    int16_t textX = 0;
    int16_t textY = 0;
};

// Pure toast layout: centered in the body region, sized for the 6x8 px Font0 glyphs.
inline ToastView buildThemeToast(const AppState& state,
                                 ScreenDimensions dims,
                                 bool compact,
                                 int16_t bodyTop,
                                 int16_t bodyBottom) {
    ToastView t{};
    if (!isThemeToastVisible(state.themeToastUntilMs, state.uptimeMs)) {
        return t;
    }
    const std::string label = themeLabel(state.theme);
    const std::string position =
        std::to_string(themeIndex(state.theme) + 1u) + "/" + std::to_string(kThemeCount);
    const std::size_t maxChars =
        static_cast<std::size_t>((std::max)(8, (static_cast<int>(dims.width) - 16) / 6));
    t.text = truncateText(compact ? ("< " + label + " >")
                                  : ("THEME " + position + ": " + label),
                          maxChars);

    const int16_t padX = compact ? 5 : 8;
    const int16_t padY = compact ? 4 : 6;
    t.w = static_cast<int16_t>(static_cast<int16_t>(t.text.size()) * 6 + padX * 2);
    t.h = static_cast<int16_t>(8 + padY * 2);
    t.x = static_cast<int16_t>((dims.width - t.w) / 2);
    t.y = static_cast<int16_t>(bodyTop + ((bodyBottom - bodyTop) - t.h) / 2);
    t.textX = static_cast<int16_t>(t.x + padX);
    t.textY = static_cast<int16_t>(t.y + padY);
    t.visible = true;
    return t;
}

// Complete immutable UI View-Model ready for a dumb graphics driver to paint.
struct UiFrame {
    ScreenDimensions dims;
    bool compact;
    ColorPalette palette;
    ScreenPage page;

    int16_t headerDividerY;
    int16_t footerDividerY;
    int16_t headerTextY;
    int16_t footerTextY;

    std::string headerLine;
    std::string footerLine;

    // PetFace page fields
    FaceDescriptor face;
    FaceGeometry faceGeom;
    int16_t speechX;
    int16_t speechTopY;
    int16_t lineStepY;
    std::string promptLabel;
    std::vector<std::string> phraseLines;
    std::string spotlightLabel;

    // NearbyRadar page fields
    std::vector<RadarRowView> radarRows;
    std::string radarEmptyHint;

    // ChannelSpectrum page fields
    std::array<ChannelBarView, 13> channelBars;
    int16_t chartBaseY;
    int16_t chartMaxBarH;
    std::string spectrumSummary;

    // RfGuard (BLE + Sub-GHz) page fields
    std::vector<RadarRowView> rfGuardRows;
    std::string rfGuardSummary;
    std::string rfGuardEmptyHint;

    // Theming & Ops HUD
    ThemeId theme;
    ThemeEffect themeEffect;
    FaceStyle faceStyle;
    uint32_t animTick;
    ToastView toast;
    bool offensiveArmed = false;
    OpsMode opsMode = OpsMode::Recon;
    std::string modeBadge;
    uint8_t level = 1;
    uint32_t xp = 0;
    uint32_t highScore = 0;
    uint8_t xpProgressPct = 0;
    std::string rankLine;
    ActivityScene scene = ActivityScene::None;
    std::string threatBanner;
};

// Pure responsive layout & view-model projection: (AppState, ScreenDimensions) -> UiFrame
// Scales cleanly across micro OLEDs (128x64), compact sticks (160x80), pocket TFTs &
// 2.13" e-paper HATs (240x135 / 250x122), and QVGA cyberdecks (320x240+).
inline UiFrame buildUiFrame(const AppState& state, ScreenDimensions dims) {
    dims.width = (std::max)(static_cast<int16_t>(96), dims.width);
    dims.height = (std::max)(static_cast<int16_t>(56), dims.height);

    const bool micro = (dims.width < 150 || dims.height < 72);
    const bool compact = (dims.width < 200 || dims.height < 100);
    const bool wide = (dims.width >= 300 && dims.height >= 180);
    const ColorPalette palette = resolvePalette(state.theme);
    const FaceDescriptor face = faceForMood(state.mood);

    const int16_t headerH = micro ? 10 : (compact ? 12 : 17);
    const int16_t footerH = micro ? 10 : (compact ? 12 : 17);
    const int16_t headerDivY = headerH;
    const int16_t footerDivY = static_cast<int16_t>(dims.height - footerH - 1);

    // Dynamic 6px monospace character budget (20 on 128px, 26 on 160px, 39 on 240px, 52 on 320px).
    // Always reserve space on the right for the active ops mode badge ([RCN]/[DEF]/[OFF]/[ARMED]).
    const std::size_t maxFrameCols =
        static_cast<std::size_t>((std::max)(12, (static_cast<int>(dims.width) - 4) / 6));
    const OpsMode effectiveMode = state.offensiveArmed ? OpsMode::Offensive : state.opsMode;
    const std::string modeBadge =
        state.offensiveArmed
            ? (compact ? std::string("[ARM]") : std::string("[ARMED]"))
            : ("[" + std::string(opsModeLabel(effectiveMode, compact)) + "]");
    const std::size_t armBadgeCols = modeBadge.size() + 1u;
    const std::size_t maxHeaderCols =
        (maxFrameCols > armBadgeCols + 6u) ? (maxFrameCols - armBadgeCols) : maxFrameCols;

    // Header text
    const std::string chText =
        state.isScanning
            ? "CH:*"
            : (state.latestScan.busiestChannel > 0
                   ? ("CH:" + twoDigit(static_cast<uint32_t>(state.latestScan.busiestChannel)))
                   : "CH:--");

    const std::string apText = "AP:" + std::to_string(state.latestScan.totalAps);
    const std::string upText = "UP:" + formatUptime(state.uptimeMs, compact);
    const std::string batPrefix = state.isCharging ? "+" : "";
    const std::string batText = batPrefix + std::to_string(state.batteryPercent) + "%";

    std::string headerLine;
    if (micro) {
        headerLine = chText + " " + apText + " " + batText;
    } else if (compact) {
        headerLine = chText + " " + apText + " " + formatUptime(state.uptimeMs, true) + " " + batText;
    } else {
        const std::string peakPart =
            "(" + std::to_string(state.peakApCount) + ")";
        headerLine = (maxHeaderCols <= 34u)
                         ? (chText + " " + apText + peakPart + " " +
                            formatUptime(state.uptimeMs, false) + " " + batText)
                         : (chText + "  " + apText + peakPart + "  " + upText + "  " + batText);
    }
    headerLine = truncateText(headerLine, maxHeaderCols);

    // Footer text
    std::string footerLine;
    if (micro) {
        const std::string statusPart =
            state.isScanning ? "SCN.." : ("#" + twoDigit(state.completedScans));
        const std::string rssiPart =
            (state.latestScan.totalAps > 0u)
                ? (std::to_string(state.latestScan.strongestRssi) + "dB")
                : "--dB";
        footerLine = statusPart + " " + rssiPart + " [A]/[B]";
    } else if (compact) {
        const std::string statusPart =
            state.isScanning ? "SCAN.." : ("#" + twoDigit(state.completedScans));
        const std::string rssiPart =
            (state.latestScan.totalAps > 0u)
                ? (std::to_string(state.latestScan.strongestRssi) + "dB")
                : "--dB";
        footerLine = statusPart + " " + rssiPart + " [A]VW [B]SCN";
    } else {
        const std::string statusPart =
            state.isScanning ? "SCANNING.." : ("SCAN #" + twoDigit(state.completedScans));
        const std::string rssiPart =
            (state.latestScan.totalAps > 0u)
                ? ("BEST " + std::to_string(state.latestScan.strongestRssi) + "dBm")
                : "BEST --dBm";
        footerLine = statusPart + "  " + rssiPart + "  [A]PG [B]SCN";
    }
    footerLine = truncateText(footerLine, maxFrameCols);

    // PetFace geometry (Centered Hero Stack across all display profiles)
    const int16_t bodyTop = static_cast<int16_t>(headerDivY + 1);
    const int16_t bodyBottom = static_cast<int16_t>(footerDivY - 1);
    const int16_t bodyH = static_cast<int16_t>(bodyBottom - bodyTop);

    const ActivityScene scene =
        state.isScanning
            ? ActivityScene::RadarDish
            : ((effectiveMode == OpsMode::Offensive)
                   ? ActivityScene::SatelliteBeam
                   : ((effectiveMode == OpsMode::Defensive || state.mood == Mood::ThreatAlert)
                          ? ActivityScene::ThreatShield
                          : ActivityScene::None));

    FaceGeometry geom{};
    geom.centerX = static_cast<int16_t>(dims.width / 2);
    int16_t speechX = 0;
    int16_t speechTopY = 0;
    int16_t lineStepY = 0;
    std::size_t speechCols = 0;
    std::size_t speechMaxLines = 0;

    if (micro) {
        // 128x64 OLED centered layout
        geom.centerY = static_cast<int16_t>(bodyTop + (bodyH / 2) + 1);
        geom.eyeOffsetX = 9;
        geom.eyeY = static_cast<int16_t>(geom.centerY - 2);
        geom.eyeRadius = 4;
        geom.mouthY = static_cast<int16_t>(geom.centerY + 5);
        geom.mouthRadius = 3;
        geom.bracketOffsetX = 21;
        geom.bracketHalfHeight = 7;
        geom.moodBadgeY = static_cast<int16_t>(bodyBottom - 8);

        speechX = 4;
        speechTopY = static_cast<int16_t>(bodyTop + 1);
        lineStepY = 8;
        const int16_t reserve = (scene != ActivityScene::None) ? 18 : 0;
        speechCols = static_cast<std::size_t>((std::max)(6, (dims.width - 8 - reserve) / 6));
        speechMaxLines = 1u;
    } else if (compact) {
        // 160x80 centered layout
        geom.centerY = static_cast<int16_t>(bodyTop + (bodyH / 2));
        geom.eyeOffsetX = 11;
        geom.eyeY = static_cast<int16_t>(geom.centerY - 2);
        geom.eyeRadius = 5;
        geom.mouthY = static_cast<int16_t>(geom.centerY + 6);
        geom.mouthRadius = 4;
        geom.bracketOffsetX = 26;
        geom.bracketHalfHeight = 10;
        geom.moodBadgeY = static_cast<int16_t>(bodyBottom - 9);

        speechX = 4;
        speechTopY = static_cast<int16_t>(bodyTop + 2);
        lineStepY = 9;
        const int16_t reserve = (scene != ActivityScene::None) ? 24 : 0;
        speechCols = static_cast<std::size_t>((std::max)(8, (dims.width - 8 - reserve) / 6));
        speechMaxLines = 1u;
    } else if (wide) {
        // 320x240+ QVGA cyberdeck centered layout
        geom.centerY = static_cast<int16_t>(bodyTop + (bodyH / 2) - 4);
        geom.eyeOffsetX = 22;
        geom.eyeY = static_cast<int16_t>(geom.centerY - 5);
        geom.eyeRadius = 10;
        geom.mouthY = static_cast<int16_t>(geom.centerY + 13);
        geom.mouthRadius = 8;
        geom.bracketOffsetX = 54;
        geom.bracketHalfHeight = 26;
        geom.moodBadgeY = static_cast<int16_t>(bodyBottom - 34);

        speechX = 6;
        speechTopY = static_cast<int16_t>(bodyTop + 4);
        lineStepY = 11;
        const int16_t reserve = (scene != ActivityScene::None) ? 40 : 0;
        speechCols = static_cast<std::size_t>((std::max)(12, (dims.width - 12 - reserve) / 6));
        speechMaxLines = 2u;
    } else {
        // 240x135 / 250x122 standard pocket & e-paper centered layout
        geom.centerY = static_cast<int16_t>(bodyTop + (bodyH / 2));
        geom.eyeOffsetX = 16;
        geom.eyeY = static_cast<int16_t>(geom.centerY - 4);
        geom.eyeRadius = 7;
        geom.mouthY = static_cast<int16_t>(geom.centerY + 8);
        geom.mouthRadius = 5;
        geom.bracketOffsetX = 38;
        geom.bracketHalfHeight = 14;
        geom.moodBadgeY = static_cast<int16_t>(bodyBottom - 19);

        speechX = 4;
        speechTopY = static_cast<int16_t>(bodyTop + 2);
        lineStepY = 9;
        const int16_t reserve = (scene != ActivityScene::None) ? 32 : 0;
        speechCols = static_cast<std::size_t>((std::max)(12, (dims.width - 8 - reserve) / 6));
        speechMaxLines = 1u;
    }

    const bool onPetFace = (state.page == ScreenPage::PetFace);
    const bool onRadar = (state.page == ScreenPage::NearbyRadar);
    const bool onSpectrum = (state.page == ScreenPage::ChannelSpectrum);
    const bool onRfGuard = (state.page == ScreenPage::RfGuard);

    const LevelInfo lvlInfo = deriveLevelInfo(state.xp);
    std::string promptLabel;
    std::vector<std::string> wrappedPhrase;
    std::string rankLine;
    std::string threatBanner;
    if (!state.lastThreatLabel.empty()) {
        threatBanner = truncateText("! " + state.lastThreatLabel, maxFrameCols);
    }
    std::string spotlightLabel;
    if (onPetFace) {
        const std::size_t promptMaxCols =
            compact ? (speechCols > 10u ? (std::min)(std::size_t{9}, speechCols / 2u) : speechCols)
                    : speechCols;
        promptLabel = truncateText(state.petName + ">", promptMaxCols);
        const std::size_t phraseCols =
            compact
                ? ((speechCols > promptLabel.size() + 1u) ? (speechCols - promptLabel.size() - 1u)
                                                         : 0u)
                : speechCols;
        wrappedPhrase = wrapWords(state.phrase, phraseCols, speechMaxLines);

        if (!compact) {
            const std::size_t maxRankCols =
                wide ? ((dims.width > 68) ? static_cast<std::size_t>((dims.width - 64) / 6)
                                          : maxFrameCols)
                     : 16u;
            rankLine = truncateText(
                "LV" + std::to_string(lvlInfo.level) + " HI:" + std::to_string(state.highScore),
                maxRankCols);
        }

        if (!compact && !threatBanner.empty()) {
            spotlightLabel = threatBanner;
        } else if (!compact && state.latestScan.totalAps > 0u &&
                   !state.latestScan.strongestSsid.empty()) {
            const std::string rawSpot =
                "> " + state.latestScan.strongestSsid + " (" +
                std::to_string(state.latestScan.strongestRssi) + ")";
            spotlightLabel = truncateText(rawSpot, maxFrameCols);
        }
    }

    // Shared layout bounds for NearbyRadar and RfGuard row lists
    const int16_t radarRowStep = compact ? 12 : 15;
    const std::size_t maxRadarRows = static_cast<std::size_t>(
        (std::max)(2, (static_cast<int>(bodyH) - (compact ? 4 : 5)) / radarRowStep));
    const std::size_t maxSsidChars = static_cast<std::size_t>(
        (std::max)(6, (static_cast<int>(dims.width) - (micro ? 80 : (compact ? 88 : 126))) / 6));

    // NearbyRadar rows (computed only when NearbyRadar page is active)
    std::vector<RadarRowView> radarRows;
    std::string radarEmptyHint;
    if (onRadar) {
        const std::vector<AccessPoint> visibleAps =
            fp::take(state.latestScan.topNetworks, maxRadarRows);
        radarRows = fp::map(visibleAps, [&](const AccessPoint& ap) -> RadarRowView {
            const std::string chStr =
                (ap.channel > 0) ? ("c" + twoDigit(static_cast<uint32_t>(ap.channel))) : "c--";
            const std::string detail = chStr + " " + std::to_string(ap.rssi);
            return RadarRowView{
                truncateText(ap.ssid, maxSsidChars),
                detail,
                rssiToBars(ap.rssi),
                ap.secure
            };
        });
        radarEmptyHint = truncateText(
            state.isScanning
                ? "Scanning nearby WiFi..."
                : (state.hasScannedOnce ? "No WiFi APs in range." : "Waiting for first scan..."),
            maxFrameCols);
    }

    // ChannelSpectrum bars (computed only when ChannelSpectrum page is active)
    const int16_t chartBaseY = static_cast<int16_t>(bodyBottom - (micro ? 9 : (compact ? 11 : 14)));
    const int16_t chartMaxBarH = static_cast<int16_t>(
        (std::max)(14, static_cast<int>(chartBaseY - bodyTop) - (micro ? 12 : (compact ? 16 : 29))));
    std::array<ChannelBarView, 13> channelBars{};
    std::string spectrumSummary;
    if (onSpectrum) {
        uint16_t maxChCount = 1u;
        for (std::size_t ch = 1u; ch <= 13u; ++ch) {
            if (state.latestScan.histogram.counts[ch] > maxChCount) {
                maxChCount = state.latestScan.histogram.counts[ch];
            }
        }
        for (std::size_t idx = 0u; idx < 13u; ++idx) {
            const uint16_t c = state.latestScan.histogram.counts[idx + 1u];
            const int16_t barH =
                (c == 0u) ? static_cast<int16_t>(0)
                          : static_cast<int16_t>((std::max)(
                                2, static_cast<int>((static_cast<int32_t>(c) * chartMaxBarH) /
                                                    static_cast<int32_t>(maxChCount))));
            channelBars[idx] = ChannelBarView{
                static_cast<int32_t>(idx + 1u),
                c,
                barH
            };
        }
        spectrumSummary =
            compact ? ("SEC:" + std::to_string(state.latestScan.secureAps) +
                       " OPN:" + std::to_string(state.latestScan.openAps))
                    : ("2.4GHz CH 1-13 | SEC:" + std::to_string(state.latestScan.secureAps) +
                       " OPEN:" + std::to_string(state.latestScan.openAps));
    }

    // RfGuard (BLE + Sub-GHz CC1101) rows (computed only when RfGuard page is active)
    std::string rfGuardSummary;
    std::vector<RadarRowView> rfGuardRows;
    std::string rfGuardEmptyHint;
    if (onRfGuard) {
        std::size_t bleThreatCnt = 0u;
        for (const BleDevice& d : state.bleDevices) {
            if (d.threat != BleThreatKind::None) {
                ++bleThreatCnt;
            }
        }
        rfGuardSummary =
            compact ? ("B:" + std::to_string(state.bleDevices.size()) +
                       " T:" + std::to_string(bleThreatCnt) + " " +
                       formatFreqMhz(state.subGhzFreqKhz))
                    : ("BLE:" + std::to_string(state.bleDevices.size()) +
                       " TAG:" + std::to_string(bleThreatCnt) + " | SUB:" +
                       formatFreqMhz(state.subGhzFreqKhz));

        const std::size_t maxGuardRows = (maxRadarRows > 1u) ? (maxRadarRows - 1u) : 1u;
        for (const BleDevice& d : state.bleDevices) {
            if (rfGuardRows.size() >= maxGuardRows) {
                break;
            }
            const bool isThreat = (d.threat != BleThreatKind::None);
            const std::string title = isThreat
                                          ? ("[" + std::string(bleThreatLabel(d.threat)) + "] " +
                                             (d.name.empty() ? d.mac : d.name))
                                          : (d.name.empty() ? d.mac : d.name);
            const std::string detail = "BLE " + std::to_string(d.rssi);
            rfGuardRows.push_back(RadarRowView{
                truncateText(title, maxSsidChars),
                detail,
                rssiToBars(d.rssi),
                isThreat
            });
        }
        for (const SubGhzSignal& sig : state.subGhzSignals) {
            if (rfGuardRows.size() >= maxGuardRows) {
                break;
            }
            const bool isAnom = (sig.anomaly != SubGhzAnomaly::None);
            const std::string title =
                formatFreqMhz(sig.freqKhz) + " " + sig.protocol +
                (isAnom ? (" " + std::string(subGhzAnomalyLabel(sig.anomaly))) : "");
            const std::string detail = "SUB " + std::to_string(sig.rssi);
            rfGuardRows.push_back(RadarRowView{
                truncateText(title, maxSsidChars),
                detail,
                rssiToBars(sig.rssi),
                isAnom
            });
        }
        rfGuardEmptyHint = truncateText(
            "RF Guard idle (" + formatFreqMhz(state.subGhzFreqKhz) + ")", maxFrameCols);
    }

    return UiFrame{
        dims,
        compact,
        palette,
        state.page,
        headerDivY,
        footerDivY,
        static_cast<int16_t>(micro ? 1 : (compact ? 2 : 5)),
        static_cast<int16_t>(footerDivY + (micro ? 2 : (compact ? 3 : 5))),
        headerLine,
        footerLine,
        face,
        geom,
        speechX,
        speechTopY,
        lineStepY,
        promptLabel,
        wrappedPhrase,
        spotlightLabel,
        radarRows,
        radarEmptyHint,
        channelBars,
        chartBaseY,
        chartMaxBarH,
        spectrumSummary,
        rfGuardRows,
        rfGuardSummary,
        rfGuardEmptyHint,
        state.theme,
        themeSpec(state.theme).effect,
        themeFaceStyle(state.theme),
        state.uptimeMs / 140u,
        buildThemeToast(state, dims, compact, bodyTop, bodyBottom),
        state.offensiveArmed,
        effectiveMode,
        modeBadge,
        lvlInfo.level,
        lvlInfo.xp,
        state.highScore,
        lvlInfo.progressPct,
        rankLine,
        scene,
        threatBanner
    };
}

// Pure ASCII representation of a UiFrame for Serial Monitor diagnostics and unit tests.
inline std::string renderAsciiPreview(const UiFrame& frame) {
    const std::size_t innerW =
        (frame.dims.width == 160)
            ? 28u
            : static_cast<std::size_t>((std::max)(22, static_cast<int>(frame.dims.width) / 6));
    const auto padLine = [&](const std::string& content) {
        const std::string clipped = truncateText(content, innerW);
        return "| " + clipped + std::string(innerW - clipped.size(), ' ') + " |\n";
    };
    const std::string border = "+-" + std::string(innerW, '-') + "-+\n";

    std::string out = border;
    out += padLine(frame.headerLine + " " + frame.modeBadge);
    out += border;

    if (frame.toast.visible) {
        out += padLine("** " + frame.toast.text + " **");
    }

    if (frame.page == ScreenPage::PetFace) {
        out += padLine(std::string(frame.face.asciiFace) + "  " + frame.promptLabel);
        for (const auto& line : frame.phraseLines) {
            out += padLine("       " + line);
        }
        out += padLine("[" + std::string(frame.face.moodLabel) + "] " + frame.rankLine);
        if (!frame.spotlightLabel.empty()) {
            out += padLine("       " + frame.spotlightLabel);
        }
    } else if (frame.page == ScreenPage::NearbyRadar) {
        out += padLine("NEARBY WIFI RADAR");
        if (frame.radarRows.empty()) {
            out += padLine(frame.radarEmptyHint);
        } else {
            for (const auto& row : frame.radarRows) {
                const std::string lockChar = row.secure ? "*" : " ";
                out += padLine(lockChar + row.ssid + " " + row.details);
            }
        }
    } else if (frame.page == ScreenPage::ChannelSpectrum) {
        out += padLine(frame.spectrumSummary);
        std::string countsRow = "CH:";
        for (std::size_t i = 0; i < 13u; ++i) {
            countsRow += std::to_string(frame.channelBars[i].count);
            if (i + 1u < 13u) countsRow += " ";
        }
        out += padLine(countsRow);
    } else {
        out += padLine(frame.rfGuardSummary);
        if (frame.rfGuardRows.empty()) {
            out += padLine(frame.rfGuardEmptyHint);
        } else {
            for (const auto& row : frame.rfGuardRows) {
                const std::string alertChar = row.secure ? "!" : " ";
                out += padLine(alertChar + row.ssid + " " + row.details);
            }
        }
    }

    out += border;
    out += padLine(frame.footerLine);
    out += border;
    return out;
}

}  // namespace zd
