#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>

#include "domain.hpp"
#include "fp.hpp"
#include "theme.hpp"
#include "wifi_analysis.hpp"

namespace zd {

// Visual building blocks for the Pwnagotchi face renderer (pure data description).
enum class EyeGlyph : uint8_t {
    RoundCenter = 0,
    RoundLeft,
    RoundRight,
    HappyArc,
    WideSparkle,
    Sunglasses,
    SadDroop,
    HalfLid,
    SleepingLine,
    CyberWink,
    LaserVisor,
    ShieldVisor,
    StarEyes,
    AlertRing
};

enum class MouthGlyph : uint8_t {
    DoubleSmile = 0,  // Classic Pwnagotchi ‿‿
    BigGrin,          // Open happy D / o mouth
    Smirk,            // Cool subtle half-smile
    FlatLine,         // Neutral/sleepy __
    SadWave,          // Lonely frown
    Fangs             // Playful cyber mischief / attack fangs
};

struct FaceDescriptor {
    EyeGlyph eyes;
    MouthGlyph mouth;
    bool showBlush;
    bool showTear;
    bool showZzz;
    const char* asciiFace;
    const char* moodLabel;
};

// Pure total mapping from Mood -> FaceDescriptor.
constexpr FaceDescriptor faceForMood(Mood mood) {
    switch (mood) {
        case Mood::Awake:
            return {EyeGlyph::RoundCenter, MouthGlyph::DoubleSmile, false, false, false,
                    "(o_o)", "AWAKE"};
        case Mood::LookingLeft:
            return {EyeGlyph::RoundLeft, MouthGlyph::DoubleSmile, false, false, false,
                    "( o_o)", "SCAN"};
        case Mood::LookingRight:
            return {EyeGlyph::RoundRight, MouthGlyph::DoubleSmile, false, false, false,
                    "(o_o )", "SCAN"};
        case Mood::Happy:
            return {EyeGlyph::HappyArc, MouthGlyph::DoubleSmile, true, false, false,
                    "(^_^)", "HAPPY"};
        case Mood::Excited:
            return {EyeGlyph::WideSparkle, MouthGlyph::BigGrin, true, false, false,
                    "(*O*)", "HYPED"};
        case Mood::Cool:
            return {EyeGlyph::Sunglasses, MouthGlyph::Smirk, false, false, false,
                    "[B_B]", "COOL"};
        case Mood::Lonely:
            return {EyeGlyph::SadDroop, MouthGlyph::SadWave, false, true, false,
                    "(;_;)", "LONELY"};
        case Mood::Bored:
            return {EyeGlyph::HalfLid, MouthGlyph::FlatLine, false, false, false,
                    "(._.)", "BORED"};
        case Mood::Sleepy:
            return {EyeGlyph::SleepingLine, MouthGlyph::FlatLine, false, false, true,
                    "(-_-)", "SLEEPY"};
        case Mood::Grateful:
            return {EyeGlyph::HappyArc, MouthGlyph::BigGrin, true, false, false,
                    "(^o^)", "LUV!"};
        case Mood::Mischief:
            return {EyeGlyph::CyberWink, MouthGlyph::Fangs, true, false, false,
                    "(>_*)", "PWN!"};
        case Mood::ScanningDish:
            return {EyeGlyph::RoundLeft, MouthGlyph::FlatLine, false, false, false,
                    "((o_o))", "DISH"};
        case Mood::CyberAttack:
            return {EyeGlyph::LaserVisor, MouthGlyph::Fangs, false, false, false,
                    "[>_<]", "STRIKE"};
        case Mood::ShieldGuard:
            return {EyeGlyph::ShieldVisor, MouthGlyph::FlatLine, false, false, false,
                    "[O_O]", "GUARD"};
        case Mood::ThreatAlert:
            return {EyeGlyph::AlertRing, MouthGlyph::SadWave, false, false, false,
                    "(!_!)", "ALERT!"};
        case Mood::LevelUp:
            return {EyeGlyph::StarEyes, MouthGlyph::BigGrin, true, false, false,
                    "(*v*)", "LVL UP"};
    }
    return {EyeGlyph::RoundCenter, MouthGlyph::DoubleSmile, false, false, false, "(o_o)", "AWAKE"};
}

// Pure cycle helpers for screen pages. (Theme cycling lives in theme.hpp: nextTheme/prevTheme.)
constexpr bool isValidPage(ScreenPage p) {
    return static_cast<uint8_t>(p) <= static_cast<uint8_t>(ScreenPage::RfGuard);
}

constexpr ScreenPage cyclePage(ScreenPage current, int step) {
    constexpr int kPageCount = 4;
    const int base = isValidPage(current) ? static_cast<int>(current) : 0;
    const int idx = ((base + (step % kPageCount)) % kPageCount + kPageCount) % kPageCount;
    return static_cast<ScreenPage>(idx);
}

constexpr ScreenPage nextPage(ScreenPage current) {
    return cyclePage(current, +1);
}

constexpr ScreenPage prevPage(ScreenPage current) {
    return cyclePage(current, -1);
}

// Pure derivation of pet mood from the latest WiFi scan metrics.
constexpr Mood deriveMoodFromScan(const ScanSummary& summary) {
    if (summary.totalAps == 0) {
        return Mood::Lonely;
    }
    if (summary.totalAps >= 10) {
        return Mood::Excited;
    }
    if (summary.strongestRssi >= -50) {
        return Mood::Cool;
    }
    if (summary.totalAps >= 3) {
        return Mood::Happy;
    }
    return Mood::Bored;
}

// Pure phrase generator threading deterministic PRNG state.
inline fp::RngPick<std::string> selectPhrase(Mood mood, const ScanSummary& scan, uint32_t seed) {
    switch (mood) {
        case Mood::Awake: {
            constexpr std::array<const char*, 4> kPhrases = {
                "Antenna warm! Ready to explore.",
                "Listening to 2.4GHz airwaves...",
                "Press [A] for views, [B] to scan!",
                "ZeroDay awake and feeling curious."
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::LookingLeft:
        case Mood::LookingRight: {
            constexpr std::array<const char*, 4> kPhrases = {
                "Looking around the airwaves...",
                "Sweeping WiFi channels 1 to 13...",
                "Counting nearby WiFi beacons...",
                "Scanning... anyone broadcasting?"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Happy: {
            const uint32_t s1 = fp::nextSeed(seed);
            if ((s1 % 3u) == 0u && scan.busiestChannel > 0) {
                return {
                    "Spotted " + std::to_string(scan.totalAps) + " APs! Ch " +
                        std::to_string(scan.busiestChannel) + " is cozy.",
                    s1
                };
            }
            constexpr std::array<const char*, 3> kPhrases = {
                "Nice neighborhood! Good signals.",
                "Found friendly routers nearby~",
                "Cruising through clean airwaves!"
            };
            const auto pick = fp::pickFrom(s1, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Excited: {
            const uint32_t s1 = fp::nextSeed(seed);
            if ((s1 % 2u) == 0u && scan.totalAps > 0u) {
                return {
                    "Whoa! " + std::to_string(scan.totalAps) + " WiFi networks at once!!",
                    s1
                };
            }
            constexpr std::array<const char*, 3> kPhrases = {
                "Spectrum party! Beacons everywhere!",
                "So many signals! My antenna tingles!",
                "Crowded airwaves! Look at all of em!"
            };
            const auto pick = fp::pickFrom(s1, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Cool: {
            const uint32_t s1 = fp::nextSeed(seed);
            if ((s1 % 2u) == 0u && scan.totalAps > 0u) {
                return {
                    "Crisp " + std::to_string(scan.strongestRssi) + "dBm signal right here!",
                    s1
                };
            }
            constexpr std::array<const char*, 3> kPhrases = {
                "Shades on. Full bars in range.",
                "Crystal clear beacon right next door.",
                "Strongest signal in town. Smooth."
            };
            const auto pick = fp::pickFrom(s1, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Lonely: {
            constexpr std::array<const char*, 3> kPhrases = {
                "Zero networks... is anyone out there?",
                "Radio silence. Are we underground?",
                "Not a single beacon in sight..."
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Bored: {
            constexpr std::array<const char*, 3> kPhrases = {
                "Only a couple faint signals here.",
                "Quiet airwaves... let's take a walk!",
                "Same quiet routers on the horizon."
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Sleepy: {
            constexpr std::array<const char*, 3> kPhrases = {
                "Zzz... resting my pixels...",
                "Power nap... tap or press to wake me.",
                "Dreaming of 5-bar beacons... zZz"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Grateful: {
            constexpr std::array<const char*, 3> kPhrases = {
                "Nom nom! Fresh 802.11 snack~",
                "Happy pixels! Antenna feels warm.",
                "Purring across 2.4 GHz~ thank u!"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::Mischief: {
            constexpr std::array<const char*, 3> kPhrases = {
                "Handshake bagged! Pure craft.",
                "Zero noise, 100% signal craft.",
                "Frame captured and logged!"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::ScanningDish: {
            constexpr std::array<const char*, 3> kPhrases = {
                "Dish locked! Sweeping RF spectrum...",
                "Listening across WiFi, BLE & Sub-GHz!",
                "Parabolic sweep active... ping!"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::CyberAttack: {
            constexpr std::array<const char*, 3> kPhrases = {
                "OFFENSE ARMED! Satellite uplink hot.",
                "Authorized strike mode standing by.",
                "Orbital beam locked on allow-list."
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::ShieldGuard: {
            constexpr std::array<const char*, 3> kPhrases = {
                "DEFENSE UP! Watching BLE & Sub-GHz.",
                "Shield grid active. Scanning for tags.",
                "Guarding airwaves against rogue gear."
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::ThreatAlert: {
            constexpr std::array<const char*, 3> kPhrases = {
                "ALERT! Suspicious RF/tracker spotted!",
                "Guard ping! Check RF Guard view!",
                "Warning: unknown beacon or burst!"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
        case Mood::LevelUp: {
            constexpr std::array<const char*, 3> kPhrases = {
                "LEVEL UP! New RF rank unlocked!",
                "XP milestone reached! Highscore up!",
                "Power-up! Antenna sensitivity boosted!"
            };
            const auto pick = fp::pickFrom(seed, kPhrases);
            return {std::string(pick.value), pick.nextSeed};
        }
    }
    return {"Ready.", fp::nextSeed(seed)};
}

// 10-tier progression table shared with the Web Port.
struct LevelInfo {
    uint8_t level;
    const char* title;
    uint32_t xp;
    uint32_t nextXp;
    uint8_t progressPct;
};

constexpr LevelInfo deriveLevelInfo(uint32_t xp) {
    struct Tier {
        uint8_t level;
        uint32_t minXp;
        const char* title;
    };
    constexpr std::array<Tier, 10> kTiers = {{
        {1u, 0u,    "Packet Sprout"},
        {2u, 40u,   "Beacon Pup"},
        {3u, 110u,  "Channel Surfer"},
        {4u, 220u,  "Frame Ninja"},
        {5u, 380u,  "Spectrum Scout"},
        {6u, 600u,  "BLE Tracker"},
        {7u, 900u,  "SubGHz Stalker"},
        {8u, 1300u, "RF Sentinel"},
        {9u, 1850u, "802.11 Wizard"},
        {10u, 2500u, "ZeroDay Legend"},
    }};
    Tier current = kTiers[0];
    std::size_t nextIdx = 1u;
    for (std::size_t i = 0u; i < kTiers.size(); ++i) {
        if (xp >= kTiers[i].minXp) {
            current = kTiers[i];
            nextIdx = i + 1u;
        }
    }
    if (nextIdx >= kTiers.size()) {
        return LevelInfo{current.level, current.title, xp, current.minXp, 100u};
    }
    const uint32_t nextMin = kTiers[nextIdx].minXp;
    const uint32_t span = nextMin - current.minXp;
    const uint32_t pct = (span > 0u) ? ((xp - current.minXp) * 100u) / span : 100u;
    return LevelInfo{
        current.level,
        current.title,
        xp,
        nextMin,
        static_cast<uint8_t>(pct > 100u ? 100u : pct)
    };
}

inline void awardXp(AppState& next, uint32_t gain, uint32_t nowMs) {
    const uint8_t prevLevel = next.level;
    next.xp += gain;
    if (next.xp > next.highScore) {
        next.highScore = next.xp;
    }
    const LevelInfo info = deriveLevelInfo(next.xp);
    next.level = info.level;
    if (next.level > prevLevel) {
        uint32_t until = nowMs + 2400u;
        if (until == 0u) {
            until = 1u;
        }
        next.levelUpUntilMs = until;
    }
}

constexpr OpsMode cycleOpsMode(OpsMode current) {
    switch (current) {
        case OpsMode::Recon:     return OpsMode::Defensive;
        case OpsMode::Defensive: return OpsMode::Offensive;
        case OpsMode::Offensive: return OpsMode::Recon;
    }
    return OpsMode::Recon;
}

constexpr Mood idleMoodForState(const AppState& s) {
    if (s.offensiveArmed || s.opsMode == OpsMode::Offensive) {
        return Mood::CyberAttack;
    }
    if (s.opsMode == OpsMode::Defensive) {
        return !s.lastThreatLabel.empty() ? Mood::ThreatAlert : Mood::ShieldGuard;
    }
    return s.hasScannedOnce ? deriveMoodFromScan(s.latestScan) : Mood::Awake;
}

// Pure phrase the pet says when it gets a fresh coat of paint.
inline fp::RngPick<std::string> selectThemePhrase(ThemeId theme, uint32_t seed) {
    const std::string name = themeSpec(theme).name;
    const uint32_t s1 = fp::nextSeed(seed);
    switch (s1 % 4u) {
        case 0u:
            return {"New look: " + name + "!", s1};
        case 1u:
            return {"Ooh, " + name + " suits me.", s1};
        case 2u:
            return {"Repainted in " + name + "~", s1};
        default:
            return {"Fresh pixels! " + name + " mode.", s1};
    }
}

// Pure page transition shared by ButtonA and semantic page events.
inline AppState applyPage(const AppState& state, ScreenPage page, uint32_t nowMs) {
    AppState next = state;
    next.uptimeMs = nowMs;
    next.lastInteractionMs = nowMs;
    next.page = isValidPage(page) ? page : state.page;
    if (!next.isScanning && next.mood == Mood::Sleepy) {
        next.mood = idleMoodForState(next);
        const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
        next.phrase = picked.value;
        next.rngSeed = picked.nextSeed;
        next.lastPhraseChangeMs = nowMs;
    }
    return next;
}

// Pure theme transition shared by every theme-changing event.
inline AppState applyTheme(const AppState& state, ThemeId theme, uint32_t nowMs, bool announce) {
    AppState next = state;
    next.uptimeMs = nowMs;
    next.lastInteractionMs = nowMs;
    next.theme = isValidTheme(theme) ? theme : state.theme;
    if (announce) {
        next.themeToastUntilMs = nowMs + kThemeToastMs;
        if (next.themeToastUntilMs == 0u) {
            next.themeToastUntilMs = 1u;  // 0 is reserved for "no toast"
        }
        // Keep scan commentary intact while the radio is busy.
        if (!next.isScanning) {
            const auto picked = selectThemePhrase(next.theme, next.rngSeed);
            next.phrase = picked.value;
            next.rngSeed = picked.nextSeed;
            next.lastPhraseChangeMs = nowMs;
        }
    }
    return next;
}

// Pure factory constructing initial boot state.
inline AppState initialState(uint32_t bootSeed = 0x5EED2026u) {
    AppState s{};
    s.rngSeed = (bootSeed == 0u) ? 0x5EED2026u : bootSeed;
    s.mood = Mood::Awake;
    s.page = ScreenPage::PetFace;
    s.theme = ThemeId::PaperInk;
    s.petName = "zeroday";
    s.phrase = "Hello world! Ready to scan.";
    return s;
}

// Pure predicate determining whether the imperative shell should launch a new WiFi scan.
constexpr bool shouldTriggerScan(const AppState& state,
                                 uint32_t nowMs,
                                 uint32_t autoIntervalMs = 12000u) {
    if (state.isScanning) {
        return false;
    }
    if (state.manualScanRequested) {
        return true;
    }
    // Perform first automatic scan shortly after boot (1.5s) so boot greeting shows briefly.
    if (!state.hasScannedOnce) {
        return nowMs >= 1500u;
    }
    const uint32_t effectiveInterval =
        (state.mood == Mood::Sleepy) ? (autoIntervalMs * 2u) : autoIntervalMs;
    return (nowMs - state.lastScanCompleteMs) >= effectiveInterval;
}

// Pure state reducer: (AppState, AppEvent) -> AppState
// Never mutates input `state`; returns a new AppState value.
inline AppState reduce(const AppState& state, const AppEvent& event) {
    return std::visit(
        fp::Overloaded{
            [&](const TickEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.batteryPercent = fp::clampVal<int32_t>(ev.batteryPercent, 0, 100);
                next.isCharging = ev.isCharging;

                if (next.isScanning) {
                    // Animate eyes left/right (or dish sweep) every 450ms during active async scan.
                    const uint8_t phase =
                        static_cast<uint8_t>(((ev.nowMs - next.lastScanStartMs) / 450u) % 2u);
                    next.scanAnimTick = phase;
                    next.mood = (next.opsMode == OpsMode::Defensive)
                                    ? Mood::ScanningDish
                                    : ((phase == 0u) ? Mood::LookingLeft : Mood::LookingRight);
                    return next;
                }

                // Level-up celebration window
                if (isThemeToastVisible(next.levelUpUntilMs, ev.nowMs)) {
                    if (next.mood != Mood::LevelUp) {
                        next.mood = Mood::LevelUp;
                        const auto picked = selectPhrase(Mood::LevelUp, next.latestScan, next.rngSeed);
                        next.phrase = picked.value;
                        next.rngSeed = picked.nextSeed;
                        next.lastPhraseChangeMs = ev.nowMs;
                    }
                    return next;
                } else if (next.mood == Mood::LevelUp) {
                    next.levelUpUntilMs = 0u;
                    next.mood = idleMoodForState(next);
                }

                // Transition to Sleepy if idle >= 60s in a quiet WiFi area (Recon mode only).
                const bool quietArea = next.latestScan.totalAps <= 2u && next.opsMode == OpsMode::Recon &&
                                       !next.offensiveArmed;
                const bool idleLong = (ev.nowMs - next.lastInteractionMs) >= 60000u &&
                                      ev.nowMs >= 60000u;
                if (quietArea && idleLong && next.mood != Mood::Sleepy) {
                    next.mood = Mood::Sleepy;
                    const auto picked = selectPhrase(Mood::Sleepy, next.latestScan, next.rngSeed);
                    next.phrase = picked.value;
                    next.rngSeed = picked.nextSeed;
                    next.lastPhraseChangeMs = ev.nowMs;
                } else if ((ev.nowMs - next.lastPhraseChangeMs) >= 9000u && next.hasScannedOnce) {
                    const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
                    next.phrase = picked.value;
                    next.rngSeed = picked.nextSeed;
                    next.lastPhraseChangeMs = ev.nowMs;
                }
                return next;
            },

            [&](const ButtonAPressedEvent& ev) -> AppState {
                return applyPage(state, nextPage(state.page), ev.nowMs);
            },

            [&](const CyclePageEvent& ev) -> AppState {
                return applyPage(state, cyclePage(state.page, ev.step), ev.nowMs);
            },

            [&](const SetPageEvent& ev) -> AppState {
                return applyPage(state, ev.page, ev.nowMs);
            },

            [&](const ButtonBPressedEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.lastInteractionMs = ev.nowMs;
                if (!next.isScanning) {
                    next.manualScanRequested = true;
                }
                return next;
            },

            [&](const ButtonBLongPressedEvent& ev) -> AppState {
                return applyTheme(state, nextTheme(state.theme), ev.nowMs, true);
            },

            [&](const CycleThemeEvent& ev) -> AppState {
                return applyTheme(state, cycleTheme(state.theme, ev.step), ev.nowMs, true);
            },

            [&](const SetThemeEvent& ev) -> AppState {
                return applyTheme(state, ev.theme, ev.nowMs, ev.announce);
            },

            [&](const SetOffensiveArmedEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.lastInteractionMs = ev.nowMs;
                next.offensiveArmed = ev.armed;
                next.opsMode = ev.armed ? OpsMode::Offensive : OpsMode::Defensive;
                if (!next.isScanning) {
                    next.mood = idleMoodForState(next);
                    const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
                    next.phrase = picked.value;
                    next.rngSeed = picked.nextSeed;
                    next.lastPhraseChangeMs = ev.nowMs;
                }
                return next;
            },

            [&](const CycleOpsModeEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.lastInteractionMs = ev.nowMs;
                next.opsMode = cycleOpsMode(state.opsMode);
                if (!next.isScanning) {
                    next.mood = idleMoodForState(next);
                    const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
                    next.phrase = picked.value;
                    next.rngSeed = picked.nextSeed;
                    next.lastPhraseChangeMs = ev.nowMs;
                }
                return next;
            },

            [&](const SetOpsModeEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.lastInteractionMs = ev.nowMs;
                next.opsMode = ev.mode;
                if (!next.isScanning) {
                    next.mood = idleMoodForState(next);
                    const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
                    next.phrase = picked.value;
                    next.rngSeed = picked.nextSeed;
                    next.lastPhraseChangeMs = ev.nowMs;
                }
                return next;
            },

            [&](const BleScanCompletedEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.bleDevices.clear();
                next.bleDevices.reserve(ev.devices.size());
                uint32_t threatCount = 0u;
                std::string topThreat;
                int32_t topThreatRssi = -120;
                for (BleDevice d : ev.devices) {
                    d.threat = (d.threat != BleThreatKind::None)
                                   ? d.threat
                                   : classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid,
                                                       d.trackerPayload);
                    if (d.threat != BleThreatKind::None) {
                        ++threatCount;
                        if (d.rssi > topThreatRssi) {
                            topThreatRssi = d.rssi;
                            topThreat = std::string(bleThreatLabel(d.threat)) + " " +
                                        std::to_string(d.rssi) + "dB";
                        }
                    }
                    next.bleDevices.push_back(std::move(d));
                }
                std::sort(next.bleDevices.begin(), next.bleDevices.end(),
                          [](const BleDevice& a, const BleDevice& b) {
                              if ((a.threat != BleThreatKind::None) !=
                                  (b.threat != BleThreatKind::None)) {
                                  return a.threat != BleThreatKind::None;
                              }
                              return a.rssi > b.rssi;
                          });
                if (next.bleDevices.size() > 16u) {
                    next.bleDevices.resize(16u);
                }
                if (threatCount > 0u) {
                    next.threatsDetected += threatCount;
                    next.lastThreatLabel = topThreat;
                    awardXp(next, 25u, ev.nowMs);
                    if (!next.isScanning && next.opsMode != OpsMode::Offensive &&
                        !next.offensiveArmed) {
                        next.mood = Mood::ThreatAlert;
                        next.phrase = "DEFENSE! " + topThreat + " nearby!";
                        next.lastPhraseChangeMs = ev.nowMs;
                    }
                } else {
                    awardXp(next, next.bleDevices.empty() ? 1u : 4u, ev.nowMs);
                }
                return next;
            },

            [&](const SubGhzObservedEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.subGhzFreqKhz = ev.signal.freqKhz;
                next.subGhzSignals.insert(next.subGhzSignals.begin(), ev.signal);
                if (next.subGhzSignals.size() > 12u) {
                    next.subGhzSignals.resize(12u);
                }
                if (ev.signal.anomaly != SubGhzAnomaly::None) {
                    next.threatsDetected += 1u;
                    next.lastThreatLabel =
                        formatFreqMhz(ev.signal.freqKhz) + " " +
                        subGhzAnomalyLabel(ev.signal.anomaly);
                    awardXp(next, 25u, ev.nowMs);
                    if (!next.isScanning && next.opsMode != OpsMode::Offensive &&
                        !next.offensiveArmed) {
                        next.mood = Mood::ThreatAlert;
                        next.phrase = "SUBGHZ! " + next.lastThreatLabel;
                        next.lastPhraseChangeMs = ev.nowMs;
                    }
                } else {
                    awardXp(next, 10u, ev.nowMs);
                }
                return next;
            },

            [&](const SetSubGhzFreqEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.lastInteractionMs = ev.nowMs;
                if (ev.freqKhz >= 300000u && ev.freqKhz <= 928000u) {
                    next.subGhzFreqKhz = ev.freqKhz;
                    next.phrase = "CC1101 tuned to " + formatFreqMhz(ev.freqKhz);
                    next.lastPhraseChangeMs = ev.nowMs;
                }
                return next;
            },

            [&](const SetHighScoreEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                if (ev.xp > next.xp) {
                    next.xp = ev.xp;
                    next.level = deriveLevelInfo(next.xp).level;
                }
                if (ev.highScore > next.highScore) {
                    next.highScore = ev.highScore;
                }
                if (next.xp > next.highScore) {
                    next.highScore = next.xp;
                }
                return next;
            },

            [&](const ScanStartedEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.isScanning = true;
                next.manualScanRequested = false;
                next.lastScanStartMs = ev.nowMs;
                next.scanAnimTick = 0;
                next.mood = (next.opsMode == OpsMode::Defensive) ? Mood::ScanningDish
                                                                 : Mood::LookingLeft;
                const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
                next.phrase = picked.value;
                next.rngSeed = picked.nextSeed;
                next.lastPhraseChangeMs = ev.nowMs;
                return next;
            },

            [&](const ScanCompletedEvent& ev) -> AppState {
                AppState next = state;
                next.uptimeMs = ev.nowMs;
                next.isScanning = false;
                next.manualScanRequested = false;
                next.hasScannedOnce = true;
                next.lastScanCompleteMs = ev.nowMs;
                next.completedScans = state.completedScans + 1u;
                next.latestScan = summarizeScan(ev.rawNetworks, 12u);
                if (next.latestScan.totalAps > next.peakApCount) {
                    next.peakApCount = static_cast<uint32_t>(next.latestScan.totalAps);
                }
                const uint32_t apBonus = static_cast<uint32_t>(next.latestScan.totalAps / 2u);
                const uint32_t xpGain =
                    (next.latestScan.totalAps > 0u) ? (3u + (apBonus > 12u ? 12u : apBonus)) : 1u;
                awardXp(next, xpGain, ev.nowMs);
                next.mood = idleMoodForState(next);
                const auto picked = selectPhrase(next.mood, next.latestScan, next.rngSeed);
                next.phrase = picked.value;
                next.rngSeed = picked.nextSeed;
                next.lastPhraseChangeMs = ev.nowMs;
                return next;
            }
        },
        event);
}

}  // namespace zd
