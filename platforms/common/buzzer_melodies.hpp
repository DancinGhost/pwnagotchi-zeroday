#pragma once

// Pure non-blocking chiptune melody sequencer for piezos / I2S speakers.
// Zero OS or Arduino dependencies; drives hardware via optional ToneCommand steps.

#include <cstddef>
#include <cstdint>
#include <optional>

namespace zd {

struct ToneNote {
    uint16_t freqHz;      // 0 = rest / silence
    uint16_t durationMs;
};

enum class MelodyId : uint8_t {
    Boot = 0,
    ScanDone,
    ThemeSwitch,
    ThreatAlert,
    LevelUp,
    ButtonClick,
    ModeSwitch
};

inline const ToneNote* melodyNotes(MelodyId id, std::size_t& outCount) {
    static constexpr ToneNote kBoot[] = {
        {523u, 55u}, {659u, 55u}, {784u, 65u}, {1046u, 110u}};
    static constexpr ToneNote kScanDone[] = {
        {660u, 45u}, {880u, 65u}};
    static constexpr ToneNote kThemeSwitch[] = {
        {440u, 38u}, {554u, 38u}, {659u, 55u}};
    static constexpr ToneNote kThreatAlert[] = {
        {880u, 75u}, {0u, 25u}, {622u, 85u}, {0u, 25u}, {880u, 90u}};
    static constexpr ToneNote kLevelUp[] = {
        {523u, 50u}, {659u, 50u}, {784u, 50u}, {1046u, 80u}, {1319u, 120u}};
    static constexpr ToneNote kButtonClick[] = {
        {1200u, 18u}};
    static constexpr ToneNote kModeSwitch[] = {
        {494u, 42u}, {740u, 65u}};

    switch (id) {
        case MelodyId::Boot:        outCount = sizeof(kBoot) / sizeof(kBoot[0]); return kBoot;
        case MelodyId::ScanDone:    outCount = sizeof(kScanDone) / sizeof(kScanDone[0]); return kScanDone;
        case MelodyId::ThemeSwitch: outCount = sizeof(kThemeSwitch) / sizeof(kThemeSwitch[0]); return kThemeSwitch;
        case MelodyId::ThreatAlert: outCount = sizeof(kThreatAlert) / sizeof(kThreatAlert[0]); return kThreatAlert;
        case MelodyId::LevelUp:     outCount = sizeof(kLevelUp) / sizeof(kLevelUp[0]); return kLevelUp;
        case MelodyId::ButtonClick: outCount = sizeof(kButtonClick) / sizeof(kButtonClick[0]); return kButtonClick;
        case MelodyId::ModeSwitch:  outCount = sizeof(kModeSwitch) / sizeof(kModeSwitch[0]); return kModeSwitch;
    }
    outCount = 0u;
    return nullptr;
}

class MelodyPlayer {
public:
    struct ToneCommand {
        bool active = false;
        uint16_t freqHz = 0u;
        uint16_t durationMs = 0u;
    };

    void setMuted(bool muted) {
        if (muted_ == muted) {
            return;
        }
        muted_ = muted;
        if (muted_ && playing_) {
            playing_ = false;
            notes_ = nullptr;
            count_ = 0u;
            pendingStop_ = true;
        }
    }

    bool isMuted() const { return muted_; }
    bool isPlaying() const { return playing_; }

    void trigger(MelodyId id, uint32_t nowMs) {
        if (muted_) {
            return;
        }
        std::size_t cnt = 0u;
        const ToneNote* seq = melodyNotes(id, cnt);
        if (seq == nullptr || cnt == 0u) {
            return;
        }
        notes_ = seq;
        count_ = cnt;
        index_ = 0u;
        noteStartMs_ = nowMs;
        startedCurrent_ = false;
        playing_ = true;
        pendingStop_ = false;
    }

    std::optional<ToneCommand> step(uint32_t nowMs) {
        if (pendingStop_) {
            pendingStop_ = false;
            return ToneCommand{false, 0u, 0u};
        }
        if (!playing_ || notes_ == nullptr || index_ >= count_) {
            return std::nullopt;
        }
        if (!startedCurrent_) {
            startedCurrent_ = true;
            noteStartMs_ = nowMs;
            const ToneNote& n = notes_[index_];
            return ToneCommand{n.freqHz > 0u, n.freqHz, n.durationMs};
        }
        const uint32_t elapsed = nowMs - noteStartMs_;
        if (elapsed < 0x80000000u && elapsed >= notes_[index_].durationMs) {
            ++index_;
            if (index_ >= count_) {
                playing_ = false;
                notes_ = nullptr;
                count_ = 0u;
                return ToneCommand{false, 0u, 0u};
            }
            noteStartMs_ = nowMs;
            const ToneNote& n = notes_[index_];
            return ToneCommand{n.freqHz > 0u, n.freqHz, n.durationMs};
        }
        return std::nullopt;
    }

private:
    const ToneNote* notes_ = nullptr;
    std::size_t count_ = 0u;
    std::size_t index_ = 0u;
    uint32_t noteStartMs_ = 0u;
    bool muted_ = false;
    bool playing_ = false;
    bool startedCurrent_ = false;
    bool pendingStop_ = false;
};

}  // namespace zd
