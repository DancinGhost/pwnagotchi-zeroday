#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zd/hal.hpp"
#include "zd/render/gif_export.hpp"
#include "zd/render/painter.hpp"
#include "zd/render/surface_rgb565.hpp"

namespace {

class FakeRadio final : public zd::hal::IRadioScanner {
public:
    bool startAsyncScan() override {
        started = true;
        return true;
    }

    zd::hal::ScanPollResult pollScan() override {
        if (!ready) {
            return {zd::hal::ScanPollState::Running, {}};
        }
        return {
            zd::hal::ScanPollState::Completed,
            {
                {"PocketDeck_2G", -46, 6, true},
                {"OpenCafe", -62, 1, false},
                {"LabBench_AP", -54, 6, true},
                {"Relay_11", -73, 11, true},
                {"SensorNode", -81, 3, true}
            }
        };
    }

    void clearScan() override { clearedCount++; }

    bool started = false;
    bool ready = false;
    int clearedCount = 0;
};

void testPainterAcrossDevicesThemesAndMoods() {
    zd::AppState base = zd::initialState(1337u);
    base = zd::reduce(
        base,
        zd::ScanCompletedEvent{
            12000u,
            {
                {"MeshAlpha", -44, 6, true},
                {"CafeGuest", -58, 1, false},
                {"Workshop_AP", -65, 11, true},
                {"Node_04", -71, 6, true},
                {"Node_05", -77, 9, true},
                {"Node_06", -82, 13, true},
                {"Node_07", -85, 3, false}
            }
        });

    constexpr std::array<zd::Mood, 16> kMoods = {
        zd::Mood::Awake, zd::Mood::LookingLeft, zd::Mood::LookingRight,
        zd::Mood::Happy, zd::Mood::Excited,     zd::Mood::Cool,
        zd::Mood::Lonely, zd::Mood::Bored,      zd::Mood::Sleepy,
        zd::Mood::Grateful, zd::Mood::Mischief, zd::Mood::ScanningDish,
        zd::Mood::CyberAttack, zd::Mood::ShieldGuard, zd::Mood::ThreatAlert,
        zd::Mood::LevelUp
    };
    constexpr std::array<zd::ScreenPage, 5> kPages = {
        zd::ScreenPage::PetFace,
        zd::ScreenPage::NearbyRadar,
        zd::ScreenPage::ChannelSpectrum,
        zd::ScreenPage::RfGuard,
        zd::ScreenPage::Captures
    };

    base = zd::reduce(base, zd::BleScanCompletedEvent{
                                12100u,
                                {{"7a:3c:91:04:88:12", "Tracker_Tag", -52, 0x004Cu, 0u, true,
                                  zd::BleThreatKind::AirTagTracker},
                                 {"00:80:e1:42:13:37", "SubGHz_Tool", -58, 0u, 0x3082u, false,
                                  zd::BleThreatKind::MultiToolBle}}});
    base = zd::reduce(base, zd::SubGhzObservedEvent{
                                12200u, zd::SubGhzSignal{433920u, -49, "OOK", 6u,
                                                         zd::SubGhzAnomaly::ReplayBurst}});

    // Every screen profile x every theme x every page (with and without toast) must paint
    // strictly inside bounds and produce visible foreground pixels + valid 1-bit export.
    for (const zd::ScreenProfile& prof : zd::kScreenProfiles) {
        for (const zd::ThemeSpec& theme : zd::kThemeCatalog) {
            zd::AppState themed = zd::reduce(base, zd::SetThemeEvent{12500u, theme.id, true});
            for (zd::ScreenPage page : kPages) {
                themed = zd::reduce(themed, zd::SetPageEvent{12500u, page});
                const zd::UiFrame frameWithToast = zd::buildUiFrame(themed, prof.dims);
                assert(frameWithToast.toast.visible);

                zd::render::Rgb565Surface surf(prof.dims.width, prof.dims.height);
                zd::render::paintUiFrame(surf, frameWithToast);
                assert(surf.outOfBoundsDrops() == 0u);

                std::size_t fgPixels = 0u;
                for (uint16_t px : surf.pixels()) {
                    if (px != frameWithToast.palette.bg) {
                        ++fgPixels;
                    }
                }
                assert(fgPixels > 100u);

                // Verify 1-bit monochrome export & RGB888 export sizes
                const auto rgb = surf.toRgb888Buffer();
                assert(rgb.size() ==
                       static_cast<std::size_t>(prof.dims.width * prof.dims.height * 3));
                const auto mono = surf.toMono1BitPacked(frameWithToast.palette.bg);
                const std::size_t expectedMonoBytes =
                    ((static_cast<std::size_t>(prof.dims.width) + 7u) / 8u) *
                    static_cast<std::size_t>(prof.dims.height);
                assert(mono.size() == expectedMonoBytes);
            }
        }

        // Every mood expression on PetFace page must stay strictly in-bounds across ClassicFace themes.
        for (zd::ThemeId styleTheme : {zd::ThemeId::PaperInk, zd::ThemeId::AmberCrt, zd::ThemeId::ZeroDayCyan}) {
            for (zd::Mood mood : kMoods) {
                zd::AppState moodState = zd::reduce(base, zd::SetThemeEvent{12600u, styleTheme, false});
                moodState.mood = mood;
                moodState.page = zd::ScreenPage::PetFace;
                const zd::UiFrame frame = zd::buildUiFrame(moodState, prof.dims);
                assert(frame.faceGeom.centerX == prof.dims.width / 2);
                assert(frame.faceStyle == zd::FaceStyle::ClassicFace);
                assert(frame.faceStyle == zd::themeFaceStyle(styleTheme));
                zd::render::Rgb565Surface surf(prof.dims.width, prof.dims.height);
                zd::render::paintUiFrame(surf, frame);
                assert(surf.outOfBoundsDrops() == 0u);
            }
        }

        // CaptureSaved notifications & Captures page stay strictly in-bounds on every profile
        zd::AppState capState = zd::reduce(
            base, zd::CaptureSavedEvent{22000u, 1u, "/home/user/captures/session_01.pcap", "EAPOL", true});
        for (zd::ScreenPage page : kPages) {
            capState = zd::reduce(capState, zd::SetPageEvent{22100u, page});
            const zd::UiFrame cf = zd::buildUiFrame(capState, prof.dims);
            assert(cf.notifyActive);
            zd::render::Rgb565Surface capSurf(prof.dims.width, prof.dims.height);
            zd::render::paintUiFrame(capSurf, cf);
            assert(capSurf.outOfBoundsDrops() == 0u);
        }

        // Animated backdrop effects (RadarDish, LightningStorm, SatelliteBeam, TacticalHud)
        // must animate cleanly and stay strictly in-bounds across multiple ticks (including lightning strike).
        for (zd::ThemeId fxTheme : {zd::ThemeId::ZeroDayCyan, zd::ThemeId::CodeRain,
                                    zd::ThemeId::RedTeam, zd::ThemeId::BlueTeam}) {
            zd::AppState s1 = zd::reduce(base, zd::SetThemeEvent{20000u, fxTheme, false});
            zd::AppState s2 = zd::reduce(s1, zd::TickEvent{20700u, 90, false});
            zd::AppState sStrike = zd::reduce(s1, zd::TickEvent{12u * 140u, 90, false});
            const zd::UiFrame f1 = zd::buildUiFrame(s1, prof.dims);
            const zd::UiFrame f2 = zd::buildUiFrame(s2, prof.dims);
            const zd::UiFrame fStrike = zd::buildUiFrame(sStrike, prof.dims);
            assert(f1.animTick != f2.animTick);

            zd::render::Rgb565Surface surf1(prof.dims.width, prof.dims.height);
            zd::render::Rgb565Surface surf2(prof.dims.width, prof.dims.height);
            zd::render::Rgb565Surface surf3(prof.dims.width, prof.dims.height);
            zd::render::paintUiFrame(surf1, f1);
            zd::render::paintUiFrame(surf2, f2);
            zd::render::paintUiFrame(surf3, fStrike);
            assert(surf1.outOfBoundsDrops() == 0u);
            assert(surf2.outOfBoundsDrops() == 0u);
            assert(surf3.outOfBoundsDrops() == 0u);
            assert(surf1.pixels() != surf2.pixels());
        }

        // ScanningDish & Defensive / Offensive scenes stay strictly in-bounds on every profile
        for (zd::OpsMode m : {zd::OpsMode::Recon, zd::OpsMode::Defensive, zd::OpsMode::Offensive}) {
            zd::AppState ms = zd::reduce(base, zd::SetOpsModeEvent{21500u, m});
            const zd::UiFrame mf = zd::buildUiFrame(ms, prof.dims);
            zd::render::Rgb565Surface msSurf(prof.dims.width, prof.dims.height);
            zd::render::paintUiFrame(msSurf, mf);
            assert(msSurf.outOfBoundsDrops() == 0u);
        }

        // Offensive armed badge renders within bounds and visibly changes header pixels.
        const zd::AppState armed = zd::reduce(base, zd::SetOffensiveArmedEvent{21000u, true});
        const zd::UiFrame fSafe = zd::buildUiFrame(base, prof.dims);
        const zd::UiFrame fArmed = zd::buildUiFrame(armed, prof.dims);
        zd::render::Rgb565Surface surfSafe(prof.dims.width, prof.dims.height);
        zd::render::Rgb565Surface surfArmed(prof.dims.width, prof.dims.height);
        zd::render::paintUiFrame(surfSafe, fSafe);
        zd::render::paintUiFrame(surfArmed, fArmed);
        assert(surfSafe.outOfBoundsDrops() == 0u);
        assert(surfArmed.outOfBoundsDrops() == 0u);
        assert(surfSafe.pixels() != surfArmed.pixels());
    }
}

void testHalPlatformSessionAndCli() {
    zd::hal::MemoryThemeStore store("neon", 77u);
    zd::hal::FixedPowerSensor power(76, true);
    FakeRadio radio;
    zd::hal::PlatformSession session;

    // Boot restores persisted theme alias ("neon" -> ZeroDayCyan) and highscore silently
    session.boot(99u, 0u, &store);
    assert(session.state().theme == zd::ThemeId::ZeroDayCyan);
    assert(session.state().highScore == 77u);
    assert(session.state().themeToastUntilMs == 0u);

    // Cycle theme forward -> CodeRain, persisted to store
    session.dispatch(zd::CycleThemeEvent{500u, +1}, &store);
    assert(session.state().theme == zd::ThemeId::CodeRain);
    assert(store.storedKey() == "rain");

    // Step radio lifecycle
    assert(session.stepRadio(1600u, radio) != nullptr);
    assert(session.state().isScanning);
    radio.ready = true;
    const char* doneTag = session.stepRadio(2400u, radio);
    assert(doneTag != nullptr && std::string(doneTag) == "SCAN_DONE");
    assert(!session.state().isScanning);
    assert(session.state().latestScan.totalAps == 5u);

    session.stepTick(2500u, power);
    assert(session.state().batteryPercent == 76);
    assert(session.state().isCharging);

    // Portable CLI interpreter
    const auto listOut =
        zd::hal::interpretCliLine("themes", session.state(), {240, 135}, 2600u);
    assert(listOut.output.find("cyan") != std::string::npos);
    assert(listOut.output.find("blueteam") != std::string::npos);

    const auto setOut =
        zd::hal::interpretCliLine("theme operator", session.state(), {240, 135}, 2700u);
    assert(setOut.event.has_value());
    session.dispatch(*setOut.event, &store);
    assert(session.state().theme == zd::ThemeId::BlueTeam);
    assert(store.storedKey() == "blueteam");

    const auto prevOut =
        zd::hal::interpretCliLine("theme prev", session.state(), {240, 135}, 2800u);
    assert(prevOut.event.has_value());
    session.dispatch(*prevOut.event, &store);
    assert(session.state().theme == zd::ThemeId::RedTeam);

    const auto modeOut =
        zd::hal::interpretCliLine("mode defense", session.state(), {240, 135}, 2900u);
    assert(modeOut.event.has_value());
    session.dispatch(*modeOut.event, &store);
    assert(session.state().opsMode == zd::OpsMode::Defensive);
}

void test5GhzSpectrumAndGifExport() {
    // 1. 5 GHz-only ChannelSpectrum must render within bounds across every screen profile.
    zd::AppState st = zd::initialState(99u);
    st = zd::reduce(std::move(st), zd::ScanCompletedEvent{
        1000u,
        {{"Corp5G", -46, 36, true}, {"Lab5G", -52, 149, true}, {"SixG", -60, zd::k6GhzChannelBase + 37, true}}});
    st = zd::reduce(std::move(st), zd::SetPageEvent{1100u, zd::ScreenPage::ChannelSpectrum});
    for (const zd::ScreenProfile& prof : zd::kScreenProfiles) {
        const zd::UiFrame f = zd::buildUiFrame(st, prof.dims);
        zd::render::Rgb565Surface surf(prof.dims.width, prof.dims.height);
        zd::render::paintUiFrame(surf, f);
        assert(surf.outOfBoundsDrops() == 0u);
    }

    // 2. Animated GIF89a export
    std::vector<zd::render::Rgb565Surface> frames;
    for (int i = 0; i < 4; ++i) {
        const zd::AppState cur = zd::reduce(
            st, zd::SetPageEvent{static_cast<uint32_t>(1200 + i * 200),
                                 (i % 2 == 0) ? zd::ScreenPage::PetFace : zd::ScreenPage::ChannelSpectrum});
        zd::render::Rgb565Surface surf(160, 80);
        zd::render::paintUiFrame(surf, zd::buildUiFrame(cur, {160, 80}));
        frames.push_back(std::move(surf));
    }
    const std::vector<uint8_t> gif = zd::render::encodeAnimatedGif(frames, 12u);
    assert(gif.size() > 900u);
    assert(std::string(gif.begin(), gif.begin() + 6) == "GIF89a");
    assert(gif.back() == 0x3Bu);
    const std::string gifStr(gif.begin(), gif.end());
    assert(gifStr.find("NETSCAPE2.0") != std::string::npos);

    // Invalid inputs fail cleanly
    assert(zd::render::encodeAnimatedGif({}, 12u).empty());
    std::vector<zd::render::Rgb565Surface> mismatch;
    mismatch.emplace_back(160, 80);
    mismatch.emplace_back(240, 135);
    assert(zd::render::encodeAnimatedGif(mismatch, 12u).empty());
}

void testBandedClippingBitExact() {
    class BandAdapter {
    public:
        BandAdapter(zd::render::Rgb565Surface& surf, int32_t yOffset, int32_t bandHeight)
            : surf_(surf), yOffset_(yOffset), bandHeight_(bandHeight) {}

        int32_t clipYMin() const { return yOffset_; }
        int32_t clipYMax() const { return yOffset_ + bandHeight_; }

        void fillScreen(uint16_t color) { surf_.fillScreen(color); }
        void fillRect(int32_t x, int32_t y, int32_t w, int32_t h, uint16_t color) {
            if ((y + h) <= yOffset_ || y >= (yOffset_ + bandHeight_)) {
                return;
            }
            surf_.fillRect(x, y - yOffset_, w, h, color);
        }
        void fillRoundRect(int32_t x, int32_t y, int32_t w, int32_t h, int32_t r, uint16_t color) {
            if ((y + h) <= yOffset_ || y >= (yOffset_ + bandHeight_)) {
                return;
            }
            surf_.fillRoundRect(x, y - yOffset_, w, h, r, color);
        }
        void fillCircle(int32_t x, int32_t y, int32_t r, uint16_t color) {
            if ((y + r) < yOffset_ || (y - r) >= (yOffset_ + bandHeight_)) {
                return;
            }
            surf_.fillCircle(x, y - yOffset_, r, color);
        }
        void fillArc(int32_t x, int32_t y, int32_t r0, int32_t r1, float a0, float a1,
                     uint16_t color) {
            const int32_t maxR = (std::max)(r0, r1);
            if ((y + maxR) < yOffset_ || (y - maxR) >= (yOffset_ + bandHeight_)) {
                return;
            }
            surf_.fillArc(x, y - yOffset_, r0, r1, a0, a1, color);
        }
        void drawLine(int32_t x0, int32_t y0, int32_t x1, int32_t y1, uint16_t color) {
            const int32_t minY = (std::min)(y0, y1);
            const int32_t maxY = (std::max)(y0, y1);
            if (maxY < yOffset_ || minY >= (yOffset_ + bandHeight_)) {
                return;
            }
            surf_.drawLine(x0, y0 - yOffset_, x1, y1 - yOffset_, color);
        }
        void setTextColor(uint16_t fg, uint16_t bg) { surf_.setTextColor(fg, bg); }
        void drawString(const char* text, int32_t x, int32_t y) {
            if ((y + 8) <= yOffset_ || y >= (yOffset_ + bandHeight_)) {
                return;
            }
            surf_.drawString(text, x, y - yOffset_);
        }

    private:
        zd::render::Rgb565Surface& surf_;
        int32_t yOffset_;
        int32_t bandHeight_;
    };

    zd::AppState st = zd::initialState(99u);
    st = zd::reduce(std::move(st), zd::ScanCompletedEvent{
                                       12u * 140u,
                                       {{"LabNet", -44, 6, true}, {"OpenGuest", -62, 1, false}}});
    constexpr std::array<zd::ScreenPage, 5> kPages = {
        zd::ScreenPage::PetFace, zd::ScreenPage::NearbyRadar, zd::ScreenPage::ChannelSpectrum,
        zd::ScreenPage::RfGuard, zd::ScreenPage::Captures};
    for (const zd::ThemeSpec& theme : zd::kThemeCatalog) {
        zd::AppState ts = zd::reduce(st, zd::SetThemeEvent{12u * 140u, theme.id, true});
        for (zd::ScreenPage page : kPages) {
            ts = zd::reduce(ts, zd::SetPageEvent{12u * 140u, page});
            const zd::UiFrame frame = zd::buildUiFrame(ts, {320, 240});

            zd::render::Rgb565Surface fullSurf(320, 240);
            zd::render::paintUiFrame(fullSurf, frame);

            std::vector<uint16_t> bandedPixels(320u * 240u, 0u);
            for (int32_t yOff = 0; yOff < 240; yOff += 30) {
                zd::render::Rgb565Surface band(320, 30);
                BandAdapter gfx(band, yOff, 30);
                zd::render::paintUiFrame(gfx, frame);
                for (int32_t row = 0; row < 30; ++row) {
                    for (int32_t col = 0; col < 320; ++col) {
                        bandedPixels[static_cast<std::size_t>((yOff + row) * 320 + col)] =
                            band.pixelAt(col, row);
                    }
                }
            }
            assert(bandedPixels == fullSurf.pixels());
        }
    }
}

}  // namespace

int main() {
    testPainterAcrossDevicesThemesAndMoods();
    testHalPlatformSessionAndCli();
    test5GhzSpectrumAndGifExport();
    testBandedClippingBitExact();
    std::cout << "All cross-device painter, framebuffer, and HAL session tests PASSED!\n";
    return 0;
}
