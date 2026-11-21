#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "zd/hal.hpp"
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
    constexpr std::array<zd::ScreenPage, 4> kPages = {
        zd::ScreenPage::PetFace,
        zd::ScreenPage::NearbyRadar,
        zd::ScreenPage::ChannelSpectrum,
        zd::ScreenPage::RfGuard
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

        // Every mood expression on PetFace page must also stay strictly in-bounds
        for (zd::Mood mood : kMoods) {
            zd::AppState moodState = base;
            moodState.mood = mood;
            moodState.page = zd::ScreenPage::PetFace;
            const zd::UiFrame frame = zd::buildUiFrame(moodState, prof.dims);
            zd::render::Rgb565Surface surf(prof.dims.width, prof.dims.height);
            zd::render::paintUiFrame(surf, frame);
            assert(surf.outOfBoundsDrops() == 0u);
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

}  // namespace

int main() {
    testPainterAcrossDevicesThemesAndMoods();
    testHalPlatformSessionAndCli();
    std::cout << "All cross-device painter, framebuffer, and HAL session tests PASSED!\n";
    return 0;
}
