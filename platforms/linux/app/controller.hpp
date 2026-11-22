#pragma once

// AppController: the single imperative boundary shared by the CLI/TUI and the Qt GUI.
//
// It owns the pet session (portable UI core) and the security session (offensive/defensive
// engine), plus the hybrid Linux backend, and exposes a small synchronous API the UIs call
// on a timer. All policy (mood, layout, defensive detection, the transmit authorization
// gate) stays in the pure cores; this file only sequences hardware I/O and scheduling.

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "zd/hal.hpp"
#include "zd/report.hpp"
#include "zd/secops_hal.hpp"
#include "zd/ui_model.hpp"

#include "../backend/cli_backend.hpp"
#include "async_job.hpp"
#include "clock.hpp"

#ifdef ZD_WITH_LIBPCAP
#include "../backend/native_backend.hpp"
#endif

namespace zd {
namespace linux_app {

enum class CaptureEngine { None, Native, Cli };

struct ActionResult {
    bool ok = false;
    std::string message;
};

// Monitor start/stop and deauth all shell out to commands that can block for a while
// (airmon-ng, aireplay-ng); all three run through one single-flight AsyncJob so the UI
// thread is never stuck waiting, and so they can never race each other.
enum class AsyncActionKind { StartMonitor, StopMonitor, SetChannel, Deauth };

struct AsyncActionOutcome {
    AsyncActionKind kind = AsyncActionKind::StartMonitor;
    ActionResult result;
    std::string monitorIface;  // StartMonitor only: resolved interface, or "" on failure
    bool killedNetworkManager = false;
};

class AppController {
public:
    explicit AppController(std::string iface = "wlan0")
        : iface_(sec::isValidIfaceName(iface) ? std::move(iface) : std::string("wlan0")) {}

    AppController(const AppController&) = delete;
    AppController& operator=(const AppController&) = delete;
    ~AppController() { shutdown(); }

    // Synchronously wait for any in-flight background job and restore managed WiFi if
    // monitor mode is active (or was just brought up by an in-flight StartMonitor).
    void shutdown() {
        actionJob_.wait();
        if (std::optional<AsyncActionOutcome> outcome = actionJob_.collect()) {
            if (outcome->kind == AsyncActionKind::StartMonitor && !outcome->monitorIface.empty()) {
                monitor_.applyUp(outcome->monitorIface, outcome->killedNetworkManager);
                monitoring_ = true;
            }
        }
        if (monitoring_ || monitor_.isMonitor()) {
            const std::string monIface = monitor_.monitorIface();
            const bool restartNm = monitor_.killedNetworkManager();
            monitoring_ = false;
            monitor_.applyDown();
            if (capture_) {
                capture_->stop();
                capture_.reset();
            }
            injector_.reset();
            engine_ = CaptureEngine::None;
            if (!monIface.empty()) {
                linux_backend::CliMonitorControl::takeDownMonitor(monIface, restartNm);
            }
        }
    }

    void boot(uint32_t seed = 0xC0FFEEu) {
        pet_.boot(seed, nowMs(), &themeStore_);
        sec_.setTrustedBssids(themeStore_.loadTrustedBssids());
    }

    // --- Per-tick drive (call ~10 Hz from the UI) ---
    void step() {
        pollAsyncJobs();
        const uint32_t now = nowMs();
        if (!replayMode_ && !monitoring_ && !actionJob_.running()) {
            const char* tag = pet_.stepRadio(now, scanner_);
            if (tag != nullptr && std::string(tag) == "SCAN_DONE") {
                feedScanIntoSecurity(now);
            }
        }
        if (monitoring_ && capture_ && capture_->running()) {
            for (const sec::CapturedFrame& f : capture_->poll()) {
                sec_.ingest(f);
                if (f.kind == sec::FrameKind::Eapol || f.kind == sec::FrameKind::Pmkid) {
                    channelHopper_.notifyEapolActivity(now);
                }
            }
            if (hopEnabled_ && !actionJob_.running()) {
                if (const auto nextCh = channelHopper_.step(now)) {
                    (void)setChannel(*nextCh);
                }
            }
            if (sec_.state().revision != lastPetSyncRev_ && (now - lastPetSyncMs_) >= 2000u) {
                syncPetFromSec(now);
            }
        }
        if (ble_.available()) {
            auto devs = ble_.pollBleDevices(now);
            if (!devs.empty()) {
                ingestBle(devs);
            }
        }
        if (subGhz_.available()) {
            if (auto sig = subGhz_.pollSignal(now)) {
                ingestSubGhz(*sig);
            }
        }
        pet_.stepTick(now, power_);
    }

    // --- Channel hopping & BLE/SubGHz/Report controls ---
    void setChannelHopEnabled(bool on) { hopEnabled_ = on; }
    bool channelHopEnabled() const { return hopEnabled_; }
    void setHop5Ghz(bool on) { channelHopper_.setInclude5Ghz(on); }
    bool hop5Ghz() const { return channelHopper_.config().include5Ghz; }
    int currentHopChannel() const { return channelHopper_.currentChannel(); }

    ActionResult requestBleScan() {
        if (!ble_.available()) {
            return {false, "bluetoothctl not found on this system"};
        }
        return ble_.startAsyncScan() ? ActionResult{true, "BLE scan started..."}
                                     : ActionResult{false, "BLE scan already in progress"};
    }
    bool bleAvailable() const { return ble_.available(); }
    void clearThreat() { pet_.dispatch(ClearThreatEvent{nowMs()}, &themeStore_); }

    bool toggleTrustBssid(const std::string& bssid) {
        const bool wasTrusted = sec::isTrustedBssid(sec_.state(), bssid);
        const bool ok = wasTrusted ? sec_.untrustBssid(bssid) : sec_.trustBssid(bssid);
        if (ok) {
            themeStore_.saveTrustedBssids(sec_.state().trustedBssids);
        }
        return !wasTrusted && ok;
    }

    ActionResult exportReport(const std::string& path) const {
        if (path.empty()) {
            return {false, "missing output path"};
        }
        const std::optional<sec::ReportFormat> fmt = sec::reportFormatFromPath(path);
        if (!fmt.has_value()) {
            return {false, "unknown report extension (expected .md, .csv, or .html)"};
        }
        const uint32_t refMs = replayMode_ ? sec_.state().lastEventMs : nowMs();
        const std::string body = sec::formatReport(sec_.state(), *fmt, refMs);
        const int fd = linux_backend::openSecureWriteRegular(path, /*append=*/false);
        if (fd < 0) {
            return {false, "failed to open report file: " + path};
        }
        const bool wrote = linux_backend::writeAllFd(fd, body.data(), body.size());
        ::close(fd);
        return wrote ? ActionResult{true, "exported report to " + path}
                     : ActionResult{false, "failed to write report to " + path};
    }

    // --- Recon (active scan via NetworkManager; no monitor mode needed) ---
    void requestScan() {
        replayMode_ = false;
        pet_.dispatch(ButtonBPressedEvent{nowMs()}, &themeStore_);
    }

    // --- Monitor mode lifecycle (needed for capture + injection) ---
    // airmon-ng commonly takes seconds, so both of these only *kick off* a worker-thread
    // job and return immediately; the real outcome surfaces later via takeLastAsyncResult()
    // once pollAsyncJobs() (called every step()) collects it.
    ActionResult startMonitor() {
        replayMode_ = false;
        if (monitoring_) {
            return {true, "already monitoring on " + monitor_.monitorIface()};
        }
        if (actionJob_.running()) {
            return {false, "an action is already in progress"};
        }
        pendingKind_ = AsyncActionKind::StartMonitor;
        actionJob_.start([iface = iface_]() {
            const linux_backend::MonitorBringUpResult up =
                linux_backend::CliMonitorControl::bringUpMonitorDetailed(iface);
            const bool ok = !up.monitorIface.empty();
            ActionResult res{ok, ok ? ("monitor interface " + up.monitorIface + " is up")
                                    : ("failed to enable monitor mode on " + iface +
                                       " (need root / supported adapter)")};
            return AsyncActionOutcome{AsyncActionKind::StartMonitor, res, up.monitorIface,
                                      up.killedNetworkManager};
        });
        return {true, "starting monitor mode on " + iface_ + "..."};
    }

    ActionResult stopMonitor() {
        if (!monitoring_) {
            return {true, "not monitoring"};
        }
        if (actionJob_.running()) {
            return {false, "an action is already in progress"};
        }
        // Flip state synchronously, before the worker thread touches anything: step()
        // must never call capture_->poll() again once monitoring_ is false, and moving
        // capture_/injector_ out gives the worker thread exclusive, uncontended ownership.
        monitoring_ = false;
        const std::string monIface = monitor_.monitorIface();
        const bool restartNm = monitor_.killedNetworkManager();
        monitor_.applyDown();
        std::unique_ptr<sec::ICaptureSource> cap = std::move(capture_);
        injector_.reset();
        engine_ = CaptureEngine::None;
        pendingKind_ = AsyncActionKind::StopMonitor;
        actionJob_.start([cap = std::move(cap), monIface, restartNm]() mutable {
            if (cap) {
                cap->stop();
            }
            linux_backend::CliMonitorControl::takeDownMonitor(monIface, restartNm);
            return AsyncActionOutcome{AsyncActionKind::StopMonitor,
                                      {true, "monitor mode stopped"}, {}, false};
        });
        return {true, "stopping monitor mode..."};
    }

    ActionResult setChannel(int channel) {
        if (!monitoring_) {
            return {false, "not in monitor mode"};
        }
        if (channel < 1 || channel > 177) {
            return {false, "invalid channel (must be 1..177)"};
        }
        if (actionJob_.running()) {
            return {false, "an action is already in progress"};
        }
        const std::string monIface = monitor_.monitorIface();
        pendingKind_ = AsyncActionKind::SetChannel;
        actionJob_.start([monIface, channel]() {
            const bool ok =
                linux_backend::CliMonitorControl::setChannelOnIface(monIface, channel);
            return AsyncActionOutcome{
                AsyncActionKind::SetChannel,
                {ok, ok ? ("channel " + std::to_string(channel)) : "failed to set channel"},
                {},
                false};
        });
        return {true, "switching to channel " + std::to_string(channel) + "..."};
    }

    // --- Authorization (operator-only; drives the transmit gate) ---
    void confirmAuthorization(bool on) {
        const bool prev = sec_.authorization().operatorConfirmed;
        sec_.authorization().operatorConfirmed = on;
        if (prev != on) {
            (void)audit_.record(on ? "ARM operatorConfirmed=true" : "DISARM operatorConfirmed=false");
            pet_.dispatch(SetOffensiveArmedEvent{nowMs(), on}, &themeStore_);
        }
    }

    void cycleOpsMode() {
        pet_.dispatch(CycleOpsModeEvent{nowMs()}, &themeStore_);
    }

    void setOpsMode(OpsMode mode) {
        pet_.dispatch(SetOpsModeEvent{nowMs(), mode}, &themeStore_);
    }

    void ingestBle(const std::vector<BleDevice>& devices) {
        const uint32_t now = nowMs();
        for (const BleDevice& d : devices) {
            sec_.dispatch(sec::BleObserved{now, d.mac, d.name, d.rssi, d.companyId,
                                           d.serviceUuid, d.trackerPayload});
        }
        pet_.dispatch(BleScanCompletedEvent{now, devices}, &themeStore_);
    }

    void ingestSubGhz(const SubGhzSignal& sig) {
        const uint32_t now = nowMs();
        sec_.dispatch(sec::SubGhzObserved{now, sig.freqKhz, sig.rssi, sig.protocol,
                                          sig.burstCount,
                                          sig.anomaly == SubGhzAnomaly::JammingCarrier});
        pet_.dispatch(SubGhzObservedEvent{now, sig}, &themeStore_);
    }
    bool allowBssid(const std::string& bssid) { return sec_.authorization().allow(bssid); }
    bool toggleAllowBssid(const std::string& bssid) {
        if (sec_.authorization().isAllowed(bssid)) {
            sec_.authorization().disallow(bssid);
            return false;
        }
        return sec_.authorization().allow(bssid);
    }
    void setAllowAll(bool on) { sec_.authorization().allowAll = on; }
    const sec::Authorization& authorization() const { return sec_.authorization(); }

    // Pre-flight authorization check that also writes a blocked audit record when refused
    // (used by CLI subcommands before touching monitor mode / NetworkManager).
    sec::AuthDecision preflightDeauth(const std::string& bssid, const std::string& client,
                                      uint32_t count) {
        const sec::AuthDecision d = sec::authorize(sec_.authorization(), bssid);
        if (d != sec::AuthDecision::Allowed) {
            return sec_.beginDeauth(bssid, client, count, nowMs(), &audit_);
        }
        return d;
    }

    // --- The one offensive transmit entry point (gate enforced inside SecSession) ---
    // The gate check + state/audit recording (beginDeauth) is fast and runs synchronously
    // right here; only the actual transmit (aireplay-ng, or a bounded pcap_sendpacket loop
    // for large counts) runs on a worker thread, since that can take a while.
    ActionResult requestDeauth(const std::string& bssid, const std::string& client,
                               uint32_t count) {
        if (!injector_ || !injector_->available()) {
            return {false, "no injector available (start monitor mode first)"};
        }
        if (!sec::isValidMac(bssid)) {
            return {false, "invalid target BSSID '" + bssid + "'"};
        }
        if (!sec::isValidClientTarget(client)) {
            return {false, "invalid client MAC '" + client + "'"};
        }
        if (count < 1u || count > 1000u) {
            return {false, "invalid deauth frame count (must be 1..1000)"};
        }
        if (actionJob_.running()) {
            return {false, "an action is already in progress"};
        }
        const sec::AuthDecision decision = sec_.beginDeauth(bssid, client, count, nowMs(), &audit_);
        if (decision != sec::AuthDecision::Allowed) {
            return {false, std::string("deauth refused: ") + sec::authDecisionLabel(decision)};
        }
        sec::IInjector* injector = injector_.get();
        pendingKind_ = AsyncActionKind::Deauth;
        actionJob_.start([injector, bssid, client, count]() {
            const sec::InjectResult r = injector->deauth(bssid, client, count);
            return AsyncActionOutcome{AsyncActionKind::Deauth, {r.transmitted, r.detail}, {}, false};
        });
        return {true, "transmitting " + std::to_string(count) + " deauth frame(s)..."};
    }

    // --- Async action status (polled by the UI) ---
    bool asyncBusy() const { return actionJob_.running(); }

    // Which kind of action is currently in flight, if any. monitoring() alone can't tell
    // a UI "starting" apart from "stopping" here, since stopMonitor() flips it to false
    // immediately (see its comment) rather than waiting for the worker thread.
    std::optional<AsyncActionKind> pendingActionKind() const {
        return actionJob_.running() ? std::optional<AsyncActionKind>(pendingKind_) : std::nullopt;
    }

    // Consumes (returns-and-clears) the most recently completed monitor/deauth result, or
    // nullopt if nothing new has finished since the last call.
    std::optional<ActionResult> takeLastAsyncResult() {
        std::optional<ActionResult> out = std::move(lastAsyncResult_);
        lastAsyncResult_.reset();
        return out;
    }

    // --- Pet UI event passthrough ---
    void dispatchPet(const AppEvent& ev) { pet_.dispatch(ev, &themeStore_); }

    // --- Session record & replay ---
    ActionResult startRecording(const std::string& path) {
        if (path.empty()) {
            recorder_.close();
            sec_.setRecorder(nullptr);
            return {true, "recording stopped"};
        }
        if (!recorder_.open(path)) {
            return {false, "failed to open session record file: " + path};
        }
        sec_.setRecorder(&recorder_);
        return {true, "recording events to " + path};
    }

    ActionResult saveSession(const std::string& path) const {
        if (path.empty()) {
            return {false, "missing file path"};
        }
        if (!linux_backend::saveEventsToFile(path, sec_.events())) {
            return {false, "failed to write session to " + path};
        }
        return {true, "saved " + std::to_string(sec_.events().size()) + " event(s) to " + path};
    }

    void setPcapDumpPath(std::string path) { pcapDumpPath_ = std::move(path); }

    ActionResult loadSession(const std::string& path) {
        if (path.empty()) {
            return {false, "missing file path"};
        }
        const auto decoded = linux_backend::loadEventsFromFile(path);
        if (!decoded.has_value()) {
            return {false, "failed to read session file: " + path};
        }
        replayMode_ = true;
        sec_.loadEvents(*decoded);
        sec_.setTrustedBssids(themeStore_.loadTrustedBssids());
        syncPetFromSec(sec_.state().lastEventMs);
        return {true, "replayed " + std::to_string(decoded->size()) + " event(s) from " + path +
                          " (" + std::to_string(sec_.state().targets.size()) + " APs, " +
                          std::to_string(sec_.state().stations.size()) + " stations)"};
    }

    bool recording() const { return recorder_.active(); }
    const std::string& recordingPath() const { return recorder_.path(); }

    // --- Read-only views for the UIs ---
    UiFrame petFrame(ScreenDimensions dims) const { return pet_.buildFrame(dims); }
    const AppState& petState() const { return pet_.state(); }
    const sec::SecState& secState() const { return sec_.state(); }
    sec::SecMood secMood() const {
        const uint32_t refMs = replayMode_ ? sec_.state().lastEventMs : nowMs();
        return sec::deriveSecMood(sec_.state(), refMs);
    }
    const std::vector<linux_backend::ScannedAp>& lastScan() const { return scanner_.detailed(); }

    bool monitoring() const { return monitoring_; }
    std::string monitorIface() const { return monitor_.monitorIface(); }
    std::string interfaceName() const { return iface_; }
    std::string engineLabel() const {
        switch (engine_) {
            case CaptureEngine::Native: return "libpcap (native frame capture)";
            case CaptureEngine::Cli:    return "airodump-ng (CLI)";
            case CaptureEngine::None:   break;
        }
        return "none";
    }
    std::string auditPath() const { return audit_.path(); }

private:
    // UI-thread-only: collects a finished monitor/deauth job and commits whatever state
    // change it implies. Called at the top of every step().
    void pollAsyncJobs() {
        std::optional<AsyncActionOutcome> outcome = actionJob_.collect();
        if (!outcome.has_value()) {
            return;
        }
        if (outcome->kind == AsyncActionKind::StartMonitor) {
            monitor_.applyUp(outcome->monitorIface, outcome->killedNetworkManager);
            if (!outcome->monitorIface.empty() && monitor_.isMonitor()) {
                buildCaptureAndInjector();
                if (capture_ && capture_->start(outcome->monitorIface)) {
                    monitoring_ = true;
                } else {
                    linux_backend::CliMonitorControl::takeDownMonitor(
                        outcome->monitorIface, outcome->killedNetworkManager);
                    monitor_.applyDown();
                    capture_.reset();
                    injector_.reset();
                    engine_ = CaptureEngine::None;
                    outcome->result = {false, "monitor up but capture failed to start on " +
                                                   outcome->monitorIface};
                }
            } else {
                monitoring_ = false;
            }
        }
        // StopMonitor already applied its state transition synchronously in stopMonitor(),
        // and Deauth's gate/state update already ran synchronously in beginDeauth() before
        // the job was started — neither needs further commit here.
        lastAsyncResult_ = outcome->result;
    }

    void syncPetFromSec(uint32_t now) {
        lastPetSyncRev_ = sec_.state().revision;
        lastPetSyncMs_ = now;
        std::vector<AccessPoint> aps;
        aps.reserve(sec_.state().targets.size());
        for (const sec::WifiTarget& t : sec_.state().targets) {
            aps.push_back(AccessPoint{
                t.ssid,
                t.rssi,
                t.channel,
                t.enc != sec::Encryption::Open && t.enc != sec::Encryption::Unknown
            });
        }
        std::vector<BleDevice> devs;
        devs.reserve(sec_.state().bleTargets.size());
        std::string topThreat;
        for (const sec::BleTarget& bt : sec_.state().bleTargets) {
            devs.push_back(BleDevice{bt.mac, bt.name, bt.rssi, bt.companyId, bt.serviceUuid,
                                     bt.trackerPayload, bt.threat});
        }
        for (auto it = sec_.state().alerts.rbegin(); it != sec_.state().alerts.rend(); ++it) {
            if (it->severity == sec::Severity::Critical || it->severity == sec::Severity::Warn) {
                topThreat = std::string(sec::alertKindLabel(it->kind)) + " " +
                            (it->ssid.empty() ? it->bssid : it->ssid);
                break;
            }
        }
        pet_.dispatch(SyncMonitorSnapshotEvent{
            now, std::move(aps), std::move(devs),
            static_cast<uint32_t>(sec_.state().totalAlertsEmitted), std::move(topThreat)},
            &themeStore_);
    }

    void feedScanIntoSecurity(uint32_t now) {
        for (const linux_backend::ScannedAp& ap : scanner_.detailed()) {
            sec_.dispatch(sec::ApObserved{now, ap.bssid, ap.ssid, ap.channel, ap.rssi, ap.enc, ap.wps});
        }
    }

    void buildCaptureAndInjector() {
#ifdef ZD_WITH_LIBPCAP
        auto nativeCap = std::make_unique<linux_backend::NativeCaptureSource>();
        if (!pcapDumpPath_.empty()) {
            nativeCap->setPcapDumpPath(pcapDumpPath_);
        }
        capture_ = std::move(nativeCap);
        injector_ = std::make_unique<linux_backend::NativeInjector>(&monitor_);
        engine_ = CaptureEngine::Native;
#else
        capture_ = std::make_unique<linux_backend::CliCaptureSource>();
        injector_ = std::make_unique<linux_backend::CliInjector>(&monitor_);
        engine_ = CaptureEngine::Cli;
#endif
    }

    std::string iface_;
    std::string pcapDumpPath_;
    hal::PlatformSession pet_;
    sec::SecSession sec_;
    linux_backend::CliMonitorControl monitor_;
    linux_backend::CliRadioScanner scanner_{iface_};
    linux_backend::SysfsPowerSensor power_;
    linux_backend::FileThemeStore themeStore_;
    linux_backend::FileAuditLog audit_;
    linux_backend::FileSessionRecorder recorder_;
    std::unique_ptr<sec::ICaptureSource> capture_;
    std::unique_ptr<sec::IInjector> injector_;
    linux_backend::CliBleScanner ble_;
    linux_backend::Rtl433Source subGhz_;
    sec::ChannelHopper channelHopper_;
    CaptureEngine engine_ = CaptureEngine::None;
    bool monitoring_ = false;
    bool replayMode_ = false;
    bool hopEnabled_ = false;
    uint64_t lastPetSyncRev_ = UINT64_MAX;
    uint32_t lastPetSyncMs_ = 0u;

    // Declared last so it is destroyed *first*: AsyncJob's destructor joins its worker
    // thread, which must happen before capture_/injector_ (which that thread may be using)
    // are torn down.
    linux_app::AsyncJob<AsyncActionOutcome> actionJob_;
    AsyncActionKind pendingKind_ = AsyncActionKind::StartMonitor;
    std::optional<ActionResult> lastAsyncResult_;
};

}  // namespace linux_app
}  // namespace zd
