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
#include "wigle.hpp"

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
enum class AsyncActionKind { StartMonitor, StopMonitor, SetChannel, Deauth, PmkidProbe };

struct AsyncActionOutcome {
    AsyncActionKind kind = AsyncActionKind::StartMonitor;
    ActionResult result;
    std::string monitorIface;  // StartMonitor only: resolved interface, or "" on failure
    bool killedNetworkManager = false;
    bool virtualVif = false;    // StartMonitor only: monitorIface is a virtual vif (not the parent)
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
        stopWardrive();
        gpsd_.stop();
        subGhz_.stop();
        actionJob_.wait();
        if (std::optional<AsyncActionOutcome> outcome = actionJob_.collect()) {
            if (outcome->kind == AsyncActionKind::StartMonitor && !outcome->monitorIface.empty()) {
                monitor_.applyUp(outcome->monitorIface, outcome->killedNetworkManager,
                                 outcome->virtualVif);
                monitoring_ = true;
            }
        }
        if (monitoring_ || monitor_.isMonitor()) {
            const std::string monIface = monitor_.monitorIface();
            const bool restartNm = monitor_.killedNetworkManager();
            const bool virtualVif = monitor_.virtualVif();
            monitoring_ = false;
            monitor_.applyDown();
            if (capture_) {
                capture_->stop();
                capture_.reset();
            }
            injector_.reset();
            engine_ = CaptureEngine::None;
            if (!monIface.empty()) {
                linux_backend::CliMonitorControl::takeDownMonitor(monIface, restartNm, virtualVif);
            }
        }
    }

    void boot(uint32_t seed = 0xC0FFEEu) {
        pet_.boot(seed, nowMs(), &themeStore_);
        sec_.setTrustedBssids(themeStore_.loadTrustedBssids());
        pet_.dispatch(CaptureSavedEvent{nowMs(), 0u, activeCapturePath(), "Ready", false},
                      &themeStore_);
    }

    // --- Per-tick drive (call ~10 Hz from the UI) ---
    void step() {
        pollAsyncJobs();
        const uint32_t now = nowMs();
        if (gpsdEnabled_ || wardriving_) {
            gpsd_.poll(now);
        }
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
                // Reward the adaptive "brain" for activity found on the current channel so it
                // learns to dwell where handshakes/threats actually appear.
                channelHopper_.notifyReward(hopRewardFor(f.kind));
            }
            // Passive peering: greet newly-seen ZeroDay / Pwnagotchi / Palnagotchi units.
            for (const auto& sighting : capture_->pollPeers()) {
                if (peers_.observeWifi(sighting.hit, sighting.rssi, sighting.nowMs)) {
                    std::string name = sighting.hit.hasAdvert
                                           ? sighting.hit.advert.name
                                           : std::string(zd::peer::peerKindLabel(sighting.hit.kind));
                    pet_.dispatch(PeerSpottedEvent{sighting.nowMs, std::move(name), sighting.rssi},
                                  &themeStore_);
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
            if (ble_.consumeCompletedScan()) {
                lastBleScanCount_ = devs.size();
                lastBleScanFinished_ = true;
            }
            if (!devs.empty()) {
                ingestBle(devs);
            }
        }
        if (subGhz_.available()) {
            if (auto sig = subGhz_.pollSignal(now)) {
                ingestSubGhz(*sig);
            }
        }
        if (wardriving_ && gpsd_.state().hasFix && (now - lastWardriveFlushMs_) >= 2000u) {
            (void)flushWardrive(now);
        }
        checkNewCriticalAlerts();
        pet_.stepTick(now, power_);
    }

    // --- Channel hopping & BLE/SubGHz/Report controls ---
    void setChannelHopEnabled(bool on) { hopEnabled_ = on; }
    bool channelHopEnabled() const { return hopEnabled_; }
    void setHop5Ghz(bool on) { channelHopper_.setInclude5Ghz(on); }
    bool hop5Ghz() const { return channelHopper_.config().include5Ghz; }
    int currentHopChannel() const { return channelHopper_.currentChannel(); }
    // Adaptive "brain": UCB1 channel selection that learns which channels pay off.
    void setAdaptiveHop(bool on) { channelHopper_.setAdaptive(on); }
    bool adaptiveHop() const { return channelHopper_.adaptive(); }

    ActionResult requestBleScan() {
        if (!ble_.available()) {
            return {false, "bluetoothctl/btmgmt not found on this system"};
        }
        return ble_.startAsyncScan() ? ActionResult{true, "Bluetooth scan started..."}
                                     : ActionResult{false, "Bluetooth scan already in progress"};
    }
    bool bleAvailable() const { return ble_.available(); }
    bool bleScanning() const { return ble_.scanning(); }
    void setBleAutoEnabled(bool on) { ble_.setAutoEnabled(on); }
    bool bleAutoEnabled() const { return ble_.autoEnabled(); }
    std::size_t lastBleScanCount() const { return lastBleScanCount_; }
    bool consumeBleScanFinished(std::size_t* countOut = nullptr) {
        if (!lastBleScanFinished_) {
            return false;
        }
        lastBleScanFinished_ = false;
        if (countOut != nullptr) {
            *countOut = lastBleScanCount_;
        }
        return true;
    }

    bool subGhzAvailable() const { return subGhz_.available(); }
    bool subGhzRunning() const { return subGhz_.running(); }
    ActionResult startSubGhz(uint32_t freqKhz = 433920u) {
        if (!subGhz_.available()) {
            return {false, "rtl_433 not found on this system"};
        }
        if (!subGhz_.tuneFrequency(freqKhz)) {
            return {false, "invalid Sub-GHz frequency (expected 300000..928000 kHz)"};
        }
        return subGhz_.start() ? ActionResult{true, "rtl_433 listening on " +
                                                        formatFreqMhz(subGhz_.frequencyKhz())}
                               : ActionResult{false, "failed to launch rtl_433"};
    }
    ActionResult stopSubGhz() {
        subGhz_.stop();
        return {true, "rtl_433 stopped"};
    }
    void clearThreat() { pet_.dispatch(ClearThreatEvent{nowMs()}, &themeStore_); }

    bool toggleTrustBssid(const std::string& bssid) {
        const bool wasTrusted = sec::isTrustedBssid(sec_.state(), bssid);
        const bool ok = wasTrusted ? sec_.untrustBssid(bssid) : sec_.trustBssid(bssid);
        if (ok) {
            themeStore_.saveTrustedBssids(sec_.state().trustedBssids);
        }
        return !wasTrusted && ok;
    }

    ActionResult exportReport(const std::string& path) {
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
        if (wrote) {
            lastSavedPath_ = path;
            pet_.dispatch(CaptureSavedEvent{nowMs(), 1u, path, "Report exported", true},
                          &themeStore_);
        }
        return wrote ? ActionResult{true, "exported report to " + path}
                     : ActionResult{false, "failed to write report to " + path};
    }

    // Write every strictly validated, crackable handshake/PMKID as a hashcat 22000
    // (.hc22000) file — no external hcxpcapngtool step required.
    // Number of strictly validated, crackable handshakes/PMKIDs collected this session.
    std::size_t collectedHandshakeCount() const { return sec_.collectedHandshakes().size(); }

    // Distinct peer units greeted this session, and the live registry (for a UI peers list).
    uint32_t peersMet() const { return peers_.peersMet(); }
    const zd::peer::PeerRegistry& peers() const { return peers_; }

    ActionResult exportHandshakes(const std::string& path) {
        if (path.empty()) {
            return {false, "missing output path"};
        }
        const std::size_t n = sec_.collectedHandshakes().size();
        if (n == 0u) {
            return {false, "no crackable handshakes/PMKIDs captured yet"};
        }
        const std::string body = sec_.exportHc22000();
        const int fd = linux_backend::openSecureWriteRegular(path, /*append=*/false);
        if (fd < 0) {
            return {false, "failed to open hc22000 file: " + path};
        }
        const bool wrote = linux_backend::writeAllFd(fd, body.data(), body.size());
        ::close(fd);
        return wrote ? ActionResult{true, "exported " + std::to_string(n) + " hashcat line(s) to " +
                                              path}
                     : ActionResult{false, "failed to write hc22000 to " + path};
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
                                      up.killedNetworkManager, up.virtualVif};
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
        const bool virtualVif = monitor_.virtualVif();
        monitor_.applyDown();
        std::unique_ptr<sec::ICaptureSource> cap = std::move(capture_);
        injector_.reset();
        engine_ = CaptureEngine::None;
        pendingKind_ = AsyncActionKind::StopMonitor;
        actionJob_.start([cap = std::move(cap), monIface, restartNm, virtualVif]() mutable {
            if (cap) {
                cap->stop();
            }
            linux_backend::CliMonitorControl::takeDownMonitor(monIface, restartNm, virtualVif);
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

    // Same pre-flight contract for a clientless PMKID probe (writes a blocked audit record
    // when refused, so an unauthorized probe never reaches monitor-mode setup).
    sec::AuthDecision preflightPmkidProbe(const std::string& bssid, uint32_t count) {
        const sec::AuthDecision d = sec::authorize(sec_.authorization(), bssid);
        if (d != sec::AuthDecision::Allowed) {
            return sec_.beginPmkidProbe(bssid, count, nowMs(), &audit_);
        }
        return d;
    }

    // --- The one offensive transmit entry point (gate enforced inside SecSession) ---
    // The gate check + state/audit recording (beginDeauth) is fast and runs synchronously
    // right here; only the actual transmit (aireplay-ng, or a bounded pcap_sendpacket loop
    // for large counts) runs on a worker thread, since that can take a while.
    ActionResult requestDeauth(const std::string& bssid, const std::string& client,
                               uint32_t count, int tuneChannel = 0) {
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
        if (tuneChannel != 0 && (tuneChannel < 1 || tuneChannel > 177)) {
            return {false, "invalid channel (must be 1..177)"};
        }
        if (actionJob_.running()) {
            return {false, "an action is already in progress"};
        }
        const sec::AuthDecision decision = sec_.beginDeauth(bssid, client, count, nowMs(), &audit_);
        if (decision != sec::AuthDecision::Allowed) {
            return {false, std::string("deauth refused: ") + sec::authDecisionLabel(decision)};
        }
        sec::IInjector* injector = injector_.get();
        const std::string monIface = monitor_.monitorIface();
        pendingKind_ = AsyncActionKind::Deauth;
        actionJob_.start([injector, monIface, bssid, client, count, tuneChannel]() {
            if (tuneChannel >= 1 && tuneChannel <= 177 && !monIface.empty()) {
                if (!linux_backend::CliMonitorControl::setChannelOnIface(monIface, tuneChannel)) {
                    return AsyncActionOutcome{
                        AsyncActionKind::Deauth,
                        {false, "failed to tune monitor interface to ch " +
                                    std::to_string(tuneChannel)},
                        {},
                        false};
                }
            }
            const sec::InjectResult r = injector->deauth(bssid, client, count);
            return AsyncActionOutcome{AsyncActionKind::Deauth, {r.transmitted, r.detail}, {}, false};
        });
        return {true, "transmitting " + std::to_string(count) + " deauth frame(s)..."};
    }

    // Clientless PMKID probe (auth->assoc) through the same gate as requestDeauth. The SSID
    // is resolved from the observed target so the Association Request's SSID element matches.
    // Complements deauth; against WPA3-SAE/PMF (no PMKID) use requestDeauth instead.
    ActionResult requestPmkidProbe(const std::string& bssid, uint32_t count, int tuneChannel = 0) {
        if (!injector_ || !injector_->available()) {
            return {false, "no injector available (start monitor mode first)"};
        }
        if (!sec::isValidMac(bssid) || sec::isMulticastMac(bssid)) {
            return {false, "invalid target BSSID '" + bssid + "'"};
        }
        if (count < 1u || count > 1000u) {
            return {false, "invalid probe count (must be 1..1000)"};
        }
        if (tuneChannel != 0 && (tuneChannel < 1 || tuneChannel > 177)) {
            return {false, "invalid channel (must be 1..177)"};
        }
        if (actionJob_.running()) {
            return {false, "an action is already in progress"};
        }
        const sec::AuthDecision decision = sec_.beginPmkidProbe(bssid, count, nowMs(), &audit_);
        if (decision != sec::AuthDecision::Allowed) {
            return {false, std::string("pmkid probe refused: ") + sec::authDecisionLabel(decision)};
        }
        std::string ssid;
        if (const sec::WifiTarget* t = sec::findTarget(sec_.state(), bssid)) {
            ssid = t->ssid;
        }
        sec::IInjector* injector = injector_.get();
        const std::string monIface = monitor_.monitorIface();
        pendingKind_ = AsyncActionKind::PmkidProbe;
        actionJob_.start([injector, monIface, bssid, ssid, count, tuneChannel]() {
            if (tuneChannel >= 1 && tuneChannel <= 177 && !monIface.empty()) {
                if (!linux_backend::CliMonitorControl::setChannelOnIface(monIface, tuneChannel)) {
                    return AsyncActionOutcome{
                        AsyncActionKind::PmkidProbe,
                        {false, "failed to tune monitor interface to ch " +
                                    std::to_string(tuneChannel)},
                        {},
                        false};
                }
            }
            const sec::InjectResult r = injector->pmkidProbe(bssid, ssid, count);
            return AsyncActionOutcome{AsyncActionKind::PmkidProbe, {r.transmitted, r.detail}, {},
                                      false};
        });
        return {true, "sending " + std::to_string(count) + " clientless PMKID probe(s)..."};
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
        pet_.dispatch(CaptureSavedEvent{nowMs(), 0u, activeCapturePath(), "Recording active", false},
                      &themeStore_);
        return {true, "recording events to " + path};
    }

    ActionResult saveSession(const std::string& path) {
        if (path.empty()) {
            return {false, "missing file path"};
        }
        if (!linux_backend::saveEventsToFile(path, sec_.events())) {
            return {false, "failed to write session to " + path};
        }
        lastSavedPath_ = path;
        pet_.dispatch(CaptureSavedEvent{nowMs(), 1u, path, "Session saved", true}, &themeStore_);
        return {true, "saved " + std::to_string(sec_.events().size()) + " event(s) to " + path};
    }

    void setPcapDumpPath(std::string path) {
        pcapDumpPath_ = std::move(path);
        pet_.dispatch(
            CaptureSavedEvent{nowMs(), 0u, activeCapturePath(), "PCAP target set", false},
            &themeStore_);
    }

    std::string activeCapturePath() const {
        if (!pcapDumpPath_.empty()) {
            return pcapDumpPath_;
        }
        if (recorder_.active() && !recorder_.path().empty()) {
            return recorder_.path();
        }
        if (!lastSavedPath_.empty()) {
            return lastSavedPath_;
        }
        return linux_backend::homeDir() + "/.local/share/pwnagotchi-zeroday/captures.zds";
    }

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
        lastNotifiedTotalAlerts_ = sec_.state().totalAlertsEmitted;
        syncPetFromSec(sec_.state().lastEventMs);
        return {true, "replayed " + std::to_string(decoded->size()) + " event(s) from " + path +
                          " (" + std::to_string(sec_.state().targets.size()) + " APs, " +
                          std::to_string(sec_.state().stations.size()) + " stations)"};
    }

    bool recording() const { return recorder_.active(); }
    const std::string& recordingPath() const { return recorder_.path(); }

    // --- Desktop critical notifications (libnotify) ---
    void setNotificationsEnabled(bool on) {
        notifier_.setEnabled(on);
        if (on) {
            lastNotifiedTotalAlerts_ = sec_.state().totalAlertsEmitted;
        }
    }
    bool notificationsEnabled() const { return notifier_.enabled(); }
    void setNotifierDryRun(bool on) { notifier_.setDryRun(on); }
    uint32_t notificationsSent() const { return notifier_.sentCount(); }
    const std::string& lastNotificationTitle() const { return notifier_.lastTitle(); }
    const std::string& lastNotificationBody() const { return notifier_.lastBody(); }

    void processFrame(const sec::CapturedFrame& f) {
        sec_.ingest(f);
        checkNewCriticalAlerts();
    }

    // --- Linux gpsd & WiGLE wardriving ---
    ActionResult startWardrive(const std::string& path, bool connectGpsd = true) {
        if (path.empty()) {
            return {false, "missing wardrive CSV path"};
        }
        stopWardrive();
        const int fd = linux_backend::openSecureWriteRegular(path, /*append=*/false);
        if (fd < 0) {
            return {false, "cannot safely open wardrive CSV: " + path};
        }
        const std::string hdr = zd::formatWigleHeader("zd-linux", "Linux", "x86_64");
        const bool ok = linux_backend::writeAllFd(fd, hdr.data(), hdr.size());
        ::close(fd);
        if (!ok) {
            return {false, "failed writing WiGLE header to: " + path};
        }
        wigleLogger_.reset();
        wardrivePath_ = path;
        wardriving_ = true;
        lastWardriveFlushMs_ = 0u;
        if (connectGpsd) {
            gpsdEnabled_ = true;
            (void)gpsd_.start();
        }
        return {true, "wardriving to " + path};
    }

    void stopWardrive() {
        if (wardriving_) {
            (void)flushWardrive(nowMs());
        }
        wardriving_ = false;
    }

    bool wardriving() const { return wardriving_; }
    const std::string& wardrivePath() const { return wardrivePath_; }
    uint32_t wardriveLoggedCount() const { return wigleLogger_.loggedCount(); }

    bool ingestGpsLine(const std::string& line, uint32_t nowMs) {
        gpsdEnabled_ = true;
        return gpsd_.ingestLine(line, nowMs);
    }

    const esp32_common::GpsState& gpsState() const { return gpsd_.state(); }

    std::size_t flushWardrive(uint32_t now) {
        lastWardriveFlushMs_ = now;
        if (!wardriving_ || wardrivePath_.empty() || !gpsd_.state().hasFix) {
            return 0u;
        }
        std::vector<AccessPoint> aps;
        std::vector<std::string> bssids;
        aps.reserve(sec_.state().targets.size());
        bssids.reserve(sec_.state().targets.size());
        for (const sec::WifiTarget& t : sec_.state().targets) {
            aps.push_back(AccessPoint{
                t.ssid, t.rssi, t.channel,
                t.enc != sec::Encryption::Open && t.enc != sec::Encryption::Unknown});
            bssids.push_back(t.bssid);
        }
        const std::vector<std::string> rows = wigleLogger_.recordScan(aps, bssids, gpsd_.state());
        if (rows.empty()) {
            return 0u;
        }
        std::string batch;
        for (const std::string& r : rows) {
            batch += r;
        }
        const int fd = linux_backend::openSecureWriteRegular(wardrivePath_, /*append=*/true);
        if (fd < 0) {
            return 0u;
        }
        const bool ok = linux_backend::writeAllFd(fd, batch.data(), batch.size());
        ::close(fd);
        return ok ? rows.size() : 0u;
    }

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
    // Reward weight the adaptive channel "brain" earns for one captured frame. Crackable
    // material (handshakes/PMKIDs) is worth most, threats next, beacons/data least.
    static double hopRewardFor(sec::FrameKind kind) {
        switch (kind) {
            case sec::FrameKind::Eapol:
            case sec::FrameKind::Pmkid:   return 10.0;
            case sec::FrameKind::Deauth:
            case sec::FrameKind::Disassoc: return 3.0;
            case sec::FrameKind::Beacon:  return 1.0;
            case sec::FrameKind::Data:    return 0.2;
            default:                      return 0.0;
        }
    }

    // UI-thread-only: collects a finished monitor/deauth job and commits whatever state
    // change it implies. Called at the top of every step().
    void pollAsyncJobs() {
        std::optional<AsyncActionOutcome> outcome = actionJob_.collect();
        if (!outcome.has_value()) {
            return;
        }
        if (outcome->kind == AsyncActionKind::StartMonitor) {
            monitor_.applyUp(outcome->monitorIface, outcome->killedNetworkManager,
                             outcome->virtualVif);
            if (!outcome->monitorIface.empty() && monitor_.isMonitor()) {
                buildCaptureAndInjector();
                if (capture_ && capture_->start(outcome->monitorIface)) {
                    monitoring_ = true;
                } else {
                    linux_backend::CliMonitorControl::takeDownMonitor(
                        outcome->monitorIface, outcome->killedNetworkManager,
                        outcome->virtualVif);
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
        // and Deauth/PmkidProbe's gate/state update already ran synchronously (beginDeauth /
        // beginPmkidProbe) before the job was started — none needs further commit here.
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
        const uint32_t secCapCount = static_cast<uint32_t>(
            sec_.state().totalHandshakes + sec_.state().totalPmkids +
            sec_.state().subGhzCaptures.size());
        std::string capLabel;
        for (auto it = sec_.state().targets.rbegin(); it != sec_.state().targets.rend(); ++it) {
            if (it->handshake || it->pmkid) {
                capLabel = std::string(it->handshake ? "HS " : "PMK ") +
                           (it->ssid.empty() ? it->bssid : it->ssid);
                break;
            }
        }
        pet_.dispatch(SyncMonitorSnapshotEvent{
            now, std::move(aps), std::move(devs),
            static_cast<uint32_t>(sec_.state().totalAlertsEmitted), std::move(topThreat),
            secCapCount, activeCapturePath(), std::move(capLabel),
            sec::deriveSecMood(sec_.state(), now)},
            &themeStore_);
    }

    void feedScanIntoSecurity(uint32_t now) {
        for (const linux_backend::ScannedAp& ap : scanner_.detailed()) {
            sec_.dispatch(sec::ApObserved{now, ap.bssid, ap.ssid, ap.channel, ap.rssi, ap.enc,
                                          ap.wps, ap.pmf});
        }
    }

    void checkNewCriticalAlerts() {
        const auto& s = sec_.state();
        if (s.totalAlertsEmitted <= lastNotifiedTotalAlerts_) {
            return;
        }
        const std::size_t unseen =
            static_cast<std::size_t>(s.totalAlertsEmitted - lastNotifiedTotalAlerts_);
        const std::size_t count = (unseen < s.alerts.size()) ? unseen : s.alerts.size();
        const std::size_t start = s.alerts.size() - count;
        for (std::size_t i = start; i < s.alerts.size(); ++i) {
            if (!replayMode_) {
                (void)notifier_.notifyCritical(s.alerts[i]);
            }
        }
        lastNotifiedTotalAlerts_ = s.totalAlertsEmitted;
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
    std::string lastSavedPath_;
    hal::PlatformSession pet_;
    sec::SecSession sec_;
    zd::peer::PeerRegistry peers_;
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
    linux_backend::DesktopNotifier notifier_;
    linux_backend::GpsdClient gpsd_;
    zd::WigleLogger wigleLogger_;
    std::string wardrivePath_;
    bool wardriving_ = false;
    bool gpsdEnabled_ = false;
    uint32_t lastWardriveFlushMs_ = 0u;
    uint32_t lastNotifiedTotalAlerts_ = 0u;
    sec::ChannelHopper channelHopper_;
    CaptureEngine engine_ = CaptureEngine::None;
    bool monitoring_ = false;
    bool replayMode_ = false;
    bool hopEnabled_ = false;
    std::size_t lastBleScanCount_ = 0u;
    bool lastBleScanFinished_ = false;
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
