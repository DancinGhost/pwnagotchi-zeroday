#pragma once

// CLI-tool realizations of the security HAL, using standard Linux wireless
// toolchain already present on the system:
//   - monitor mode / channel : airmon-ng, iw
//   - AP + station discovery : airodump-ng (CSV dump, polled)
//   - active scan            : nmcli / iw
//   - deauth injection       : aireplay-ng   (authorization-gated upstream by SecSession)
//   - battery                : /sys/class/power_supply
//   - theme persistence      : ~/.config/pwnagotchi-zeroday/theme
//   - audit trail            : ~/.local/share/pwnagotchi-zeroday/audit.log
//
// This is the always-available fallback half of the hybrid backend; the native
// libpcap/libnl half (native_backend.hpp) is preferred when compiled in.

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zd/hal.hpp"
#include "zd/secops_hal.hpp"
#include "parsers.hpp"
#include "process.hpp"
#include "../app/async_job.hpp"
#include "../app/clock.hpp"

namespace zd {
namespace linux_backend {

inline std::string readFileToString(const std::string& path,
                                    std::size_t maxBytes = 4u * 1024u * 1024u) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        return {};
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return {};
    }
    std::string out;
    if (st.st_size > 0) {
        const std::size_t cap = static_cast<std::size_t>(st.st_size);
        out.reserve(cap < maxBytes ? cap : maxBytes);
    }
    char buf[4096];
    while (out.size() < maxBytes) {
        const std::size_t want =
            (maxBytes - out.size() < sizeof(buf)) ? (maxBytes - out.size()) : sizeof(buf);
        const ssize_t n = ::read(fd, buf, want);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        out.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return out;
}

inline bool writeAllFd(int fd, const char* data, std::size_t len) {
    std::size_t off = 0u;
    while (off < len) {
        const ssize_t n = ::write(fd, data + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

inline std::string homeDir() {
    // When running privileged (e.g. under sudo), do not trust an inherited $HOME pointing
    // into a non-root user's writable directory tree; resolve the effective UID's passwd entry.
    if (::geteuid() != 0) {
        const char* h = std::getenv("HOME");
        if (h != nullptr && *h != '\0') {
            return std::string(h);
        }
    }
    struct passwd pwd {};
    struct passwd* res = nullptr;
    char buf[1024];
    if (::getpwuid_r(::geteuid(), &pwd, buf, sizeof(buf), &res) == 0 && res != nullptr &&
        res->pw_dir != nullptr && *res->pw_dir != '\0') {
        return std::string(res->pw_dir);
    }
    return "/root";
}

// Create `dir` and any missing parents (POSIX `mkdir -p`, without spawning a subprocess),
// verifying each traversed component is a real directory (not a symlink).
inline bool makeDirRecursive(const std::string& dir, mode_t mode = 0700) {
    if (dir.empty()) {
        return false;
    }
    std::string partial;
    partial.reserve(dir.size());
    const uid_t euid = ::geteuid();
    for (std::size_t i = 0; i < dir.size(); ++i) {
        if (dir[i] == '/') {
            if (partial.empty()) {
                partial.push_back('/');
                continue;
            }
            if (partial.back() == '/') {
                continue;
            }
        } else {
            partial.push_back(dir[i]);
            if (i + 1u < dir.size()) {
                continue;
            }
        }
        struct stat st {};
        if (::lstat(partial.c_str(), &st) != 0) {
            if (errno != ENOENT) {
                return false;
            }
            if (::mkdir(partial.c_str(), mode) != 0 && errno != EEXIST) {
                return false;
            }
            if (::lstat(partial.c_str(), &st) != 0) {
                return false;
            }
        }
        if (!S_ISDIR(st.st_mode)) {
            return false;
        }
        if (euid == 0 && st.st_uid != 0) {
            return false;
        }
        if (dir[i] == '/') {
            partial.push_back('/');
        }
    }
    return true;
}

// Safely open a regular file for writing/appending without following symlinks or blocking on FIFOs.
inline int openSecureWriteRegular(const std::string& path, bool append) {
    const int flags = O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC |
                      (append ? O_APPEND : 0);
    const int fd = ::open(path.c_str(), flags, 0600);
    if (fd < 0) {
        return -1;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return -1;
    }
    if (::geteuid() == 0 && st.st_uid != 0) {
        ::close(fd);
        return -1;
    }
    (void)::fchmod(fd, 0600);
    if (!append && ::ftruncate(fd, 0) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

struct MonitorBringUpResult {
    std::string monitorIface;
    bool killedNetworkManager = false;
};

// --- Monitor mode / channel control --------------------------------------------------

class CliMonitorControl final : public sec::IMonitorControl {
public:
    // Slow (airmon-ng commonly takes seconds): brings an interface into monitor mode and
    // resolves the resulting interface name via `iw dev`. Touches no object state, so it
    // is safe to run on a worker thread; the caller commits the result via applyUp().
    static MonitorBringUpResult bringUpMonitorDetailed(const std::string& iface) {
        MonitorBringUpResult res;
        if (!sec::isValidIfaceName(iface)) {
            return res;
        }
        // Try non-destructive `iw` monitor mode switch first before falling back to airmon-ng.
        runCapture({"ip", "link", "set", iface, "down"});
        if (runCapture({"iw", "dev", iface, "set", "type", "monitor"}).exitCode == 0 &&
            runCapture({"ip", "link", "set", iface, "up"}).exitCode == 0) {
            const std::string mon = findMonitorInterface(iface);
            if (!mon.empty()) {
                res.monitorIface = mon;
                res.killedNetworkManager = false;
                return res;
            }
        }
        runCapture({"airmon-ng", "check", "kill"});
        res.killedNetworkManager = true;
        runCapture({"airmon-ng", "start", "--", iface});
        res.monitorIface = findMonitorInterface(iface);  // "" if no monitor interface resulted
        return res;
    }

    static std::string bringUpMonitor(const std::string& iface) {
        return bringUpMonitorDetailed(iface).monitorIface;
    }

    // Slow: tears down monitor mode on `monitorIface`. Only restarts NetworkManager if
    // `restartNetworkManager` is true (i.e. `airmon-ng check kill` actually ran).
    static void takeDownMonitor(const std::string& monitorIface,
                                bool restartNetworkManager = false) {
        if (!sec::isValidIfaceName(monitorIface)) {
            return;
        }
        runCapture({"airmon-ng", "stop", "--", monitorIface});
        runCapture({"ip", "link", "set", monitorIface, "down"});
        runCapture({"iw", "dev", monitorIface, "set", "type", "managed"});
        runCapture({"ip", "link", "set", monitorIface, "up"});
        if (restartNetworkManager) {
            runCapture({"systemctl", "start", "NetworkManager"});
        }
    }

    // Static channel switcher safe to call from a worker thread.
    static bool setChannelOnIface(const std::string& monitorIface, int channel) {
        if (channel <= 0 || !sec::isValidIfaceName(monitorIface)) {
            return false;
        }
        const CommandResult r =
            runCapture({"iw", "dev", monitorIface, "set", "channel", std::to_string(channel)});
        return r.exitCode == 0;
    }

    // Fast, UI-thread-only state commit from a bringUpMonitor()/takeDownMonitor() result.
    void applyUp(const std::string& mon, bool killedNm = false) {
        if (mon.empty()) {
            isMonitor_ = false;
            monitorIface_.clear();
            killedNetworkManager_ = false;
        } else {
            monitorIface_ = mon;
            isMonitor_ = true;
            killedNetworkManager_ = killedNm;
        }
    }
    void applyDown() {
        isMonitor_ = false;
        monitorIface_.clear();
        killedNetworkManager_ = false;
    }

    bool killedNetworkManager() const { return killedNetworkManager_; }

    // Synchronous convenience wrappers (fine for one-shot CLI use).
    std::string enableMonitor(const std::string& iface) override {
        const MonitorBringUpResult r = bringUpMonitorDetailed(iface);
        applyUp(r.monitorIface, r.killedNetworkManager);
        return r.monitorIface;
    }

    void disableMonitor() override {
        if (!isMonitor_) {
            return;
        }
        takeDownMonitor(monitorIface_, killedNetworkManager_);
        applyDown();
    }

    bool setChannel(int channel) override {
        if (!isMonitor_) {
            return false;
        }
        return setChannelOnIface(monitorIface_, channel);
    }

    bool isMonitor() const override { return isMonitor_; }
    std::string monitorIface() const override { return monitorIface_; }

private:
    // Parse `iw dev` for an interface currently in "type monitor". Prefers one whose name
    // relates to `base` (e.g. wlan0mon / wlan0), else returns the first monitor interface.
    static std::string findMonitorInterface(const std::string& base) {
        const CommandResult dev = runCapture({"iw", "dev"});
        std::istringstream in(dev.stdoutText);
        std::string line;
        std::string current;
        std::string firstMonitor;
        std::string relatedMonitor;
        while (std::getline(in, line)) {
            const std::string t = trimLine(line);
            if (t.rfind("Interface ", 0) == 0) {
                current = t.substr(10);
            } else if (t.find("type monitor") != std::string::npos && !current.empty()) {
                if (firstMonitor.empty()) {
                    firstMonitor = current;
                }
                if (current.find(base) != std::string::npos) {
                    relatedMonitor = current;
                }
            }
        }
        return !relatedMonitor.empty() ? relatedMonitor : firstMonitor;
    }

    static std::string trimLine(const std::string& s) {
        std::size_t a = 0;
        std::size_t b = s.size();
        while (a < b && (s[a] == ' ' || s[a] == '\t')) {
            ++a;
        }
        while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) {
            --b;
        }
        return s.substr(a, b - a);
    }

    bool isMonitor_ = false;
    bool killedNetworkManager_ = false;
    std::string monitorIface_;
};

// --- airodump-ng CSV capture source --------------------------------------------------
//
// Enumerates APs and associated stations (channel-hopping handled by airodump itself).
// Frame-level events (deauth/EAPOL/PMKID) require the native libpcap source; see
// native_backend.hpp. poll() emits deltas so the engine sees each AP/station once.

class CliCaptureSource final : public sec::ICaptureSource {
public:
    CliCaptureSource() = default;
    CliCaptureSource(const CliCaptureSource&) = delete;
    CliCaptureSource& operator=(const CliCaptureSource&) = delete;
    ~CliCaptureSource() override { stop(); }

    bool start(const std::string& monitorIface) override {
        if (running_) {
            return true;
        }
        if (!sec::isValidIfaceName(monitorIface)) {
            return false;
        }
        seenApBeacons_.clear();
        seenStations_.clear();
        seenProbes_.clear();
        lastPollMs_ = 0u;
        // Create an isolated private temporary directory (mode 0700) to prevent symlink/TOCTOU
        // attacks and protect sniffed wireless telemetry on multi-user systems.
        char templ[] = "/tmp/zd-airodump-XXXXXX";
        char* d = ::mkdtemp(templ);
        if (d == nullptr) {
            return false;
        }
        tempDir_ = d;
        prefix_ = tempDir_ + "/capture";
        csvPath_ = prefix_ + "-01.csv";
        const bool ok = proc_.start({"airodump-ng", "--output-format", "csv", "--write-interval",
                                     "1", "-w", prefix_, "--", monitorIface});
        running_ = ok;
        if (!ok) {
            cleanTempDir();
        }
        return ok;
    }

    std::vector<sec::CapturedFrame> poll() override {
        std::vector<sec::CapturedFrame> frames;
        if (!running_) {
            return frames;
        }
        const uint32_t now = linux_app::nowMs();
        if (lastPollMs_ != 0u && (now - lastPollMs_) < 950u) {
            return frames;
        }
        lastPollMs_ = now;
        const std::string csv = readFileToString(csvPath_);
        if (csv.empty()) {
            return frames;
        }
        // Bound in-memory deduplication tables so long-running captures cannot leak RAM.
        if (seenApBeacons_.size() > kMaxSeenEntries) {
            seenApBeacons_.clear();
        }
        if (seenStations_.size() > kMaxSeenEntries) {
            seenStations_.clear();
        }
        if (seenProbes_.size() > kMaxSeenEntries) {
            seenProbes_.clear();
        }
        const AirodumpDump dump = parseAirodumpCsv(csv);
        for (const AirodumpAp& ap : dump.aps) {
            auto it = seenApBeacons_.find(ap.bssid);
            if (it != seenApBeacons_.end() && it->second == ap.beacons) {
                continue;
            }
            seenApBeacons_[ap.bssid] = ap.beacons;
            sec::CapturedFrame f;
            f.nowMs = now;
            f.kind = sec::FrameKind::Beacon;
            f.bssid = ap.bssid;
            f.ssid = ap.ssid;
            f.channel = ap.channel;
            f.rssi = ap.rssi;
            f.enc = ap.enc;
            frames.push_back(f);
        }
        for (const AirodumpStation& st : dump.stations) {
            if (!st.bssid.empty() && !sec::isMulticastMac(st.bssid)) {
                const std::string key = st.mac + "@" + st.bssid;
                if (seenStations_.insert(key).second) {
                    sec::CapturedFrame f;
                    f.nowMs = now;
                    f.kind = sec::FrameKind::Data;
                    f.bssid = st.bssid;
                    f.source = st.mac;
                    frames.push_back(f);
                }
            }
            for (const std::string& probed : st.probedEssids) {
                const std::string pkey = st.mac + "?" + probed;
                if (seenProbes_.insert(pkey).second) {
                    sec::CapturedFrame pf;
                    pf.nowMs = now;
                    pf.kind = sec::FrameKind::ProbeRequest;
                    pf.source = st.mac;
                    pf.ssid = probed;
                    frames.push_back(pf);
                }
            }
        }
        return frames;
    }

    void stop() override {
        proc_.stop();
        running_ = false;
        cleanTempDir();
    }

    bool running() const override { return running_ && proc_.running(); }

private:
    void cleanTempDir() {
        if (tempDir_.empty()) {
            return;
        }
        if (!csvPath_.empty()) {
            std::remove(csvPath_.c_str());
            csvPath_.clear();
        }
        std::remove((prefix_ + "-01.kismet.csv").c_str());
        std::remove((prefix_ + "-01.kismet.netxml").c_str());
        std::remove((prefix_ + "-01.log.csv").c_str());
        ::rmdir(tempDir_.c_str());
        tempDir_.clear();
        prefix_.clear();
    }

    static constexpr std::size_t kMaxSeenEntries = 2048u;
    DetachedProcess proc_;
    std::string tempDir_;
    std::string prefix_;
    std::string csvPath_;
    std::unordered_map<std::string, uint32_t> seenApBeacons_;
    std::set<std::string> seenStations_;
    std::set<std::string> seenProbes_;
    uint32_t lastPollMs_ = 0u;
    bool running_ = false;
};

// --- Active scan (no root needed; NetworkManager) ------------------------------------
//
// Both front-ends drive this from one periodic UI-thread tick, so the rescan kick +
// settle wait + list fetch (each a blocking nmcli subprocess call) run entirely on a
// worker thread via AsyncJob; pollScan() only ever inspects whether that job has finished.

class CliRadioScanner final : public zd::hal::IRadioScanner {
public:
    explicit CliRadioScanner(std::string iface = "wlan0") : iface_(std::move(iface)) {}

    // Detailed results are retained so the shell can feed BSSID/encryption/WPS into secops.
    // Only ever written on the UI thread (inside pollScan(), after the worker has finished).
    const std::vector<ScannedAp>& detailed() const { return detailed_; }

    bool startAsyncScan() override {
        const std::string iface = iface_;
        return job_.start([iface]() -> std::vector<ScannedAp> {
            const bool validIface = sec::isValidIfaceName(iface);
            std::vector<ScannedAp> list;
            if (validIface) {
                const CommandResult r = runCapture({
                    "nmcli", "-t", "-f", "BSSID,SSID,CHAN,SECURITY,SIGNAL",
                    "dev", "wifi", "list", "--rescan", "auto", "ifname", iface
                });
                if (r.exitCode == 0 && !r.stdoutText.empty()) {
                    list = parseNmcliScanDetailed(r.stdoutText);
                }
            }
            if (list.empty()) {
                const CommandResult r = runCapture({
                    "nmcli", "-t", "-f", "BSSID,SSID,CHAN,SECURITY,SIGNAL",
                    "dev", "wifi", "list", "--rescan", "auto"
                });
                if (r.exitCode == 0 && !r.stdoutText.empty()) {
                    list = parseNmcliScanDetailed(r.stdoutText);
                }
            }
            // Merge WPS flags from kernel scan cache, or fall back to active `iw scan`.
            if (validIface) {
                const CommandResult iwRes = runCapture(
                    list.empty()
                        ? std::vector<std::string>{"iw", "dev", iface, "scan"}
                        : std::vector<std::string>{"iw", "dev", iface, "scan", "dump"},
                    8000u);
                if (iwRes.exitCode == 0 && !iwRes.stdoutText.empty()) {
                    std::vector<ScannedAp> iwList = parseIwScanDetailed(iwRes.stdoutText);
                    if (list.empty()) {
                        list = std::move(iwList);
                    } else {
                        std::unordered_map<std::string, bool> wpsByBssid;
                        for (const ScannedAp& iwAp : iwList) {
                            if (iwAp.wps) {
                                wpsByBssid[iwAp.bssid] = true;
                            }
                        }
                        for (ScannedAp& ap : list) {
                            if (wpsByBssid.find(ap.bssid) != wpsByBssid.end()) {
                                ap.wps = true;
                            }
                        }
                    }
                }
            }
            return list;
        });
    }

    zd::hal::ScanPollResult pollScan() override {
        if (job_.running()) {
            return {zd::hal::ScanPollState::Running, {}};
        }
        const std::optional<std::vector<ScannedAp>> res = job_.collect();
        if (!res.has_value()) {
            return {zd::hal::ScanPollState::Failed, {}};
        }
        detailed_ = *res;
        std::vector<AccessPoint> aps;
        aps.reserve(detailed_.size());
        for (const ScannedAp& item : detailed_) {
            AccessPoint ap;
            ap.ssid = item.ssid;
            ap.rssi = item.rssi;
            ap.channel = item.channel;
            ap.secure = (item.enc != sec::Encryption::Open && item.enc != sec::Encryption::Unknown);
            aps.push_back(std::move(ap));
        }
        return {zd::hal::ScanPollState::Completed, std::move(aps)};
    }

    void clearScan() override {}

private:
    std::string iface_;
    std::vector<ScannedAp> detailed_;
    linux_app::AsyncJob<std::vector<ScannedAp>> job_;
};

// --- Deauth injection (gate enforced by SecSession before this is reached) ------------

class CliInjector final : public sec::IInjector {
public:
    explicit CliInjector(sec::IMonitorControl* monitor) : monitor_(monitor) {}

    bool available() const override {
        return monitor_ != nullptr && monitor_->isMonitor();
    }

    sec::InjectResult deauth(const std::string& bssid, const std::string& client,
                             uint32_t count) override {
        sec::InjectResult res;
        res.decision = sec::AuthDecision::Allowed;  // caller already cleared the gate
        if (monitor_ == nullptr || !monitor_->isMonitor()) {
            res.transmitted = false;
            res.detail = "no monitor interface";
            return res;
        }
        const std::string monIface = monitor_->monitorIface();
        if (!sec::isValidIfaceName(monIface)) {
            res.transmitted = false;
            res.detail = "invalid monitor interface name";
            return res;
        }
        if (!sec::isValidMac(bssid) || !sec::isValidClientTarget(client)) {
            res.transmitted = false;
            res.detail = "invalid BSSID or client MAC";
            return res;
        }
        const uint32_t safeCount = (count < 1u) ? 1u : ((count > 1000u) ? 1000u : count);
        const std::string normBssid = sec::normalizeMac(bssid);
        std::vector<std::string> argv = {"aireplay-ng", "--deauth", std::to_string(safeCount), "-a",
                                         normBssid};
        if (!client.empty()) {
            const std::string normClient = sec::normalizeMac(client);
            if (!sec::isBroadcastMac(normClient)) {
                argv.push_back("-c");
                argv.push_back(normClient);
            }
        }
        argv.push_back("--");
        argv.push_back(monIface);
        const CommandResult r = runCapture(argv);
        res.transmitted = (r.exitCode == 0);
        res.detail = res.transmitted
                         ? ("aireplay-ng sent " + std::to_string(safeCount) + " deauth")
                         : ("aireplay-ng failed (exit " + std::to_string(r.exitCode) + ")");
        return res;
    }

private:
    sec::IMonitorControl* monitor_;
};

// --- Battery via sysfs ---------------------------------------------------------------

class SysfsPowerSensor final : public zd::hal::IPowerSensor {
public:
    zd::hal::PowerStatus readPower() override {
        const auto now = std::chrono::steady_clock::now();
        if (hasCache_ && (now - lastRead_) < std::chrono::seconds(5)) {
            return cached_;
        }
        lastRead_ = now;
        hasCache_ = true;

        zd::hal::PowerStatus st{100, false};
        std::error_code ec;
        std::filesystem::directory_iterator it("/sys/class/power_supply", ec);
        if (ec) {
            cached_ = st;
            return st;
        }
        for (const auto& entry : it) {
            const std::string name = entry.path().filename().string();
            if (name.empty() || name[0] == '.') {
                continue;
            }
            const std::string base = "/sys/class/power_supply/" + name;
            const std::string ptype = trim(readFileToString(base + "/type", 64u));
            if (ptype != "Battery") {
                continue;
            }
            const std::string cap = readFileToString(base + "/capacity", 64u);
            if (!cap.empty()) {
                const int32_t pct = sec::detail::parseI32(cap);
                st.batteryPercent = (pct < 0) ? 0 : ((pct > 100) ? 100 : pct);
                const std::string status = readFileToString(base + "/status", 64u);
                st.isCharging = (status.find("Charging") != std::string::npos) ||
                                (status.find("Full") != std::string::npos);
                cached_ = st;
                return st;
            }
        }
        cached_ = st;
        return st;  // desktop with no battery => 100%, not charging
    }

private:
    zd::hal::PowerStatus cached_{100, false};
    std::chrono::steady_clock::time_point lastRead_{};
    bool hasCache_ = false;
};

// --- File-backed theme, score & trusted-BSSID store ----------------------------------

class FileThemeStore final : public zd::hal::IThemeStore {
public:
    FileThemeStore() {
        const std::string dir = homeDir() + "/.config/pwnagotchi-zeroday";
        dirOk_ = makeDirRecursive(dir, 0700);
        path_ = dir + "/theme";
        hiScorePath_ = dir + "/highscore";
        trustedPath_ = dir + "/trusted_bssids";
        mutedPath_ = dir + "/audio_muted";
    }

    std::string loadThemeKey() override {
        if (!dirOk_) {
            return {};
        }
        const std::string raw = readFileToString(path_, 256u);
        std::string key;
        for (char c : raw) {
            if (c == '\n' || c == '\r' || c == ' ') {
                break;
            }
            key.push_back(c);
        }
        return key;
    }

    void saveThemeKey(std::string_view key) override {
        if (!dirOk_) {
            return;
        }
        const int fd = openSecureWriteRegular(path_, /*append=*/false);
        if (fd >= 0) {
            const std::string entry = std::string(key.data(), key.size()) + "\n";
            (void)writeAllFd(fd, entry.data(), entry.size());
            ::close(fd);
        }
    }

    uint32_t loadHighScore() override {
        if (!dirOk_) {
            return 0u;
        }
        const std::string raw = readFileToString(hiScorePath_, 64u);
        return sec::detail::parseU32(raw);
    }

    void saveHighScore(uint32_t score) override {
        if (!dirOk_) {
            return;
        }
        const int fd = openSecureWriteRegular(hiScorePath_, /*append=*/false);
        if (fd >= 0) {
            const std::string entry = std::to_string(score) + "\n";
            (void)writeAllFd(fd, entry.data(), entry.size());
            ::close(fd);
        }
    }

    bool loadAudioMuted() override {
        if (!dirOk_) {
            return false;
        }
        const std::string raw = trim(readFileToString(mutedPath_, 16u));
        return raw == "1" || raw == "true";
    }

    void saveAudioMuted(bool muted) override {
        if (!dirOk_) {
            return;
        }
        const int fd = openSecureWriteRegular(mutedPath_, /*append=*/false);
        if (fd >= 0) {
            const char* entry = muted ? "1\n" : "0\n";
            (void)writeAllFd(fd, entry, 2u);
            ::close(fd);
        }
    }

    std::vector<std::string> loadTrustedBssids() override {
        std::vector<std::string> out;
        if (!dirOk_) {
            return out;
        }
        std::istringstream in(readFileToString(trustedPath_, 64u * 1024u));
        std::string line;
        while (std::getline(in, line)) {
            const std::string mac = trim(line);
            if (sec::isValidMac(mac)) {
                out.push_back(sec::normalizeMac(mac));
            }
        }
        return out;
    }

    void saveTrustedBssids(const std::vector<std::string>& bssids) override {
        if (!dirOk_) {
            return;
        }
        const int fd = openSecureWriteRegular(trustedPath_, /*append=*/false);
        if (fd >= 0) {
            std::string body;
            for (const std::string& b : bssids) {
                body += b + "\n";
            }
            (void)writeAllFd(fd, body.data(), body.size());
            ::close(fd);
        }
    }

private:
    std::string path_;
    std::string hiScorePath_;
    std::string trustedPath_;
    std::string mutedPath_;
    bool dirOk_ = false;
};

// --- Append-only audit log for every transmit decision -------------------------------

class FileAuditLog final : public sec::IAuditLog {
public:
    FileAuditLog() {
        const std::string dir = (::geteuid() == 0)
                                    ? std::string("/var/log/pwnagotchi-zeroday")
                                    : (homeDir() + "/.local/share/pwnagotchi-zeroday");
        dirOk_ = makeDirRecursive(dir, 0700);
        path_ = dir + "/audit.log";
    }

    explicit FileAuditLog(std::string customPath) : path_(std::move(customPath)) {
        const std::size_t slash = path_.rfind('/');
        if (slash != std::string::npos && slash > 0u) {
            dirOk_ = makeDirRecursive(path_.substr(0, slash), 0700);
        } else {
            dirOk_ = true;
        }
    }

    bool record(const std::string& line) override {
        if (!dirOk_) {
            return false;
        }
        // Enforce 0600 permissions, regular file, no symlinks, sanitized single-line entry, and fsync.
        const int fd = openSecureWriteRegular(path_, /*append=*/true);
        if (fd < 0) {
            return false;
        }
        const std::string cleanLine = sec::sanitizePrintableText(line, 512u);
        const std::time_t t = std::time(nullptr);
        std::tm tmBuf{};
        ::localtime_r(&t, &tmBuf);
        char ts[32] = {0};
        std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmBuf);
        const std::string entry = std::string(ts) + " " + cleanLine + "\n";
        const bool ok = writeAllFd(fd, entry.data(), entry.size()) && (::fsync(fd) == 0);
        ::close(fd);
        return ok;
    }

    const std::string& path() const { return path_; }

private:
    std::string path_;
    bool dirOk_ = false;
};

// --- Live session event recorder (--record <file>) & file I/O helpers ----------------

class FileSessionRecorder final : public sec::ISessionRecorder {
public:
    FileSessionRecorder() = default;
    FileSessionRecorder(const FileSessionRecorder&) = delete;
    FileSessionRecorder& operator=(const FileSessionRecorder&) = delete;
    bool open(const std::string& path) {
        close();
        fd_ = openSecureWriteRegular(path, /*append=*/true);
        if (fd_ < 0) {
            return false;
        }
        path_ = path;
        return true;
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        path_.clear();
    }

    ~FileSessionRecorder() override { close(); }

    void recordEvent(const std::string& encodedLine) override {
        if (fd_ < 0 || encodedLine.empty()) {
            return;
        }
        const std::string line = encodedLine + "\n";
        (void)writeAllFd(fd_, line.data(), line.size());
    }

    bool active() const { return fd_ >= 0; }
    const std::string& path() const { return path_; }

private:
    int fd_ = -1;
    std::string path_;
};

template <typename Container = std::vector<sec::SecEvent>>
inline bool saveEventsToFile(const std::string& path, const Container& events) {
    const int fd = openSecureWriteRegular(path, /*append=*/false);
    if (fd < 0) {
        return false;
    }
    for (const std::string& line : sec::encodeSecEvents(events)) {
        const std::string entry = line + "\n";
        if (!writeAllFd(fd, entry.data(), entry.size())) {
            ::close(fd);
            return false;
        }
    }
    ::close(fd);
    return true;
}

inline std::optional<std::vector<sec::SecEvent>> loadEventsFromFile(
    const std::string& path,
    std::size_t maxBytes = 16u * 1024u * 1024u,
    std::size_t maxLines = 200000u) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return std::nullopt;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        ::close(fd);
        return std::nullopt;
    }
    if (st.st_size > 0 && static_cast<std::size_t>(st.st_size) > maxBytes) {
        ::close(fd);
        return std::nullopt;
    }
    std::string content;
    if (st.st_size > 0) {
        content.reserve(static_cast<std::size_t>(st.st_size));
    }
    char buf[8192];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            return std::nullopt;
        }
        if (n == 0) {
            break;
        }
        if (content.size() + static_cast<std::size_t>(n) > maxBytes) {
            ::close(fd);
            return std::nullopt;
        }
        content.append(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);

    std::istringstream in(content);
    std::vector<std::string> lines;
    std::string line;
    while (lines.size() < maxLines && std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(std::move(line));
    }
    return sec::decodeSecEvents(lines);
}

// --- Async BlueZ BLE Scanner & Optional rtl_433 Sub-GHz Receiver ---------------------

class CliBleScanner final : public zd::hal::IBleScanner {
public:
    CliBleScanner() : available_(!detail::resolveTrustedExecutable("bluetoothctl").empty()) {}

    bool available() const override { return available_; }

    bool startAsyncScan() {
        if (!available_) {
            return false;
        }
        return job_.start([]() -> std::vector<BleDevice> {
            (void)runCapture({"bluetoothctl", "--timeout", "2", "scan", "on"}, 3000u, 65536u);
            const CommandResult r = runCapture({"bluetoothctl", "devices"}, 2000u, 256u * 1024u);
            std::vector<BleDevice> out;
            if (!r.launched) {
                return out;
            }
            std::istringstream in(r.stdoutText);
            std::string line;
            while (std::getline(in, line)) {
                if (const auto d = parseBluezBleLine(line)) {
                    out.push_back(BleDevice{
                        d->mac, d->name, d->rssi, d->companyId, d->serviceUuid,
                        d->trackerPayload, d->threat});
                }
            }
            return out;
        });
    }

    std::vector<BleDevice> pollBleDevices(uint32_t nowMs) override {
        if (!available_) {
            return {};
        }
        if (const auto res = job_.collect()) {
            return *res;
        }
        if (!job_.running() && autoEnabled_ && (nowMs - lastKickMs_) >= 15000u) {
            lastKickMs_ = nowMs;
            (void)startAsyncScan();
        }
        return {};
    }

    void setAutoEnabled(bool en) { autoEnabled_ = en; }
    bool autoEnabled() const { return autoEnabled_; }

private:
    bool available_ = false;
    bool autoEnabled_ = false;
    uint32_t lastKickMs_ = 0u;
    linux_app::AsyncJob<std::vector<BleDevice>> job_;
};

class Rtl433Source final : public zd::hal::ISubGhzRadio {
public:
    Rtl433Source() : binary_(!detail::resolveTrustedExecutable("rtl_433").empty()) {}
    Rtl433Source(const Rtl433Source&) = delete;
    Rtl433Source& operator=(const Rtl433Source&) = delete;
    ~Rtl433Source() override { stop(); }

    bool available() const override { return binary_; }
    uint32_t frequencyKhz() const override { return freqKhz_; }

    bool tuneFrequency(uint32_t freqKhz) override {
        if (freqKhz < 300000u || freqKhz > 928000u) {
            return false;
        }
        freqKhz_ = freqKhz;
        if (running_) {
            stop();
            return start();
        }
        return binary_;
    }

    bool start() {
        if (!binary_ || running_) {
            return running_;
        }
        const std::string resolved = detail::resolveTrustedExecutable("rtl_433");
        if (resolved.empty()) {
            return false;
        }
        int pipefd[2];
        if (::pipe(pipefd) != 0) {
            return false;
        }
        ::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        ::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        ::fcntl(pipefd[0], F_SETFL, O_NONBLOCK);

        const std::string freqArg = std::to_string(freqKhz_) + "k";
        std::vector<std::string> args = {resolved, "-f", freqArg, "-M", "level", "-F", "kv"};
        std::vector<char*> cargv;
        cargv.reserve(args.size() + 1u);
        for (std::string& a : args) cargv.push_back(a.data());
        cargv.push_back(nullptr);
        const char* const execPath = resolved.c_str();
        char* const* const execArgv = cargv.data();
        char* const* const execEnv = detail::safeEnviron();
        const int maxFd = detail::safeMaxFd();

        const pid_t pid = ::fork();
        if (pid < 0) {
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            return false;
        }
        if (pid == 0) {
            ::setpgid(0, 0);
            const int devnull = ::open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                ::dup2(devnull, STDIN_FILENO);
                ::dup2(devnull, STDERR_FILENO);
                if (devnull > STDERR_FILENO) {
                    ::close(devnull);
                }
            }
            ::dup2(pipefd[1], STDOUT_FILENO);
            if (pipefd[0] > STDERR_FILENO) {
                ::close(pipefd[0]);
            }
            if (pipefd[1] > STDERR_FILENO) {
                ::close(pipefd[1]);
            }
            detail::closeNonStdioFds(maxFd);
            ::execve(execPath, execArgv, execEnv);
            ::_exit(127);
        }
        ::close(pipefd[1]);
        readFd_ = pipefd[0];
        pid_ = pid;
        running_ = true;
        return true;
    }

    void stop() {
        if (readFd_ >= 0) {
            ::close(readFd_);
            readFd_ = -1;
        }
        if (pid_ > 0) {
            detail::terminateChild(pid_);
            pid_ = -1;
        }
        running_ = false;
        buf_.clear();
    }

    std::optional<SubGhzSignal> pollSignal(uint32_t nowMs) override {
        (void)nowMs;
        if (!running_ || readFd_ < 0) {
            return std::nullopt;
        }
        char tmp[1024];
        const ssize_t n = ::read(readFd_, tmp, sizeof(tmp));
        if (n > 0) {
            buf_.append(tmp, static_cast<std::size_t>(n));
            if (buf_.size() > 8192u) {
                buf_.erase(0, buf_.size() - 4096u);
            }
        }
        const std::size_t nl = buf_.find('\n');
        if (nl == std::string::npos) {
            return std::nullopt;
        }
        const std::string line = buf_.substr(0, nl);
        buf_.erase(0, nl + 1u);
        if (const auto sig = parseRtl433Line(line)) {
            const SubGhzAnomaly anom =
                sig->continuousCarrier
                    ? SubGhzAnomaly::JammingCarrier
                    : (sig->burstCount >= 5u ? SubGhzAnomaly::ReplayBurst : SubGhzAnomaly::None);
            return SubGhzSignal{sig->freqKhz, sig->rssi, sig->protocol, sig->burstCount, anom};
        }
        return std::nullopt;
    }

private:
    bool binary_ = false;
    bool running_ = false;
    uint32_t freqKhz_ = 433920u;
    int readFd_ = -1;
    pid_t pid_ = -1;
    std::string buf_;
};

}  // namespace linux_backend
}  // namespace zd
