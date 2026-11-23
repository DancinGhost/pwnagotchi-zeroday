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
#include <deque>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zd/hal.hpp"
#include "zd/secops_hal.hpp"
#include "nmea.hpp"
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

// Open/create `dir` component-by-component via openat(O_NOFOLLOW | O_DIRECTORY) + mkdirat(),
// eliminating intermediate symlink races and TOCTOU windows. Returns an open dirfd or -1.
inline int openDirNoFollowRecursive(const std::string& dir, mode_t mode = 0700,
                                    bool requireRootOwner = false) {
    if (dir.empty()) {
        return -1;
    }
    int curFd = ::open((dir[0] == '/') ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (curFd < 0) {
        return -1;
    }
    const uid_t euid = ::geteuid();
    std::size_t pos = (dir[0] == '/') ? 1u : 0u;
    while (pos < dir.size()) {
        while (pos < dir.size() && dir[pos] == '/') {
            ++pos;
        }
        if (pos >= dir.size()) {
            break;
        }
        std::size_t end = dir.find('/', pos);
        if (end == std::string::npos) {
            end = dir.size();
        }
        const std::string comp = dir.substr(pos, end - pos);
        pos = end;
        if (comp == ".") {
            continue;
        }
        if (comp == "..") {
            ::close(curFd);
            return -1;
        }
        int nextFd = ::openat(curFd, comp.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nextFd < 0 && errno == ENOENT) {
            if (::mkdirat(curFd, comp.c_str(), mode) != 0 && errno != EEXIST) {
                ::close(curFd);
                return -1;
            }
            nextFd = ::openat(curFd, comp.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (nextFd < 0) {
            ::close(curFd);
            return -1;
        }
        struct stat st {};
        if (::fstat(nextFd, &st) != 0 || !S_ISDIR(st.st_mode) ||
            (requireRootOwner && euid == 0 && st.st_uid != 0)) {
            ::close(nextFd);
            ::close(curFd);
            return -1;
        }
        ::close(curFd);
        curFd = nextFd;
    }
    return curFd;
}

// Create `dir` and any missing parents (POSIX `mkdir -p`, without spawning a subprocess),
// verifying each traversed component is a real directory (not a symlink).
inline bool makeDirRecursive(const std::string& dir, mode_t mode = 0700) {
    const int dirFd = openDirNoFollowRecursive(dir, mode, ::geteuid() == 0);
    if (dirFd < 0) {
        return false;
    }
    ::close(dirFd);
    return true;
}

inline std::string resolveLexicalPath(const std::string& path) {
    if (path.empty()) {
        return {};
    }
    std::string combined = path;
    if (combined[0] != '/') {
        char cwdBuf[4096];
        if (::getcwd(cwdBuf, sizeof(cwdBuf)) != nullptr) {
            combined = std::string(cwdBuf) + "/" + combined;
        }
    }
    std::vector<std::string> parts;
    std::size_t pos = 0u;
    while (pos < combined.size()) {
        while (pos < combined.size() && combined[pos] == '/') {
            ++pos;
        }
        if (pos >= combined.size()) {
            break;
        }
        std::size_t end = combined.find('/', pos);
        if (end == std::string::npos) {
            end = combined.size();
        }
        const std::string seg = combined.substr(pos, end - pos);
        pos = end;
        if (seg == ".") {
            continue;
        }
        if (seg == "..") {
            if (!parts.empty()) {
                parts.pop_back();
            }
            continue;
        }
        parts.push_back(seg);
    }
    std::string norm;
    for (const std::string& p : parts) {
        norm.push_back('/');
        norm += p;
    }
    if (norm.empty() && combined[0] == '/') {
        norm = "/";
    }
    return norm;
}

inline bool isBlockedSystemPrefix(const std::string& path) {
    const std::string norm = resolveLexicalPath(path);
    if (norm.empty()) {
        return false;
    }
    if (norm == "/var/tmp" || norm.rfind("/var/tmp/", 0) == 0) {
        return false;
    }
    static constexpr const char* kBlocked[] = {
        "/etc", "/usr", "/bin", "/sbin", "/boot", "/lib", "/lib64", "/proc", "/sys", "/dev",
        "/var", "/run"
    };
    for (const char* p : kBlocked) {
        const std::size_t plen = std::char_traits<char>::length(p);
        if (norm == p || (norm.rfind(p, 0) == 0 && norm.size() > plen && norm[plen] == '/')) {
            return true;
        }
    }
    return false;
}

inline std::string resolveDirFdPath(int dirFd) {
    if (dirFd < 0) {
        return {};
    }
    const std::string linkPath = "/proc/self/fd/" + std::to_string(dirFd);
    char buf[4096];
    const ssize_t n = ::readlink(linkPath.c_str(), buf, sizeof(buf) - 1);
    if (n <= 0) {
        return {};
    }
    buf[n] = '\0';
    return std::string(buf, static_cast<std::size_t>(n));
}

// Safely open a regular file for writing/appending without following parent/leaf symlinks,
// hardlink attacks, blocking on FIFOs, or overwriting privileged system files.
inline int openSecureWriteRegular(const std::string& path, bool append) {
    if (path.empty() || path.back() == '/') {
        return -1;
    }
    if (::geteuid() == 0 && isBlockedSystemPrefix(path)) {
        return -1;
    }
    const std::size_t slash = path.rfind('/');
    const std::string parentDir =
        (slash == std::string::npos) ? std::string(".")
                                     : ((slash == 0u) ? std::string("/") : path.substr(0u, slash));
    const std::string leaf =
        (slash == std::string::npos) ? path : path.substr(slash + 1u);
    if (leaf.empty() || leaf == "." || leaf == "..") {
        return -1;
    }

    const int dirFd = openDirNoFollowRecursive(parentDir, 0700, /*requireRootOwner=*/false);
    if (dirFd < 0) {
        return -1;
    }

    if (::geteuid() == 0) {
        const std::string canonicalDir = resolveDirFdPath(dirFd);
        if (!canonicalDir.empty()) {
            const std::string fullCanonical =
                (canonicalDir == "/") ? ("/" + leaf) : (canonicalDir + "/" + leaf);
            if (isBlockedSystemPrefix(fullCanonical)) {
                ::close(dirFd);
                return -1;
            }
        }
    }

    const int createFlags =
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (append ? O_APPEND : 0);
    int fd = ::openat(dirFd, leaf.c_str(), createFlags, 0600);
    if (fd < 0 && errno == EEXIST) {
        const int openFlags =
            O_WRONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | (append ? O_APPEND : 0);
        fd = ::openat(dirFd, leaf.c_str(), openFlags);
    }
    ::close(dirFd);
    if (fd < 0) {
        return -1;
    }

    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        ::close(fd);
        return -1;
    }
    if (::geteuid() == 0 && (st.st_uid != 0 || (st.st_mode & 0022) != 0)) {
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
    // True when monitorIface is a *virtual* monitor vif added alongside the still-managed
    // parent (iw interface add), rather than the parent itself flipped to monitor type.
    // Teardown deletes the vif instead of reverting the parent to managed.
    bool virtualVif = false;
};

// --- Monitor mode / channel control --------------------------------------------------

class CliMonitorControl final : public sec::IMonitorControl {
public:
    // Name of the virtual monitor vif we create alongside a still-managed parent.
    static constexpr const char* kVirtualMonIface = "zdmon0";

    // Slow (airmon-ng commonly takes seconds): brings an interface into monitor mode and
    // resolves the resulting interface name via `iw dev`. Touches no object state, so it
    // is safe to run on a worker thread; the caller commits the result via applyUp().
    static MonitorBringUpResult bringUpMonitorDetailed(const std::string& iface) {
        MonitorBringUpResult res;
        if (!sec::isValidIfaceName(iface)) {
            return res;
        }
        // Gold path: add a *virtual* monitor interface alongside the parent so the laptop's
        // managed connection (NetworkManager, SSH, etc.) stays fully online. Works on most
        // mac80211 drivers and is the only path that never knocks the host offline.
        runCapture({"iw", "dev", kVirtualMonIface, "del"});  // clean up any stale vif
        if (runCapture({"iw", "dev", iface, "interface", "add", kVirtualMonIface, "type",
                        "monitor"})
                    .exitCode == 0 &&
            runCapture({"ip", "link", "set", kVirtualMonIface, "up"}).exitCode == 0) {
            const std::string mon = findMonitorInterface(kVirtualMonIface);
            if (!mon.empty()) {
                res.monitorIface = mon;
                res.killedNetworkManager = false;
                res.virtualVif = true;
                return res;
            }
            runCapture({"iw", "dev", kVirtualMonIface, "del"});  // partial failure; don't leak it
        }
        // Fallback: flip the parent interface itself to monitor (still skips check kill, but
        // takes the parent offline for the duration of the session).
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
        // Last resort: airmon-ng, which kills NetworkManager and takes the host offline.
        runCapture({"airmon-ng", "check", "kill"});
        res.killedNetworkManager = true;
        runCapture({"airmon-ng", "start", "--", iface});
        res.monitorIface = findMonitorInterface(iface);  // "" if no monitor interface resulted
        if (res.monitorIface.empty()) {
            runCapture({"systemctl", "start", "NetworkManager"});
            res.killedNetworkManager = false;
        }
        return res;
    }

    static std::string bringUpMonitor(const std::string& iface) {
        return bringUpMonitorDetailed(iface).monitorIface;
    }

    // Slow: tears down monitor mode on `monitorIface`. A virtual vif is simply deleted,
    // leaving the parent interface untouched. Only restarts NetworkManager if
    // `restartNetworkManager` is true (i.e. `airmon-ng check kill` actually ran).
    static void takeDownMonitor(const std::string& monitorIface,
                                bool restartNetworkManager = false,
                                bool virtualVif = false) {
        if (!sec::isValidIfaceName(monitorIface)) {
            return;
        }
        if (virtualVif) {
            // The parent stayed managed/online; just remove the monitor vif.
            runCapture({"ip", "link", "set", monitorIface, "down"});
            runCapture({"iw", "dev", monitorIface, "del"});
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
    void applyUp(const std::string& mon, bool killedNm = false, bool virtualVif = false) {
        if (mon.empty()) {
            isMonitor_ = false;
            monitorIface_.clear();
            killedNetworkManager_ = false;
            virtualVif_ = false;
        } else {
            monitorIface_ = mon;
            isMonitor_ = true;
            killedNetworkManager_ = killedNm;
            virtualVif_ = virtualVif;
        }
    }
    void applyDown() {
        isMonitor_ = false;
        monitorIface_.clear();
        killedNetworkManager_ = false;
        virtualVif_ = false;
    }

    bool killedNetworkManager() const { return killedNetworkManager_; }
    bool virtualVif() const { return virtualVif_; }

    // Synchronous convenience wrappers (fine for one-shot CLI use).
    std::string enableMonitor(const std::string& iface) override {
        const MonitorBringUpResult r = bringUpMonitorDetailed(iface);
        applyUp(r.monitorIface, r.killedNetworkManager, r.virtualVif);
        return r.monitorIface;
    }

    void disableMonitor() override {
        if (!isMonitor_) {
            return;
        }
        takeDownMonitor(monitorIface_, killedNetworkManager_, virtualVif_);
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
    bool virtualVif_ = false;
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
        seenApOrder_.clear();
        seenStations_.clear();
        seenStationOrder_.clear();
        seenProbes_.clear();
        seenProbeOrder_.clear();
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
        const AirodumpDump dump = parseAirodumpCsv(csv);
        for (const AirodumpAp& ap : dump.aps) {
            auto it = seenApBeacons_.find(ap.bssid);
            if (it != seenApBeacons_.end() && it->second == ap.beacons) {
                continue;
            }
            if (it == seenApBeacons_.end()) {
                while (seenApBeacons_.size() >= kMaxSeenEntries && !seenApOrder_.empty()) {
                    seenApBeacons_.erase(seenApOrder_.front());
                    seenApOrder_.pop_front();
                }
                seenApOrder_.push_back(ap.bssid);
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
                if (seenStations_.find(key) == seenStations_.end()) {
                    while (seenStations_.size() >= kMaxSeenEntries && !seenStationOrder_.empty()) {
                        seenStations_.erase(seenStationOrder_.front());
                        seenStationOrder_.pop_front();
                    }
                    seenStations_.insert(key);
                    seenStationOrder_.push_back(key);
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
                if (seenProbes_.find(pkey) == seenProbes_.end()) {
                    while (seenProbes_.size() >= kMaxSeenEntries && !seenProbeOrder_.empty()) {
                        seenProbes_.erase(seenProbeOrder_.front());
                        seenProbeOrder_.pop_front();
                    }
                    seenProbes_.insert(pkey);
                    seenProbeOrder_.push_back(pkey);
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
    std::deque<std::string> seenApOrder_;
    std::set<std::string> seenStations_;
    std::deque<std::string> seenStationOrder_;
    std::set<std::string> seenProbes_;
    std::deque<std::string> seenProbeOrder_;
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
                        struct IwFlags {
                            bool wps = false;
                            sec::PmfStatus pmf = sec::PmfStatus::Disabled;
                        };
                        std::unordered_map<std::string, IwFlags> flagsByBssid;
                        for (const ScannedAp& iwAp : iwList) {
                            if (iwAp.wps || iwAp.pmf != sec::PmfStatus::Disabled) {
                                IwFlags& fl = flagsByBssid[iwAp.bssid];
                                fl.wps = fl.wps || iwAp.wps;
                                if (static_cast<uint8_t>(iwAp.pmf) > static_cast<uint8_t>(fl.pmf)) {
                                    fl.pmf = iwAp.pmf;
                                }
                            }
                        }
                        for (ScannedAp& ap : list) {
                            const auto it = flagsByBssid.find(ap.bssid);
                            if (it != flagsByBssid.end()) {
                                if (it->second.wps) {
                                    ap.wps = true;
                                }
                                if (it->second.pmf != sec::PmfStatus::Disabled) {
                                    ap.pmf = it->second.pmf;
                                }
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
        ::gmtime_r(&t, &tmBuf);
        char ts[32] = {0};
        std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmBuf);
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
    CliBleScanner()
        : hasBluetoothctl_(!detail::resolveTrustedExecutable("bluetoothctl").empty()),
          hasBtmgmt_(!detail::resolveTrustedExecutable("btmgmt").empty()),
          available_(hasBluetoothctl_ || hasBtmgmt_) {}

    bool available() const override { return available_; }
    bool scanning() const { return job_.running(); }
    bool hasCompletedScan() const { return scanCompleted_; }
    std::size_t lastScanCount() const { return lastScanCount_; }
    bool consumeCompletedScan() {
        const bool was = scanCompleted_;
        scanCompleted_ = false;
        return was;
    }

    bool startAsyncScan() {
        if (!available_) {
            return false;
        }
        const bool useCtl = hasBluetoothctl_;
        const bool useBtm = hasBtmgmt_;
        return job_.start([useCtl, useBtm]() -> std::vector<BleDevice> {
            std::unordered_map<std::string, BleDevice> byMac;
            std::vector<std::string> order;
            auto mergeScanned = [&](const ScannedBleDevice& d) {
                if (d.mac.empty() || sec::isBroadcastMac(d.mac)) {
                    return;
                }
                auto it = byMac.find(d.mac);
                if (it == byMac.end()) {
                    order.push_back(d.mac);
                    byMac.emplace(
                        d.mac, BleDevice{d.mac, d.name, d.rssi, d.companyId, d.serviceUuid,
                                         d.trackerPayload, d.threat});
                    return;
                }
                BleDevice& cur = it->second;
                if (!d.name.empty() &&
                    (cur.name.empty() || ble_parse_detail::isPlaceholderMacName(cur.name, cur.mac))) {
                    cur.name = d.name;
                }
                if (d.rssi != -100 && (cur.rssi == -100 || cur.rssi == -65 || d.rssi != -65)) {
                    cur.rssi = d.rssi;
                }
                if (d.companyId != 0u) {
                    cur.companyId = d.companyId;
                }
                ble_parse_detail::assignPriorityServiceUuid(cur.serviceUuid, d.serviceUuid);
                cur.trackerPayload = cur.trackerPayload || d.trackerPayload;
                cur.threat = classifyBleDevice(cur.mac, cur.name, cur.companyId, cur.serviceUuid,
                                               cur.trackerPayload);
            };

            if (useCtl) {
                const CommandResult scanRes =
                    runCapture({"bluetoothctl", "--timeout", "4", "scan", "on"}, 6000u, 256u * 1024u);
                if (scanRes.launched) {
                    for (const ScannedBleDevice& d : parseBluezScanOutput(scanRes.stdoutText)) {
                        mergeScanned(d);
                    }
                }
                const CommandResult devRes =
                    runCapture({"bluetoothctl", "devices"}, 2000u, 256u * 1024u);
                if (devRes.launched) {
                    std::istringstream in(devRes.stdoutText);
                    std::string line;
                    while (std::getline(in, line)) {
                        if (const auto d = parseBluezBleLine(line)) {
                            mergeScanned(*d);
                        }
                    }
                }
                // Enrich up to 20 devices missing real RSSI or vendor/service metadata within a 3s budget.
                const auto enrichDeadline =
                    std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
                std::size_t infoCalls = 0u;
                for (const std::string& mac : order) {
                    if (infoCalls >= 20u || std::chrono::steady_clock::now() >= enrichDeadline) {
                        break;
                    }
                    BleDevice& cur = byMac[mac];
                    if ((cur.rssi == -65 || cur.rssi == -100) ||
                        (cur.companyId == 0u && cur.serviceUuid == 0u)) {
                        const CommandResult infoRes =
                            runCapture({"bluetoothctl", "info", mac}, 1000u, 32u * 1024u);
                        ++infoCalls;
                        if (infoRes.launched && !infoRes.stdoutText.empty()) {
                            ScannedBleDevice tmp{};
                            tmp.mac = cur.mac;
                            tmp.name = cur.name;
                            tmp.rssi = cur.rssi;
                            tmp.companyId = cur.companyId;
                            tmp.serviceUuid = cur.serviceUuid;
                            tmp.trackerPayload = cur.trackerPayload;
                            if (parseBluezDeviceInfo(infoRes.stdoutText, tmp)) {
                                mergeScanned(tmp);
                            }
                        }
                    }
                }
            }
            if (order.empty() && useBtm) {
                const CommandResult btmRes = runCapture({"btmgmt", "find"}, 5000u, 256u * 1024u);
                if (btmRes.launched) {
                    for (const ScannedBleDevice& d : parseBtmgmtFindOutput(btmRes.stdoutText)) {
                        mergeScanned(d);
                    }
                }
            }

            std::vector<BleDevice> out;
            out.reserve(order.size());
            for (const std::string& mac : order) {
                BleDevice d = byMac[mac];
                d.threat = classifyBleDevice(d.mac, d.name, d.companyId, d.serviceUuid,
                                             d.trackerPayload);
                out.push_back(std::move(d));
            }
            return out;
        });
    }

    std::vector<BleDevice> pollBleDevices(uint32_t nowMs) override {
        if (!available_) {
            return {};
        }
        if (const auto res = job_.collect()) {
            scanCompleted_ = true;
            lastScanCount_ = res->size();
            return *res;
        }
        if (!job_.running() && autoEnabled_ &&
            (lastKickMs_ == 0u || (nowMs - lastKickMs_) >= 15000u)) {
            lastKickMs_ = nowMs;
            (void)startAsyncScan();
        }
        return {};
    }

    void setAutoEnabled(bool en) { autoEnabled_ = en; }
    bool autoEnabled() const { return autoEnabled_; }

private:
    bool hasBluetoothctl_ = false;
    bool hasBtmgmt_ = false;
    bool available_ = false;
    bool autoEnabled_ = false;
    bool scanCompleted_ = false;
    std::size_t lastScanCount_ = 0u;
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
    bool running() const { return running_; }
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
#if defined(__linux__)
        if (::pipe2(pipefd, O_CLOEXEC) != 0) {
            return false;
        }
#else
        if (::pipe(pipefd) != 0) {
            return false;
        }
        ::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        ::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
#endif
        ::fcntl(pipefd[0], F_SETFL, O_NONBLOCK);

        const std::string freqArg = std::to_string(freqKhz_) + "k";
        std::vector<std::string> args = {resolved, "-f", freqArg, "-M", "level", "-F", "json"};
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
        } else if (n == 0) {
            stop();
            return std::nullopt;
        }
        const std::size_t nl = buf_.find('\n');
        if (nl == std::string::npos) {
            return std::nullopt;
        }
        const std::string line = buf_.substr(0, nl);
        buf_.erase(0, nl + 1u);
        if (const auto sig = parseRtl433Line(line, freqKhz_)) {
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

// Best-effort desktop notifications via libnotify (`notify-send`) on Critical alerts.
// Uses strict `--` argument separation and printable-ASCII sanitization; dryRun_ mode lets
// unit tests exercise trigger logic cleanly without DBus/display dependencies.
class DesktopNotifier {
public:
    void setEnabled(bool on) { enabled_ = on; }
    bool enabled() const { return enabled_; }
    void setDryRun(bool on) { dryRun_ = on; }
    bool dryRun() const { return dryRun_; }

    uint32_t sentCount() const { return sentCount_; }
    const std::string& lastTitle() const { return lastTitle_; }
    const std::string& lastBody() const { return lastBody_; }

    bool notifyCritical(const sec::Alert& al) {
        if (!enabled_ || al.severity != sec::Severity::Critical) {
            return false;
        }
        const std::string title =
            std::string("[ZeroDay] ") + sec::alertKindLabel(al.kind);
        const std::string target =
            al.ssid.empty() ? sec::sanitizePrintableText(al.bssid, 32u)
                            : (sec::sanitizePrintableText(al.ssid, 40u) + " (" +
                               sec::sanitizePrintableText(al.bssid, 32u) + ")");
        const std::string msg = sec::sanitizePrintableText(al.message, 140u);
        const std::string body = target.empty() ? msg : (target + ": " + msg);
        lastTitle_ = title;
        lastBody_ = body;
        sentCount_ += 1u;
        if (dryRun_) {
            return true;
        }
        const CommandResult res = runCapture(
            {"notify-send", "-u", "critical", "-a", "pwnagotchi-zeroday", "--", title, body},
            800u, 4096u);
        return res.launched && res.exitCode == 0;
    }

private:
    bool enabled_ = false;
    bool dryRun_ = false;
    uint32_t sentCount_ = 0u;
    std::string lastTitle_;
    std::string lastBody_;
};

// Non-blocking TCP client for local `gpsd` daemon (127.0.0.1:2947).
class GpsdClient {
public:
    GpsdClient() = default;
    GpsdClient(const GpsdClient&) = delete;
    GpsdClient& operator=(const GpsdClient&) = delete;
    ~GpsdClient() { stop(); }

    bool start(const std::string& host = "127.0.0.1", uint16_t port = 2947u) {
        stop();
        const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            return false;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            ::close(fd);
            return false;
        }
        const int rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
        if (rc < 0 && errno != EINPROGRESS) {
            ::close(fd);
            return false;
        }
        fd_ = fd;
        watchSent_ = false;
        return true;
    }

    void stop() {
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
        watchSent_ = false;
        buf_.clear();
    }

    bool connected() const { return fd_ >= 0; }

    void poll(uint32_t nowMs) {
        zd::esp32_common::expireStaleGpsFix(gps_, nowMs);
        if (fd_ < 0) {
            return;
        }
        pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = static_cast<short>(POLLIN | (watchSent_ ? 0 : POLLOUT));
        const int pr = ::poll(&pfd, 1, 0);
        if (pr <= 0) {
            return;
        }
        if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            stop();
            return;
        }
        if (!watchSent_ && (pfd.revents & POLLOUT) != 0) {
            static constexpr char kWatchCmd[] =
                "?WATCH={\"enable\":true,\"json\":true,\"nmea\":true};\n";
            const ssize_t wn = ::send(fd_, kWatchCmd, sizeof(kWatchCmd) - 1u, MSG_NOSIGNAL);
            if (wn > 0) {
                watchSent_ = true;
            }
        }
        if ((pfd.revents & POLLIN) != 0) {
            char tmp[1024];
            const ssize_t n = ::recv(fd_, tmp, sizeof(tmp), 0);
            if (n > 0) {
                buf_.append(tmp, static_cast<std::size_t>(n));
                if (buf_.size() > 8192u) {
                    buf_.erase(0, buf_.size() - 4096u);
                }
                for (;;) {
                    const std::size_t nl = buf_.find('\n');
                    if (nl == std::string::npos) {
                        break;
                    }
                    const std::string line = buf_.substr(0, nl);
                    buf_.erase(0, nl + 1u);
                    (void)parseGpsdLine(line, gps_, nowMs);
                }
            } else if (n == 0) {
                stop();
            }
        }
    }

    bool ingestLine(const std::string& line, uint32_t nowMs) {
        return parseGpsdLine(line, gps_, nowMs);
    }

    const zd::esp32_common::GpsState& state() const { return gps_; }

private:
    int fd_ = -1;
    bool watchSent_ = false;
    std::string buf_;
    zd::esp32_common::GpsState gps_{};
};

}  // namespace linux_backend
}  // namespace zd
