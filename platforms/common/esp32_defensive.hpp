#pragma once

// Pure, lock-free ESP32 promiscuous 802.11 defensive monitor core.
//
// Zero Arduino or ESP-IDF headers live here so the ring buffer, decoder wiring,
// SecSession ingestion, and PetMood synchronization compile and run under `-fno-exceptions
// -fno-rtti` in host unit tests (`tests/core/test_esp32_common.cpp`).

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "zd/dot11_decode.hpp"
#include "zd/hal.hpp"
#include "zd/peering.hpp"
#include "zd/secops.hpp"
#include "zd/secops_hal.hpp"

namespace zd {
namespace esp32_common {

// Max captured bytes per frame. 256 clipped trailing RSN/WPS/vendor IEs on modern
// WiFi 6 / enterprise beacons (which routinely exceed 256 bytes); 512 covers the vast
// majority while keeping the ring's RAM footprint bounded (~512 B * kRingCapacity).
static constexpr std::size_t kMaxFrameLen = 512u;

struct RawDot11Packet {
    uint32_t nowMs = 0u;
    int32_t rssi = -100;
    uint16_t len = 0u;
    std::array<uint8_t, kMaxFrameLen> data{};
};

class Esp32DefensiveMonitorCore {
public:
    // Power-of-two capacity for lock-free single-producer/single-consumer ring indexing.
    // 32 slots absorb dense mgmt bursts between the 10-15 ms monitor loop ticks that
    // 16 slots dropped.
    static constexpr std::size_t kRingCapacity = 32u;

    void setEnabled(bool on) { enabled_.store(on, std::memory_order_release); }
    bool enabled() const { return enabled_.load(std::memory_order_acquire); }

    void reset() {
        writeIdx_.store(0u, std::memory_order_release);
        readIdx_.store(0u, std::memory_order_release);
        rxPackets_.store(0u, std::memory_order_release);
        droppedPackets_.store(0u, std::memory_order_release);
        decodedPackets_ = 0u;
        lastAlertTotal_ = 0u;
        lastSyncedMood_ = zd::SecMood::Calm;
        lastMoodSyncMs_ = 0u;
    }

    // Lock-free enqueue callable from WiFi promiscuous RX callback without heap allocation.
    bool enqueueFromIsr(const uint8_t* payload, std::size_t len, int32_t rssi, uint32_t nowMs) {
        if (!enabled_.load(std::memory_order_acquire) || payload == nullptr || len < 24u) {
            return false;
        }
        rxPackets_.fetch_add(1u, std::memory_order_relaxed);
        const uint32_t w = writeIdx_.load(std::memory_order_relaxed);
        const uint32_t r = readIdx_.load(std::memory_order_acquire);
        if ((w - r) >= static_cast<uint32_t>(kRingCapacity)) {
            droppedPackets_.fetch_add(1u, std::memory_order_relaxed);
            return false;
        }
        RawDot11Packet& slot = ring_[w & (kRingCapacity - 1u)];
        const std::size_t copyLen =
            (len <= slot.data.size()) ? len : slot.data.size();
        slot.nowMs = nowMs;
        slot.rssi = rssi;
        slot.len = static_cast<uint16_t>(copyLen);
        std::memcpy(slot.data.data(), payload, copyLen);
        writeIdx_.store(w + 1u, std::memory_order_release);
        return true;
    }

    // Drain queued 802.11 frames into `sec` and push derived SecMood changes to `pet`.
    // Returns number of decoded frames ingested in this call.
    uint32_t step(zd::sec::SecSession& sec,
                  uint32_t nowMs,
                  zd::hal::PlatformSession* pet = nullptr,
                  zd::hal::IThemeStore* themeStore = nullptr) {
        uint32_t decodedNow = 0u;
        for (std::size_t i = 0u; i < kRingCapacity; ++i) {
            const uint32_t r = readIdx_.load(std::memory_order_relaxed);
            const uint32_t w = writeIdx_.load(std::memory_order_acquire);
            if (r == w) {
                break;
            }
            const RawDot11Packet& slot = ring_[r & (kRingCapacity - 1u)];
            const std::optional<zd::sec::CapturedFrame> frame =
                zd::dot11::decodeDot11(slot.data.data(), slot.len, slot.nowMs, slot.rssi);
            // Passive peer discovery: greet other ZeroDay units and classic Pwnagotchi /
            // Palnagotchi beacons sharing the airwaves.
            if (const auto hit = zd::peer::classifyWifiPeer(slot.data.data(), slot.len)) {
                const bool firstGreeting = peers_.observeWifi(*hit, slot.rssi, slot.nowMs);
                // A brand-new peer gives the pet a social moment (XP + a friendly phrase).
                if (firstGreeting && pet != nullptr) {
                    std::string name = hit->hasAdvert
                                           ? hit->advert.name
                                           : std::string(zd::peer::peerKindLabel(hit->kind));
                    pet->dispatch(zd::PeerSpottedEvent{slot.nowMs, std::move(name), slot.rssi},
                                  themeStore);
                }
            }
            readIdx_.store(r + 1u, std::memory_order_release);
            if (frame.has_value()) {
                sec.ingest(*frame);
                decodedPackets_ += 1u;
                decodedNow += 1u;
            }
        }

        const zd::sec::SecState& st = sec.state();
        const zd::SecMood mood = zd::sec::deriveSecMood(st, nowMs);
        const bool alertsChanged = (st.totalAlertsEmitted != lastAlertTotal_);
        const bool moodChanged = (mood != lastSyncedMood_);
        const uint32_t syncElapsed = nowMs - lastMoodSyncMs_;
        if (alertsChanged || moodChanged ||
            (mood != zd::SecMood::Calm && syncElapsed < 0x80000000u && syncElapsed >= 2000u)) {
            std::string detail;
            for (auto it = st.alerts.rbegin(); it != st.alerts.rend(); ++it) {
                if (it->severity == zd::sec::Severity::Critical ||
                    it->severity == zd::sec::Severity::Warn) {
                    detail = std::string(zd::sec::alertKindLabel(it->kind)) + " " +
                             (it->ssid.empty() ? it->bssid : it->ssid);
                    break;
                }
            }
            if (pet != nullptr) {
                pet->dispatch(zd::SetSecMoodEvent{nowMs, mood, std::move(detail)}, themeStore);
            }
            lastAlertTotal_ = st.totalAlertsEmitted;
            lastSyncedMood_ = mood;
            lastMoodSyncMs_ = nowMs;
        }
        return decodedNow;
    }

    uint32_t rxPackets() const { return rxPackets_.load(std::memory_order_relaxed); }
    uint32_t decodedPackets() const { return decodedPackets_; }
    const zd::peer::PeerRegistry& peers() const { return peers_; }
    // Mutable access so other transports (BLE / LoRa) record their peer sightings into the same
    // unified registry (so peersMet() and the `peers` list span every transport).
    zd::peer::PeerRegistry& mutablePeers() { return peers_; }
    uint32_t peersMet() const { return peers_.peersMet(); }
    uint32_t droppedPackets() const { return droppedPackets_.load(std::memory_order_relaxed); }
    zd::SecMood lastSyncedMood() const { return lastSyncedMood_; }

    std::string formatStatus(const zd::sec::SecState& st) const {
        char buf[160];
        std::snprintf(
            buf, sizeof(buf),
            "DEFMON: %s | rx=%lu dec=%lu drop=%lu | aps=%zu alerts=%lu mood=%s\n",
            enabled() ? "ON" : "OFF",
            static_cast<unsigned long>(rxPackets()),
            static_cast<unsigned long>(decodedPackets_),
            static_cast<unsigned long>(droppedPackets()),
            st.targets.size(),
            static_cast<unsigned long>(st.totalAlertsEmitted),
            zd::sec::secMoodLabel(lastSyncedMood_));
        return std::string(buf);
    }

private:
    std::array<RawDot11Packet, kRingCapacity> ring_{};
    std::atomic<uint32_t> writeIdx_{0u};
    std::atomic<uint32_t> readIdx_{0u};
    std::atomic<uint32_t> rxPackets_{0u};
    std::atomic<uint32_t> droppedPackets_{0u};
    std::atomic<bool> enabled_{true};
    uint32_t decodedPackets_ = 0u;
    uint32_t lastAlertTotal_ = 0u;
    zd::SecMood lastSyncedMood_ = zd::SecMood::Calm;
    uint32_t lastMoodSyncMs_ = 0u;
    zd::peer::PeerRegistry peers_{};
};

}  // namespace esp32_common
}  // namespace zd
