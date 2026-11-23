#pragma once

// Portable, hardware-free helper for persisting captured security artifacts to SD on ESP32
// field units (T-Deck / CYD), turning them into genuine standalone tools:
//   - a streamed `.zds` defensive event log (via ISessionRecorder), and
//   - a `.hc22000` crackable-handshake/PMKID export (hashcat-ready, no hcxpcapngtool).
//
// The actual SD File I/O lives in each platform main.cpp (Arduino SD.h). This buffer stays
// pure (zero Arduino/SD headers) so it compiles under `-fno-exceptions -fno-rtti` and is
// directly host-unit-tested in tests/core/test_esp32_common.cpp.

#include <cstddef>
#include <string>

#include "zd/secops_hal.hpp"

namespace zd {
namespace esp32_common {

class SdCaptureBuffer final : public zd::sec::ISessionRecorder {
public:
    explicit SdCaptureBuffer(std::size_t maxBytes = 8192u) : maxBytes_(maxBytes) {}

    // ISessionRecorder: buffer each encoded `.zds` event line for a later batched SD append.
    // Bounded: once the buffer is full, further lines are dropped and the overflow flag is
    // set so the platform can warn the operator instead of blocking the capture loop.
    void recordEvent(const std::string& encodedLine) override {
        if (pending_.size() + encodedLine.size() + 1u > maxBytes_) {
            overflowed_ = true;
            return;
        }
        pending_ += encodedLine;
        pending_.push_back('\n');
    }

    bool hasPendingEvents() const { return !pending_.empty(); }
    bool overflowed() const { return overflowed_; }

    // Hand the buffered `.zds` lines to the caller for a single SD append, clearing the
    // buffer (and the overflow flag) so new events accumulate afresh.
    std::string takePendingEvents() {
        std::string out;
        out.swap(pending_);
        overflowed_ = false;
        return out;
    }

    void clear() {
        pending_.clear();
        overflowed_ = false;
    }

    // True when the crackable-handshake count has grown since the last successful hc22000
    // flush — i.e. there is new material worth rewriting the `.hc22000` file for.
    bool handshakesChanged(std::size_t currentCount) const {
        return currentCount != lastHandshakeCount_;
    }
    void markHandshakesFlushed(std::size_t count) { lastHandshakeCount_ = count; }
    std::size_t lastHandshakeCount() const { return lastHandshakeCount_; }

private:
    std::size_t maxBytes_;
    std::string pending_;
    bool overflowed_ = false;
    std::size_t lastHandshakeCount_ = 0u;
};

}  // namespace esp32_common
}  // namespace zd
