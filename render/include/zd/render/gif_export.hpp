#pragma once

// Zero-dependency animated GIF89a & LZW exporter for `Rgb565Surface` frame sequences.
// Ideal for capturing animated UI previews from `zd_sim` (`--gif out.gif`) and verifying
// multi-frame animations without external image encoders.

#include "surface_rgb565.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#if (defined(__unix__) || defined(__APPLE__)) && !defined(ESP_PLATFORM)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace zd {
namespace render {

namespace gif_detail {

inline void pushU16Le(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8u) & 0xFFu));
}

inline Rgb888 rgb565ToRgb888(uint16_t c) {
    const uint8_t r5 = static_cast<uint8_t>((c >> 11u) & 0x1Fu);
    const uint8_t g6 = static_cast<uint8_t>((c >> 5u) & 0x3Fu);
    const uint8_t b5 = static_cast<uint8_t>(c & 0x1Fu);
    return Rgb888{
        static_cast<uint8_t>((r5 << 3u) | (r5 >> 2u)),
        static_cast<uint8_t>((g6 << 2u) | (g6 >> 4u)),
        static_cast<uint8_t>((b5 << 3u) | (b5 >> 2u)),
    };
}

class GifLzwSubBlockWriter {
public:
    explicit GifLzwSubBlockWriter(std::vector<uint8_t>& out) : out_(out) {}

    void writeBits(uint32_t code, int bitCount) {
        bitBuf_ |= (code << bitPos_);
        bitPos_ += bitCount;
        while (bitPos_ >= 8) {
            block_[blockLen_++] = static_cast<uint8_t>(bitBuf_ & 0xFFu);
            if (blockLen_ == 255u) {
                flushBlock();
            }
            bitBuf_ >>= 8u;
            bitPos_ -= 8;
        }
    }

    void finish() {
        if (bitPos_ > 0) {
            block_[blockLen_++] = static_cast<uint8_t>(bitBuf_ & 0xFFu);
            if (blockLen_ == 255u) {
                flushBlock();
            }
            bitBuf_ = 0u;
            bitPos_ = 0;
        }
        flushBlock();
        out_.push_back(0x00u);  // block terminator
    }

private:
    void flushBlock() {
        if (blockLen_ == 0u) {
            return;
        }
        out_.push_back(static_cast<uint8_t>(blockLen_));
        out_.insert(out_.end(), block_.begin(), block_.begin() + static_cast<std::ptrdiff_t>(blockLen_));
        blockLen_ = 0u;
    }

    std::vector<uint8_t>& out_;
    std::array<uint8_t, 255> block_{};
    std::size_t blockLen_ = 0u;
    uint32_t bitBuf_ = 0u;
    int bitPos_ = 0;
};

// Emits 8-bit LZW compressed pixels, resetting the dictionary with Clear=256 whenever the
// dictionary reaches 511 entries so codes strictly remain 9-bit (never overflowing decoders).
inline void encodeLzw9Bit(std::vector<uint8_t>& out, const std::vector<uint8_t>& indices) {
    out.push_back(8u);  // LZW minimum code size = 8
    GifLzwSubBlockWriter bw(out);
    static constexpr uint16_t kClearCode = 256u;
    static constexpr uint16_t kEoiCode = 257u;
    static constexpr uint16_t kFirstDictCode = 258u;
    static constexpr uint16_t kResetLimit = 511u;

    bw.writeBits(kClearCode, 9);
    if (indices.empty()) {
        bw.writeBits(kEoiCode, 9);
        bw.finish();
        return;
    }

    // Open-addressed hash table keyed on `(prefix << 8) | suffix`.
    static constexpr std::size_t kHashSize = 2048u;
    std::vector<uint32_t> hashKeys(kHashSize, 0xFFFFFFFFu);
    std::vector<uint16_t> hashVals(kHashSize, 0u);
    auto clearDict = [&](uint16_t& nextCode) {
        std::fill(hashKeys.begin(), hashKeys.end(), 0xFFFFFFFFu);
        nextCode = kFirstDictCode;
    };

    uint16_t nextCode = kFirstDictCode;
    uint16_t prefix = indices[0];
    for (std::size_t i = 1u; i < indices.size(); ++i) {
        const uint8_t sym = indices[i];
        const uint32_t key = (static_cast<uint32_t>(prefix) << 8u) | sym;
        std::size_t slot = (key * 2654435761u) & (kHashSize - 1u);
        bool found = false;
        while (hashKeys[slot] != 0xFFFFFFFFu) {
            if (hashKeys[slot] == key) {
                prefix = hashVals[slot];
                found = true;
                break;
            }
            slot = (slot + 1u) & (kHashSize - 1u);
        }
        if (found) {
            continue;
        }
        bw.writeBits(prefix, 9);
        if (nextCode < kResetLimit) {
            hashKeys[slot] = key;
            hashVals[slot] = nextCode++;
        } else {
            bw.writeBits(kClearCode, 9);
            clearDict(nextCode);
        }
        prefix = sym;
    }
    bw.writeBits(prefix, 9);
    bw.writeBits(kEoiCode, 9);
    bw.finish();
}

}  // namespace gif_detail

// Encode a sequence of equal-sized Rgb565Surface frames into a looping GIF89a byte stream.
// Uses lossless palette indexing whenever <= 256 distinct RGB565 colors appear across all frames,
// falling back cleanly to 3-3-2 RGB quantization otherwise.
inline std::vector<uint8_t> encodeAnimatedGif(const std::vector<Rgb565Surface>& frames,
                                              uint16_t delayCentisec = 15u) {
    if (frames.empty()) {
        return {};
    }
    const int16_t w = frames[0].width();
    const int16_t h = frames[0].height();
    for (const Rgb565Surface& f : frames) {
        if (f.width() != w || f.height() != h) {
            return {};
        }
    }

    // Collect distinct colors across frames up to 256 entries.
    std::unordered_map<uint16_t, uint8_t> colorMap;
    colorMap.reserve(256u);
    std::array<Rgb888, 256> gct{};
    bool exactPalette = true;
    for (const Rgb565Surface& f : frames) {
        for (uint16_t px : f.pixels()) {
            if (colorMap.find(px) == colorMap.end()) {
                if (colorMap.size() >= 256u) {
                    exactPalette = false;
                    break;
                }
                const uint8_t idx = static_cast<uint8_t>(colorMap.size());
                colorMap.emplace(px, idx);
                gct[idx] = gif_detail::rgb565ToRgb888(px);
            }
        }
        if (!exactPalette) {
            break;
        }
    }

    if (!exactPalette) {
        for (std::size_t idx = 0u; idx < 256u; ++idx) {
            const uint8_t r3 = static_cast<uint8_t>((idx >> 5u) & 0x07u);
            const uint8_t g3 = static_cast<uint8_t>((idx >> 2u) & 0x07u);
            const uint8_t b2 = static_cast<uint8_t>(idx & 0x03u);
            gct[idx] = Rgb888{
                static_cast<uint8_t>((r3 * 255u) / 7u),
                static_cast<uint8_t>((g3 * 255u) / 7u),
                static_cast<uint8_t>((b2 * 255u) / 3u),
            };
        }
    }

    std::vector<uint8_t> out;
    out.reserve(1024u + frames.size() * (static_cast<std::size_t>(w) * static_cast<std::size_t>(h)));

    // Header: GIF89a
    out.insert(out.end(), {'G', 'I', 'F', '8', '9', 'a'});
    // Logical Screen Descriptor: 256-entry Global Color Table (packed 0xF7)
    gif_detail::pushU16Le(out, static_cast<uint16_t>(w));
    gif_detail::pushU16Le(out, static_cast<uint16_t>(h));
    out.push_back(0xF7u);
    out.push_back(0x00u);  // background color index
    out.push_back(0x00u);  // pixel aspect ratio

    // Global Color Table (256 * 3 bytes)
    for (std::size_t i = 0u; i < 256u; ++i) {
        out.push_back(gct[i].r);
        out.push_back(gct[i].g);
        out.push_back(gct[i].b);
    }

    // Netscape 2.0 Application Extension (infinite loop = 0)
    static constexpr uint8_t kNetscapeExt[] = {
        0x21u, 0xFFu, 0x0Bu,
        'N', 'E', 'T', 'S', 'C', 'A', 'P', 'E', '2', '.', '0',
        0x03u, 0x01u, 0x00u, 0x00u, 0x00u};
    out.insert(out.end(), std::begin(kNetscapeExt), std::end(kNetscapeExt));

    std::vector<uint8_t> frameIndices(static_cast<std::size_t>(w) * static_cast<std::size_t>(h), 0u);
    for (const Rgb565Surface& f : frames) {
        // Graphic Control Extension
        out.push_back(0x21u);
        out.push_back(0xF9u);
        out.push_back(0x04u);
        out.push_back(0x04u);  // disposal method 1 (leave in place), no transparency
        gif_detail::pushU16Le(out, delayCentisec);
        out.push_back(0x00u);  // transparent color index
        out.push_back(0x00u);  // block terminator

        // Image Descriptor
        out.push_back(0x2Cu);
        gif_detail::pushU16Le(out, 0u);
        gif_detail::pushU16Le(out, 0u);
        gif_detail::pushU16Le(out, static_cast<uint16_t>(w));
        gif_detail::pushU16Le(out, static_cast<uint16_t>(h));
        out.push_back(0x00u);

        const auto& px = f.pixels();
        if (exactPalette) {
            for (std::size_t i = 0u; i < px.size(); ++i) {
                frameIndices[i] = colorMap[px[i]];
            }
        } else {
            for (std::size_t i = 0u; i < px.size(); ++i) {
                const Rgb888 c = gif_detail::rgb565ToRgb888(px[i]);
                const uint8_t r3 = static_cast<uint8_t>(c.r >> 5u);
                const uint8_t g3 = static_cast<uint8_t>(c.g >> 5u);
                const uint8_t b2 = static_cast<uint8_t>(c.b >> 6u);
                frameIndices[i] = static_cast<uint8_t>((r3 << 5u) | (g3 << 2u) | b2);
            }
        }
        gif_detail::encodeLzw9Bit(out, frameIndices);
    }

    out.push_back(0x3Bu);  // GIF trailer
    return out;
}

inline bool writeAnimatedGifFile(const std::string& path,
                                 const std::vector<Rgb565Surface>& frames,
                                 uint16_t delayCentisec = 15u) {
    if (path.empty()) {
        return false;
    }
    const std::vector<uint8_t> bytes = encodeAnimatedGif(frames, delayCentisec);
    if (bytes.empty()) {
        return false;
    }
#if (defined(__unix__) || defined(__APPLE__)) && !defined(ESP_PLATFORM)
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                          0644);
    if (fd < 0) {
        return false;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || ::ftruncate(fd, 0) != 0) {
        ::close(fd);
        return false;
    }
    std::size_t off = 0u;
    bool ok = true;
    while (off < bytes.size()) {
        const ssize_t n = ::write(fd, bytes.data() + off, bytes.size() - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ok = false;
            break;
        }
        off += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return ok;
#else
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
#endif
}

}  // namespace render
}  // namespace zd
