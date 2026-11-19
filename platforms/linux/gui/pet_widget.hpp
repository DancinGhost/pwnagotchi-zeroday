#pragma once

// A QWidget that renders the portable pet UiFrame pixel-for-pixel, exactly like the device
// screen: it runs the same immediate-mode painter onto a reused RGB565 software surface,
// converts directly into a reused QImage, and blits nearest-neighbor scaled. Also exposes
// accessible name/description for assistive technologies.

#include <cstdint>
#include <memory>
#include <string>

#include <QColor>
#include <QImage>
#include <QPainter>
#include <QPen>
#include <QString>
#include <QWidget>

#include "zd/render/painter.hpp"
#include "zd/render/surface_rgb565.hpp"
#include "zd/secops.hpp"
#include "zd/ui_model.hpp"

namespace zd {
namespace linux_gui {

class PetWidget : public QWidget {
    Q_OBJECT
public:
    explicit PetWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumSize(360, 200);
        setAccessibleName("ZeroDay Pet Display");
        setAccessibleDescription("Virtual pet status display");
    }

    void setFrame(const UiFrame& frame) {
        const std::string sig = frameSignature(frame);
        if (sig == lastFrameSig_ && !image_.isNull()) {
            return;
        }
        lastFrameSig_ = sig;

        if (!surface_ || surface_->width() != frame.dims.width ||
            surface_->height() != frame.dims.height) {
            surface_ = std::make_unique<render::Rgb565Surface>(frame.dims.width, frame.dims.height);
            image_ = QImage(frame.dims.width, frame.dims.height, QImage::Format_RGB888);
        }
        render::paintUiFrame(*surface_, frame);

        const auto& pixels = surface_->pixels();
        const int w = frame.dims.width;
        const int h = frame.dims.height;
        for (int y = 0; y < h; ++y) {
            uchar* dst = image_.scanLine(y);
            const std::size_t rowOff = static_cast<std::size_t>(y) * static_cast<std::size_t>(w);
            for (int x = 0; x < w; ++x) {
                const Rgb888 c = fromRgb565(pixels[rowOff + static_cast<std::size_t>(x)]);
                dst[x * 3 + 0] = c.r;
                dst[x * 3 + 1] = c.g;
                dst[x * 3 + 2] = c.b;
            }
        }

        // Update screen-reader description whenever the rendered screen content changes.
        std::string desc = std::string(frame.face.moodLabel) + " — " + frame.headerLine;
        if (!frame.phraseLines.empty()) {
            desc += " — ";
            for (std::size_t i = 0; i < frame.phraseLines.size(); ++i) {
                if (i != 0u) desc += " ";
                desc += frame.phraseLines[i];
            }
        }
        setAccessibleDescription(QString::fromStdString(desc));
        update();
    }

    void setSecMood(sec::SecMood mood) {
        if (secMood_ != mood) {
            secMood_ = mood;
            update();
        }
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.fillRect(rect(), Qt::black);
        if (image_.isNull()) {
            return;
        }
        // Preserve aspect ratio, integer-ish scaling, crisp pixels.
        const QSize target = image_.size().scaled(size(), Qt::KeepAspectRatio);
        const QRect dst(QPoint((width() - target.width()) / 2, (height() - target.height()) / 2),
                        target);
        p.drawImage(dst, image_);

        // Ambient threat-level bezel shift driven by SecMood (Watchful = amber, Alarmed = red).
        if (secMood_ != sec::SecMood::Calm) {
            const QColor bezel = (secMood_ == sec::SecMood::Alarmed)
                                     ? QColor(220, 30, 30)
                                     : QColor(230, 160, 0);
            p.setPen(QPen(bezel, 3));
            p.drawRect(rect().adjusted(1, 1, -2, -2));
        }
    }

private:
    static std::string frameSignature(const UiFrame& f) {
        std::string s;
        s.reserve(256);
        s += std::to_string(f.dims.width) + "x" + std::to_string(f.dims.height) + "|";
        s += std::to_string(static_cast<int>(f.page)) + "|";
        s += std::to_string(static_cast<int>(f.theme)) + "|";
        if (f.themeEffect != ThemeEffect::None) {
            s += std::to_string(f.animTick) + "|";
        }
        s += f.headerLine + "|" + f.footerLine + "|";
        s += std::string(f.face.moodLabel) + "|" + f.face.asciiFace + "|";
        s += f.toast.visible ? ("T:" + f.toast.text + "|") : "T0|";
        if (f.page == ScreenPage::PetFace) {
            s += f.spotlightLabel + "|";
            for (const auto& l : f.phraseLines) {
                s += l + "/";
            }
        } else if (f.page == ScreenPage::NearbyRadar) {
            for (const auto& r : f.radarRows) {
                s += r.ssid + ":" + r.details + ";";
            }
        } else {
            s += f.spectrumSummary + "|";
            for (const auto& b : f.channelBars) {
                s += std::to_string(b.count) + ",";
            }
        }
        return s;
    }

    std::unique_ptr<render::Rgb565Surface> surface_;
    QImage image_;
    std::string lastFrameSig_;
    sec::SecMood secMood_ = sec::SecMood::Calm;
};

}  // namespace linux_gui
}  // namespace zd
