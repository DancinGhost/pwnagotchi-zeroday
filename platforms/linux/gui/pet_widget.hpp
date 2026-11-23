#pragma once

// A QWidget that renders the portable pet UiFrame pixel-for-pixel, exactly like the device
// screen: it runs the same immediate-mode painter onto a reused RGB565 software surface,
// converts directly into a reused QImage, and blits nearest-neighbor scaled. Also exposes
// accessible name/description for assistive technologies.

#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>

#include <QAccessible>
#include <QColor>
#include <QImage>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>
#include <QString>
#include <QWidget>

#include "../app/clock.hpp"
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
        setFocusPolicy(Qt::StrongFocus);
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
            image_ = QImage(frame.dims.width, frame.dims.height, QImage::Format_RGB16);
        }
        render::paintUiFrame(*surface_, frame);

        const auto& pixels = surface_->pixels();
        const int w = frame.dims.width;
        const int h = frame.dims.height;
        const std::size_t rowBytes = static_cast<std::size_t>(w) * sizeof(uint16_t);
        for (int y = 0; y < h; ++y) {
            const std::size_t rowOff = static_cast<std::size_t>(y) * static_cast<std::size_t>(w);
            std::memcpy(image_.scanLine(y), pixels.data() + rowOff, rowBytes);
        }

        lastFrame_ = frame;
        lastFrameValid_ = true;
        syncAccessibleDescription();
        update();
    }

    void setSecMood(sec::SecMood mood) {
        if (secMood_ != mood) {
            secMood_ = mood;
            syncAccessibleDescription();
            update();
        }
    }

    void setEventCallback(std::function<void(const AppEvent&)> cb) {
        onEvent_ = std::move(cb);
        if (onEvent_) {
            setCursor(Qt::PointingHandCursor);
            setToolTip("Body: next view (Right-click: prev) | Header: cycle theme / right badge: OpsMode | Footer right: Scan");
        }
    }

protected:
    void keyPressEvent(QKeyEvent* ev) override {
        if (!onEvent_) {
            QWidget::keyPressEvent(ev);
            return;
        }
        const uint32_t now = linux_app::nowMs();
        const int8_t step = (ev->modifiers() & Qt::ShiftModifier) ? -1 : 1;
        switch (ev->key()) {
            case Qt::Key_Space:
            case Qt::Key_Return:
            case Qt::Key_Enter:
                onEvent_(CyclePageEvent{now, step});
                ev->accept();
                return;
            case Qt::Key_Right:
                onEvent_(CyclePageEvent{now, +1});
                ev->accept();
                return;
            case Qt::Key_Left:
                onEvent_(CyclePageEvent{now, -1});
                ev->accept();
                return;
            case Qt::Key_T:
                onEvent_(CycleThemeEvent{now, step});
                ev->accept();
                return;
            case Qt::Key_B:
                onEvent_(ButtonBPressedEvent{now});
                ev->accept();
                return;
            case Qt::Key_M:
                onEvent_(CycleOpsModeEvent{now});
                ev->accept();
                return;
            default:
                QWidget::keyPressEvent(ev);
                return;
        }
    }

    void mousePressEvent(QMouseEvent* ev) override {
        if (!onEvent_ || !lastFrameValid_ || image_.isNull()) {
            QWidget::mousePressEvent(ev);
            return;
        }
        const QSize target = image_.size().scaled(size(), Qt::KeepAspectRatio);
        const QRect dst(QPoint((width() - target.width()) / 2, (height() - target.height()) / 2),
                        target);
        if (target.width() <= 0 || target.height() <= 0 || !dst.contains(ev->pos())) {
            QWidget::mousePressEvent(ev);
            return;
        }
        const double lx =
            ((ev->pos().x() - dst.x()) * static_cast<double>(lastFrame_.dims.width)) / target.width();
        const double ly =
            ((ev->pos().y() - dst.y()) * static_cast<double>(lastFrame_.dims.height)) / target.height();
        const uint32_t now = linux_app::nowMs();
        const bool rightClick = (ev->button() == Qt::RightButton);
        const int8_t step = static_cast<int8_t>(rightClick ? -1 : 1);
        if (ly <= lastFrame_.headerDividerY) {
            if (lx >= lastFrame_.dims.width * 0.72) {
                onEvent_(CycleOpsModeEvent{now});
            } else {
                onEvent_(CycleThemeEvent{now, step});
            }
        } else if (ly >= lastFrame_.footerDividerY) {
            if (lx >= lastFrame_.dims.width * 0.72) {
                onEvent_(ButtonBPressedEvent{now});
            } else {
                onEvent_(CyclePageEvent{now, 1});
            }
        } else {
            onEvent_(CyclePageEvent{now, step});
        }
        ev->accept();
    }

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
        if (hasFocus()) {
            p.setPen(QPen(QColor(56, 189, 248), 2));
            p.drawRect(rect().adjusted(2, 2, -3, -3));
        }
    }

private:
    void syncAccessibleDescription() {
        if (!lastFrameValid_) {
            return;
        }
        // Exclude ticking uptime clock from accessibility signature so screen readers are not
        // interrupted every second when only uptime changes.
        std::string sig = std::to_string(static_cast<int>(lastFrame_.page)) + "|" +
                          std::to_string(static_cast<int>(lastFrame_.theme)) + "|" +
                          lastFrame_.face.moodLabel + "|" +
                          sec::secMoodLabel(secMood_) + "|" +
                          std::to_string(lastFrame_.radarRows.size()) + "|";
        for (const auto& l : lastFrame_.phraseLines) {
            sig += l + "/";
        }
        if (sig == lastAccessibleSig_) {
            return;
        }
        lastAccessibleSig_ = sig;

        std::string desc = std::string("Security ") + sec::secMoodLabel(secMood_) + " — Pet " +
                           lastFrame_.face.moodLabel;
        if (!lastFrame_.phraseLines.empty()) {
            desc += " — ";
            for (std::size_t i = 0; i < lastFrame_.phraseLines.size(); ++i) {
                if (i != 0u) desc += " ";
                desc += lastFrame_.phraseLines[i];
            }
        }
        setAccessibleDescription(QString::fromStdString(desc));
        QAccessibleEvent accEv(this, QAccessible::DescriptionChanged);
        QAccessible::updateAccessibility(&accEv);
    }

    static std::string frameSignature(const UiFrame& f) {
        std::string s;
        s.reserve(256);
        s += std::to_string(f.dims.width) + "x" + std::to_string(f.dims.height) + "|";
        s += std::to_string(static_cast<int>(f.page)) + "|";
        s += std::to_string(static_cast<int>(f.theme)) + "|";
        s += std::to_string(static_cast<int>(f.opsMode)) + "|" + f.modeBadge + "|";
        s += std::to_string(static_cast<int>(f.scene)) + "|" + f.rankLine + "|";
        if (f.themeEffect != ThemeEffect::None || f.scene != ActivityScene::None) {
            s += std::to_string(f.animTick) + "|";
        }
        s += f.headerLine + "|" + f.footerLine + "|";
        s += std::string(f.face.moodLabel) + "|" + f.face.asciiFace + "|";
        s += std::to_string(f.capturesSaved) + "|" + f.capturePath + "|";
        s += f.notifyActive ? ("N:" + f.notifyBanner + "|") : "N0|";
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
        } else if (f.page == ScreenPage::ChannelSpectrum) {
            s += f.spectrumSummary + "|";
            for (const auto& b : f.channelBars) {
                s += std::to_string(b.count) + ",";
            }
        } else if (f.page == ScreenPage::RfGuard) {
            s += f.rfGuardSummary + "|";
            for (const auto& r : f.rfGuardRows) {
                s += r.ssid + ":" + r.details + ";";
            }
        } else {
            s += f.captureSummary + "|";
            for (const auto& r : f.captureRows) {
                s += r + ";";
            }
        }
        return s;
    }

    std::unique_ptr<render::Rgb565Surface> surface_;
    QImage image_;
    std::string lastFrameSig_;
    std::string lastAccessibleSig_;
    UiFrame lastFrame_{};
    bool lastFrameValid_ = false;
    sec::SecMood secMood_ = sec::SecMood::Calm;
    std::function<void(const AppEvent&)> onEvent_;
};

}  // namespace linux_gui
}  // namespace zd
