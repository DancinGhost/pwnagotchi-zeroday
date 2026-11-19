#pragma once

// Hardware-agnostic painter: rasterizes a pure `zd::UiFrame` onto any graphics target
// exposing the M5GFX / LovyanGFX-style immediate-mode API. Works unchanged with
// M5.Display, M5Canvas sprites, LGFX panels (ESP32-S3/C3/RP2040 boards), M5GFX's SDL
// desktop backend, or a test double.
//
// Required `Gfx` operations (colors are RGB565 `uint16_t`, coordinates are ints):
//   fillScreen(c)                  fillRect(x, y, w, h, c)
//   fillRoundRect(x, y, w, h, r, c) fillCircle(x, y, r, c)
//   fillArc(x, y, r0, r1, a0, a1, c) drawLine(x0, y0, x1, y1, c)
//   setTextColor(fg, bg)           drawString(const char*, x, y)
//
// Text layout assumes a 6x8 px monospace font (Font0). Select it on the target *before*
// calling `paintUiFrame` (font handles are backend-specific, so the painter never does).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

#include "zd/ui_model.hpp"

namespace zd {
namespace render {

template <typename Gfx>
void drawFaceBrackets(Gfx& gfx, const zd::FaceGeometry& g, uint16_t color, bool compact) {
    const int16_t r = static_cast<int16_t>(g.bracketHalfHeight + (compact ? 4 : 6));
    const int16_t thickness = compact ? 2 : 3;

    const int16_t leftArcCenterX = static_cast<int16_t>(g.centerX - g.bracketOffsetX + r);
    const int16_t rightArcCenterX = static_cast<int16_t>(g.centerX + g.bracketOffsetX - r);

    gfx.fillArc(leftArcCenterX, g.centerY, r, r - thickness, 142.0f, 218.0f, color);
    gfx.fillArc(rightArcCenterX, g.centerY, r, r - thickness, 322.0f, 38.0f, color);
}

template <typename Gfx>
void drawSingleEye(Gfx& gfx,
                   int16_t cx,
                   int16_t cy,
                   int16_t r,
                   zd::EyeGlyph style,
                   const zd::ColorPalette& pal,
                   bool compact,
                   bool isRightEye = false) {
    const int16_t stroke = compact ? 2 : 3;

    switch (style) {
        case zd::EyeGlyph::RoundCenter: {
            gfx.fillCircle(cx, cy, r, pal.fg);
            gfx.fillCircle(cx - (r / 3), cy - (r / 3), (std::max)(1, r / 4), pal.bg);
            break;
        }
        case zd::EyeGlyph::RoundLeft: {
            const int16_t shift = compact ? -2 : -4;
            gfx.fillCircle(cx + shift, cy, r, pal.fg);
            gfx.fillCircle(cx + shift - (r / 3), cy - (r / 4), (std::max)(1, r / 4), pal.bg);
            break;
        }
        case zd::EyeGlyph::RoundRight: {
            const int16_t shift = compact ? 2 : 4;
            gfx.fillCircle(cx + shift, cy, r, pal.fg);
            gfx.fillCircle(cx + shift + (r / 3), cy - (r / 4), (std::max)(1, r / 4), pal.bg);
            break;
        }
        case zd::EyeGlyph::HappyArc: {
            gfx.fillArc(cx, cy + (r / 3), r, r - stroke, 200.0f, 340.0f, pal.fg);
            break;
        }
        case zd::EyeGlyph::WideSparkle: {
            gfx.fillCircle(cx, cy, r + 1, pal.fg);
            gfx.fillCircle(cx, cy, (std::max)(2, r - stroke), pal.bg);
            gfx.fillCircle(cx, cy, (std::max)(1, r / 3), pal.fg);
            break;
        }
        case zd::EyeGlyph::Sunglasses: {
            const int16_t w = static_cast<int16_t>(r * 2 + (compact ? 2 : 4));
            const int16_t h = static_cast<int16_t>(r + (compact ? 3 : 5));
            gfx.fillRoundRect(cx - (w / 2), cy - (h / 2), w, h, 2, pal.fg);
            // Diagonal lens glint
            gfx.drawLine(cx - (w / 4), cy - (h / 2) + 2, cx - (w / 2) + 2, cy + (h / 4), pal.bg);
            break;
        }
        case zd::EyeGlyph::SadDroop: {
            gfx.fillCircle(cx, cy, r - 1, pal.fg);
            gfx.fillCircle(cx, cy - 1, (std::max)(1, r / 3), pal.bg);
            // Slanted sad eyebrow (mirrored across left/right eyes)
            if (!isRightEye) {
                gfx.drawLine(cx - r, cy - r - 1, cx + r, cy - r - 3, pal.fg);
            } else {
                gfx.drawLine(cx - r, cy - r - 3, cx + r, cy - r - 1, pal.fg);
            }
            break;
        }
        case zd::EyeGlyph::HalfLid: {
            gfx.fillCircle(cx, cy, r, pal.fg);
            gfx.fillRect(cx - r - 1, cy - r - 1, r * 2 + 3, r, pal.bg);
            gfx.fillRect(cx - r, cy - 1, r * 2 + 1, stroke, pal.fg);
            break;
        }
        case zd::EyeGlyph::SleepingLine: {
            gfx.fillArc(cx, cy - (r / 3), r, r - stroke, 25.0f, 155.0f, pal.fg);
            break;
        }
    }
}

template <typename Gfx>
void drawMouth(Gfx& gfx, const zd::FaceGeometry& g, zd::MouthGlyph mouth, const zd::ColorPalette& pal, bool compact) {
    (void)compact;
    const int16_t stroke = 2;
    const int16_t r = g.mouthRadius;

    switch (mouth) {
        case zd::MouthGlyph::DoubleSmile: {
            // Classic Pwnagotchi double-curve ‿‿
            gfx.fillArc(g.centerX - r + 1, g.mouthY - (r / 2), r, r - stroke, 18.0f, 162.0f, pal.fg);
            gfx.fillArc(g.centerX + r - 1, g.mouthY - (r / 2), r, r - stroke, 18.0f, 162.0f, pal.fg);
            break;
        }
        case zd::MouthGlyph::BigGrin: {
            gfx.fillArc(g.centerX, g.mouthY - 2, r + 2, 0, 10.0f, 170.0f, pal.fg);
            gfx.fillArc(g.centerX, g.mouthY - 2, (std::max)(1, r - 1), 0, 15.0f, 165.0f, pal.highlight);
            break;
        }
        case zd::MouthGlyph::Smirk: {
            gfx.fillRect(g.centerX - r, g.mouthY, r * 2, stroke, pal.fg);
            gfx.fillArc(g.centerX + r, g.mouthY - 2, 4, 4 - stroke, 15.0f, 110.0f, pal.fg);
            break;
        }
        case zd::MouthGlyph::FlatLine: {
            gfx.fillRect(g.centerX - r - 1, g.mouthY, (r + 1) * 2, stroke, pal.fg);
            break;
        }
        case zd::MouthGlyph::SadWave: {
            gfx.fillArc(g.centerX, g.mouthY + r, r + 1, r + 1 - stroke, 205.0f, 335.0f, pal.fg);
            break;
        }
    }
}

template <typename Gfx>
void drawPwnagotchiFace(Gfx& gfx, const zd::UiFrame& frame) {
    const auto& g = frame.faceGeom;
    const auto& pal = frame.palette;
    const auto& f = frame.face;

    drawFaceBrackets(gfx, g, pal.fg, frame.compact);

    const int16_t leftEyeX = static_cast<int16_t>(g.centerX - g.eyeOffsetX);
    const int16_t rightEyeX = static_cast<int16_t>(g.centerX + g.eyeOffsetX);

    drawSingleEye(gfx, leftEyeX, g.eyeY, g.eyeRadius, f.eyes, pal, frame.compact, false);
    drawSingleEye(gfx, rightEyeX, g.eyeY, g.eyeRadius, f.eyes, pal, frame.compact, true);

    // Connect sunglasses bridge and temple arm
    if (f.eyes == zd::EyeGlyph::Sunglasses) {
        gfx.fillRect(leftEyeX + g.eyeRadius, g.eyeY - 2, (rightEyeX - leftEyeX) - (g.eyeRadius * 2), 3, pal.fg);
        gfx.fillRect(leftEyeX - g.eyeRadius - (frame.compact ? 5 : 8), g.eyeY - 2,
                     frame.compact ? 5 : 8, 2, pal.fg);
    }

    if (f.showBlush) {
        const int16_t blushR = frame.compact ? 2 : 3;
        gfx.fillCircle(leftEyeX - g.eyeRadius - 1, g.mouthY - 1, blushR, pal.highlight);
        gfx.fillCircle(rightEyeX + g.eyeRadius + 1, g.mouthY - 1, blushR, pal.highlight);
    }

    if (f.showTear) {
        gfx.fillCircle(rightEyeX + g.eyeRadius - 1, g.eyeY + g.eyeRadius + 3,
                       frame.compact ? 1 : 2, pal.accent);
    }

    if (f.showZzz) {
        gfx.setTextColor(pal.accent, pal.bg);
        gfx.drawString("zZ", rightEyeX + g.eyeRadius + 2, g.eyeY - g.eyeRadius - (frame.compact ? 5 : 8));
    }

    drawMouth(gfx, g, f.mouth, pal, frame.compact);

    // Centered mood tag beneath the face
    const std::string badge = "[" + std::string(f.moodLabel) + "]";
    const int16_t badgeW = static_cast<int16_t>(badge.size() * 6);
    gfx.setTextColor(pal.muted, pal.bg);
    gfx.drawString(badge.c_str(), (std::max)(2, g.centerX - (badgeW / 2)), g.moodBadgeY);
}

template <typename Gfx>
void drawSignalMeter(Gfx& gfx, int16_t x, int16_t bottomY, int bars, const zd::ColorPalette& pal, bool compact) {
    const int16_t barW = compact ? 2 : 3;
    const int16_t gap = 1;
    for (int i = 0; i < 4; ++i) {
        const int16_t h = static_cast<int16_t>((i + 1) * (compact ? 2 : 3));
        const int16_t bx = static_cast<int16_t>(x + i * (barW + gap));
        const int16_t by = static_cast<int16_t>(bottomY - h);
        if (i < bars) {
            gfx.fillRect(bx, by, barW, h, pal.fg);
        } else {
            gfx.fillRect(bx, bottomY - 1, barW, 1, pal.muted);
        }
    }
}

template <typename Gfx>
void drawPetFacePage(Gfx& gfx, const zd::UiFrame& frame) {
    drawPwnagotchiFace(gfx, frame);

    // Subtle vertical divider between face and speech column on full-size displays
    if (!frame.compact) {
        gfx.drawLine(frame.speechX - 6, frame.headerDividerY + 5,
                     frame.speechX - 6, frame.footerDividerY - 5, frame.palette.muted);
    }

    // Pet prompt header ("zeroday>")
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.promptLabel.c_str(), frame.speechX, frame.speechTopY);

    // Wrapped phrase lines
    gfx.setTextColor(frame.palette.fg, frame.palette.bg);
    int16_t y = static_cast<int16_t>(frame.speechTopY + frame.lineStepY + (frame.compact ? 1 : 2));
    for (const std::string& line : frame.phraseLines) {
        gfx.drawString(line.c_str(), frame.speechX, y);
        y = static_cast<int16_t>(y + frame.lineStepY);
    }

    // Strongest nearby SSID ticker at bottom of speech column (240x135)
    if (!frame.spotlightLabel.empty()) {
        gfx.setTextColor(frame.palette.muted, frame.palette.bg);
        gfx.drawString(frame.spotlightLabel.c_str(), frame.speechX, frame.footerDividerY - 12);
    }
}

template <typename Gfx>
void drawRadarPage(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.radarRows.empty()) {
        gfx.setTextColor(frame.palette.muted, frame.palette.bg);
        const int16_t textW = static_cast<int16_t>(frame.radarEmptyHint.size() * 6);
        const int16_t cx = (std::max)(4, (frame.dims.width - textW) / 2);
        const int16_t cy = static_cast<int16_t>((frame.headerDividerY + frame.footerDividerY) / 2 - 4);
        gfx.drawString(frame.radarEmptyHint.c_str(), cx, cy);
        return;
    }

    const int16_t rowStep = frame.compact ? 12 : 15;
    int16_t y = static_cast<int16_t>(frame.headerDividerY + (frame.compact ? 4 : 5));

    for (const auto& row : frame.radarRows) {
        drawSignalMeter(gfx, 4, y + (frame.compact ? 8 : 9), row.bars, frame.palette, frame.compact);

        const int16_t textX = frame.compact ? 19 : 24;
        const std::string prefix = row.secure ? "*" : " ";
        gfx.setTextColor(frame.palette.fg, frame.palette.bg);
        gfx.drawString((prefix + row.ssid).c_str(), textX, y);

        const int16_t detailW = static_cast<int16_t>(row.details.size() * 6);
        gfx.setTextColor(frame.palette.accent, frame.palette.bg);
        gfx.drawString(row.details.c_str(), frame.dims.width - detailW - 4, y);

        y = static_cast<int16_t>(y + rowStep);
    }
}

template <typename Gfx>
void drawSpectrumPage(Gfx& gfx, const zd::UiFrame& frame) {
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.spectrumSummary.c_str(), 4, frame.headerDividerY + (frame.compact ? 3 : 5));

    const int16_t usableW = static_cast<int16_t>(frame.dims.width - 12);
    const int16_t slotW = static_cast<int16_t>(usableW / 13);
    const int16_t barW = (std::max)(3, slotW - (frame.compact ? 2 : 4));
    const int16_t startX = static_cast<int16_t>((frame.dims.width - (slotW * 13)) / 2);

    gfx.drawLine(startX, frame.chartBaseY, startX + slotW * 13, frame.chartBaseY, frame.palette.muted);

    for (std::size_t i = 0; i < 13u; ++i) {
        const auto& bar = frame.channelBars[i];
        const int16_t bx = static_cast<int16_t>(startX + static_cast<int16_t>(i) * slotW + 1);
        if (bar.heightPx > 0) {
            gfx.fillRect(bx, frame.chartBaseY - bar.heightPx, barW, bar.heightPx, frame.palette.fg);
        }
        // Label key channels (1, 6, 11, 13 on compact; odd channels on full display)
        const bool showLabel = frame.compact
                                   ? (bar.channel == 1 || bar.channel == 6 || bar.channel == 11 || bar.channel == 13)
                                   : ((bar.channel % 2) == 1);
        if (showLabel) {
            gfx.setTextColor(frame.palette.muted, frame.palette.bg);
            gfx.drawString(std::to_string(bar.channel).c_str(), bx,
                           frame.chartBaseY + (frame.dims.height < 72 ? 1 : 2));
        }
    }
}

template <typename Gfx>
void drawDigitalRainBackdrop(Gfx& gfx, const zd::UiFrame& frame) {
    const int16_t top = static_cast<int16_t>(frame.headerDividerY + 2);
    const int16_t bottom = static_cast<int16_t>(frame.footerDividerY - 2);
    const int16_t bodyH = static_cast<int16_t>(bottom - top);
    if (bodyH < 12 || frame.dims.width < 96) {
        return;
    }

    const int16_t colStep = frame.compact ? 22 : 18;
    const int16_t rows = static_cast<int16_t>(bodyH / 8);
    if (rows < 2) {
        return;
    }

    const int32_t span = static_cast<int32_t>(rows) + 4;
    const int32_t trail = frame.compact ? 2 : 3;
    static constexpr const char kGlyphs[] = "01:+=*|7x;<>";
    constexpr uint32_t kGlyphCount = 12u;

    const auto& g = frame.faceGeom;
    const int16_t faceLeft = static_cast<int16_t>(g.centerX - g.bracketOffsetX - 6);
    const int16_t faceRight = static_cast<int16_t>(g.centerX + g.bracketOffsetX + 6);
    const int16_t faceTop = static_cast<int16_t>(g.centerY - g.bracketHalfHeight - 6);
    const int16_t faceBottom = static_cast<int16_t>(g.moodBadgeY + 9);

    for (int32_t col = 0;; ++col) {
        const int16_t x = static_cast<int16_t>(4 + col * colStep);
        if (x + 6 > frame.dims.width - 2) {
            break;
        }
        const uint32_t h = (static_cast<uint32_t>(col + 1) * 2654435761u) ^ 0x9E3779B9u;
        const uint32_t speed = (h & 1u) ? 2u : 1u;
        const uint32_t phase = (h >> 4u) % static_cast<uint32_t>(span);
        const int32_t headRow =
            static_cast<int32_t>(((frame.animTick * speed) + phase) % static_cast<uint32_t>(span));

        for (int32_t k = 0; k < trail; ++k) {
            const int32_t r = headRow - k;
            if (r < 0 || r >= rows) {
                continue;
            }
            const int16_t gy = static_cast<int16_t>(top + r * 8);
            if (gy < top || (gy + 8) > bottom) {
                continue;
            }
            // Keep the pet face and mood badge unobstructed for crisp legibility.
            if (frame.page == zd::ScreenPage::PetFace &&
                (x + 6) > faceLeft && x < faceRight &&
                (gy + 8) > faceTop && gy < faceBottom) {
                continue;
            }
            const uint32_t gh = h ^
                                (static_cast<uint32_t>(r) * 2246822519u) ^
                                ((frame.animTick >> 1u) * 374761393u);
            const char glyph[2] = {kGlyphs[gh % kGlyphCount], '\0'};
            gfx.setTextColor(frame.palette.muted, frame.palette.bg);
            gfx.drawString(glyph, x, gy);
            if (k == 0 && !frame.compact) {
                gfx.fillRect(x + 1, gy + 7, 2, 1, frame.palette.accent);
            }
        }
    }
}

template <typename Gfx>
void drawTacticalHudBackdrop(Gfx& gfx, const zd::UiFrame& frame) {
    const int16_t top = static_cast<int16_t>(frame.headerDividerY + 2);
    const int16_t bottom = static_cast<int16_t>(frame.footerDividerY - 2);
    const int16_t left = 2;
    const int16_t right = static_cast<int16_t>(frame.dims.width - 3);
    const int16_t corner = frame.compact ? 4 : 7;

    if ((bottom - top) < (corner * 2 + 2) || (right - left) < (corner * 2 + 2)) {
        return;
    }

    const uint16_t col = frame.palette.muted;
    // Four tactical corner reticle brackets
    gfx.drawLine(left, top, left + corner, top, col);
    gfx.drawLine(left, top, left, top + corner, col);

    gfx.drawLine(right - corner, top, right, top, col);
    gfx.drawLine(right, top, right, top + corner, col);

    gfx.drawLine(left, bottom, left + corner, bottom, col);
    gfx.drawLine(left, bottom - corner, left, bottom, col);

    gfx.drawLine(right - corner, bottom, right, bottom, col);
    gfx.drawLine(right, bottom - corner, right, bottom, col);

    // Subtle rangefinder ticks along top divider edge
    if ((frame.headerDividerY + 2) < frame.footerDividerY) {
        const int16_t tickStep = frame.compact ? 32 : 24;
        for (int16_t tx = 16; tx < (frame.dims.width - 12); tx = static_cast<int16_t>(tx + tickStep)) {
            gfx.fillRect(tx, frame.headerDividerY + 1, 1, 2, col);
        }
    }
}

template <typename Gfx>
void drawThemeBackdrop(Gfx& gfx, const zd::UiFrame& frame) {
    switch (frame.themeEffect) {
        case zd::ThemeEffect::None:
            break;
        case zd::ThemeEffect::DigitalRain:
            drawDigitalRainBackdrop(gfx, frame);
            break;
        case zd::ThemeEffect::TacticalHud:
            drawTacticalHudBackdrop(gfx, frame);
            break;
    }
}

template <typename Gfx>
void drawThemeDividerAccent(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.themeEffect != zd::ThemeEffect::TacticalHud) {
        return;
    }
    const int16_t pipW = frame.compact ? 6 : 10;
    const int32_t travel = static_cast<int32_t>(frame.dims.width) - static_cast<int32_t>(pipW);
    if (travel <= 1) {
        return;
    }
    const uint32_t period = static_cast<uint32_t>(travel) * 2u;
    const uint32_t step = (frame.animTick * (frame.compact ? 4u : 6u)) % period;
    const int16_t pipX = static_cast<int16_t>((step <= static_cast<uint32_t>(travel))
                                                  ? step
                                                  : (period - step));
    gfx.fillRect(pipX, frame.headerDividerY, pipW, 1, frame.palette.highlight);
}

template <typename Gfx>
void drawThemeToast(Gfx& gfx, const zd::UiFrame& frame) {
    const auto& t = frame.toast;
    if (!t.visible) {
        return;
    }
    const auto& pal = frame.palette;
    // Accent ring + inverted fill so the toast reads clearly on every theme.
    gfx.fillRoundRect(t.x - 2, t.y - 2, t.w + 4, t.h + 4, 4, pal.accent);
    gfx.fillRoundRect(t.x, t.y, t.w, t.h, 3, pal.fg);
    gfx.setTextColor(pal.bg, pal.fg);
    gfx.drawString(t.text.c_str(), t.textX, t.textY);
}

template <typename Gfx>
void paintUiFrame(Gfx& gfx, const zd::UiFrame& frame) {
    gfx.fillScreen(frame.palette.bg);

    // Optional zero-RAM procedural theme backdrop (drawn behind all UI chrome)
    drawThemeBackdrop(gfx, frame);

    // Top telemetry bar
    gfx.setTextColor(frame.palette.fg, frame.palette.bg);
    gfx.drawString(frame.headerLine.c_str(), 4, frame.headerTextY);
    gfx.drawLine(0, frame.headerDividerY, frame.dims.width - 1, frame.headerDividerY, frame.palette.muted);
    drawThemeDividerAccent(gfx, frame);

    // Main content page
    switch (frame.page) {
        case zd::ScreenPage::PetFace:
            drawPetFacePage(gfx, frame);
            break;
        case zd::ScreenPage::NearbyRadar:
            drawRadarPage(gfx, frame);
            break;
        case zd::ScreenPage::ChannelSpectrum:
            drawSpectrumPage(gfx, frame);
            break;
    }

    // Bottom status bar
    gfx.drawLine(0, frame.footerDividerY, frame.dims.width - 1, frame.footerDividerY, frame.palette.muted);
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.footerLine.c_str(), 4, frame.footerTextY);

    // Transient overlays last so they sit on top of everything else
    drawThemeToast(gfx, frame);
}

}  // namespace render
}  // namespace zd
