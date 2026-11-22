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
#include <cstdio>
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
                   uint32_t animTick,
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
        case zd::EyeGlyph::CyberWink: {
            if (!isRightEye) {
                const int16_t span = (std::max)(static_cast<int16_t>(2), static_cast<int16_t>(r - 1));
                gfx.drawLine(cx - span, cy - span, cx + span - 1, cy, pal.fg);
                gfx.drawLine(cx - span, cy + span, cx + span - 1, cy, pal.fg);
                if (stroke > 1) {
                    gfx.drawLine(cx - span, cy - span + 1, cx + span - 2, cy, pal.fg);
                    gfx.drawLine(cx - span, cy + span - 1, cx + span - 2, cy, pal.fg);
                }
            } else {
                gfx.fillCircle(cx, cy, r, pal.fg);
                gfx.fillCircle(cx, cy, (std::max)(1, r - stroke), pal.bg);
                gfx.fillCircle(cx, cy, (std::max)(1, r / 3), pal.highlight);
            }
            break;
        }
        case zd::EyeGlyph::LaserVisor: {
            const int16_t vw = static_cast<int16_t>(r * 2 + 1);
            const int16_t vh = static_cast<int16_t>((std::max)(4, static_cast<int>(r)));
            const int16_t vx = static_cast<int16_t>(cx - r);
            const int16_t vy = static_cast<int16_t>(cy - vh / 2);
            gfx.fillRoundRect(vx, vy, vw, vh, 1, pal.fg);
            const int16_t gw = static_cast<int16_t>((std::max)(2, static_cast<int>(r / 2)));
            const int16_t travel = static_cast<int16_t>((std::max)(1, static_cast<int>(vw - gw - 2)));
            const int16_t gx = static_cast<int16_t>(vx + 1 + static_cast<int16_t>((animTick * 2u) % static_cast<uint32_t>(travel)));
            gfx.fillRect(gx, cy - 1, gw, 2, pal.highlight);
            break;
        }
        case zd::EyeGlyph::ShieldVisor: {
            const int16_t vw = static_cast<int16_t>(r * 2);
            const int16_t vh = static_cast<int16_t>((std::max)(4, static_cast<int>(r * 2 - 1)));
            const int16_t vx = static_cast<int16_t>(cx - r);
            const int16_t vy = static_cast<int16_t>(cy - r + 1);
            gfx.fillRoundRect(vx, vy, vw, vh, 2, pal.fg);
            if (vw > 4 && vh > 4) {
                gfx.fillRoundRect(vx + 2, vy + 2, vw - 4, vh - 4, 1, pal.bg);
            }
            gfx.fillRect(cx - 1, cy - 1, 2, 2, pal.accent);
            break;
        }
        case zd::EyeGlyph::StarEyes: {
            const int16_t sr = (std::max)(static_cast<int16_t>(2), r);
            gfx.drawLine(cx, cy - sr, cx, cy + sr, pal.fg);
            gfx.drawLine(cx - sr, cy, cx + sr, cy, pal.fg);
            gfx.drawLine(cx - (sr / 2), cy - (sr / 2), cx + (sr / 2), cy + (sr / 2), pal.fg);
            gfx.drawLine(cx - (sr / 2), cy + (sr / 2), cx + (sr / 2), cy - (sr / 2), pal.fg);
            gfx.fillCircle(cx, cy, (std::max)(1, r / 3), pal.highlight);
            break;
        }
        case zd::EyeGlyph::AlertRing: {
            gfx.fillCircle(cx, cy, r, pal.highlight);
            gfx.fillCircle(cx, cy, (std::max)(1, r - stroke), pal.bg);
            if ((animTick & 1u) == 0u) {
                gfx.fillRect(cx - 1, cy - (std::max)(1, r / 2), 2, (std::max)(2, r - 1), pal.fg);
            } else {
                gfx.fillCircle(cx, cy, (std::max)(1, r / 3), pal.highlight);
            }
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
        case zd::MouthGlyph::Fangs: {
            gfx.fillRect(g.centerX - r, g.mouthY, r * 2, stroke, pal.fg);
            const int16_t fh = compact ? 2 : 3;
            gfx.fillRect(g.centerX - r + 1, g.mouthY + stroke, 2, fh, pal.fg);
            gfx.fillRect(g.centerX + r - 3, g.mouthY + stroke, 2, fh, pal.fg);
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

    drawSingleEye(gfx, leftEyeX, g.eyeY, g.eyeRadius, f.eyes, pal, frame.compact, frame.animTick, false);
    drawSingleEye(gfx, rightEyeX, g.eyeY, g.eyeRadius, f.eyes, pal, frame.compact, frame.animTick, true);

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
    char badge[24];
    std::snprintf(badge, sizeof(badge), "[%s]", f.moodLabel);
    const int16_t badgeW = static_cast<int16_t>(std::char_traits<char>::length(badge) * 6);
    gfx.setTextColor(pal.accent, pal.bg);
    gfx.drawString(badge, (std::max)(2, g.centerX - (badgeW / 2)), g.moodBadgeY);
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
void drawPixelArtDish(Gfx& gfx, int16_t sx, int16_t sy, int16_t sw, int16_t sh,
                      const zd::ColorPalette& pal, uint32_t animTick) {
    const int16_t bx = static_cast<int16_t>(sx + 4);
    const int16_t by = static_cast<int16_t>(sy + sh - 1);
    // Tripod base
    gfx.drawLine(bx, by - 3, bx - 2, by, pal.accent);
    gfx.drawLine(bx, by - 3, bx + 2, by, pal.accent);
    // Tilted dish bowl
    const int16_t tilt = static_cast<int16_t>((animTick % 3u) == 1u ? 1 : 0);
    const int16_t dr = static_cast<int16_t>((std::min)(5, static_cast<int>(sh / 2 - 1)));
    const int16_t dcx = static_cast<int16_t>(sx + 5);
    const int16_t dcy = static_cast<int16_t>(sy + sh - 4);
    gfx.fillArc(dcx, dcy, dr, (std::max)(1, dr - 2), 115.0f + tilt * 10.0f, 225.0f + tilt * 10.0f, pal.fg);
    // Feedhorn
    const int16_t fx = static_cast<int16_t>(dcx + 2);
    const int16_t fy = static_cast<int16_t>(dcy - 2 - tilt);
    gfx.drawLine(dcx, dcy, fx, fy, pal.accent);
    gfx.fillRect(fx, fy, 2, 2, pal.highlight);
    // Animated concentric radio wave pips radiating top-right
    const int16_t maxRx = static_cast<int16_t>(sx + sw - 2 - fx);
    const int16_t maxRy = static_cast<int16_t>(fy - sy);
    const int16_t maxWr = (std::min)(maxRx, maxRy);
    const uint32_t phase = animTick % 3u;
    for (int16_t step = 0; step < 3; ++step) {
        const int16_t wr = static_cast<int16_t>(3 + step * 3);
        if (wr > maxWr || wr <= 1) {
            continue;
        }
        const uint16_t wcol = (static_cast<uint32_t>(step) == phase) ? pal.highlight : pal.accent;
        gfx.fillArc(fx, fy, wr, wr - 1, 290.0f, 355.0f, wcol);
    }
}

template <typename Gfx>
void drawPixelArtSatellite(Gfx& gfx, int16_t sx, int16_t sy, int16_t sw, int16_t sh,
                           const zd::ColorPalette& pal, uint32_t animTick) {
    const int16_t ey = static_cast<int16_t>(sy + sh - 1);
    // Earth horizon arc/band at bottom of widget
    gfx.fillRect(sx + 2, ey - 1, (std::max)(4, sw - 4), 2, pal.accent);
    if (sw >= 18) {
        gfx.fillRect(sx + 5, ey - 2, sw - 10, 1, pal.accent);
    }
    // Orbiting satellite at top
    const int16_t drift = static_cast<int16_t>((animTick % 4u == 1u) ? 1 : ((animTick % 4u == 3u) ? -1 : 0));
    const int16_t satX = static_cast<int16_t>(sx + sw / 2 + drift);
    const int16_t satY = static_cast<int16_t>(sy + 2);
    const int16_t wingW = (sw >= 24) ? 5 : 2;
    gfx.fillRect(satX - 1, satY - 1, 3, 3, pal.fg);
    gfx.fillRect(satX - 2 - wingW, satY, wingW, 2, pal.accent);
    gfx.fillRect(satX + 3, satY, wingW, 2, pal.accent);
    // Orbital beam shooting down to Earth + traveling energy pulse
    const int16_t beamTop = static_cast<int16_t>(satY + 2);
    const int16_t beamBot = static_cast<int16_t>(ey - 2);
    if (beamBot > beamTop) {
        gfx.drawLine(satX, beamTop, satX, beamBot, pal.muted);
        const int16_t span = static_cast<int16_t>(beamBot - beamTop);
        const int16_t py = static_cast<int16_t>(beamTop + static_cast<int16_t>((animTick * 2u) % static_cast<uint32_t>(span)));
        gfx.fillRect(satX, py, 1, (std::min)(2, static_cast<int>(beamBot - py + 1)), pal.highlight);
    }
    if ((animTick & 1u) == 0u) {
        gfx.fillRect(satX - 2, ey - 2, 5, 1, pal.highlight);
    }
}

template <typename Gfx>
void drawPixelArtShield(Gfx& gfx, int16_t sx, int16_t sy, int16_t sw, int16_t sh,
                        const zd::ColorPalette& pal, uint32_t animTick, bool alertActive) {
    const int16_t cx = static_cast<int16_t>(sx + sw / 2);
    const int16_t cy = static_cast<int16_t>(sy + sh / 2);
    const int16_t sr = static_cast<int16_t>((std::max)(3, (std::min)(static_cast<int>(sw), static_cast<int>(sh)) / 2 - 1));
    const uint16_t col = alertActive ? pal.highlight : pal.accent;
    gfx.fillRoundRect(cx - sr, cy - sr, sr * 2, sr * 2, 2, col);
    if (sr > 2) {
        gfx.fillRoundRect(cx - sr + 2, cy - sr + 2, sr * 2 - 4, sr * 2 - 4, 1, pal.bg);
    }
    // Radar sweep dot inside shield
    const int16_t ox = static_cast<int16_t>((animTick % 4u == 0u || animTick % 4u == 3u) ? -1 : 1);
    const int16_t oy = static_cast<int16_t>((animTick % 4u < 2u) ? -1 : 1);
    gfx.fillRect(cx + ox - 1, cy + oy - 1, 2, 2, alertActive ? pal.highlight : pal.fg);
}

template <typename Gfx>
void drawActivitySceneWidget(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.scene == zd::ActivityScene::None) {
        return;
    }
    const bool micro = (frame.dims.width < 150 || frame.dims.height < 72);
    const int16_t sw = micro ? 14 : (frame.compact ? 20 : (frame.dims.width >= 300 ? 36 : 28));
    const int16_t sh = micro ? 10 : (frame.compact ? 12 : (frame.dims.width >= 300 ? 18 : 16));
    const int16_t sx = static_cast<int16_t>(frame.dims.width - sw - (micro || frame.compact ? 3 : 4));
    const int16_t sy = static_cast<int16_t>(frame.headerDividerY + (micro || frame.compact ? 2 : 3));

    switch (frame.scene) {
        case zd::ActivityScene::RadarDish:
            drawPixelArtDish(gfx, sx, sy, sw, sh, frame.palette, frame.animTick);
            break;
        case zd::ActivityScene::SatelliteBeam:
            drawPixelArtSatellite(gfx, sx, sy, sw, sh, frame.palette, frame.animTick);
            break;
        case zd::ActivityScene::ThreatShield:
            drawPixelArtShield(gfx, sx, sy, sw, sh, frame.palette, frame.animTick,
                               !frame.threatBanner.empty());
            break;
        case zd::ActivityScene::None:
            break;
    }
}

template <typename Gfx>
void drawClassicFaceProps(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.dims.width < 160 || frame.dims.height < 72) {
        return;
    }
    const auto& g = frame.faceGeom;
    const auto& pal = frame.palette;
    const uint16_t tipCol = ((frame.animTick & 1u) != 0u) ? pal.highlight : pal.accent;

    // Pixel-art antenna ear-mounts flanking the classic face brackets
    const int16_t antW = frame.compact ? 2 : 3;
    const int16_t antH = frame.compact ? 4 : 6;
    const int16_t antY = static_cast<int16_t>(g.centerY - g.bracketHalfHeight + 2);
    const int16_t lAntX = static_cast<int16_t>(g.centerX - g.bracketOffsetX - antW);
    const int16_t rAntX = static_cast<int16_t>(g.centerX + g.bracketOffsetX);
    if (lAntX >= 2 && (rAntX + antW) < frame.dims.width - 2 && antY > frame.headerDividerY + 2) {
        gfx.fillRect(lAntX, antY, antW, antH, pal.accent);
        gfx.fillRect(lAntX + (antW / 2), antY - 2, 1, 2, pal.fg);
        gfx.fillRect(lAntX + (antW / 2) - 1, antY - 3, 2, 2, tipCol);

        gfx.fillRect(rAntX, antY, antW, antH, pal.accent);
        gfx.fillRect(rAntX + (antW / 2), antY - 2, 1, 2, pal.fg);
        gfx.fillRect(rAntX + (antW / 2), antY - 3, 2, 2, tipCol);
    }

    // Companion mini pixel-art gear props on full-size displays (>= 220px wide)
    if (frame.compact || frame.dims.width < 220) {
        return;
    }
    const int16_t p = (frame.dims.width >= 300 && frame.dims.height >= 180) ? 2 : 1;
    // Left mini hacker terminal
    const int16_t lx = static_cast<int16_t>(g.centerX - g.bracketOffsetX - (13 * p) - 6);
    const int16_t ly = static_cast<int16_t>(g.centerY - (3 * p));
    if (lx >= 4 && (ly + 9 * p) < g.moodBadgeY) {
        gfx.fillRect(lx + p, ly, 9 * p, 6 * p, pal.accent);
        gfx.fillRect(lx + 2 * p, ly + p, 7 * p, 4 * p, pal.bg);
        gfx.fillRect(lx + 3 * p, ly + 2 * p, 4 * p, p, pal.fg);
        gfx.fillRect(lx + 3 * p, ly + 4 * p, ((frame.animTick & 1u) ? 5 : 3) * p, p, pal.highlight);
        gfx.fillRect(lx, ly + 6 * p, 11 * p, 2 * p, pal.fg);
    }
    // Right reactive RF prop
    const int16_t rx = static_cast<int16_t>(g.centerX + g.bracketOffsetX + 7);
    const int16_t ry = static_cast<int16_t>(g.centerY - (4 * p));
    const int16_t rw = static_cast<int16_t>(14 * p);
    const int16_t rh = static_cast<int16_t>(11 * p);
    if ((rx + rw) <= frame.dims.width - 4 && (ry + rh) < g.moodBadgeY) {
        if (frame.scene == zd::ActivityScene::RadarDish || frame.face.moodLabel[0] == 'D') {
            drawPixelArtDish(gfx, rx, ry, rw, rh, pal, frame.animTick);
        } else if (frame.scene == zd::ActivityScene::SatelliteBeam) {
            drawPixelArtSatellite(gfx, rx, ry, rw, rh, pal, frame.animTick);
        } else if (frame.scene == zd::ActivityScene::ThreatShield) {
            drawPixelArtShield(gfx, rx, ry, static_cast<int16_t>(12 * p), rh, pal, frame.animTick,
                               !frame.threatBanner.empty());
        } else {
            // Mini 4-bar RF analyzer tower
            gfx.fillRect(rx, ry + 9 * p, 12 * p, 2 * p, pal.accent);
            for (int16_t i = 0; i < 4; ++i) {
                const uint32_t lv = ((frame.animTick + static_cast<uint32_t>(i)) % 4u) + 1u;
                const int16_t bh = static_cast<int16_t>(lv * 2 * p);
                gfx.fillRect(rx + i * 3 * p + p, ry + 9 * p - bh, 2 * p, bh,
                             (lv >= 4u) ? pal.highlight : pal.fg);
            }
        }
    }
}

enum class MascotCol : uint8_t { Fg = 0, Bg, Accent, Highlight, Muted };

struct MascotRect {
    int8_t x;
    int8_t y;
    int8_t w;
    int8_t h;
    MascotCol col;
};

inline uint16_t mascotPaletteColor(const zd::ColorPalette& pal, MascotCol c) {
    switch (c) {
        case MascotCol::Fg:        return pal.fg;
        case MascotCol::Bg:        return pal.bg;
        case MascotCol::Accent:    return pal.accent;
        case MascotCol::Highlight: return pal.highlight;
        case MascotCol::Muted:     return pal.muted;
    }
    return pal.fg;
}

template <typename Gfx, std::size_t N>
inline void drawMascotRects(Gfx& gfx,
                            int16_t cx,
                            int16_t cy,
                            int16_t px,
                            const zd::ColorPalette& pal,
                            const MascotRect (&rects)[N]) {
    for (std::size_t i = 0u; i < N; ++i) {
        const auto& m = rects[i];
        gfx.fillRect(cx + static_cast<int16_t>(m.x) * px,
                     cy + static_cast<int16_t>(m.y) * px,
                     static_cast<int16_t>(m.w) * px,
                     static_cast<int16_t>(m.h) * px,
                     mascotPaletteColor(pal, m.col));
    }
}

template <typename Gfx>
void drawMascotEyes(Gfx& gfx,
                    int16_t cx,
                    int16_t cy,
                    int16_t px,
                    zd::EyeGlyph style,
                    const zd::ColorPalette& pal,
                    uint32_t animTick) {
    static constexpr MascotRect kRoundCenter[] = {
        {-5, -5, 3, 3, MascotCol::Fg}, {-5, -5, 1, 1, MascotCol::Bg},
        {2, -5, 3, 3, MascotCol::Fg},  {2, -5, 1, 1, MascotCol::Bg}};
    static constexpr MascotRect kRoundLeft[] = {
        {-6, -5, 3, 3, MascotCol::Fg}, {-6, -5, 1, 1, MascotCol::Bg},
        {1, -5, 3, 3, MascotCol::Fg},  {1, -5, 1, 1, MascotCol::Bg}};
    static constexpr MascotRect kRoundRight[] = {
        {-4, -5, 3, 3, MascotCol::Fg}, {-4, -5, 1, 1, MascotCol::Bg},
        {3, -5, 3, 3, MascotCol::Fg},  {3, -5, 1, 1, MascotCol::Bg}};
    static constexpr MascotRect kHappyArc[] = {
        {-5, -3, 1, 1, MascotCol::Fg}, {-4, -4, 1, 1, MascotCol::Fg},
        {-3, -3, 1, 1, MascotCol::Fg}, {2, -3, 1, 1, MascotCol::Fg},
        {3, -4, 1, 1, MascotCol::Fg},  {4, -3, 1, 1, MascotCol::Fg}};
    static constexpr MascotRect kWideSparkle[] = {
        {-6, -5, 4, 3, MascotCol::Fg}, {-5, -4, 2, 1, MascotCol::Bg},
        {-5, -4, 1, 1, MascotCol::Highlight}, {2, -5, 4, 3, MascotCol::Fg},
        {3, -4, 2, 1, MascotCol::Bg},  {4, -4, 1, 1, MascotCol::Highlight}};
    static constexpr MascotRect kSunglasses[] = {
        {-6, -5, 5, 3, MascotCol::Fg}, {-5, -5, 1, 1, MascotCol::Bg},
        {1, -5, 5, 3, MascotCol::Fg},  {2, -5, 1, 1, MascotCol::Bg},
        {-1, -5, 2, 1, MascotCol::Fg}};
    static constexpr MascotRect kSadDroop[] = {
        {-6, -6, 2, 1, MascotCol::Fg}, {-5, -5, 2, 3, MascotCol::Fg},
        {4, -6, 2, 1, MascotCol::Fg},  {3, -5, 2, 3, MascotCol::Fg}};
    static constexpr MascotRect kHalfLid[] = {
        {-5, -4, 3, 1, MascotCol::Fg}, {-5, -3, 2, 1, MascotCol::Accent},
        {2, -4, 3, 1, MascotCol::Fg},  {3, -3, 2, 1, MascotCol::Accent}};
    static constexpr MascotRect kSleepingLine[] = {
        {-5, -3, 3, 1, MascotCol::Fg}, {2, -3, 3, 1, MascotCol::Fg}};
    static constexpr MascotRect kCyberWink[] = {
        {-5, -5, 1, 1, MascotCol::Fg}, {-4, -4, 1, 1, MascotCol::Fg},
        {-5, -3, 1, 1, MascotCol::Fg}, {2, -5, 3, 3, MascotCol::Fg},
        {3, -4, 1, 1, MascotCol::Highlight}};
    static constexpr MascotRect kShieldVisor[] = {
        {-6, -5, 5, 3, MascotCol::Fg}, {-5, -4, 3, 1, MascotCol::Bg},
        {-4, -4, 1, 1, MascotCol::Accent}, {1, -5, 5, 3, MascotCol::Fg},
        {2, -4, 3, 1, MascotCol::Bg},  {3, -4, 1, 1, MascotCol::Accent}};

    const auto r = [&](int16_t gx, int16_t gy, int16_t gw, int16_t gh, uint16_t col) {
        gfx.fillRect(cx + gx * px, cy + gy * px, gw * px, gh * px, col);
    };

    switch (style) {
        case zd::EyeGlyph::RoundCenter:  drawMascotRects(gfx, cx, cy, px, pal, kRoundCenter); break;
        case zd::EyeGlyph::RoundLeft:    drawMascotRects(gfx, cx, cy, px, pal, kRoundLeft); break;
        case zd::EyeGlyph::RoundRight:   drawMascotRects(gfx, cx, cy, px, pal, kRoundRight); break;
        case zd::EyeGlyph::HappyArc:     drawMascotRects(gfx, cx, cy, px, pal, kHappyArc); break;
        case zd::EyeGlyph::WideSparkle:  drawMascotRects(gfx, cx, cy, px, pal, kWideSparkle); break;
        case zd::EyeGlyph::Sunglasses:   drawMascotRects(gfx, cx, cy, px, pal, kSunglasses); break;
        case zd::EyeGlyph::SadDroop:     drawMascotRects(gfx, cx, cy, px, pal, kSadDroop); break;
        case zd::EyeGlyph::HalfLid:      drawMascotRects(gfx, cx, cy, px, pal, kHalfLid); break;
        case zd::EyeGlyph::SleepingLine: drawMascotRects(gfx, cx, cy, px, pal, kSleepingLine); break;
        case zd::EyeGlyph::CyberWink:    drawMascotRects(gfx, cx, cy, px, pal, kCyberWink); break;
        case zd::EyeGlyph::ShieldVisor:  drawMascotRects(gfx, cx, cy, px, pal, kShieldVisor); break;
        case zd::EyeGlyph::LaserVisor: {
            r(-6, -4, 12, 2, pal.fg);
            const int16_t lx = static_cast<int16_t>(-5 + static_cast<int16_t>((animTick * 2u) % 9u));
            r(lx, -4, 2, 2, pal.highlight);
            break;
        }
        case zd::EyeGlyph::StarEyes: {
            const uint16_t sc = ((animTick & 1u) != 0u) ? pal.highlight : pal.fg;
            r(-5, -4, 3, 1, sc);
            r(-4, -5, 1, 3, sc);
            r(2, -4, 3, 1, sc);
            r(3, -5, 1, 3, sc);
            break;
        }
        case zd::EyeGlyph::AlertRing: {
            r(-5, -5, 3, 3, pal.highlight);
            r(-4, -4, 1, 1, ((animTick & 1u) == 0u) ? pal.fg : pal.bg);
            r(2, -5, 3, 3, pal.highlight);
            r(3, -4, 1, 1, ((animTick & 1u) == 0u) ? pal.fg : pal.bg);
            break;
        }
    }
}

template <typename Gfx>
void drawMascotMouth(Gfx& gfx,
                     int16_t cx,
                     int16_t cy,
                     int16_t px,
                     zd::MouthGlyph mouth,
                     const zd::ColorPalette& pal) {
    static constexpr MascotRect kDoubleSmile[] = {
        {-3, 0, 2, 1, MascotCol::Fg}, {-1, -1, 2, 1, MascotCol::Fg},
        {1, 0, 2, 1, MascotCol::Fg}};
    static constexpr MascotRect kBigGrin[] = {
        {-3, -1, 6, 1, MascotCol::Fg}, {-2, 0, 4, 2, MascotCol::Fg},
        {-1, 0, 2, 1, MascotCol::Highlight}};
    static constexpr MascotRect kSmirk[] = {
        {-3, 0, 5, 1, MascotCol::Fg}, {2, -1, 1, 1, MascotCol::Fg}};
    static constexpr MascotRect kFlatLine[] = {{-3, 0, 6, 1, MascotCol::Fg}};
    static constexpr MascotRect kSadWave[] = {
        {-2, 0, 4, 1, MascotCol::Fg}, {-3, 1, 1, 1, MascotCol::Fg},
        {2, 1, 1, 1, MascotCol::Fg}};
    static constexpr MascotRect kFangs[] = {
        {-3, 0, 6, 1, MascotCol::Fg}, {-3, 1, 1, 1, MascotCol::Fg},
        {2, 1, 1, 1, MascotCol::Fg}};

    switch (mouth) {
        case zd::MouthGlyph::DoubleSmile: drawMascotRects(gfx, cx, cy, px, pal, kDoubleSmile); break;
        case zd::MouthGlyph::BigGrin:     drawMascotRects(gfx, cx, cy, px, pal, kBigGrin); break;
        case zd::MouthGlyph::Smirk:       drawMascotRects(gfx, cx, cy, px, pal, kSmirk); break;
        case zd::MouthGlyph::FlatLine:    drawMascotRects(gfx, cx, cy, px, pal, kFlatLine); break;
        case zd::MouthGlyph::SadWave:     drawMascotRects(gfx, cx, cy, px, pal, kSadWave); break;
        case zd::MouthGlyph::Fangs:       drawMascotRects(gfx, cx, cy, px, pal, kFangs); break;
    }
}

template <typename Gfx>
void drawPixelArtMascot(Gfx& gfx, const zd::UiFrame& frame) {
    const auto& g = frame.faceGeom;
    const auto& pal = frame.palette;
    const auto& f = frame.face;
    const uint32_t animTick = frame.animTick;

    const bool micro = (frame.dims.width < 150 || frame.dims.height < 72);
    const bool wide = (frame.dims.width >= 300 && frame.dims.height >= 180);
    const int16_t px = (micro || frame.compact) ? 1 : (wide ? 3 : 2);
    const int16_t cx = g.centerX;
    const int16_t cy = g.centerY;

    const auto r = [&](int16_t gx, int16_t gy, int16_t gw, int16_t gh, uint16_t col) {
        gfx.fillRect(cx + gx * px, cy + gy * px, gw * px, gh * px, col);
    };

    // Static mascot silhouette: ears, mast, headphone cups, rounded visor head, torso, feet, and deck
    static constexpr MascotRect kMascotBase[] = {
        // Ears & transceiver mast
        {-7, -9, 2, 2, MascotCol::Fg},      {-6, -10, 1, 1, MascotCol::Accent},
        {5, -9, 2, 2, MascotCol::Fg},       {5, -10, 1, 1, MascotCol::Accent},
        {0, -9, 1, 2, MascotCol::Accent},
        // Cyber-headphone cups + rounded visor head chassis
        {-10, -5, 2, 5, MascotCol::Accent}, {-11, -4, 1, 3, MascotCol::Highlight},
        {8, -5, 2, 5, MascotCol::Accent},   {10, -4, 1, 3, MascotCol::Highlight},
        {-8, -7, 16, 10, MascotCol::Fg},    {-8, -7, 1, 1, MascotCol::Bg},
        {7, -7, 1, 1, MascotCol::Bg},       {-8, 2, 1, 1, MascotCol::Bg},
        {7, 2, 1, 1, MascotCol::Bg},        {-7, -6, 14, 8, MascotCol::Bg},
        // Cyber-vest torso & boots
        {-6, 3, 12, 6, MascotCol::Accent},  {-4, 4, 8, 4, MascotCol::Bg},
        {-5, 9, 3, 2, MascotCol::Fg},       {2, 9, 3, 2, MascotCol::Fg},
        // Left gear prop: cyber-deck console base
        {-26, -1, 11, 7, MascotCol::Accent}, {-25, 0, 9, 5, MascotCol::Bg},
        {-24, 1, 5, 1, MascotCol::Fg},      {-27, 6, 13, 3, MascotCol::Fg},
        {-25, 7, 9, 1, MascotCol::Muted},   {-25, 9, 2, 2, MascotCol::Muted},
        {-17, 9, 2, 2, MascotCol::Muted}
    };
    drawMascotRects(gfx, cx, cy, px, pal, kMascotBase);

    // Pulsing signal beacon
    r(-1, -10, 3, 1, ((animTick & 1u) != 0u) ? pal.highlight : pal.fg);

    // Expressive pixel eyes, mouth & cheek/tear/sleep overlays
    drawMascotEyes(gfx, cx, cy, px, f.eyes, pal, animTick);
    drawMascotMouth(gfx, cx, cy, px, f.mouth, pal);

    if (f.showBlush) {
        r(-6, -1, 2, 1, pal.highlight);
        r(4, -1, 2, 1, pal.highlight);
    }
    if (f.showTear) {
        r(5, -2, 1, 2, pal.accent);
    }
    if (f.showZzz) {
        static constexpr MascotRect kZzz[] = {
            {9, -9, 3, 1, MascotCol::Accent},
            {10, -8, 1, 1, MascotCol::Accent},
            {9, -7, 3, 1, MascotCol::Accent}};
        drawMascotRects(gfx, cx, cy, px, pal, kZzz);
    }

    // Animated chest core, paws & cyber-deck trace
    r(-1, 5, 2, 2, ((animTick & 1u) != 0u) ? pal.highlight : pal.fg);
    const int16_t pawLift = ((animTick & 1u) != 0u) ? 0 : 1;
    r(-8, 5 + pawLift, 2, 2, pal.fg);
    r(6, 6 - pawLift, 2, 2, pal.fg);
    r(-24, 3, ((animTick & 1u) != 0u) ? 7 : 4, 1, pal.highlight);

    // Right gear prop: Mood & OpsMode-reactive pixel equipment
    const bool isScanningScene =
        (frame.scene == zd::ActivityScene::RadarDish) ||
        (f.eyes == zd::EyeGlyph::RoundLeft || f.eyes == zd::EyeGlyph::RoundRight);
    const bool isOffenseScene = (frame.scene == zd::ActivityScene::SatelliteBeam);
    const bool isDefenseScene =
        (frame.scene == zd::ActivityScene::ThreatShield) || (f.eyes == zd::EyeGlyph::AlertRing);

    if (isScanningScene) {
        static constexpr MascotRect kDishTripod[] = {
            {16, 8, 1, 3, MascotCol::Accent},
            {20, 8, 1, 3, MascotCol::Accent},
            {17, 7, 3, 1, MascotCol::Accent}};
        drawMascotRects(gfx, cx, cy, px, pal, kDishTripod);
        const int16_t tilt = ((animTick % 3u) == 1u) ? 1 : 0;
        r(15, 2 + tilt, 2, 4, pal.fg);
        r(17, 4 + tilt, 3, 3, pal.fg);
        r(19, 6 + tilt, 3, 1, pal.fg);
        r(18, 2 + tilt, 1, 2, pal.accent);
        r(19, 1 + tilt, 2, 2, pal.highlight);
        const uint32_t wavePhase = animTick % 3u;
        r(22, 0, 1, 2, (wavePhase == 0u) ? pal.highlight : pal.accent);
        r(24, -2, 1, 3, (wavePhase == 1u) ? pal.highlight : pal.accent);
        r(26, -4, 1, 4, (wavePhase == 2u) ? pal.highlight : pal.accent);
    } else if (isOffenseScene) {
        static constexpr MascotRect kTower[] = {
            {15, 7, 10, 4, MascotCol::Accent}, {17, 8, 6, 2, MascotCol::Fg},
            {19, -9, 3, 3, MascotCol::Fg},     {15, -8, 4, 2, MascotCol::Accent},
            {22, -8, 4, 2, MascotCol::Accent}, {20, -6, 1, 13, MascotCol::Muted}};
        drawMascotRects(gfx, cx, cy, px, pal, kTower);
        const int16_t pulseY = static_cast<int16_t>(-5 + static_cast<int16_t>((animTick * 2u) % 10u));
        r(20, pulseY, 1, 2, pal.highlight);
    } else if (isDefenseScene) {
        const bool alertActive = !frame.threatBanner.empty() || (f.eyes == zd::EyeGlyph::AlertRing);
        const uint16_t shieldCol = alertActive ? pal.highlight : pal.accent;
        r(15, -1, 10, 9, shieldCol);
        r(17, 8, 6, 2, shieldCol);
        r(19, 10, 2, 1, shieldCol);
        r(17, 1, 6, 6, pal.bg);
        const int16_t sx = ((animTick & 1u) != 0u) ? 20 : 18;
        const int16_t sy = ((animTick & 2u) != 0u) ? 4 : 2;
        r(sx, sy, 2, 2, alertActive ? pal.highlight : pal.fg);
    } else if (f.showZzz) {
        static constexpr MascotRect kSleepBattery[] = {
            {14, 6, 12, 4, MascotCol::Accent}, {15, 7, 10, 2, MascotCol::Bg},
            {18, 1, 3, 1, MascotCol::Accent},  {19, 2, 1, 1, MascotCol::Accent},
            {18, 3, 3, 1, MascotCol::Accent}};
        drawMascotRects(gfx, cx, cy, px, pal, kSleepBattery);
        const int16_t fill = static_cast<int16_t>(2 + static_cast<int16_t>((animTick % 3u) * 3u));
        r(16, 7, fill, 2, pal.fg);
    } else {
        // Multi-bar RF spectrum analyzer tower
        r(14, 7, 12, 4, pal.accent);
        r(15, 8, 10, 2, pal.bg);
        for (int16_t i = 0; i < 4; ++i) {
            const int16_t bh = static_cast<int16_t>(
                2 + static_cast<int16_t>(((animTick + static_cast<uint32_t>(i)) % 4u) * 2u));
            r(15 + i * 3, 7 - bh, 2, bh, (bh >= 8) ? pal.highlight : pal.fg);
        }
    }

    // Centered mood tag beneath the mascot
    char badge[24];
    std::snprintf(badge, sizeof(badge), "[%s]", f.moodLabel);
    const int16_t badgeW = static_cast<int16_t>(std::char_traits<char>::length(badge) * 6);
    gfx.setTextColor(pal.accent, pal.bg);
    gfx.drawString(badge, (std::max)(2, static_cast<int>(g.centerX) - (badgeW / 2)), g.moodBadgeY);
}

template <typename Gfx>
void drawPetFacePage(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.faceStyle == zd::FaceStyle::PixelArtMascot) {
        drawPixelArtMascot(gfx, frame);
    } else {
        drawPwnagotchiFace(gfx, frame);
        drawClassicFaceProps(gfx, frame);
    }
    drawActivitySceneWidget(gfx, frame);

    // Top speech bubble (prompt + wrapped phrase)
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.promptLabel.c_str(), frame.speechX, frame.speechTopY);

    gfx.setTextColor(frame.palette.fg, frame.palette.bg);
    if (frame.compact) {
        if (!frame.phraseLines.empty()) {
            const int16_t inlineX = static_cast<int16_t>(
                frame.speechX + (static_cast<int16_t>(frame.promptLabel.size()) + 1) * 6);
            gfx.drawString(frame.phraseLines[0].c_str(), inlineX, frame.speechTopY);
        }
    } else {
        const bool wide = (frame.dims.width >= 300 && frame.dims.height >= 180);
        int16_t y = static_cast<int16_t>(frame.speechTopY + frame.lineStepY + (wide ? 2 : 0));
        for (const std::string& line : frame.phraseLines) {
            gfx.drawString(line.c_str(), frame.speechX, y);
            y = static_cast<int16_t>(y + frame.lineStepY);
        }
    }

    // Bottom telemetry stack (rank / XP bar + strongest SSID / threat banner)
    if (!frame.compact) {
        const bool wide = (frame.dims.width >= 300 && frame.dims.height >= 180);
        const int16_t padX = wide ? 6 : 4;
        const int16_t rankY = wide ? static_cast<int16_t>(frame.footerDividerY - 21)
                                   : static_cast<int16_t>(frame.footerDividerY - 10);
        const int16_t barW = wide ? 48 : 24;
        const int16_t barX = static_cast<int16_t>(frame.dims.width - barW - padX);
        const int16_t barY = static_cast<int16_t>(rankY + 2);

        if (!frame.rankLine.empty()) {
            gfx.setTextColor(frame.palette.accent, frame.palette.bg);
            gfx.drawString(frame.rankLine.c_str(), padX, rankY);
            if (barX > padX + static_cast<int16_t>(frame.rankLine.size() * 6) + 4) {
                gfx.fillRect(barX, barY, barW, 4, frame.palette.muted);
                const int16_t fillW =
                    static_cast<int16_t>((static_cast<int32_t>(barW) * frame.xpProgressPct) / 100);
                if (fillW > 0) {
                    gfx.fillRect(barX, barY, fillW, 4, frame.palette.highlight);
                }
            }
        }

        if (!frame.spotlightLabel.empty()) {
            const uint16_t spotCol =
                !frame.threatBanner.empty() ? frame.palette.highlight : frame.palette.accent;
            gfx.setTextColor(spotCol, frame.palette.bg);
            if (wide) {
                gfx.drawString(frame.spotlightLabel.c_str(), padX, frame.footerDividerY - 11);
            } else {
                const int16_t leftEnd =
                    static_cast<int16_t>(padX + static_cast<int16_t>(frame.rankLine.size() * 6) + 6);
                const int16_t availPx = static_cast<int16_t>(barX - 4 - leftEnd);
                if (availPx >= 30) {
                    const std::string clipped =
                        zd::truncateText(frame.spotlightLabel, static_cast<std::size_t>(availPx / 6));
                    gfx.drawString(clipped.c_str(), leftEnd, rankY);
                }
            }
        }
    }
}

template <typename Gfx>
void drawRadarPage(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.radarRows.empty()) {
        gfx.setTextColor(frame.palette.fg, frame.palette.bg);
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
        char ssidLine[64];
        std::snprintf(ssidLine, sizeof(ssidLine), "%c%s", row.secure ? '*' : ' ', row.ssid.c_str());
        gfx.setTextColor(frame.palette.fg, frame.palette.bg);
        gfx.drawString(ssidLine, textX, y);

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
            char chLbl[16];
            std::snprintf(chLbl, sizeof(chLbl), "%d", static_cast<int>(bar.channel));
            gfx.setTextColor(frame.palette.accent, frame.palette.bg);
            gfx.drawString(chLbl, bx, frame.chartBaseY + (frame.dims.height < 72 ? 1 : 2));
        }
    }
}

template <typename Gfx>
void drawRfGuardPage(Gfx& gfx, const zd::UiFrame& frame) {
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.rfGuardSummary.c_str(), 4, frame.headerDividerY + (frame.compact ? 2 : 4));

    if (frame.rfGuardRows.empty()) {
        gfx.setTextColor(frame.palette.fg, frame.palette.bg);
        const int16_t textW = static_cast<int16_t>(frame.rfGuardEmptyHint.size() * 6);
        const int16_t cx = (std::max)(4, (frame.dims.width - textW) / 2);
        const int16_t cy = static_cast<int16_t>((frame.headerDividerY + frame.footerDividerY) / 2 - 2);
        gfx.drawString(frame.rfGuardEmptyHint.c_str(), cx, cy);
        return;
    }

    const int16_t rowStep = frame.compact ? 11 : 14;
    int16_t y = static_cast<int16_t>(frame.headerDividerY + (frame.compact ? 12 : 16));
    for (const auto& row : frame.rfGuardRows) {
        if (y + 9 >= frame.footerDividerY) {
            break;
        }
        drawSignalMeter(gfx, 4, y + (frame.compact ? 7 : 8), row.bars, frame.palette, frame.compact);

        const int16_t textX = frame.compact ? 19 : 24;
        char lineBuf[64];
        std::snprintf(lineBuf, sizeof(lineBuf), "%c%s", row.secure ? '!' : ' ', row.ssid.c_str());
        gfx.setTextColor(row.secure ? frame.palette.highlight : frame.palette.fg, frame.palette.bg);
        gfx.drawString(lineBuf, textX, y);

        const int16_t detailW = static_cast<int16_t>(row.details.size() * 6);
        gfx.setTextColor(frame.palette.accent, frame.palette.bg);
        gfx.drawString(row.details.c_str(), frame.dims.width - detailW - 4, y);

        y = static_cast<int16_t>(y + rowStep);
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
    const bool micro = (frame.dims.width < 150 || frame.dims.height < 72);
    const bool wide = (frame.dims.width >= 300 && frame.dims.height >= 180);
    const int16_t px = (micro || frame.compact) ? 1 : (wide ? 3 : 2);
    const int16_t halfArtW = (frame.faceStyle == zd::FaceStyle::PixelArtMascot)
                                 ? static_cast<int16_t>(28 * px)
                                 : static_cast<int16_t>(g.bracketOffsetX + 6);
    const int16_t halfArtH = (frame.faceStyle == zd::FaceStyle::PixelArtMascot)
                                 ? static_cast<int16_t>(11 * px)
                                 : static_cast<int16_t>(g.bracketHalfHeight + 6);
    const int16_t faceLeft = static_cast<int16_t>(g.centerX - halfArtW);
    const int16_t faceRight = static_cast<int16_t>(g.centerX + halfArtW);
    const int16_t faceTop = static_cast<int16_t>(g.centerY - halfArtH);
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
void drawLightningStormBackdrop(Gfx& gfx, const zd::UiFrame& frame) {
    drawDigitalRainBackdrop(gfx, frame);
    const int16_t top = static_cast<int16_t>(frame.headerDividerY + 2);
    const int16_t bottom = static_cast<int16_t>(frame.footerDividerY - 2);
    if ((bottom - top) < 12 || frame.dims.width < 96) {
        return;
    }

    // Slanted falling rain streaks in background columns
    const int16_t stepX = frame.compact ? 24 : 20;
    const int16_t spanY = static_cast<int16_t>((std::max)(8, static_cast<int>(bottom - top - 5)));
    for (int16_t rx = 8; rx + 3 < frame.dims.width - 2; rx = static_cast<int16_t>(rx + stepX)) {
        const uint32_t h = static_cast<uint32_t>(rx) * 2654435761u;
        const int16_t ry = static_cast<int16_t>(
            top + static_cast<int16_t>(((frame.animTick * 3u) + (h >> 8u)) % static_cast<uint32_t>(spanY)));
        if (frame.page == zd::ScreenPage::PetFace) {
            const auto& g = frame.faceGeom;
            const int16_t fL = static_cast<int16_t>(g.centerX - g.bracketOffsetX - 6);
            const int16_t fR = static_cast<int16_t>(g.centerX + g.bracketOffsetX + 6);
            if (rx >= fL && (rx - 2) <= fR) {
                continue;
            }
        }
        gfx.drawLine(rx, ry, rx - 2, ry + 4, frame.palette.muted);
    }

    // Periodic forked lightning bolt strike (2 frames every 12 ticks)
    if ((frame.animTick % 12u) < 2u) {
        const int16_t bx = static_cast<int16_t>(frame.dims.width - (frame.compact ? 12 : 20));
        const int16_t midY = static_cast<int16_t>((top + bottom) / 2);
        gfx.drawLine(bx, top, bx - 4, midY, frame.palette.highlight);
        gfx.drawLine(bx - 4, midY, bx + 2, midY, frame.palette.highlight);
        gfx.drawLine(bx + 2, midY, bx - 3, bottom, frame.palette.fg);
        // Side fork
        const int16_t forkY = static_cast<int16_t>(midY + (bottom - midY) / 2);
        if (bx >= 10 && forkY <= bottom) {
            gfx.drawLine(bx - 4, midY, bx - 8, forkY, frame.palette.accent);
        }
        // Ground splash spark
        if (bx >= 6 && bx + 1 < frame.dims.width) {
            gfx.fillRect(bx - 5, bottom - 1, 5, 1, frame.palette.highlight);
        }
    }
}

template <typename Gfx>
void drawRadarDishBackdrop(Gfx& gfx, const zd::UiFrame& frame) {
    const int16_t top = static_cast<int16_t>(frame.headerDividerY + 2);
    const int16_t bottom = static_cast<int16_t>(frame.footerDividerY - 2);
    if ((bottom - top) < 16 || frame.dims.width < 96) {
        return;
    }
    const int16_t ox = static_cast<int16_t>(frame.dims.width - 6);
    const int16_t oy = static_cast<int16_t>(bottom - 2);
    const int16_t maxR = static_cast<int16_t>((std::min)(frame.compact ? 18 : 30, static_cast<int>(oy - top - 1)));
    const uint32_t phase = frame.animTick % 3u;
    for (uint32_t k = 0; k < 3u; ++k) {
        const int16_t r = static_cast<int16_t>(6 + static_cast<int16_t>(k) * (frame.compact ? 5 : 9));
        if (r > maxR || (ox - r) < 2) {
            continue;
        }
        const uint16_t col = (k == phase) ? frame.palette.accent : frame.palette.muted;
        gfx.fillArc(ox, oy, r, r - 1, 185.0f, 260.0f, col);
    }
}

template <typename Gfx>
void drawSatelliteBeamBackdrop(Gfx& gfx, const zd::UiFrame& frame) {
    drawTacticalHudBackdrop(gfx, frame);
    const int16_t top = static_cast<int16_t>(frame.headerDividerY + 3);
    const int16_t bottom = static_cast<int16_t>(frame.footerDividerY - 3);
    if ((bottom - top) < 12) {
        return;
    }
    const int16_t bx = static_cast<int16_t>(frame.dims.width - 5);
    gfx.drawLine(bx, top, bx, bottom, frame.palette.muted);
    const int16_t span = static_cast<int16_t>(bottom - top);
    const int16_t py = static_cast<int16_t>(top + static_cast<int16_t>((frame.animTick * 3u) % static_cast<uint32_t>(span)));
    gfx.fillRect(bx - 1, py, 3, (std::min)(3, static_cast<int>(bottom - py + 1)), frame.palette.highlight);
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
        case zd::ThemeEffect::LightningStorm:
            drawLightningStormBackdrop(gfx, frame);
            break;
        case zd::ThemeEffect::RadarDish:
            drawRadarDishBackdrop(gfx, frame);
            break;
        case zd::ThemeEffect::SatelliteBeam:
            drawSatelliteBeamBackdrop(gfx, frame);
            break;
    }
}

template <typename Gfx>
void drawThemeDividerAccent(Gfx& gfx, const zd::UiFrame& frame) {
    if (frame.themeEffect != zd::ThemeEffect::TacticalHud &&
        frame.themeEffect != zd::ThemeEffect::SatelliteBeam) {
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

    // Top telemetry bar + active ops mode badge
    gfx.setTextColor(frame.palette.fg, frame.palette.bg);
    gfx.drawString(frame.headerLine.c_str(), 4, frame.headerTextY);
    if (!frame.modeBadge.empty()) {
        const int16_t bw = static_cast<int16_t>(frame.modeBadge.size() * 6);
        const int16_t bx = static_cast<int16_t>(frame.dims.width - bw - 2);
        const int16_t by = static_cast<int16_t>((std::max)(0, static_cast<int>(frame.headerTextY) - 1));
        const int16_t bh = static_cast<int16_t>((std::min)(10, static_cast<int>(frame.headerDividerY) - by));
        const bool isOff = frame.offensiveArmed || frame.opsMode == zd::OpsMode::Offensive;
        const bool isDef = frame.opsMode == zd::OpsMode::Defensive;
        if (isOff || isDef) {
            const uint16_t badgeBg = isOff ? frame.palette.highlight : frame.palette.accent;
            if (bh > 0 && bx >= 1) {
                gfx.fillRect(bx - 1, by, bw + 2, bh, badgeBg);
            }
            gfx.setTextColor(frame.palette.bg, badgeBg);
        } else {
            gfx.setTextColor(frame.palette.accent, frame.palette.bg);
        }
        gfx.drawString(frame.modeBadge.c_str(), bx, frame.headerTextY);
    }
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
        case zd::ScreenPage::RfGuard:
            drawRfGuardPage(gfx, frame);
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
