// Crisp pixel-buffer M5GFX software rasterizer + 5x7 Font0 bitmap glyphs
// (ported from core/include/zd/ui_model.hpp and render/include/zd/render/{painter,surface_rgb565}.hpp).
(function (root) {
  'use strict';

  const logic =
    (root.ZD && root.ZD.petLogic) ||
    (typeof require === 'function' ? require('./pet_logic.js') : null);

  // Classic 5x7 GLCD / Adafruit GFX Font0 printable ASCII (0x20 ' ' .. 0x7E '~'), 5 bytes/char.
  // Bit 0 (0x01) = top pixel row, Bit 6 (0x40) = bottom pixel row, Bit 7 (0x80) = descender.
  const FONT_5X7 = [
    [0x00, 0x00, 0x00, 0x00, 0x00], // 32 ' '
    [0x00, 0x00, 0x5F, 0x00, 0x00], // 33 '!'
    [0x00, 0x07, 0x00, 0x07, 0x00], // 34 '"'
    [0x14, 0x7F, 0x14, 0x7F, 0x14], // 35 '#'
    [0x24, 0x2A, 0x7F, 0x2A, 0x12], // 36 '$'
    [0x23, 0x13, 0x08, 0x64, 0x62], // 37 '%'
    [0x36, 0x49, 0x55, 0x22, 0x50], // 38 '&'
    [0x00, 0x05, 0x03, 0x00, 0x00], // 39 '''
    [0x00, 0x1C, 0x22, 0x41, 0x00], // 40 '('
    [0x00, 0x41, 0x22, 0x1C, 0x00], // 41 ')'
    [0x14, 0x08, 0x3E, 0x08, 0x14], // 42 '*'
    [0x08, 0x08, 0x3E, 0x08, 0x08], // 43 '+'
    [0x00, 0x50, 0x30, 0x00, 0x00], // 44 ','
    [0x08, 0x08, 0x08, 0x08, 0x08], // 45 '-'
    [0x00, 0x60, 0x60, 0x00, 0x00], // 46 '.'
    [0x20, 0x10, 0x08, 0x04, 0x02], // 47 '/'
    [0x3E, 0x51, 0x49, 0x45, 0x3E], // 48 '0'
    [0x00, 0x42, 0x7F, 0x40, 0x00], // 49 '1'
    [0x42, 0x61, 0x51, 0x49, 0x46], // 50 '2'
    [0x21, 0x41, 0x45, 0x4B, 0x31], // 51 '3'
    [0x18, 0x14, 0x12, 0x7F, 0x10], // 52 '4'
    [0x27, 0x45, 0x45, 0x45, 0x39], // 53 '5'
    [0x3C, 0x4A, 0x49, 0x49, 0x30], // 54 '6'
    [0x01, 0x71, 0x09, 0x05, 0x03], // 55 '7'
    [0x36, 0x49, 0x49, 0x49, 0x36], // 56 '8'
    [0x06, 0x49, 0x49, 0x29, 0x1E], // 57 '9'
    [0x00, 0x36, 0x36, 0x00, 0x00], // 58 ':'
    [0x00, 0x56, 0x36, 0x00, 0x00], // 59 ';'
    [0x08, 0x14, 0x22, 0x41, 0x00], // 60 '<'
    [0x14, 0x14, 0x14, 0x14, 0x14], // 61 '='
    [0x00, 0x41, 0x22, 0x14, 0x08], // 62 '>'
    [0x02, 0x01, 0x51, 0x09, 0x06], // 63 '?'
    [0x32, 0x49, 0x79, 0x41, 0x3E], // 64 '@'
    [0x7E, 0x11, 0x11, 0x11, 0x7E], // 65 'A'
    [0x7F, 0x49, 0x49, 0x49, 0x36], // 66 'B'
    [0x3E, 0x41, 0x41, 0x41, 0x22], // 67 'C'
    [0x7F, 0x41, 0x41, 0x22, 0x1C], // 68 'D'
    [0x7F, 0x49, 0x49, 0x49, 0x41], // 69 'E'
    [0x7F, 0x09, 0x09, 0x09, 0x01], // 70 'F'
    [0x3E, 0x41, 0x49, 0x49, 0x7A], // 71 'G'
    [0x7F, 0x08, 0x08, 0x08, 0x7F], // 72 'H'
    [0x00, 0x41, 0x7F, 0x41, 0x00], // 73 'I'
    [0x20, 0x40, 0x41, 0x3F, 0x01], // 74 'J'
    [0x7F, 0x08, 0x14, 0x22, 0x41], // 75 'K'
    [0x7F, 0x40, 0x40, 0x40, 0x40], // 76 'L'
    [0x7F, 0x02, 0x0C, 0x02, 0x7F], // 77 'M'
    [0x7F, 0x04, 0x08, 0x10, 0x7F], // 78 'N'
    [0x3E, 0x41, 0x41, 0x41, 0x3E], // 79 'O'
    [0x7F, 0x09, 0x09, 0x09, 0x06], // 80 'P'
    [0x3E, 0x41, 0x51, 0x21, 0x5E], // 81 'Q'
    [0x7F, 0x09, 0x19, 0x29, 0x46], // 82 'R'
    [0x46, 0x49, 0x49, 0x49, 0x31], // 83 'S'
    [0x01, 0x01, 0x7F, 0x01, 0x01], // 84 'T'
    [0x3F, 0x40, 0x40, 0x40, 0x3F], // 85 'U'
    [0x1F, 0x20, 0x40, 0x20, 0x1F], // 86 'V'
    [0x3F, 0x40, 0x38, 0x40, 0x3F], // 87 'W'
    [0x63, 0x14, 0x08, 0x14, 0x63], // 88 'X'
    [0x07, 0x08, 0x70, 0x08, 0x07], // 89 'Y'
    [0x61, 0x51, 0x49, 0x45, 0x43], // 90 'Z'
    [0x00, 0x7F, 0x41, 0x41, 0x00], // 91 '['
    [0x02, 0x04, 0x08, 0x10, 0x20], // 92 '\'
    [0x00, 0x41, 0x41, 0x7F, 0x00], // 93 ']'
    [0x04, 0x02, 0x01, 0x02, 0x04], // 94 '^'
    [0x40, 0x40, 0x40, 0x40, 0x40], // 95 '_'
    [0x00, 0x01, 0x02, 0x04, 0x00], // 96 '`'
    [0x20, 0x54, 0x54, 0x54, 0x78], // 97 'a'
    [0x7F, 0x48, 0x44, 0x44, 0x38], // 98 'b'
    [0x38, 0x44, 0x44, 0x44, 0x20], // 99 'c'
    [0x38, 0x44, 0x44, 0x48, 0x7F], // 100 'd'
    [0x38, 0x54, 0x54, 0x54, 0x18], // 101 'e'
    [0x08, 0x7E, 0x09, 0x01, 0x02], // 102 'f'
    [0x0C, 0x52, 0x52, 0x52, 0x3E], // 103 'g'
    [0x7F, 0x08, 0x04, 0x04, 0x78], // 104 'h'
    [0x00, 0x44, 0x7D, 0x40, 0x00], // 105 'i'
    [0x20, 0x40, 0x44, 0x3D, 0x00], // 106 'j'
    [0x7F, 0x10, 0x28, 0x44, 0x00], // 107 'k'
    [0x00, 0x41, 0x7F, 0x40, 0x00], // 108 'l'
    [0x7C, 0x04, 0x18, 0x04, 0x78], // 109 'm'
    [0x7C, 0x08, 0x04, 0x04, 0x78], // 110 'n'
    [0x38, 0x44, 0x44, 0x44, 0x38], // 111 'o'
    [0x7C, 0x14, 0x14, 0x14, 0x08], // 112 'p'
    [0x08, 0x14, 0x14, 0x18, 0x7C], // 113 'q'
    [0x7C, 0x08, 0x04, 0x04, 0x08], // 114 'r'
    [0x48, 0x54, 0x54, 0x54, 0x20], // 115 's'
    [0x04, 0x3F, 0x44, 0x40, 0x20], // 116 't'
    [0x3C, 0x40, 0x40, 0x20, 0x7C], // 117 'u'
    [0x1C, 0x20, 0x40, 0x20, 0x1C], // 118 'v'
    [0x3C, 0x40, 0x30, 0x40, 0x3C], // 119 'w'
    [0x44, 0x28, 0x10, 0x28, 0x44], // 120 'x'
    [0x0C, 0x50, 0x50, 0x50, 0x3C], // 121 'y'
    [0x44, 0x64, 0x54, 0x4C, 0x44], // 122 'z'
    [0x00, 0x08, 0x36, 0x41, 0x00], // 123 '{'
    [0x00, 0x00, 0x7F, 0x00, 0x00], // 124 '|'
    [0x00, 0x41, 0x36, 0x08, 0x00], // 125 '}'
    [0x08, 0x04, 0x08, 0x10, 0x08]  // 126 '~'
  ];

  // Headless-safe RGBA pixel buffer mimicking M5Canvas / M5GFX primitives.
  // Accepts an optional pre-allocated Uint8ClampedArray (e.g. ImageData.data) for zero-copy blitting.
  function createPixelBuffer(width, height, backingData) {
    const w = Math.max(1, Math.trunc(width));
    const h = Math.max(1, Math.trunc(height));
    const data = backingData && backingData.length === w * h * 4
      ? backingData
      : new Uint8ClampedArray(w * h * 4);
    let textFg = { r: 255, g: 255, b: 255 };
    let textBg = null;

    function setPixel(x, y, col) {
      const ix = Math.trunc(x);
      const iy = Math.trunc(y);
      if (ix < 0 || ix >= w || iy < 0 || iy >= h) return;
      const idx = (iy * w + ix) * 4;
      data[idx] = col.r;
      data[idx + 1] = col.g;
      data[idx + 2] = col.b;
      data[idx + 3] = 255;
    }

    function fillScreen(col) {
      for (let i = 0; i < data.length; i += 4) {
        data[i] = col.r;
        data[i + 1] = col.g;
        data[i + 2] = col.b;
        data[i + 3] = 255;
      }
    }

    function fillRect(x, y, rw, rh, col) {
      const x0 = Math.max(0, Math.trunc(x));
      const y0 = Math.max(0, Math.trunc(y));
      const x1 = Math.min(w, Math.trunc(x) + Math.trunc(rw));
      const y1 = Math.min(h, Math.trunc(y) + Math.trunc(rh));
      for (let py = y0; py < y1; py++) {
        let idx = (py * w + x0) * 4;
        for (let px = x0; px < x1; px++) {
          data[idx] = col.r;
          data[idx + 1] = col.g;
          data[idx + 2] = col.b;
          data[idx + 3] = 255;
          idx += 4;
        }
      }
    }

    function drawLine(x0In, y0In, x1In, y1In, col) {
      let x0 = Math.trunc(x0In);
      let y0 = Math.trunc(y0In);
      const x1 = Math.trunc(x1In);
      const y1 = Math.trunc(y1In);

      const dx = Math.abs(x1 - x0);
      const sx = x0 < x1 ? 1 : -1;
      const dy = -Math.abs(y1 - y0);
      const sy = y0 < y1 ? 1 : -1;
      let err = dx + dy;

      while (true) {
        setPixel(x0, y0, col);
        if (x0 === x1 && y0 === y1) break;
        const e2 = 2 * err;
        if (e2 >= dy) {
          err += dy;
          x0 += sx;
        }
        if (e2 <= dx) {
          err += dx;
          y0 += sy;
        }
      }
    }

    function fillCircle(cxIn, cyIn, rIn, col) {
      const cx = Math.trunc(cxIn);
      const cy = Math.trunc(cyIn);
      const r = Math.max(0, Math.trunc(rIn));
      if (r === 0) {
        setPixel(cx, cy, col);
        return;
      }
      const limitSq = r * r + r * 0.4;
      for (let dy = -r; dy <= r; dy++) {
        for (let dx = -r; dx <= r; dx++) {
          if (dx * dx + dy * dy <= limitSq) {
            setPixel(cx + dx, cy + dy, col);
          }
        }
      }
    }

    function fillRoundRect(xIn, yIn, rwIn, rhIn, radiusIn, col) {
      const x = Math.trunc(xIn);
      const y = Math.trunc(yIn);
      const rw = Math.trunc(rwIn);
      const rh = Math.trunc(rhIn);
      const rad = Math.max(0, Math.min(Math.trunc(radiusIn), Math.floor(Math.min(rw, rh) / 2)));
      if (rad <= 0) {
        fillRect(x, y, rw, rh, col);
        return;
      }
      fillRect(x + rad, y, rw - 2 * rad, rh, col);
      fillRect(x, y + rad, rad, rh - 2 * rad, col);
      fillRect(x + rw - rad, y + rad, rad, rh - 2 * rad, col);
      fillCircle(x + rad, y + rad, rad, col);
      fillCircle(x + rw - rad - 1, y + rad, rad, col);
      fillCircle(x + rad, y + rh - rad - 1, rad, col);
      fillCircle(x + rw - rad - 1, y + rh - rad - 1, rad, col);
    }

    // M5GFX fillArc convention: 0 deg = +X (right), 90 deg = +Y (down),
    // 180 deg = -X (left), 270 deg = -Y (up), sweeping clockwise deg0 -> deg1.
    // Uses trig + cross-product half-plane tests matching surface_rgb565.hpp.
    function fillArc(cxIn, cyIn, r0In, r1In, deg0In, deg1In, col) {
      const cx = Math.trunc(cxIn);
      const cy = Math.trunc(cyIn);
      const rOuter = Math.max(r0In, r1In);
      const rInner = Math.max(0, Math.min(r0In, r1In));
      if (rOuter <= 0) {
        return;
      }
      const normDeg = function (d) {
        const m = d % 360;
        return m < 0 ? m + 360 : m;
      };
      const a0 = normDeg(deg0In);
      const a1 = normDeg(deg1In);
      const span = a0 > a1 ? 360 - a0 + a1 : a1 - a0;
      const fullCircle = Math.abs(deg1In - deg0In) >= 360;
      const reflex = span > 180;
      const degToRad = Math.PI / 180;
      const c0x = Math.cos(a0 * degToRad);
      const c0y = Math.sin(a0 * degToRad);
      const c1x = Math.cos(a1 * degToRad);
      const c1y = Math.sin(a1 * degToRad);

      const outerSq = rOuter * rOuter;
      const innerSq = rInner * rInner;
      const bound = Math.ceil(rOuter);

      for (let dy = -bound; dy <= bound; dy++) {
        for (let dx = -bound; dx <= bound; dx++) {
          const dSq = dx * dx + dy * dy;
          if (dSq > outerSq || dSq < innerSq) continue;
          if (fullCircle || (dx === 0 && dy === 0)) {
            setPixel(cx + dx, cy + dy, col);
            continue;
          }
          const cross0 = c0x * dy - c0y * dx;
          const cross1 = c1x * dy - c1y * dx;
          const inAngle = reflex
            ? cross0 >= -1e-4 || cross1 <= 1e-4
            : cross0 >= -1e-4 && cross1 <= 1e-4;
          if (inAngle) {
            setPixel(cx + dx, cy + dy, col);
          }
        }
      }
    }

    function setTextColor(fg, bg) {
      textFg = fg;
      textBg = bg || null;
    }

    function drawChar(code, x, y) {
      const idx = code >= 32 && code <= 126 ? code - 32 : 31; // fallback '?'
      const cols = FONT_5X7[idx];
      if (textBg) {
        fillRect(x, y, 6, 8, textBg);
      }
      for (let cx = 0; cx < 5; cx++) {
        const mask = cols[cx];
        if (mask === 0) continue;
        for (let cy = 0; cy < 8; cy++) {
          if ((mask & (1 << cy)) !== 0) {
            setPixel(x + cx, y + cy, textFg);
          }
        }
      }
    }

    function drawString(text, xIn, yIn) {
      const str = String(text == null ? '' : text);
      let cursorX = Math.trunc(xIn);
      const cursorY = Math.trunc(yIn);
      for (let i = 0; i < str.length; i++) {
        drawChar(str.charCodeAt(i), cursorX, cursorY);
        cursorX += 6;
      }
    }

    return {
      width: w,
      height: h,
      data,
      setPixel,
      fillScreen,
      fillRect,
      drawLine,
      fillCircle,
      fillRoundRect,
      fillArc,
      setTextColor,
      drawString
    };
  }

  // --- Exact pwnagotchi-zeroday UI Painting Primitives (ported from painter.hpp) ---

  function drawFaceBrackets(gfx, g, color, compact) {
    const r = g.bracketHalfHeight + (compact ? 4 : 6);
    const thickness = compact ? 2 : 3;
    const leftArcCenterX = g.centerX - g.bracketOffsetX + r;
    const rightArcCenterX = g.centerX + g.bracketOffsetX - r;

    gfx.fillArc(leftArcCenterX, g.centerY, r, r - thickness, 142.0, 218.0, color);
    gfx.fillArc(rightArcCenterX, g.centerY, r, r - thickness, 322.0, 38.0, color);
  }

  function drawSingleEye(gfx, cx, cy, r, style, pal, compact, animTick, isRightEye) {
    const stroke = compact ? 2 : 3;

    switch (style) {
      case logic.EyeGlyph.RoundCenter: {
        gfx.fillCircle(cx, cy, r, pal.fg);
        gfx.fillCircle(
          cx - Math.trunc(r / 3),
          cy - Math.trunc(r / 3),
          Math.max(1, Math.trunc(r / 4)),
          pal.bg
        );
        break;
      }
      case logic.EyeGlyph.RoundLeft: {
        const shift = compact ? -2 : -4;
        gfx.fillCircle(cx + shift, cy, r, pal.fg);
        gfx.fillCircle(
          cx + shift - Math.trunc(r / 3),
          cy - Math.trunc(r / 4),
          Math.max(1, Math.trunc(r / 4)),
          pal.bg
        );
        break;
      }
      case logic.EyeGlyph.RoundRight: {
        const shift = compact ? 2 : 4;
        gfx.fillCircle(cx + shift, cy, r, pal.fg);
        gfx.fillCircle(
          cx + shift + Math.trunc(r / 3),
          cy - Math.trunc(r / 4),
          Math.max(1, Math.trunc(r / 4)),
          pal.bg
        );
        break;
      }
      case logic.EyeGlyph.HappyArc: {
        gfx.fillArc(cx, cy + Math.trunc(r / 3), r, r - stroke, 200.0, 340.0, pal.fg);
        break;
      }
      case logic.EyeGlyph.WideSparkle: {
        gfx.fillCircle(cx, cy, r + 1, pal.fg);
        gfx.fillCircle(cx, cy, Math.max(2, r - stroke), pal.bg);
        gfx.fillCircle(cx, cy, Math.max(1, Math.trunc(r / 3)), pal.fg);
        break;
      }
      case logic.EyeGlyph.Sunglasses: {
        const w = r * 2 + (compact ? 2 : 4);
        const h = r + (compact ? 3 : 5);
        gfx.fillRoundRect(cx - Math.trunc(w / 2), cy - Math.trunc(h / 2), w, h, 2, pal.fg);
        gfx.drawLine(
          cx - Math.trunc(w / 4),
          cy - Math.trunc(h / 2) + 2,
          cx - Math.trunc(w / 2) + 2,
          cy + Math.trunc(h / 4),
          pal.bg
        );
        break;
      }
      case logic.EyeGlyph.SadDroop: {
        gfx.fillCircle(cx, cy, r - 1, pal.fg);
        gfx.fillCircle(cx, cy - 1, Math.max(1, Math.trunc(r / 3)), pal.bg);
        if (!isRightEye) {
          gfx.drawLine(cx - r, cy - r - 1, cx + r, cy - r - 3, pal.fg);
        } else {
          gfx.drawLine(cx - r, cy - r - 3, cx + r, cy - r - 1, pal.fg);
        }
        break;
      }
      case logic.EyeGlyph.HalfLid: {
        gfx.fillCircle(cx, cy, r, pal.fg);
        gfx.fillRect(cx - r - 1, cy - r - 1, r * 2 + 3, r, pal.bg);
        gfx.fillRect(cx - r, cy - 1, r * 2 + 1, stroke, pal.fg);
        break;
      }
      case logic.EyeGlyph.SleepingLine: {
        gfx.fillArc(cx, cy - Math.trunc(r / 3), r, r - stroke, 25.0, 155.0, pal.fg);
        break;
      }
      case logic.EyeGlyph.CyberWink: {
        if (!isRightEye) {
          const span = Math.max(2, r - 1);
          gfx.drawLine(cx - span, cy - span, cx + span - 1, cy, pal.fg);
          gfx.drawLine(cx - span, cy + span, cx + span - 1, cy, pal.fg);
          if (stroke > 1) {
            gfx.drawLine(cx - span, cy - span + 1, cx + span - 2, cy, pal.fg);
            gfx.drawLine(cx - span, cy + span - 1, cx + span - 2, cy, pal.fg);
          }
        } else {
          gfx.fillCircle(cx, cy, r, pal.fg);
          gfx.fillCircle(cx, cy, Math.max(1, r - stroke), pal.bg);
          gfx.fillCircle(cx, cy, Math.max(1, Math.trunc(r / 3)), pal.highlight);
        }
        break;
      }
      case logic.EyeGlyph.LaserVisor: {
        const vw = r * 2 + 1;
        const vh = Math.max(4, r);
        const vx = cx - r;
        const vy = cy - Math.trunc(vh / 2);
        gfx.fillRoundRect(vx, vy, vw, vh, 1, pal.fg);
        const gw = Math.max(2, Math.trunc(r / 2));
        const travel = Math.max(1, vw - gw - 2);
        const gx = vx + 1 + (((animTick >>> 0) * 2) % travel);
        gfx.fillRect(gx, cy - 1, gw, 2, pal.highlight);
        break;
      }
      case logic.EyeGlyph.ShieldVisor: {
        const vw = r * 2;
        const vh = Math.max(4, r * 2 - 1);
        const vx = cx - r;
        const vy = cy - r + 1;
        gfx.fillRoundRect(vx, vy, vw, vh, 2, pal.fg);
        if (vw > 4 && vh > 4) {
          gfx.fillRoundRect(vx + 2, vy + 2, vw - 4, vh - 4, 1, pal.bg);
        }
        gfx.fillRect(cx - 1, cy - 1, 2, 2, pal.accent);
        break;
      }
      case logic.EyeGlyph.StarEyes: {
        const sr = Math.max(2, r);
        gfx.drawLine(cx, cy - sr, cx, cy + sr, pal.fg);
        gfx.drawLine(cx - sr, cy, cx + sr, cy, pal.fg);
        gfx.drawLine(cx - Math.trunc(sr / 2), cy - Math.trunc(sr / 2), cx + Math.trunc(sr / 2), cy + Math.trunc(sr / 2), pal.fg);
        gfx.drawLine(cx - Math.trunc(sr / 2), cy + Math.trunc(sr / 2), cx + Math.trunc(sr / 2), cy - Math.trunc(sr / 2), pal.fg);
        gfx.fillCircle(cx, cy, Math.max(1, Math.trunc(r / 3)), pal.highlight);
        break;
      }
      case logic.EyeGlyph.AlertRing: {
        gfx.fillCircle(cx, cy, r, pal.highlight);
        gfx.fillCircle(cx, cy, Math.max(1, r - stroke), pal.bg);
        if ((animTick & 1) === 0) {
          gfx.fillRect(cx - 1, cy - Math.max(1, Math.trunc(r / 2)), 2, Math.max(2, r - 1), pal.fg);
        } else {
          gfx.fillCircle(cx, cy, Math.max(1, Math.trunc(r / 3)), pal.highlight);
        }
        break;
      }
    }
  }

  function drawMouth(gfx, g, mouth, pal, compact) {
    const stroke = 2;
    const r = g.mouthRadius;

    switch (mouth) {
      case logic.MouthGlyph.DoubleSmile: {
        gfx.fillArc(
          g.centerX - r + 1,
          g.mouthY - Math.trunc(r / 2),
          r,
          r - stroke,
          18.0,
          162.0,
          pal.fg
        );
        gfx.fillArc(
          g.centerX + r - 1,
          g.mouthY - Math.trunc(r / 2),
          r,
          r - stroke,
          18.0,
          162.0,
          pal.fg
        );
        break;
      }
      case logic.MouthGlyph.BigGrin: {
        gfx.fillArc(g.centerX, g.mouthY - 2, r + 2, 0, 10.0, 170.0, pal.fg);
        gfx.fillArc(
          g.centerX,
          g.mouthY - 2,
          Math.max(1, r - 1),
          0,
          15.0,
          165.0,
          pal.highlight
        );
        break;
      }
      case logic.MouthGlyph.Smirk: {
        gfx.fillRect(g.centerX - r, g.mouthY, r * 2, stroke, pal.fg);
        gfx.fillArc(g.centerX + r, g.mouthY - 2, 4, 4 - stroke, 15.0, 110.0, pal.fg);
        break;
      }
      case logic.MouthGlyph.FlatLine: {
        gfx.fillRect(g.centerX - r - 1, g.mouthY, (r + 1) * 2, stroke, pal.fg);
        break;
      }
      case logic.MouthGlyph.SadWave: {
        gfx.fillArc(g.centerX, g.mouthY + r, r + 1, r + 1 - stroke, 205.0, 335.0, pal.fg);
        break;
      }
      case logic.MouthGlyph.Fangs: {
        gfx.fillRect(g.centerX - r, g.mouthY, r * 2, stroke, pal.fg);
        const fh = compact ? 2 : 3;
        gfx.fillRect(g.centerX - r + 1, g.mouthY + stroke, 2, fh, pal.fg);
        gfx.fillRect(g.centerX + r - 3, g.mouthY + stroke, 2, fh, pal.fg);
        break;
      }
    }
  }

  function canBlinkStyle(style) {
    return (
      style === logic.EyeGlyph.RoundCenter ||
      style === logic.EyeGlyph.WideSparkle ||
      style === logic.EyeGlyph.SadDroop ||
      style === logic.EyeGlyph.HalfLid
    );
  }

  function drawPwnagotchiFace(gfx, frame, opts) {
    const g = frame.faceGeom;
    const pal = frame.palette;
    const f = frame.face;
    const blink = Boolean(opts && opts.blink) && canBlinkStyle(f.eyes);
    const eyeStyle = blink ? logic.EyeGlyph.SleepingLine : f.eyes;
    const animTick = frame.animTick >>> 0;

    drawFaceBrackets(gfx, g, pal.fg, frame.compact);

    const leftEyeX = g.centerX - g.eyeOffsetX;
    const rightEyeX = g.centerX + g.eyeOffsetX;

    drawSingleEye(gfx, leftEyeX, g.eyeY, g.eyeRadius, eyeStyle, pal, frame.compact, animTick, false);
    drawSingleEye(gfx, rightEyeX, g.eyeY, g.eyeRadius, eyeStyle, pal, frame.compact, animTick, true);

    if (eyeStyle === logic.EyeGlyph.Sunglasses) {
      gfx.fillRect(
        leftEyeX + g.eyeRadius,
        g.eyeY - 2,
        rightEyeX - leftEyeX - g.eyeRadius * 2,
        3,
        pal.fg
      );
      const templeW = frame.compact ? 5 : 8;
      gfx.fillRect(leftEyeX - g.eyeRadius - templeW, g.eyeY - 2, templeW, 2, pal.fg);
    }

    if (f.showBlush) {
      const blushR = frame.compact ? 2 : 3;
      gfx.fillCircle(leftEyeX - g.eyeRadius - 1, g.mouthY - 1, blushR, pal.highlight);
      gfx.fillCircle(rightEyeX + g.eyeRadius + 1, g.mouthY - 1, blushR, pal.highlight);
    }

    if (f.showTear) {
      gfx.fillCircle(
        rightEyeX + g.eyeRadius - 1,
        g.eyeY + g.eyeRadius + 3,
        frame.compact ? 1 : 2,
        pal.accent
      );
    }

    if (f.showZzz) {
      gfx.setTextColor(pal.accent, pal.bg);
      gfx.drawString(
        'zZ',
        rightEyeX + g.eyeRadius + 2,
        g.eyeY - g.eyeRadius - (frame.compact ? 5 : 8)
      );
    }

    drawMouth(gfx, g, f.mouth, pal, frame.compact);

    const badge = '[' + f.moodLabel + ']';
    const badgeW = badge.length * 6;
    gfx.setTextColor(pal.accent, pal.bg);
    gfx.drawString(badge, Math.max(2, g.centerX - Math.trunc(badgeW / 2)), g.moodBadgeY);
  }

  function drawSignalMeter(gfx, x, bottomY, bars, pal, compact) {
    const barW = compact ? 2 : 3;
    const gap = 1;
    for (let i = 0; i < 4; i++) {
      const h = (i + 1) * (compact ? 2 : 3);
      const bx = x + i * (barW + gap);
      const by = bottomY - h;
      if (i < bars) {
        gfx.fillRect(bx, by, barW, h, pal.fg);
      } else {
        gfx.fillRect(bx, bottomY - 1, barW, 1, pal.muted);
      }
    }
  }

  function drawPixelArtDish(gfx, sx, sy, sw, sh, pal, animTick) {
    const bx = sx + 4;
    const by = sy + sh - 1;
    gfx.drawLine(bx, by - 3, bx - 2, by, pal.accent);
    gfx.drawLine(bx, by - 3, bx + 2, by, pal.accent);
    const tilt = animTick % 3 === 1 ? 1 : 0;
    const dr = Math.min(5, Math.trunc(sh / 2) - 1);
    const dcx = sx + 5;
    const dcy = sy + sh - 4;
    gfx.fillArc(dcx, dcy, dr, Math.max(1, dr - 2), 115.0 + tilt * 10.0, 225.0 + tilt * 10.0, pal.fg);
    const fx = dcx + 2;
    const fy = dcy - 2 - tilt;
    gfx.drawLine(dcx, dcy, fx, fy, pal.accent);
    gfx.fillRect(fx, fy, 2, 2, pal.highlight);
    const maxWr = Math.min(sx + sw - 2 - fx, fy - sy);
    const phase = animTick % 3;
    for (let step = 0; step < 3; step++) {
      const wr = 3 + step * 3;
      if (wr > maxWr || wr <= 1) continue;
      gfx.fillArc(fx, fy, wr, wr - 1, 290.0, 355.0, step === phase ? pal.highlight : pal.accent);
    }
  }

  function drawPixelArtSatellite(gfx, sx, sy, sw, sh, pal, animTick) {
    const ey = sy + sh - 1;
    gfx.fillRect(sx + 2, ey - 1, Math.max(4, sw - 4), 2, pal.accent);
    if (sw >= 18) {
      gfx.fillRect(sx + 5, ey - 2, sw - 10, 1, pal.accent);
    }
    const drift = animTick % 4 === 1 ? 1 : animTick % 4 === 3 ? -1 : 0;
    const satX = sx + Math.trunc(sw / 2) + drift;
    const satY = sy + 2;
    const wingW = sw >= 24 ? 5 : 2;
    gfx.fillRect(satX - 1, satY - 1, 3, 3, pal.fg);
    gfx.fillRect(satX - 2 - wingW, satY, wingW, 2, pal.accent);
    gfx.fillRect(satX + 3, satY, wingW, 2, pal.accent);
    const beamTop = satY + 2;
    const beamBot = ey - 2;
    if (beamBot > beamTop) {
      gfx.drawLine(satX, beamTop, satX, beamBot, pal.muted);
      const span = beamBot - beamTop;
      const py = beamTop + ((animTick * 2) % span);
      gfx.fillRect(satX, py, 1, Math.min(2, beamBot - py + 1), pal.highlight);
    }
    if ((animTick & 1) === 0) {
      gfx.fillRect(satX - 2, ey - 2, 5, 1, pal.highlight);
    }
  }

  function drawPixelArtShield(gfx, sx, sy, sw, sh, pal, animTick, alertActive) {
    const cx = sx + Math.trunc(sw / 2);
    const cy = sy + Math.trunc(sh / 2);
    const sr = Math.max(3, Math.trunc(Math.min(sw, sh) / 2) - 1);
    const col = alertActive ? pal.highlight : pal.accent;
    gfx.fillRoundRect(cx - sr, cy - sr, sr * 2, sr * 2, 2, col);
    if (sr > 2) {
      gfx.fillRoundRect(cx - sr + 2, cy - sr + 2, sr * 2 - 4, sr * 2 - 4, 1, pal.bg);
    }
    const ox = animTick % 4 === 0 || animTick % 4 === 3 ? -1 : 1;
    const oy = animTick % 4 < 2 ? -1 : 1;
    gfx.fillRect(cx + ox - 1, cy + oy - 1, 2, 2, alertActive ? pal.highlight : pal.fg);
  }

  function drawActivitySceneWidget(gfx, frame) {
    if (!frame.scene || frame.scene === 'None') return;
    const micro = frame.dims.width < 150 || frame.dims.height < 72;
    const sw = micro ? 14 : frame.compact ? 20 : frame.dims.width >= 300 ? 36 : 28;
    const sh = micro ? 10 : frame.compact ? 12 : frame.dims.width >= 300 ? 18 : 16;
    const sx = frame.dims.width - sw - (micro || frame.compact ? 3 : 4);
    const sy = frame.headerDividerY + (micro || frame.compact ? 2 : 3);
    const animTick = frame.animTick >>> 0;

    if (frame.scene === 'RadarDish') {
      drawPixelArtDish(gfx, sx, sy, sw, sh, frame.palette, animTick);
    } else if (frame.scene === 'SatelliteBeam') {
      drawPixelArtSatellite(gfx, sx, sy, sw, sh, frame.palette, animTick);
    } else if (frame.scene === 'ThreatShield') {
      drawPixelArtShield(gfx, sx, sy, sw, sh, frame.palette, animTick, Boolean(frame.threatBanner));
    }
  }

  function drawPetFacePage(gfx, frame, opts) {
    drawPwnagotchiFace(gfx, frame, opts);
    drawActivitySceneWidget(gfx, frame);

    if (!frame.compact) {
      gfx.drawLine(
        frame.speechX - 6,
        frame.headerDividerY + 5,
        frame.speechX - 6,
        frame.footerDividerY - 5,
        frame.palette.muted
      );
    }

    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.promptLabel, frame.speechX, frame.speechTopY);

    gfx.setTextColor(frame.palette.fg, frame.palette.bg);
    let y = frame.speechTopY + frame.lineStepY + (frame.compact ? 1 : 2);
    for (let i = 0; i < frame.phraseLines.length; i++) {
      gfx.drawString(frame.phraseLines[i], frame.speechX, y);
      y += frame.lineStepY;
    }

    if (!frame.compact && frame.rankLine && frame.rankLine.length > 0) {
      gfx.setTextColor(frame.palette.accent, frame.palette.bg);
      gfx.drawString(frame.rankLine, frame.speechX, frame.footerDividerY - 21);
      const barW = 28;
      const barX = frame.dims.width - barW - 4;
      const barY = frame.footerDividerY - 19;
      if (barX > frame.speechX + frame.rankLine.length * 6 + 2) {
        gfx.fillRect(barX, barY, barW, 4, frame.palette.muted);
        const fillW = Math.trunc((barW * (frame.xpProgressPct || 0)) / 100);
        if (fillW > 0) {
          gfx.fillRect(barX, barY, fillW, 4, frame.palette.highlight);
        }
      }
    }

    if (frame.spotlightLabel && frame.spotlightLabel.length > 0) {
      const spotCol = frame.threatBanner ? frame.palette.highlight : frame.palette.accent;
      gfx.setTextColor(spotCol, frame.palette.bg);
      gfx.drawString(frame.spotlightLabel, frame.speechX, frame.footerDividerY - 11);
    }
  }

  function drawRadarPage(gfx, frame) {
    if (frame.radarRows.length === 0) {
      gfx.setTextColor(frame.palette.fg, frame.palette.bg);
      const textW = frame.radarEmptyHint.length * 6;
      const cx = Math.max(4, Math.trunc((frame.dims.width - textW) / 2));
      const cy = Math.trunc((frame.headerDividerY + frame.footerDividerY) / 2) - 4;
      gfx.drawString(frame.radarEmptyHint, cx, cy);
      return;
    }

    const rowStep = frame.compact ? 12 : 15;
    let y = frame.headerDividerY + (frame.compact ? 4 : 5);

    for (let i = 0; i < frame.radarRows.length; i++) {
      const row = frame.radarRows[i];
      drawSignalMeter(gfx, 4, y + (frame.compact ? 8 : 9), row.bars, frame.palette, frame.compact);

      const textX = frame.compact ? 19 : 24;
      const prefix = row.secure ? '*' : ' ';
      gfx.setTextColor(frame.palette.fg, frame.palette.bg);
      gfx.drawString(prefix + row.ssid, textX, y);

      const detailW = row.details.length * 6;
      gfx.setTextColor(frame.palette.accent, frame.palette.bg);
      gfx.drawString(row.details, frame.dims.width - detailW - 4, y);

      y += rowStep;
    }
  }

  function drawSpectrumPage(gfx, frame) {
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.spectrumSummary, 4, frame.headerDividerY + (frame.compact ? 3 : 5));

    const usableW = frame.dims.width - 12;
    const slotW = Math.trunc(usableW / 13);
    const barW = Math.max(3, slotW - (frame.compact ? 2 : 4));
    const startX = Math.trunc((frame.dims.width - slotW * 13) / 2);

    gfx.drawLine(startX, frame.chartBaseY, startX + slotW * 13, frame.chartBaseY, frame.palette.muted);

    for (let i = 0; i < 13; i++) {
      const bar = frame.channelBars[i];
      const bx = startX + i * slotW + 1;
      if (bar.heightPx > 0) {
        gfx.fillRect(bx, frame.chartBaseY - bar.heightPx, barW, bar.heightPx, frame.palette.fg);
      }
      const showLabel = frame.compact
        ? bar.channel === 1 || bar.channel === 6 || bar.channel === 11 || bar.channel === 13
        : bar.channel % 2 === 1;
      if (showLabel) {
        gfx.setTextColor(frame.palette.accent, frame.palette.bg);
        gfx.drawString(String(bar.channel), bx, frame.chartBaseY + (frame.dims.height < 72 ? 1 : 2));
      }
    }
  }

  function drawRfGuardPage(gfx, frame) {
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.rfGuardSummary || '', 4, frame.headerDividerY + (frame.compact ? 2 : 4));

    const rows = frame.rfGuardRows || [];
    if (rows.length === 0) {
      gfx.setTextColor(frame.palette.fg, frame.palette.bg);
      const hint = frame.rfGuardEmptyHint || '';
      const cx = Math.max(4, Math.trunc((frame.dims.width - hint.length * 6) / 2));
      const cy = Math.trunc((frame.headerDividerY + frame.footerDividerY) / 2) - 2;
      gfx.drawString(hint, cx, cy);
      return;
    }

    const rowStep = frame.compact ? 11 : 14;
    let y = frame.headerDividerY + (frame.compact ? 12 : 16);
    for (let i = 0; i < rows.length; i++) {
      if (y + 9 >= frame.footerDividerY) break;
      const row = rows[i];
      drawSignalMeter(gfx, 4, y + (frame.compact ? 7 : 8), row.bars, frame.palette, frame.compact);

      const textX = frame.compact ? 19 : 24;
      const prefix = row.secure ? '!' : ' ';
      gfx.setTextColor(row.secure ? frame.palette.highlight : frame.palette.fg, frame.palette.bg);
      gfx.drawString(prefix + row.ssid, textX, y);

      const detailW = row.details.length * 6;
      gfx.setTextColor(frame.palette.accent, frame.palette.bg);
      gfx.drawString(row.details, frame.dims.width - detailW - 4, y);
      y += rowStep;
    }
  }

  function drawDigitalRainBackdrop(gfx, frame) {
    const top = frame.headerDividerY + 2;
    const bottom = frame.footerDividerY - 2;
    const bodyH = bottom - top;
    if (bodyH < 12 || frame.dims.width < 96) {
      return;
    }

    const colStep = frame.compact ? 22 : 18;
    const rows = Math.floor(bodyH / 8);
    if (rows < 2) {
      return;
    }

    const span = rows + 4;
    const trail = frame.compact ? 2 : 3;
    const glyphs = '01:+=*|7x;<>';
    const animTick = (frame.animTick >>> 0);

    const g = frame.faceGeom;
    const faceLeft = g.centerX - g.bracketOffsetX - 6;
    const faceRight = g.centerX + g.bracketOffsetX + 6;
    const faceTop = g.centerY - g.bracketHalfHeight - 6;
    const faceBottom = g.moodBadgeY + 9;

    for (let col = 0; ; col++) {
      const x = 4 + col * colStep;
      if (x + 6 > frame.dims.width - 2) {
        break;
      }
      const h = (Math.imul(col + 1, 2654435761) ^ 0x9e3779b9) >>> 0;
      const speed = (h & 1) !== 0 ? 2 : 1;
      const phase = (h >>> 4) % span;
      const headRow = ((animTick * speed + phase) % span) | 0;

      for (let k = 0; k < trail; k++) {
        const r = headRow - k;
        if (r < 0 || r >= rows) {
          continue;
        }
        const gy = top + r * 8;
        if (gy < top || gy + 8 > bottom) {
          continue;
        }
        if (
          frame.page === logic.ScreenPage.PetFace &&
          x + 6 > faceLeft &&
          x < faceRight &&
          gy + 8 > faceTop &&
          gy < faceBottom
        ) {
          continue;
        }
        const gh =
          (h ^ Math.imul(r, 2246822519) ^ Math.imul(animTick >>> 1, 374761393)) >>> 0;
        gfx.setTextColor(frame.palette.muted, frame.palette.bg);
        gfx.drawString(glyphs.charAt(gh % glyphs.length), x, gy);
        if (k === 0 && !frame.compact) {
          gfx.fillRect(x + 1, gy + 7, 2, 1, frame.palette.accent);
        }
      }
    }
  }

  function drawTacticalHudBackdrop(gfx, frame) {
    const top = frame.headerDividerY + 2;
    const bottom = frame.footerDividerY - 2;
    const left = 2;
    const right = frame.dims.width - 3;
    const corner = frame.compact ? 4 : 7;

    if (bottom - top < corner * 2 + 2 || right - left < corner * 2 + 2) {
      return;
    }

    const col = frame.palette.muted;
    gfx.drawLine(left, top, left + corner, top, col);
    gfx.drawLine(left, top, left, top + corner, col);

    gfx.drawLine(right - corner, top, right, top, col);
    gfx.drawLine(right, top, right, top + corner, col);

    gfx.drawLine(left, bottom, left + corner, bottom, col);
    gfx.drawLine(left, bottom - corner, left, bottom, col);

    gfx.drawLine(right - corner, bottom, right, bottom, col);
    gfx.drawLine(right, bottom - corner, right, bottom, col);

    if (frame.headerDividerY + 2 < frame.footerDividerY) {
      const tickStep = frame.compact ? 32 : 24;
      for (let tx = 16; tx < frame.dims.width - 12; tx += tickStep) {
        gfx.fillRect(tx, frame.headerDividerY + 1, 1, 2, col);
      }
    }
  }

  function drawLightningStormBackdrop(gfx, frame) {
    drawDigitalRainBackdrop(gfx, frame);
    const top = frame.headerDividerY + 2;
    const bottom = frame.footerDividerY - 2;
    if (bottom - top < 12 || frame.dims.width < 96) return;

    const animTick = frame.animTick >>> 0;
    const stepX = frame.compact ? 24 : 20;
    const spanY = Math.max(8, bottom - top - 5);
    for (let rx = 8; rx + 3 < frame.dims.width - 2; rx += stepX) {
      const h = Math.imul(rx, 2654435761) >>> 0;
      const ry = top + ((animTick * 3 + (h >>> 8)) % spanY);
      if (frame.page === logic.ScreenPage.PetFace) {
        const g = frame.faceGeom;
        const fL = g.centerX - g.bracketOffsetX - 6;
        const fR = g.centerX + g.bracketOffsetX + 6;
        if (rx >= fL && rx - 2 <= fR) continue;
      }
      gfx.drawLine(rx, ry, rx - 2, ry + 4, frame.palette.muted);
    }

    if (animTick % 12 < 2) {
      const bx = frame.dims.width - (frame.compact ? 12 : 20);
      const midY = Math.trunc((top + bottom) / 2);
      gfx.drawLine(bx, top, bx - 4, midY, frame.palette.highlight);
      gfx.drawLine(bx - 4, midY, bx + 2, midY, frame.palette.highlight);
      gfx.drawLine(bx + 2, midY, bx - 3, bottom, frame.palette.fg);
      const forkY = midY + Math.trunc((bottom - midY) / 2);
      if (bx >= 10 && forkY <= bottom) {
        gfx.drawLine(bx - 4, midY, bx - 8, forkY, frame.palette.accent);
      }
      if (bx >= 6 && bx + 1 < frame.dims.width) {
        gfx.fillRect(bx - 5, bottom - 1, 5, 1, frame.palette.highlight);
      }
    }
  }

  function drawRadarDishBackdrop(gfx, frame) {
    const top = frame.headerDividerY + 2;
    const bottom = frame.footerDividerY - 2;
    if (bottom - top < 16 || frame.dims.width < 96) return;

    const ox = frame.dims.width - 6;
    const oy = bottom - 2;
    const maxR = Math.min(frame.compact ? 18 : 30, oy - top - 1);
    const phase = (frame.animTick >>> 0) % 3;
    for (let k = 0; k < 3; k++) {
      const r = 6 + k * (frame.compact ? 5 : 9);
      if (r > maxR || ox - r < 2) continue;
      gfx.fillArc(ox, oy, r, r - 1, 185.0, 260.0, k === phase ? frame.palette.accent : frame.palette.muted);
    }
  }

  function drawSatelliteBeamBackdrop(gfx, frame) {
    drawTacticalHudBackdrop(gfx, frame);
    const top = frame.headerDividerY + 3;
    const bottom = frame.footerDividerY - 3;
    if (bottom - top < 12) return;
    const bx = frame.dims.width - 5;
    gfx.drawLine(bx, top, bx, bottom, frame.palette.muted);
    const span = bottom - top;
    const py = top + (((frame.animTick >>> 0) * 3) % span);
    gfx.fillRect(bx - 1, py, 3, Math.min(3, bottom - py + 1), frame.palette.highlight);
  }

  function drawThemeBackdrop(gfx, frame) {
    if (frame.themeEffect === 'DigitalRain') {
      drawDigitalRainBackdrop(gfx, frame);
    } else if (frame.themeEffect === 'TacticalHud') {
      drawTacticalHudBackdrop(gfx, frame);
    } else if (frame.themeEffect === 'LightningStorm') {
      drawLightningStormBackdrop(gfx, frame);
    } else if (frame.themeEffect === 'RadarDish') {
      drawRadarDishBackdrop(gfx, frame);
    } else if (frame.themeEffect === 'SatelliteBeam') {
      drawSatelliteBeamBackdrop(gfx, frame);
    }
  }

  function drawThemeDividerAccent(gfx, frame) {
    if (frame.themeEffect !== 'TacticalHud' && frame.themeEffect !== 'SatelliteBeam') {
      return;
    }
    const pipW = frame.compact ? 6 : 10;
    const travel = frame.dims.width - pipW;
    if (travel <= 1) {
      return;
    }
    const period = travel * 2;
    const step = (((frame.animTick >>> 0) * (frame.compact ? 4 : 6)) % period) >>> 0;
    const pipX = step <= travel ? step : period - step;
    gfx.fillRect(pipX, frame.headerDividerY, pipW, 1, frame.palette.highlight);
  }

  function drawThemeToast(gfx, frame) {
    const t = frame.toast;
    if (!t || !t.visible) {
      return;
    }
    const pal = frame.palette;
    gfx.fillRoundRect(t.x - 2, t.y - 2, t.w + 4, t.h + 4, 4, pal.accent);
    gfx.fillRoundRect(t.x, t.y, t.w, t.h, 3, pal.fg);
    gfx.setTextColor(pal.bg, pal.fg);
    gfx.drawString(t.text, t.textX, t.textY);
  }

  function paintUiFrame(gfx, frame, opts) {
    gfx.fillScreen(frame.palette.bg);

    // Optional zero-RAM procedural theme backdrop (mirrors render/include/zd/render/painter.hpp)
    drawThemeBackdrop(gfx, frame);

    // Top telemetry bar + ops mode badge
    gfx.setTextColor(frame.palette.fg, frame.palette.bg);
    gfx.drawString(frame.headerLine, 4, frame.headerTextY);
    if (frame.modeBadge && frame.modeBadge.length > 0) {
      const bw = frame.modeBadge.length * 6;
      const bx = frame.dims.width - bw - 2;
      const by = Math.max(0, frame.headerTextY - 1);
      const bh = Math.min(10, frame.headerDividerY - by);
      const isOff = frame.offensiveArmed || frame.opsMode === logic.OpsMode.Offensive;
      const isDef = frame.opsMode === logic.OpsMode.Defensive;
      if (isOff || isDef) {
        const badgeBg = isOff ? frame.palette.highlight : frame.palette.accent;
        if (bh > 0 && bx >= 1) {
          gfx.fillRect(bx - 1, by, bw + 2, bh, badgeBg);
        }
        gfx.setTextColor(frame.palette.bg, badgeBg);
      } else {
        gfx.setTextColor(frame.palette.accent, frame.palette.bg);
      }
      gfx.drawString(frame.modeBadge, bx, frame.headerTextY);
    }
    gfx.drawLine(0, frame.headerDividerY, frame.dims.width - 1, frame.headerDividerY, frame.palette.muted);
    drawThemeDividerAccent(gfx, frame);

    // Main content page
    switch (frame.page) {
      case logic.ScreenPage.PetFace:
        drawPetFacePage(gfx, frame, opts);
        break;
      case logic.ScreenPage.NearbyRadar:
        drawRadarPage(gfx, frame);
        break;
      case logic.ScreenPage.ChannelSpectrum:
        drawSpectrumPage(gfx, frame);
        break;
      case logic.ScreenPage.RfGuard:
        drawRfGuardPage(gfx, frame);
        break;
    }

    // Bottom status bar
    gfx.drawLine(0, frame.footerDividerY, frame.dims.width - 1, frame.footerDividerY, frame.palette.muted);
    gfx.setTextColor(frame.palette.accent, frame.palette.bg);
    gfx.drawString(frame.footerLine, 4, frame.footerTextY);

    // Transient theme-change toast overlay
    drawThemeToast(gfx, frame);
  }

  const canvasGfx = Object.freeze({
    FONT_5X7,
    createPixelBuffer,
    paintUiFrame
  });

  root.ZD = root.ZD || {};
  root.ZD.canvasGfx = canvasGfx;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = canvasGfx;
  }
})(typeof globalThis !== 'undefined' ? globalThis : window);
