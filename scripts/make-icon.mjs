#!/usr/bin/env node
/**
 * Generate media/icon.png, the 128x128 marketplace icon.
 *
 * The Visual Studio Marketplace requires a PNG; only shield.svg existed, so packaging failed.
 * Written with zlib rather than an image dependency, so the build stays dependency-free and
 * the icon is reproducible from source.
 *
 * Colours are taken from the landing page: #00d084 on #0f1117.
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';

const SIZE = 128;
const GREEN = [0, 208, 132];   // #00d084
const BG = [15, 17, 23];       // #0f1117

/** Shield outline, normalised coordinates, matching the existing shield.svg proportions. */
function inShield(x, y) {
  const cx = 0.5, top = 0.10, bottom = 0.94;
  if (y < top || y > bottom) return false;
  const t = (y - top) / (bottom - top);
  const halfW = 0.40 * Math.sqrt(Math.max(0, 1 - Math.pow(Math.max(0, t - 0.42) / 0.58, 2)));
  if (t < 0.08) {
    const r = (0.08 - t) / 0.08;
    return Math.abs(x - cx) <= halfW * (1 - 0.3 * r * r);
  }
  return Math.abs(x - cx) <= halfW;
}

/** Magnifier: ExtGuard inspects rather than blocks, so the glyph is a lens, not a tick. */
function inLens(x, y) {
  const cx = 0.46, cy = 0.46, rOuter = 0.155, rInner = 0.105;
  const d = Math.hypot(x - cx, y - cy);
  if (d <= rOuter && d >= rInner) return true;
  // Handle, running down-right from the rim.
  const hx = x - 0.565, hy = y - 0.565;
  const along = (hx + hy) / Math.SQRT2;
  const across = (hy - hx) / Math.SQRT2;
  return along >= 0 && along <= 0.13 && Math.abs(across) <= 0.028;
}

function render() {
  const px = new Uint8Array(SIZE * SIZE * 4);
  const SS = 4;
  for (let y = 0; y < SIZE; y++) {
    for (let x = 0; x < SIZE; x++) {
      let shield = 0, lens = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const u = (x + (sx + 0.5) / SS) / SIZE;
          const v = (y + (sy + 0.5) / SS) / SIZE;
          if (inShield(u, v)) { shield++; if (inLens(u, v)) lens++; }
        }
      }
      const n = SS * SS;
      const a = shield / n;
      const l = lens / n;
      const i = (y * SIZE + x) * 4;
      for (let k = 0; k < 3; k++) {
        // Green shield, with the lens punched back out to the background colour.
        const glyph = GREEN[k] * (1 - l / Math.max(a, 1e-6)) + BG[k] * (l / Math.max(a, 1e-6));
        px[i + k] = Math.round(BG[k] * (1 - a) + glyph * a);
      }
      px[i + 3] = 255; // opaque: the marketplace renders on its own card
    }
  }
  return px;
}

const CRC = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c; }
  return t;
})();
const crc32 = (b) => { let c = ~0; for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8); return ~c; };
const chunk = (type, data) => {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body) >>> 0);
  return Buffer.concat([len, body, crc]);
};

const rgba = render();
const stride = SIZE * 4;
const raw = Buffer.alloc((stride + 1) * SIZE);
for (let y = 0; y < SIZE; y++) {
  raw[y * (stride + 1)] = 0;
  Buffer.from(rgba.buffer, y * stride, stride).copy(raw, y * (stride + 1) + 1);
}
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0); ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; ihdr[9] = 6;
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

mkdirSync(new URL('../media/', import.meta.url), { recursive: true });
writeFileSync(new URL('../media/icon.png', import.meta.url), png);
console.log(`media/icon.png  ${SIZE}x${SIZE}  ${png.length} bytes`);
