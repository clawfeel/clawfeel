#!/usr/bin/env node
// Run: node icons/generate.mjs
// Generates icon16.png, icon48.png, icon128.png (green circle)
import { writeFileSync } from 'fs';
import { deflateSync } from 'zlib';
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const dir = dirname(fileURLToPath(import.meta.url));

function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (c & 1 ? 0xEDB88320 : 0);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function chunk(type, data) {
  const l = Buffer.alloc(4); l.writeUInt32BE(data.length);
  const t = Buffer.from(type);
  const cr = Buffer.alloc(4); cr.writeUInt32BE(crc32(Buffer.concat([t, data])));
  return Buffer.concat([l, t, data, cr]);
}

function makePNG(s) {
  const px = Buffer.alloc(s * s * 4);
  const cx = s / 2, cy = s / 2, r = s / 2 - 0.5;
  for (let y = 0; y < s; y++) for (let x = 0; x < s; x++) {
    const d = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
    const i = (y * s + x) * 4;
    if (d <= r) { px[i] = 0; px[i + 1] = 255; px[i + 2] = 136; px[i + 3] = 255; }
  }
  const raw = Buffer.alloc(s * (s * 4 + 1));
  for (let y = 0; y < s; y++) {
    raw[y * (s * 4 + 1)] = 0;
    px.copy(raw, y * (s * 4 + 1) + 1, y * s * 4, (y + 1) * s * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(s, 0); ihdr.writeUInt32BE(s, 4);
  ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

for (const s of [16, 48, 128]) {
  writeFileSync(`${dir}/icon${s}.png`, makePNG(s));
  console.log(`icon${s}.png created`);
}
