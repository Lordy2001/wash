// Kitty graphics protocol (APC _G ... ESC \), DOM-free.
//
// Supported: direct transmission (t=d) of PNG (f=100) and raw RGB/RGBA
// (f=24/32), optionally zlib-compressed (o=z); chunking (m=1); actions
// t, T, p, d, q. Image decoding to drawable bitmaps is delegated to an
// injected async decoder: decoder(img, bytes, {compressed, format, width,
// height}) -> Promise<{bitmap, width, height}>.

const MAX_BYTES = 256 << 20; // decoded image memory cap (w*h*4)
const MAX_PENDING = 400 << 20; // base64 bytes of one chunked transmission

const STRING_KEYS = new Set(['a', 't', 'o', 'd', 'U']);

export function parseKeys(s) {
  const k = {};
  if (!s) return k;
  for (const kv of s.split(',')) {
    const eq = kv.indexOf('=');
    if (eq <= 0) continue;
    const key = kv.slice(0, eq), val = kv.slice(eq + 1);
    if (STRING_KEYS.has(key)) k[key] = val;
    else { const v = parseInt(val, 10); if (!Number.isNaN(v)) k[key] = v; }
  }
  return k;
}

export function b64decode(s) {
  s = s.replace(/[^A-Za-z0-9+/]/g, '');
  const bin = atob(s.length % 4 === 0 ? s : s + '='.repeat(4 - (s.length % 4)));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

class KittyError extends Error {
  constructor(code, msg) { super(msg); this.code = code; }
}

function pngSize(b) {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (b.length < 24) return null;
  for (let i = 0; i < 8; i++) if (b[i] !== sig[i]) return null;
  const u32 = (o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
  return { w: u32(16), h: u32(20) };
}

export class KittyGraphics {
  constructor(screen, decoder) {
    this.s = screen;
    this.decoder = decoder || null;
    this.images = new Map(); // id -> image
    this.numbers = new Map(); // image number -> id
    this.pending = null;
    this.bytes = 0;
    this.seq = 0;
    this.autoId = 0x7fffffff;
  }

  clearAll() {
    this.images.clear();
    this.numbers.clear();
    this.pending = null;
    this.bytes = 0;
    if (this.s.normal) this.s.normal.placements = [];
    if (this.s.alt) this.s.alt.placements = [];
  }

  handle(payload) {
    const semi = payload.indexOf(';');
    const ctrl = semi < 0 ? payload : payload.slice(0, semi);
    const data = semi < 0 ? '' : payload.slice(semi + 1);
    const k = parseKeys(ctrl);
    if (this.pending) {
      const p = this.pending;
      p.parts.push(data);
      p.size += data.length;
      if (k.q !== undefined) p.k.q = k.q;
      if (p.size > MAX_PENDING) { this.pending = null; return; }
      if (k.m === 1) return;
      this.pending = null;
      this.process(p.k, p.parts.join(''));
      return;
    }
    if (k.m === 1) { this.pending = { k, parts: [data], size: data.length }; return; }
    this.process(k, data);
  }

  reply(k, msg, id = 0) {
    if (!k.i && !k.I) return;
    const q = k.q | 0;
    if (q >= 2 || (q === 1 && msg === 'OK')) return;
    const keys = [];
    if (k.i || id) keys.push(`i=${k.i || id}`);
    if (k.I) keys.push(`I=${k.I}`);
    if (k.p) keys.push(`p=${k.p}`);
    this.s.reply(`\x1b_G${keys.join(',')};${msg}\x1b\\`);
  }

  process(k, b64) {
    const a = k.a || 't';
    try {
      switch (a) {
        case 'q': this._prepare(k, b64); this.reply(k, 'OK'); break;
        case 't': case 'T': this._transmit(k, b64, a === 'T'); break;
        case 'p': this._put(k); break;
        case 'd': this._delete(k); break;
        default: break; // animation (f, a, c) not supported
      }
    } catch (e) {
      if (e instanceof KittyError) this.reply(k, `${e.code}:${e.message}`);
      else this.reply(k, `EINVAL:${e && e.message ? e.message : 'error'}`);
    }
  }

  /** Validates and decodes base64; returns {bytes, w, h, format, compressed}. */
  _prepare(k, b64) {
    const t = k.t || 'd';
    if (t !== 'd') throw new KittyError('EBADF', 'only direct transmission is supported');
    const format = k.f || 32;
    if (format !== 24 && format !== 32 && format !== 100) throw new KittyError('EINVAL', 'unknown format');
    const compressed = k.o === 'z';
    if (k.o && !compressed) throw new KittyError('EINVAL', 'unknown compression');
    let bytes;
    try { bytes = b64decode(b64); } catch { throw new KittyError('EINVAL', 'bad base64'); }
    if (bytes.length === 0) throw new KittyError('ENODATA', 'no image data');
    let w = 0, h = 0;
    if (format === 100) {
      if (!compressed) {
        const sz = pngSize(bytes);
        if (!sz) throw new KittyError('EBADPNG', 'not a PNG');
        w = sz.w; h = sz.h;
      }
    } else {
      w = k.s | 0; h = k.v | 0;
      if (w <= 0 || h <= 0) throw new KittyError('EINVAL', 'missing width/height');
      if (!compressed && bytes.length < w * h * (format === 24 ? 3 : 4)) throw new KittyError('ENODATA', 'insufficient image data');
    }
    if (w * h > 10000 * 10000) throw new KittyError('EFBIG', 'image too large');
    return { bytes, w, h, format, compressed };
  }

  _allocId() {
    while (this.images.has(this.autoId)) this.autoId--;
    return this.autoId--;
  }

  _removeImage(id) {
    const img = this.images.get(id);
    if (!img) return;
    this.images.delete(id);
    this.bytes -= img.mem;
    if (img.num && this.numbers.get(img.num) === id) this.numbers.delete(img.num);
    for (const b of [this.s.normal, this.s.alt]) {
      if (b) b.placements = b.placements.filter((p) => p.img !== img);
    }
    if (img.bitmap && img.bitmap.close) img.bitmap.close();
    this.s.markAllDirty();
  }

  _transmit(k, b64, display) {
    if (k.i && k.I) throw new KittyError('EINVAL', 'both i and I given');
    const d = this._prepare(k, b64);
    let id = k.i | 0;
    if (!id) id = this._allocId();
    if (this.images.has(id)) this._removeImage(id);
    const img = {
      id, num: k.I | 0, format: d.format, w: d.w, h: d.h, bitmap: null, failed: false,
      mem: Math.max(d.w * d.h * 4, d.bytes.length), seq: this.seq++,
    };
    this.images.set(id, img);
    if (img.num) this.numbers.set(img.num, id);
    this.bytes += img.mem;
    this._evict(id);
    if (this.decoder) {
      Promise.resolve(this.decoder(img, d.bytes, { compressed: d.compressed, format: d.format, width: d.w, height: d.h }))
        .then((r) => {
          if (this.images.get(id) !== img) { if (r && r.bitmap && r.bitmap.close) r.bitmap.close(); return; }
          img.bitmap = r.bitmap;
          if (!img.w || !img.h) {
            img.w = r.width; img.h = r.height;
            this.bytes += img.w * img.h * 4 - img.mem;
            img.mem = img.w * img.h * 4;
            for (const b of [this.s.normal, this.s.alt]) {
              for (const p of b.placements) if (p.img === img && p.pendingSize) this._size(p, p.k);
            }
          }
          this.s.markAllDirty();
          this.s.onImage(img);
        })
        .catch(() => { img.failed = true; });
    }
    if (display) this._place(img, k);
    this.reply(k, 'OK', id);
  }

  _evict(keep) {
    if (this.bytes <= MAX_BYTES) return;
    const imgs = [...this.images.values()].sort((a, b) => a.seq - b.seq);
    for (const img of imgs) {
      if (this.bytes <= MAX_BYTES) break;
      if (img.id !== keep) this._removeImage(img.id);
    }
  }

  _lookup(k) {
    if (k.i) return this.images.get(k.i) || null;
    if (k.I) { const id = this.numbers.get(k.I); return id ? this.images.get(id) || null : null; }
    return null;
  }

  _put(k) {
    const img = this._lookup(k);
    if (!img) throw new KittyError('ENOENT', 'no such image');
    this._place(img, k);
    this.reply(k, 'OK', img.id);
  }

  _size(pl, k) {
    const cw = this.s.cellW, ch = this.s.cellH;
    const img = pl.img;
    pl.sx = k.x | 0; pl.sy = k.y | 0;
    pl.sw = (k.w | 0) || Math.max(0, img.w - pl.sx);
    pl.sh = (k.h | 0) || Math.max(0, img.h - pl.sy);
    pl.ox = k.X | 0; pl.oy = k.Y | 0;
    let cols = k.c | 0, rows = k.r | 0;
    let dw, dh;
    if (cols && rows) { dw = cols * cw - pl.ox; dh = rows * ch - pl.oy; }
    else if (cols) { dw = cols * cw - pl.ox; dh = pl.sw ? dw * pl.sh / pl.sw : 0; rows = Math.max(1, Math.ceil((pl.oy + dh) / ch)); }
    else if (rows) { dh = rows * ch - pl.oy; dw = pl.sh ? dh * pl.sw / pl.sh : 0; cols = Math.max(1, Math.ceil((pl.ox + dw) / cw)); }
    else {
      dw = pl.sw; dh = pl.sh;
      cols = Math.max(1, Math.ceil((pl.ox + dw) / cw));
      rows = Math.max(1, Math.ceil((pl.oy + dh) / ch));
    }
    pl.dw = dw; pl.dh = dh; pl.cols = cols; pl.rows = rows;
    pl.pendingSize = !img.w || !img.h;
  }

  _place(img, k) {
    const s = this.s, b = s.buf;
    const pl = {
      img, pid: k.p | 0, abs: b.top + b.y, col: Math.min(b.x, s.cols - 1), z: k.z | 0,
      k: { x: k.x, y: k.y, w: k.w, h: k.h, X: k.X, Y: k.Y, c: k.c, r: k.r },
      sx: 0, sy: 0, sw: 0, sh: 0, ox: 0, oy: 0, dw: 0, dh: 0, cols: 1, rows: 1, pendingSize: false,
    };
    this._size(pl, pl.k);
    if (pl.pid) b.placements = b.placements.filter((p) => !(p.img === img && p.pid === pl.pid));
    b.placements.push(pl);
    b.placements.sort((a, c) => a.z - c.z);
    if (!k.C && !pl.pendingSize) s.cursorAfterImage(pl.cols, pl.rows);
    s.markAllDirty();
    return pl;
  }

  _delete(k) {
    const s = this.s, b = s.buf;
    const d = k.d || 'a';
    const what = d.toLowerCase();
    const free = d !== what;
    const top = b.top;
    const hits = (p, col, row) => col >= p.col && col < p.col + p.cols && row >= p.abs && row < p.abs + p.rows;
    let pred;
    switch (what) {
      case 'a': pred = (p) => p.abs + p.rows > top && p.abs < top + s.rows; break;
      case 'i': pred = (p) => p.img.id === k.i && (!k.p || p.pid === k.p); break;
      case 'n': pred = (p) => p.img.num === k.I && (!k.p || p.pid === k.p); break;
      case 'c': pred = (p) => hits(p, b.x, top + b.y); break;
      case 'p': pred = (p) => hits(p, (k.x | 0) - 1, top + (k.y | 0) - 1); break;
      case 'q': pred = (p) => hits(p, (k.x | 0) - 1, top + (k.y | 0) - 1) && p.z === (k.z | 0); break;
      case 'x': pred = (p) => { const c = (k.x | 0) - 1; return c >= p.col && c < p.col + p.cols; }; break;
      case 'y': pred = (p) => { const r = top + (k.y | 0) - 1; return r >= p.abs && r < p.abs + p.rows; }; break;
      case 'z': pred = (p) => p.z === (k.z | 0); break;
      default: return;
    }
    const removed = b.placements.filter(pred);
    b.placements = b.placements.filter((p) => !pred(p));
    if (free) {
      const cand = new Set(removed.map((p) => p.img));
      if (what === 'i') { const im = this.images.get(k.i); if (im) cand.add(im); }
      if (what === 'n') { const im = this._lookup({ I: k.I }); if (im) cand.add(im); }
      for (const img of cand) {
        const used = [s.normal, s.alt].some((bb) => bb.placements.some((p) => p.img === img));
        if (!used) this._removeImage(img.id);
      }
    }
    s.markAllDirty();
  }
}
