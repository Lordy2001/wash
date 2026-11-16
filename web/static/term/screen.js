// Terminal screen model (DOM-free): buffers, cursor, modes, SGR state and
// the handlers the parser dispatches to. Replies to the host (DA, DSR, ...)
// go out through onReply; images through the kitty graphics module.

import { wcwidth } from './wcwidth.js';
import { Parser } from './parser.js';
import { KittyGraphics } from './kitty.js';

// Cell attribute flags (Line.fl). Underline style lives in bits 8-10.
export const BOLD = 1, DIM = 2, ITALIC = 4, INVERSE = 8, HIDDEN = 16, STRIKE = 32, OVERLINE = 64, BLINK = 128;
export const UL_SHIFT = 8, UL_MASK = 7 << UL_SHIFT;
// underline styles: 0 none, 1 single, 2 double, 3 curly, 4 dotted, 5 dashed

// Colors: 0 = default, PAL|n = palette index, RGB|0xrrggbb = truecolor.
export const PAL = 0x1000000, RGB = 0x2000000;

export const DEFAULT_THEME = {
  background: '#101317',
  foreground: '#d8dee9',
  cursor: '#e5c07b',
  selection: 'rgba(120,150,200,0.35)',
  ansi: [
    '#1d2026', '#e06c75', '#98c379', '#e5c07b', '#61afef', '#c678dd', '#56b6c2', '#c8ccd4',
    '#5c6370', '#ff7a85', '#b5e890', '#ffd68a', '#7cc4ff', '#de9cf0', '#7fd3dd', '#ffffff',
  ],
};

export function parseColor(s) {
  if (typeof s !== 'string') return null;
  s = s.trim();
  let m = /^#([0-9a-f]{6})$/i.exec(s);
  if (m) return parseInt(m[1], 16);
  m = /^#([0-9a-f]{3})$/i.exec(s);
  if (m) { const v = m[1]; return parseInt(v[0] + v[0] + v[1] + v[1] + v[2] + v[2], 16); }
  m = /^rgb:([0-9a-f]{1,4})\/([0-9a-f]{1,4})\/([0-9a-f]{1,4})$/i.exec(s);
  if (m) {
    const c = (h) => Math.round(parseInt(h, 16) * 255 / ((1 << (4 * h.length)) - 1));
    return (c(m[1]) << 16) | (c(m[2]) << 8) | c(m[3]);
  }
  m = /^rgba?\((\d+)\s*,\s*(\d+)\s*,\s*(\d+)/i.exec(s);
  if (m) return (+m[1] << 16) | (+m[2] << 8) | +m[3];
  return null;
}

function xcolor(rgb) {
  const h = (v) => { const x = v.toString(16).padStart(2, '0'); return x + x; };
  return `rgb:${h((rgb >> 16) & 255)}/${h((rgb >> 8) & 255)}/${h(rgb & 255)}`;
}

export function defaultPalette(ansi) {
  const p = new Int32Array(256);
  for (let i = 0; i < 16; i++) p[i] = parseColor(ansi[i]) ?? 0;
  const lv = [0, 95, 135, 175, 215, 255];
  for (let i = 0; i < 216; i++) {
    p[16 + i] = (lv[Math.floor(i / 36)] << 16) | (lv[Math.floor(i / 6) % 6] << 8) | lv[i % 6];
  }
  for (let i = 0; i < 24; i++) { const v = 8 + i * 10; p[232 + i] = (v << 16) | (v << 8) | v; }
  return p;
}

const DEC_GRAPHICS = {
  0x60: '◆', 0x61: '▒', 0x62: '␉', 0x63: '␌', 0x64: '␍', 0x65: '␊', 0x66: '°', 0x67: '±',
  0x68: '␤', 0x69: '␋', 0x6a: '┘', 0x6b: '┐', 0x6c: '┌', 0x6d: '└', 0x6e: '┼', 0x6f: '⎺',
  0x70: '⎻', 0x71: '─', 0x72: '⎼', 0x73: '⎽', 0x74: '├', 0x75: '┤', 0x76: '┴', 0x77: '┬',
  0x78: '│', 0x79: '≤', 0x7a: '≥', 0x7b: 'π', 0x7c: '≠', 0x7d: '£', 0x7e: '·',
};

export class Line {
  constructor(cols, bg = 0) {
    this.ch = new Array(cols).fill(' ');
    this.wd = new Uint8Array(cols).fill(1);
    this.fg = new Int32Array(cols);
    this.bg = new Int32Array(cols);
    if (bg) this.bg.fill(bg);
    this.fl = new Uint16Array(cols);
    this.uc = new Int32Array(cols);
    this.ln = new Uint32Array(cols);
    this.wrapped = false;
    this.dirty = true;
  }
  get cols() { return this.ch.length; }
  clear(bg = 0, from = 0, to = this.ch.length) {
    to = Math.min(to, this.ch.length);
    if (from >= to) return;
    this.ch.fill(' ', from, to);
    this.wd.fill(1, from, to);
    this.fg.fill(0, from, to);
    this.bg.fill(bg, from, to);
    this.fl.fill(0, from, to);
    this.uc.fill(0, from, to);
    this.ln.fill(0, from, to);
    this.dirty = true;
  }
  reset(bg = 0) { this.clear(bg); this.wrapped = false; }
  copyCell(to, from) {
    this.ch[to] = this.ch[from]; this.wd[to] = this.wd[from]; this.fg[to] = this.fg[from];
    this.bg[to] = this.bg[from]; this.fl[to] = this.fl[from]; this.uc[to] = this.uc[from];
    this.ln[to] = this.ln[from];
  }
  resize(cols) {
    const old = this.ch.length;
    if (cols === old) return;
    const n = new Line(cols);
    const m = Math.min(cols, old);
    for (let i = 0; i < m; i++) {
      n.ch[i] = this.ch[i]; n.wd[i] = this.wd[i]; n.fg[i] = this.fg[i]; n.bg[i] = this.bg[i];
      n.fl[i] = this.fl[i]; n.uc[i] = this.uc[i]; n.ln[i] = this.ln[i];
    }
    if (m > 0 && n.wd[m - 1] === 2 && m === cols) { n.ch[m - 1] = ' '; n.wd[m - 1] = 1; }
    Object.assign(this, { ch: n.ch, wd: n.wd, fg: n.fg, bg: n.bg, fl: n.fl, uc: n.uc, ln: n.ln });
    this.dirty = true;
  }
  isBlank() {
    for (let i = 0; i < this.ch.length; i++) if (this.ch[i] !== ' ' || this.bg[i] !== 0) return false;
    return true;
  }
  text(from = 0, to = this.ch.length) {
    let s = '';
    for (let i = from; i < Math.min(to, this.ch.length); i++) if (this.wd[i] !== 0) s += this.ch[i];
    return s;
  }
}

/** Fixed-capacity ring of lines (scrollback). */
export class Ring {
  constructor(cap) { this.cap = cap; this.a = new Array(cap); this.start = 0; this.length = 0; }
  /** Pushes x; returns the evicted element (or null). */
  push(x) {
    if (this.cap === 0) return x;
    if (this.length < this.cap) { this.a[(this.start + this.length) % this.cap] = x; this.length++; return null; }
    const ev = this.a[this.start];
    this.a[this.start] = x;
    this.start = (this.start + 1) % this.cap;
    return ev;
  }
  get(i) { return this.a[(this.start + i) % this.cap]; }
  clear() { this.a = new Array(this.cap); this.start = 0; this.length = 0; }
}

class Buffer {
  constructor(cols, rows, scrollback) {
    this.lines = [];
    for (let i = 0; i < rows; i++) this.lines.push(new Line(cols));
    this.sb = scrollback > 0 ? new Ring(scrollback) : null;
    this.top = 0; // absolute row number of screen row 0
    this.x = 0; this.y = 0; this.wrapPending = false;
    this.saved = null;
    this.scrollTop = 0; this.scrollBottom = rows - 1;
    this.placements = [];
  }
  get sbLength() { return this.sb ? this.sb.length : 0; }
}

function newAttr() { return { fg: 0, bg: 0, fl: 0, uc: 0, ln: 0 }; }

export class Screen {
  /**
   * @param {number} cols
   * @param {number} rows
   * @param {{scrollback?: number, decoder?: Function, theme?: object}} opts
   */
  constructor(cols = 80, rows = 24, opts = {}) {
    this.opts = opts;
    this.scrollback = opts.scrollback ?? 5000;
    this.onReply = () => {};
    this.onTitle = () => {};
    this.onBell = () => {};
    this.onClipboard = () => {};
    this.onImage = () => {};
    this.cellW = 8; this.cellH = 16; // CSS pixels, set by the renderer
    this.cols = cols; this.rows = rows;
    this.parser = new Parser(this);
    this.kitty = new KittyGraphics(this, opts.decoder);
    this.setTheme(opts.theme || DEFAULT_THEME);
    this.focused = false;
    this.viewOffset = 0;
    this._initState();
  }

  setTheme(theme) {
    this.theme = { ...DEFAULT_THEME, ...theme };
    this.palette = defaultPalette(this.theme.ansi || DEFAULT_THEME.ansi);
    this.fgColor = parseColor(this.theme.foreground) ?? 0xd8dee9;
    this.bgColor = parseColor(this.theme.background) ?? 0x101317;
    this.cursorColor = parseColor(this.theme.cursor) ?? this.fgColor;
    this.dirtyAll = true;
  }

  _initState() {
    this.normal = new Buffer(this.cols, this.rows, this.scrollback);
    this.alt = new Buffer(this.cols, this.rows, 0);
    this.buf = this.normal;
    this.attr = newAttr();
    this.modes = {
      appCursor: false, appKeypad: false, autowrap: true, cursorVisible: true, origin: false,
      bracketedPaste: false, mouse: 0, mouseSGR: false, focus: false, sync: false,
      insert: false, lnm: false, reverse: false, altScreen: false,
    };
    this.cursorStyle = 0;
    this.charsets = ['us', 'us'];
    this.gl = 0;
    this.title = '';
    this.links = new Map(); // id -> url
    this.linkIds = new Map(); // url -> id
    this.nextLink = 1;
    this.lastChar = 0;
    this.tabs = new Uint8Array(this.cols);
    for (let i = 0; i < this.cols; i += 8) this.tabs[i] = 1;
    this.dirtyAll = true;
    this.viewOffset = 0;
  }

  // ---- public ---------------------------------------------------------------

  write(str) { this.parser.parse(str); }

  reply(s) { this.onReply(s); }

  markAllDirty() { this.dirtyAll = true; }

  /** Line at an absolute row (scrollback or screen), or null. */
  lineAt(abs) {
    const b = this.buf;
    const first = b.top - b.sbLength;
    if (abs < first) return null;
    if (abs < b.top) return b.sb.get(abs - first);
    if (abs < b.top + this.rows) return b.lines[abs - b.top];
    return null;
  }

  /** Absolute row number shown at viewport row 0. */
  get viewTop() { return this.buf.top - this.viewOffset; }

  scrollView(delta) {
    const max = this.buf.sbLength;
    const v = Math.max(0, Math.min(max, this.viewOffset + delta));
    if (v !== this.viewOffset) { this.viewOffset = v; this.dirtyAll = true; }
  }

  resize(cols, rows) {
    cols = Math.max(2, cols | 0); rows = Math.max(1, rows | 0);
    if (cols === this.cols && rows === this.rows) return;
    for (const b of [this.normal, this.alt]) {
      for (const l of b.lines) l.resize(cols);
      while (b.lines.length > rows) {
        const last = b.lines[b.lines.length - 1];
        if (b.y < b.lines.length - 1 && last.isBlank()) { b.lines.pop(); continue; }
        const l = b.lines.shift();
        if (b.sb && b === this.normal) b.sb.push(l);
        b.top++;
        b.y = Math.max(0, b.y - 1);
        if (b.saved) b.saved.y = Math.max(0, b.saved.y - 1);
      }
      while (b.lines.length < rows) b.lines.push(new Line(cols));
      b.x = Math.min(b.x, cols - 1);
      b.y = Math.min(b.y, rows - 1);
      b.wrapPending = false;
      b.scrollTop = 0; b.scrollBottom = rows - 1;
      if (b.saved) { b.saved.x = Math.min(b.saved.x, cols - 1); b.saved.y = Math.min(b.saved.y, rows - 1); }
    }
    const tabs = new Uint8Array(cols);
    for (let i = 0; i < cols; i++) tabs[i] = i < this.cols ? this.tabs[i] : (i % 8 === 0 ? 1 : 0);
    this.tabs = tabs;
    this.cols = cols; this.rows = rows;
    this.viewOffset = Math.min(this.viewOffset, this.buf.sbLength);
    this.dirtyAll = true;
  }

  /** Text between two absolute positions (inclusive start, exclusive end col). */
  getText(a, b) {
    if (a.abs > b.abs || (a.abs === b.abs && a.col > b.col)) [a, b] = [b, a];
    let out = '';
    for (let r = a.abs; r <= b.abs; r++) {
      const l = this.lineAt(r);
      if (!l) continue;
      const from = r === a.abs ? a.col : 0;
      const to = r === b.abs ? b.col : l.cols;
      let t = l.text(from, to);
      const wraps = l.wrapped && r !== b.abs && to >= l.cols;
      if (!wraps) t = t.replace(/\s+$/, '');
      out += t;
      if (r !== b.abs && !wraps) out += '\n';
    }
    return out;
  }

  // ---- cell writing ---------------------------------------------------------

  _blankBg() { return this.attr.bg; }

  print(s, start, end) {
    const cs = this.charsets[this.gl];
    for (let i = start; i < end; i++) {
      let cp = s.charCodeAt(i);
      if (cp >= 0xd800 && cp < 0xdc00 && i + 1 < end) {
        const lo = s.charCodeAt(i + 1);
        if (lo >= 0xdc00 && lo < 0xe000) { cp = ((cp - 0xd800) << 10) + (lo - 0xdc00) + 0x10000; i++; }
      }
      if (cs === 'dec' && cp >= 0x60 && cp <= 0x7e) cp = DEC_GRAPHICS[cp].codePointAt(0);
      this.putChar(cp);
    }
  }

  putChar(cp) {
    const b = this.buf;
    const w = cp < 0x300 ? 1 : wcwidth(cp);
    if (w === 0) { this._combine(cp); return; }
    const cols = this.cols;
    if (b.wrapPending) {
      if (this.modes.autowrap) {
        b.lines[b.y].wrapped = true;
        this.index();
        b.x = 0;
      }
      b.wrapPending = false;
    }
    if (w === 2 && b.x >= cols - 1) {
      if (!this.modes.autowrap) return;
      const l = b.lines[b.y];
      this._fixWide(l, b.x);
      l.clear(this.attr.bg, b.x, cols);
      l.wrapped = true;
      this.index();
      b.x = 0;
    }
    const line = b.lines[b.y];
    if (this.modes.insert) this._insertCells(line, b.x, w);
    const x = b.x;
    this._fixWide(line, x);
    if (w === 2) this._fixWide(line, x + 1);
    const a = this.attr;
    line.ch[x] = String.fromCodePoint(cp);
    line.wd[x] = w;
    line.fg[x] = a.fg; line.bg[x] = a.bg; line.fl[x] = a.fl; line.uc[x] = a.uc; line.ln[x] = a.ln;
    if (w === 2) {
      line.ch[x + 1] = '';
      line.wd[x + 1] = 0;
      line.fg[x + 1] = a.fg; line.bg[x + 1] = a.bg; line.fl[x + 1] = a.fl; line.uc[x + 1] = a.uc; line.ln[x + 1] = a.ln;
    }
    line.dirty = true;
    this.lastChar = cp;
    b.x += w;
    if (b.x >= cols) { b.x = cols - 1; b.wrapPending = true; }
  }

  _combine(cp) {
    const b = this.buf;
    if (cp === 0x200b) return;
    let t = b.wrapPending ? b.x : b.x - 1;
    if (t < 0) return;
    const l = b.lines[b.y];
    if (l.wd[t] === 0 && t > 0) t--;
    if (l.ch[t].length < 32) l.ch[t] += String.fromCodePoint(cp);
    l.dirty = true;
  }

  /** Before overwriting cell x: break up any wide character it belongs to. */
  _fixWide(l, x) {
    if (x < 0 || x >= l.cols) return;
    if (l.wd[x] === 0 && x > 0) { l.ch[x - 1] = ' '; l.wd[x - 1] = 1; }
    if (l.wd[x] === 2 && x + 1 < l.cols) { l.ch[x + 1] = ' '; l.wd[x + 1] = 1; }
  }

  _insertCells(l, x, n) {
    const cols = l.cols;
    n = Math.min(n, cols - x);
    this._fixWide(l, x);
    for (let i = cols - 1; i >= x + n; i--) l.copyCell(i, i - n);
    l.clear(this.attr.bg, x, x + n);
    if (l.wd[cols - 1] === 2) { l.ch[cols - 1] = ' '; l.wd[cols - 1] = 1; }
    l.dirty = true;
  }

  // ---- scrolling ------------------------------------------------------------

  /** Scroll the region up by n lines (content moves up). */
  scrollUp(n, top = this.buf.scrollTop, bot = this.buf.scrollBottom) {
    const b = this.buf;
    n = Math.min(n, bot - top + 1);
    if (n <= 0) return;
    const bg = this.attr.bg;
    if (top === 0 && bot === this.rows - 1) {
      for (let k = 0; k < n; k++) {
        const l = b.lines.shift();
        let rec = null;
        if (b.sb) rec = b.sb.push(l);
        else rec = l;
        if (rec && rec.cols === this.cols) rec.reset(bg);
        else rec = new Line(this.cols, bg);
        b.lines.push(rec);
        b.top++;
      }
      if (this.viewOffset > 0) this.viewOffset = Math.min(this.viewOffset + n, b.sbLength);
      if (b.placements.length) this._prunePlacements();
    } else {
      const removed = b.lines.splice(top, n);
      for (const l of removed) l.reset(bg);
      b.lines.splice(bot - n + 1, 0, ...removed);
      this._shiftPlacements(top, bot, -n);
    }
    this.dirtyAll = true;
  }

  /** Scroll the region down by n lines (content moves down). */
  scrollDown(n, top = this.buf.scrollTop, bot = this.buf.scrollBottom) {
    const b = this.buf;
    n = Math.min(n, bot - top + 1);
    if (n <= 0) return;
    const removed = b.lines.splice(bot - n + 1, n);
    for (const l of removed) l.reset(this.attr.bg);
    b.lines.splice(top, 0, ...removed);
    this._shiftPlacements(top, bot, n);
    this.dirtyAll = true;
  }

  _shiftPlacements(top, bot, delta) {
    const b = this.buf;
    if (!b.placements.length) return;
    const t = b.top + top, e = b.top + bot;
    b.placements = b.placements.filter((p) => {
      if (p.abs < t || p.abs > e) return true;
      p.abs += delta;
      return p.abs >= t && p.abs <= e;
    });
  }

  _prunePlacements() {
    const b = this.buf;
    const first = b.top - b.sbLength;
    b.placements = b.placements.filter((p) => p.abs + p.rows > first);
  }

  index() {
    const b = this.buf;
    if (b.y === b.scrollBottom) this.scrollUp(1);
    else if (b.y < this.rows - 1) b.y++;
  }

  reverseIndex() {
    const b = this.buf;
    if (b.y === b.scrollTop) this.scrollDown(1);
    else if (b.y > 0) b.y--;
  }

  // ---- cursor helpers ---------------------------------------------------------

  _setX(x) { const b = this.buf; b.x = Math.max(0, Math.min(this.cols - 1, x)); b.wrapPending = false; }
  _setY(y) {
    const b = this.buf;
    const lo = this.modes.origin ? b.scrollTop : 0, hi = this.modes.origin ? b.scrollBottom : this.rows - 1;
    b.y = Math.max(lo, Math.min(hi, y));
    b.wrapPending = false;
  }
  _moveUp(n) {
    const b = this.buf;
    const lo = b.y >= b.scrollTop ? b.scrollTop : 0;
    b.y = Math.max(lo, b.y - n); b.wrapPending = false;
  }
  _moveDown(n) {
    const b = this.buf;
    const hi = b.y <= b.scrollBottom ? b.scrollBottom : this.rows - 1;
    b.y = Math.min(hi, b.y + n); b.wrapPending = false;
  }

  _saveCursor() {
    const b = this.buf;
    b.saved = {
      x: b.x, y: b.y, wrapPending: b.wrapPending, attr: { ...this.attr }, origin: this.modes.origin,
      autowrap: this.modes.autowrap, charsets: [...this.charsets], gl: this.gl,
    };
  }

  _restoreCursor() {
    const b = this.buf;
    const s = b.saved;
    if (!s) { b.x = 0; b.y = 0; b.wrapPending = false; this.attr = newAttr(); this.modes.origin = false; return; }
    b.x = Math.min(s.x, this.cols - 1); b.y = Math.min(s.y, this.rows - 1);
    b.wrapPending = s.wrapPending;
    this.attr = { ...s.attr };
    this.modes.origin = s.origin;
    this.modes.autowrap = s.autowrap;
    this.charsets = [...s.charsets];
    this.gl = s.gl;
  }

  cursorAfterImage(cols, rows) {
    const b = this.buf;
    for (let i = 1; i < rows; i++) this.index();
    const nx = b.x + cols;
    if (nx >= this.cols) { b.x = this.cols - 1; b.wrapPending = this.modes.autowrap; }
    else { b.x = nx; b.wrapPending = false; }
  }

  // ---- erase ----------------------------------------------------------------------

  _eraseLine(l, from, to) {
    this._fixWide(l, from);
    if (to - 1 < l.cols) this._fixWide(l, to - 1);
    l.clear(this.attr.bg, from, to);
  }

  eraseInDisplay(mode) {
    const b = this.buf;
    if (mode === 0) {
      this._eraseLine(b.lines[b.y], b.x, this.cols);
      b.lines[b.y].wrapped = false;
      for (let y = b.y + 1; y < this.rows; y++) b.lines[y].reset(this.attr.bg);
    } else if (mode === 1) {
      for (let y = 0; y < b.y; y++) b.lines[y].reset(this.attr.bg);
      this._eraseLine(b.lines[b.y], 0, b.x + 1);
    } else if (mode === 2) {
      for (let y = 0; y < this.rows; y++) b.lines[y].reset(this.attr.bg);
      const top = b.top;
      b.placements = b.placements.filter((p) => p.abs + p.rows <= top);
    } else if (mode === 3) {
      if (b.sb) b.sb.clear();
      b.placements = b.placements.filter((p) => p.abs >= b.top);
      this.viewOffset = 0;
    }
    b.wrapPending = false;
    this.dirtyAll = true;
  }

  eraseInLine(mode) {
    const b = this.buf;
    const l = b.lines[b.y];
    if (mode === 0) { this._eraseLine(l, b.x, this.cols); l.wrapped = false; }
    else if (mode === 1) this._eraseLine(l, 0, b.x + 1);
    else if (mode === 2) { this._eraseLine(l, 0, this.cols); l.wrapped = false; }
    b.wrapPending = false;
  }

  // ---- alternate screen -----------------------------------------------------------

  _setAlt(on, { save = false, clear = false } = {}) {
    if (on === this.modes.altScreen) return;
    if (on) {
      if (save) this._saveCursor();
      const n = this.normal;
      this.alt.x = n.x; this.alt.y = n.y; this.alt.wrapPending = false;
      this.buf = this.alt;
      if (clear) { for (const l of this.alt.lines) l.reset(this.attr.bg); this.alt.placements = []; }
      this.modes.altScreen = true;
    } else {
      if (clear) { for (const l of this.alt.lines) l.reset(0); }
      this.alt.placements = [];
      this.buf = this.normal;
      this.modes.altScreen = false;
      if (save) this._restoreCursor();
    }
    this.viewOffset = 0;
    this.dirtyAll = true;
  }

  // ---- parser handlers --------------------------------------------------------------

  execute(c) {
    const b = this.buf;
    switch (c) {
      case 0x07: this.onBell(); break;
      case 0x08:
        if (b.wrapPending) b.wrapPending = false;
        if (b.x > 0) b.x--;
        break;
      case 0x09: {
        let x = b.x + 1;
        while (x < this.cols - 1 && !this.tabs[x]) x++;
        b.x = Math.min(x, this.cols - 1);
        b.wrapPending = false;
        break;
      }
      case 0x0a: case 0x0b: case 0x0c:
        this.index();
        if (this.modes.lnm) b.x = 0;
        b.wrapPending = false;
        break;
      case 0x0d: b.x = 0; b.wrapPending = false; break;
      case 0x0e: this.gl = 1; break;
      case 0x0f: this.gl = 0; break;
    }
  }

  esc(inter, f) {
    const b = this.buf;
    if (inter === '') {
      switch (f) {
        case '7': this._saveCursor(); break;
        case '8': this._restoreCursor(); break;
        case 'D': this.index(); break;
        case 'E': this.index(); b.x = 0; b.wrapPending = false; break;
        case 'H': this.tabs[b.x] = 1; break;
        case 'M': this.reverseIndex(); b.wrapPending = false; break;
        case 'c': this.fullReset(); break;
        case '=': this.modes.appKeypad = true; break;
        case '>': this.modes.appKeypad = false; break;
      }
    } else if (inter === '(' || inter === ')') {
      this.charsets[inter === '(' ? 0 : 1] = f === '0' ? 'dec' : 'us';
    } else if (inter === '#' && f === '8') {
      for (const l of b.lines) { l.reset(0); l.ch.fill('E'); }
      this.dirtyAll = true;
    }
  }

  fullReset() {
    this.kitty.clearAll();
    this._initState();
    this.parser.reset();
    this.setTheme(this.theme);
    this.onTitle('');
  }

  softReset() {
    const m = this.modes;
    m.insert = false; m.origin = false; m.autowrap = true; m.cursorVisible = true;
    m.appCursor = false; m.appKeypad = false;
    this.buf.scrollTop = 0; this.buf.scrollBottom = this.rows - 1;
    this.attr = newAttr();
    this.buf.saved = null;
    this.charsets = ['us', 'us']; this.gl = 0;
    this.cursorStyle = 0;
  }

  csi(prefix, params, inter, f) {
    const b = this.buf;
    const p = (i, d) => { const v = params[i] ? params[i][0] : -1; return v < 0 ? d : v; };
    const n = (i) => Math.max(1, p(i, 1));
    if (prefix === '' && inter === '') {
      switch (f) {
        case '@': this._insertCells(b.lines[b.y], b.x, n(0)); b.wrapPending = false; break;
        case 'A': this._moveUp(n(0)); break;
        case 'B': case 'e': this._moveDown(n(0)); break;
        case 'C': case 'a': this._setX(b.x + n(0)); break;
        case 'D': this._setX(Math.min(b.x, this.cols - 1) - n(0)); break;
        case 'E': this._moveDown(n(0)); b.x = 0; break;
        case 'F': this._moveUp(n(0)); b.x = 0; break;
        case 'G': case '`': this._setX(n(0) - 1); break;
        case 'H': case 'f': {
          const top = this.modes.origin ? b.scrollTop : 0;
          this._setY(top + n(0) - 1);
          this._setX(n(1) - 1);
          break;
        }
        case 'I': for (let k = n(0); k > 0; k--) this.execute(0x09); break;
        case 'J': this.eraseInDisplay(p(0, 0)); break;
        case 'K': this.eraseInLine(p(0, 0)); break;
        case 'L': case 'M': {
          if (b.y < b.scrollTop || b.y > b.scrollBottom) break;
          if (f === 'L') this.scrollDown(n(0), b.y, b.scrollBottom);
          else this.scrollUp(n(0), b.y, b.scrollBottom);
          b.x = 0; b.wrapPending = false;
          break;
        }
        case 'P': {
          const l = b.lines[b.y];
          const k = Math.min(n(0), this.cols - b.x);
          this._fixWide(l, b.x);
          if (b.x + k < this.cols) this._fixWide(l, b.x + k);
          for (let x = b.x; x < this.cols - k; x++) l.copyCell(x, x + k);
          l.clear(this.attr.bg, this.cols - k, this.cols);
          b.wrapPending = false;
          break;
        }
        case 'S': this.scrollUp(n(0)); break;
        case 'T': if (params.length <= 1) this.scrollDown(n(0)); break;
        case 'X': {
          const l = b.lines[b.y];
          this._eraseLine(l, b.x, Math.min(this.cols, b.x + n(0)));
          b.wrapPending = false;
          break;
        }
        case 'Z': {
          for (let k = n(0); k > 0 && b.x > 0; k--) {
            let x = b.x - 1;
            while (x > 0 && !this.tabs[x]) x--;
            b.x = x;
          }
          b.wrapPending = false;
          break;
        }
        case 'b': {
          if (this.lastChar) for (let k = Math.min(n(0), 65535); k > 0; k--) this.putChar(this.lastChar);
          break;
        }
        case 'c': if (p(0, 0) === 0) this.reply('\x1b[?62;22c'); break;
        case 'd': this._setY((this.modes.origin ? b.scrollTop : 0) + n(0) - 1); break;
        case 'g': {
          const m = p(0, 0);
          if (m === 0) this.tabs[b.x] = 0;
          else if (m === 3) this.tabs.fill(0);
          break;
        }
        case 'h': case 'l': {
          const on = f === 'h';
          for (const q of params) {
            if (!q) continue;
            if (q[0] === 4) this.modes.insert = on;
            else if (q[0] === 20) this.modes.lnm = on;
          }
          break;
        }
        case 'm': this._sgr(params); break;
        case 'n': {
          const m = p(0, 0);
          if (m === 5) this.reply('\x1b[0n');
          else if (m === 6) {
            const row = b.y - (this.modes.origin ? b.scrollTop : 0) + 1;
            this.reply(`\x1b[${row};${Math.min(b.x, this.cols - 1) + 1}R`);
          }
          break;
        }
        case 'r': {
          const top = p(0, 1) - 1, bot = (p(1, this.rows) || this.rows) - 1;
          const t = Math.max(0, top), e = Math.min(this.rows - 1, bot < 0 ? this.rows - 1 : bot);
          if (t < e) {
            b.scrollTop = t; b.scrollBottom = e;
            b.x = 0; b.y = this.modes.origin ? t : 0; b.wrapPending = false;
          }
          break;
        }
        case 's': this._saveCursor(); break;
        case 'u': this._restoreCursor(); break;
        case 't': {
          const m = p(0, 0);
          const cw = Math.round(this.cellW), ch = Math.round(this.cellH);
          if (m === 14) this.reply(`\x1b[4;${ch * this.rows};${cw * this.cols}t`);
          else if (m === 16) this.reply(`\x1b[6;${ch};${cw}t`);
          else if (m === 18) this.reply(`\x1b[8;${this.rows};${this.cols}t`);
          break;
        }
      }
      return;
    }
    if (prefix === '' && inter === ' ' && f === 'q') { this.cursorStyle = p(0, 0); return; }
    if (prefix === '' && inter === '!' && f === 'p') { this.softReset(); return; }
    if (inter === '$' && f === 'p') {
      const mode = p(0, 0);
      const v = this._modeState(prefix === '?', mode);
      this.reply(`\x1b[${prefix === '?' ? '?' : ''}${mode};${v}$y`);
      return;
    }
    if (prefix === '?') {
      switch (f) {
        case 'h': case 'l':
          for (const q of params) if (q) this._decset(q[0], f === 'h');
          break;
        case 'J': this.eraseInDisplay(p(0, 0)); break;
        case 'K': this.eraseInLine(p(0, 0)); break;
        case 'n':
          if (p(0, 0) === 6) {
            const row = b.y - (this.modes.origin ? b.scrollTop : 0) + 1;
            this.reply(`\x1b[?${row};${Math.min(b.x, this.cols - 1) + 1}R`);
          }
          break;
        case 'u': this.reply('\x1b[?0u'); break;
      }
      return;
    }
    if (prefix === '>') {
      if (f === 'c') this.reply('\x1b[>1;10;0c');
      else if (f === 'q') this.reply('\x1bP>|wash(0.1)\x1b\\');
    }
  }

  _modeState(priv, mode) {
    const m = this.modes;
    let v = null;
    if (!priv) {
      if (mode === 4) v = m.insert; else if (mode === 20) v = m.lnm;
    } else {
      switch (mode) {
        case 1: v = m.appCursor; break;
        case 5: v = m.reverse; break;
        case 6: v = m.origin; break;
        case 7: v = m.autowrap; break;
        case 25: v = m.cursorVisible; break;
        case 9: v = m.mouse === 9; break;
        case 1000: case 1002: case 1003: v = m.mouse === mode; break;
        case 1004: v = m.focus; break;
        case 1006: v = m.mouseSGR; break;
        case 47: case 1047: case 1049: v = m.altScreen; break;
        case 2004: v = m.bracketedPaste; break;
        case 2026: v = m.sync; break;
        case 66: v = m.appKeypad; break;
      }
    }
    return v === null ? 0 : v ? 1 : 2;
  }

  _decset(mode, on) {
    const m = this.modes;
    switch (mode) {
      case 1: m.appCursor = on; break;
      case 5: m.reverse = on; this.dirtyAll = true; break;
      case 6: m.origin = on; this.buf.x = 0; this.buf.y = on ? this.buf.scrollTop : 0; this.buf.wrapPending = false; break;
      case 7: m.autowrap = on; if (!on) this.buf.wrapPending = false; break;
      case 9: case 1000: case 1002: case 1003: m.mouse = on ? mode : 0; break;
      case 1004: m.focus = on; break;
      case 1006: m.mouseSGR = on; break;
      case 25: m.cursorVisible = on; this.dirtyAll = true; break;
      case 47: this._setAlt(on); break;
      case 1047: this._setAlt(on, { clear: !on }); break;
      case 1048: if (on) this._saveCursor(); else this._restoreCursor(); break;
      case 1049: this._setAlt(on, { save: true, clear: true }); break;
      case 2004: m.bracketedPaste = on; break;
      case 2026: m.sync = on; if (!on) this.dirtyAll = true; break;
      case 66: m.appKeypad = on; break;
    }
  }

  _sgr(params) {
    const a = this.attr;
    if (params.length === 0) { a.fg = 0; a.bg = 0; a.fl = 0; a.uc = 0; return; }
    for (let i = 0; i < params.length; i++) {
      const q = params[i] || [0];
      const v = q[0] < 0 ? 0 : q[0];
      if (v === 38 || v === 48 || v === 58) {
        let color = null;
        if (q.length > 1) {
          if (q[1] === 5 && q.length > 2) color = PAL | (q[2] & 255);
          else if (q[1] === 2) {
            const c = q.length >= 6 ? q.slice(3, 6) : q.slice(2, 5);
            if (c.length === 3) color = RGB | ((c[0] & 255) << 16) | ((c[1] & 255) << 8) | (c[2] & 255);
          }
        } else {
          const t = params[i + 1] ? params[i + 1][0] : -1;
          if (t === 5) {
            const idx = params[i + 2] ? params[i + 2][0] : -1;
            if (idx >= 0) color = PAL | (idx & 255);
            i += 2;
          } else if (t === 2) {
            const c = [0, 0, 0];
            for (let k = 0; k < 3; k++) { const x = params[i + 2 + k] ? params[i + 2 + k][0] : 0; c[k] = x < 0 ? 0 : x; }
            color = RGB | ((c[0] & 255) << 16) | ((c[1] & 255) << 8) | (c[2] & 255);
            i += 4;
          }
        }
        if (color !== null) {
          if (v === 38) a.fg = color; else if (v === 48) a.bg = color; else a.uc = color;
        }
        continue;
      }
      if (v >= 30 && v <= 37) { a.fg = PAL | (v - 30); continue; }
      if (v >= 40 && v <= 47) { a.bg = PAL | (v - 40); continue; }
      if (v >= 90 && v <= 97) { a.fg = PAL | (v - 90 + 8); continue; }
      if (v >= 100 && v <= 107) { a.bg = PAL | (v - 100 + 8); continue; }
      switch (v) {
        case 0: a.fg = 0; a.bg = 0; a.fl = 0; a.uc = 0; break;
        case 1: a.fl |= BOLD; break;
        case 2: a.fl |= DIM; break;
        case 3: a.fl |= ITALIC; break;
        case 4: {
          const st = q.length > 1 ? Math.max(0, Math.min(5, q[1])) : 1;
          a.fl = (a.fl & ~UL_MASK) | (st << UL_SHIFT);
          break;
        }
        case 5: case 6: a.fl |= BLINK; break;
        case 7: a.fl |= INVERSE; break;
        case 8: a.fl |= HIDDEN; break;
        case 9: a.fl |= STRIKE; break;
        case 21: a.fl = (a.fl & ~UL_MASK) | (2 << UL_SHIFT); break;
        case 22: a.fl &= ~(BOLD | DIM); break;
        case 23: a.fl &= ~ITALIC; break;
        case 24: a.fl &= ~UL_MASK; break;
        case 25: a.fl &= ~BLINK; break;
        case 27: a.fl &= ~INVERSE; break;
        case 28: a.fl &= ~HIDDEN; break;
        case 29: a.fl &= ~STRIKE; break;
        case 39: a.fg = 0; break;
        case 49: a.bg = 0; break;
        case 53: a.fl |= OVERLINE; break;
        case 55: a.fl &= ~OVERLINE; break;
        case 59: a.uc = 0; break;
      }
    }
  }

  osc(s) {
    const semi = s.indexOf(';');
    const num = semi < 0 ? s : s.slice(0, semi);
    const rest = semi < 0 ? '' : s.slice(semi + 1);
    switch (num) {
      case '0': case '2': this.title = rest; this.onTitle(rest); break;
      case '1': break;
      case '4': {
        const parts = rest.split(';');
        for (let i = 0; i + 1 < parts.length; i += 2) {
          const idx = parseInt(parts[i], 10);
          if (!(idx >= 0 && idx < 256)) continue;
          if (parts[i + 1] === '?') this.reply(`\x1b]4;${idx};${xcolor(this.palette[idx])}\x1b\\`);
          else { const c = parseColor(parts[i + 1]); if (c !== null) { this.palette[idx] = c; this.dirtyAll = true; } }
        }
        break;
      }
      case '104': {
        const def = defaultPalette(this.theme.ansi || DEFAULT_THEME.ansi);
        if (!rest) this.palette = def;
        else for (const x of rest.split(';')) { const i = parseInt(x, 10); if (i >= 0 && i < 256) this.palette[i] = def[i]; }
        this.dirtyAll = true;
        break;
      }
      case '10': case '11': case '12': {
        let k = parseInt(num, 10);
        for (const part of rest.split(';')) {
          if (k > 12) break;
          if (part === '?') {
            const c = k === 10 ? this.fgColor : k === 11 ? this.bgColor : this.cursorColor;
            this.reply(`\x1b]${k};${xcolor(c)}\x1b\\`);
          } else {
            const c = parseColor(part);
            if (c !== null) {
              if (k === 10) this.fgColor = c; else if (k === 11) this.bgColor = c; else this.cursorColor = c;
              this.dirtyAll = true;
            }
          }
          k++;
        }
        break;
      }
      case '110': this.fgColor = parseColor(this.theme.foreground) ?? this.fgColor; this.dirtyAll = true; break;
      case '111': this.bgColor = parseColor(this.theme.background) ?? this.bgColor; this.dirtyAll = true; break;
      case '112': this.cursorColor = parseColor(this.theme.cursor) ?? this.cursorColor; this.dirtyAll = true; break;
      case '52': {
        const j = rest.indexOf(';');
        const data = j < 0 ? '' : rest.slice(j + 1);
        if (!data || data === '?') break;
        try {
          const bin = atob(data);
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          this.onClipboard(new TextDecoder().decode(bytes));
        } catch { /* ignore */ }
        break;
      }
      case '8': {
        const j = rest.indexOf(';');
        const url = j < 0 ? '' : rest.slice(j + 1);
        if (!url) { this.attr.ln = 0; break; }
        let id = this.linkIds.get(url);
        if (!id) {
          id = this.nextLink++;
          this.linkIds.set(url, id);
          this.links.set(id, url);
          if (this.links.size > 10000) { // forget the oldest links
            const [oid, ourl] = this.links.entries().next().value;
            this.links.delete(oid); this.linkIds.delete(ourl);
          }
        }
        this.attr.ln = id;
        break;
      }
    }
  }

  dcs(s) {
    if (s.startsWith('$q')) {
      const q = s.slice(2);
      const b = this.buf;
      let r = null;
      if (q === 'm') r = '0m';
      else if (q === ' q') r = `${this.cursorStyle || 1} q`;
      else if (q === 'r') r = `${b.scrollTop + 1};${b.scrollBottom + 1}r`;
      this.reply(r === null ? '\x1bP0$r\x1b\\' : `\x1bP1$r${r}\x1b\\`);
    } else if (s.startsWith('+q')) {
      this.reply('\x1bP0+r\x1b\\');
    }
  }

  apc(s) {
    if (s.length > 0 && s[0] === 'G') this.kitty.handle(s.slice(1));
  }
}
