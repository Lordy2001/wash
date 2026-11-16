// Terminal: glues the screen model, the canvas renderer and browser input.
//
//   const t = new Terminal(el, {fontFamily, fontSize, scrollback, theme});
//   t.onData = (u8) => ...; t.onResize = (cols, rows) => ...;
//   t.write(u8 | string);

import { Screen, DEFAULT_THEME } from './screen.js';
import { CanvasRenderer } from './renderer.js';
import { encodeKey, encodeMouse, encodePaste } from './input.js';

const DEFAULT_FONT = '"JetBrains Mono", "Fira Code", "Cascadia Code", "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", "Liberation Mono", monospace';
const SYNC_TIMEOUT = 150;
const WORD_CHARS = /[\p{L}\p{N}_\-.\/~:@%+#?=&]/u;

async function inflate(bytes) {
  const ds = new DecompressionStream('deflate');
  const stream = new Blob([bytes]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Default kitty image decoder: bytes -> ImageBitmap. */
export async function browserImageDecoder(img, bytes, { compressed, format, width, height }) {
  if (compressed) bytes = await inflate(bytes);
  if (format === 100) {
    const bm = await createImageBitmap(new Blob([bytes], { type: 'image/png' }));
    return { bitmap: bm, width: bm.width, height: bm.height };
  }
  const bpp = format === 24 ? 3 : 4;
  if (bytes.length < width * height * bpp) throw new Error('short image data');
  const rgba = new Uint8ClampedArray(width * height * 4);
  if (bpp === 4) rgba.set(bytes.subarray(0, width * height * 4));
  else {
    for (let i = 0, j = 0; i < width * height; i++, j += 3) {
      rgba[i * 4] = bytes[j]; rgba[i * 4 + 1] = bytes[j + 1]; rgba[i * 4 + 2] = bytes[j + 2]; rgba[i * 4 + 3] = 255;
    }
  }
  const bm = await createImageBitmap(new ImageData(rgba, width, height));
  return { bitmap: bm, width, height };
}

export class Terminal {
  constructor(container, options = {}) {
    this.opts = {
      fontFamily: DEFAULT_FONT, fontSize: 15, scrollback: 5000, copyOnSelect: false, ctrlCopyPaste: false,
      ...options,
      theme: { ...DEFAULT_THEME, ...(options.theme || {}) },
    };
    this.onData = null;
    this.onResize = null;
    this.onTitle = null;
    this.onBell = null;
    this.container = container;
    if (getComputedStyle(container).position === 'static') container.style.position = 'relative';
    container.style.overflow = 'hidden';

    const s = new Screen(80, 24, { scrollback: this.opts.scrollback, decoder: browserImageDecoder, theme: this.opts.theme });
    this.screen = s;
    s.onReply = (str) => this._emit(str);
    s.onTitle = (t) => this.onTitle && this.onTitle(t);
    s.onBell = () => this.onBell && this.onBell();
    s.onClipboard = (text) => { navigator.clipboard?.writeText(text).catch(() => {}); };
    s.onImage = () => this._schedule();

    this.renderer = new CanvasRenderer(container, s, { fontFamily: this.opts.fontFamily, fontSize: this.opts.fontSize });
    this.canvas = this.renderer.canvas;

    const ta = document.createElement('textarea');
    ta.setAttribute('autocorrect', 'off');
    ta.setAttribute('autocapitalize', 'off');
    ta.setAttribute('autocomplete', 'off');
    ta.setAttribute('spellcheck', 'false');
    ta.setAttribute('aria-label', 'Terminal input');
    ta.setAttribute('tabindex', '0');
    Object.assign(ta.style, {
      position: 'absolute', left: '0', top: '0', width: '2px', height: '1em', opacity: '0',
      padding: '0', border: '0', margin: '0', resize: 'none', overflow: 'hidden', outline: 'none',
      whiteSpace: 'nowrap', pointerEvents: 'none', color: 'transparent', background: 'transparent', zIndex: '1',
    });
    container.appendChild(ta);
    this.textarea = ta;

    this.utf8 = new TextDecoder('utf-8');
    this.enc = new TextEncoder();
    this.cols = s.cols;
    this.rows = s.rows;
    this._raf = 0;
    this._syncStart = 0;
    this._composing = false;
    this._sel = null; // {anchor, head, mode}
    this._mouseDown = -1;
    this._lastMouseCell = '';
    this._wheelAcc = 0;
    this._disposed = false;
    this._fixed = null;                  // {cols, rows}: draw this grid (shared session, watching)
    this._font = this.opts.fontSize;     // font size in use (smaller than opts.fontSize when fixed)

    this._bind();
    this._ro = new ResizeObserver(() => this.fit());
    this._ro.observe(container);
    this.fit(true);
    queueMicrotask(() => { if (!this._disposed && this.onResize) this.onResize(this.cols, this.rows); });
    this._schedule();
  }

  // ---- public API --------------------------------------------------------------

  write(data) {
    if (this._disposed) return;
    const str = typeof data === 'string' ? data : this.utf8.decode(data, { stream: true });
    if (!str) return;
    this.screen.write(str);
    if (this.screen.viewOffset) { this.screen.viewOffset = 0; this.screen.dirtyAll = true; }
    this._schedule();
  }

  fit(silent = false) {
    const w = this.container.clientWidth, h = this.container.clientHeight;
    if (!w || !h) return;
    this.renderer.resizeCanvas(w, h);
    let cols, rows;
    if (this._fixed) {
      ({ cols, rows } = this._fixed);
      this._fitFont(w, h, cols, rows);
    } else {
      this._setFont(this.opts.fontSize);
      ({ cols, rows } = this.renderer.gridSize(w, h));
    }
    if (cols !== this.screen.cols || rows !== this.screen.rows) {
      this.screen.resize(cols, rows);
      this._clearSelection();
    }
    const changed = cols !== this.cols || rows !== this.rows;
    this.cols = cols; this.rows = rows;
    if (changed && !silent && !this._fixed && this.onResize) this.onResize(cols, rows);
    this._schedule();
  }

  /**
   * Draw a fixed grid (cols x rows) instead of fitting the grid to the
   * container: the font shrinks until it fits (never grows past fontSize).
   * null goes back to fitting. Used while watching a shared session, whose
   * size the controlling device sets. onResize is not called while fixed.
   */
  setFixedSize(size) {
    const next = size && size.cols > 0 && size.rows > 0 ? { cols: size.cols, rows: size.rows } : null;
    if (JSON.stringify(next) === JSON.stringify(this._fixed)) return;
    this._fixed = next;
    this.fit();
  }

  _setFont(px) {
    if (px === this._font) return;
    this._font = px;
    this.renderer.setFont(this.opts.fontFamily, px);
  }

  _fitFont(w, h, cols, rows) {
    const max = this.opts.fontSize;
    // estimate from the current cell size, then step down until it fits
    const cw = this.renderer.s.cellW / this._font, ch = this.renderer.s.cellH / this._font;
    let px = Math.min(max, Math.floor(Math.min(w / (cols * cw), h / (rows * ch)) * 2) / 2 + 0.5);
    px = Math.max(4, px);
    this._setFont(px);
    for (let i = 0; i < 40 && px > 4; i++) {
      const g = this.renderer.gridSize(w, h);
      if (g.cols >= cols && g.rows >= rows) break;
      px = Math.max(4, px - 0.5);
      this._setFont(px);
    }
  }

  focus() { this.textarea.focus({ preventScroll: true }); }
  blur() { this.textarea.blur(); }

  reset() {
    this.screen.fullReset();
    this._clearSelection();
    this._schedule();
  }

  setOptions(o = {}) {
    if (o.fontFamily || o.fontSize) {
      if (o.fontFamily) this.opts.fontFamily = o.fontFamily;
      if (o.fontSize) this.opts.fontSize = o.fontSize;
      this._font = this.opts.fontSize;
      this.renderer.setFont(this.opts.fontFamily, this.opts.fontSize);
      this.fit();
    }
    if (o.theme) {
      this.opts.theme = { ...this.opts.theme, ...o.theme };
      this.screen.setTheme(this.opts.theme);
    }
    if (o.copyOnSelect !== undefined) this.opts.copyOnSelect = o.copyOnSelect;
    if (o.ctrlCopyPaste !== undefined) this.opts.ctrlCopyPaste = o.ctrlCopyPaste;
    this._schedule();
  }

  /** Currently selected text ('' if none). */
  getSelection() {
    const r = this._selRange();
    return r ? this.screen.getText(r.start, r.end) : '';
  }

  dispose() {
    this._disposed = true;
    this._ro.disconnect();
    if (this._raf) cancelAnimationFrame(this._raf);
    for (const [t, ev, fn, opt] of this._listeners) t.removeEventListener(ev, fn, opt);
    this.renderer.dispose();
    this.textarea.remove();
  }

  // ---- internals ---------------------------------------------------------------

  _emit(str) {
    if (this.onData && str) this.onData(this.enc.encode(str));
  }

  _schedule() {
    if (this._raf || this._disposed) return;
    this._raf = requestAnimationFrame(() => { this._raf = 0; this._render(); });
  }

  _render() {
    const s = this.screen;
    if (s.modes.sync) {
      const now = performance.now();
      if (!this._syncStart) this._syncStart = now;
      if (now - this._syncStart < SYNC_TIMEOUT) { this._schedule(); return; }
    }
    this._syncStart = 0;
    this.renderer.selection = this._selRange();
    this.renderer.render(false);
    const b = s.buf;
    const p = this.renderer.cellPos(b.x, b.y);
    this.textarea.style.left = p.x + 'px';
    this.textarea.style.top = p.y + 'px';
    this.textarea.style.height = p.h + 'px';
  }

  _on(target, ev, fn, opt) {
    target.addEventListener(ev, fn, opt);
    (this._listeners ||= []).push([target, ev, fn, opt]);
  }

  _bind() {
    const ta = this.textarea;
    this._on(ta, 'keydown', (e) => this._keydown(e));
    this._on(ta, 'compositionstart', () => { this._composing = true; });
    this._on(ta, 'compositionend', (e) => {
      this._composing = false;
      if (e.data) this._input(e.data);
      ta.value = '';
    });
    this._on(ta, 'input', (e) => {
      if (this._composing || e.isComposing) return;
      if (e.inputType === 'insertText' || e.inputType === 'insertReplacementText') {
        if (e.data) this._input(e.data);
      } else if (e.inputType === 'deleteContentBackward') {
        this._input('\x7f');
      } else if (e.inputType === 'insertLineBreak') {
        this._input('\r');
      }
      ta.value = '';
    });
    this._on(ta, 'paste', (e) => {
      e.preventDefault();
      const text = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
      if (text) this._input(encodePaste(text, this.screen.modes.bracketedPaste));
    });
    this._on(ta, 'copy', (e) => {
      const t = this.getSelection();
      if (!t) return;
      e.preventDefault();
      e.clipboardData.setData('text/plain', t);
    });
    this._on(ta, 'focus', () => {
      this.renderer.focused = true;
      if (this.screen.modes.focus) this._emit('\x1b[I');
      this._schedule();
    });
    this._on(ta, 'blur', () => {
      this.renderer.focused = false;
      if (this.screen.modes.focus) this._emit('\x1b[O');
      this._schedule();
    });

    const c = this.canvas;
    this._on(c, 'mousedown', (e) => this._mousedown(e));
    this._on(window, 'mousemove', (e) => this._mousemove(e));
    this._on(window, 'mouseup', (e) => this._mouseup(e));
    this._on(c, 'wheel', (e) => this._wheel(e), { passive: false });
    this._on(c, 'contextmenu', (e) => { if (this._mouseReporting(e)) e.preventDefault(); });
    this._on(c, 'touchstart', () => this.focus(), { passive: true });
  }

  _input(str) {
    this._snapToBottom();
    this._emit(str);
  }

  _snapToBottom() {
    if (this.screen.viewOffset) { this.screen.viewOffset = 0; this.screen.dirtyAll = true; this._schedule(); }
  }

  _keydown(e) {
    if (e.isComposing || e.keyCode === 229 || this._composing) return;
    const s = this.screen;
    if (e.ctrlKey && e.shiftKey && e.code === 'KeyC') {
      e.preventDefault();
      const t = this.getSelection();
      if (t) navigator.clipboard?.writeText(t).catch(() => {});
      return;
    }
    if (e.ctrlKey && e.shiftKey && e.code === 'KeyV') return; // let the paste event fire
    if (this.opts.ctrlCopyPaste && e.ctrlKey && !e.shiftKey && !e.altKey && !e.metaKey) {
      // Ctrl+C copies when text is selected (else it is ^C as usual);
      // Ctrl+V pastes (the literal-next ^V is lost; Ctrl+Shift+V also pastes)
      if (e.code === 'KeyC') {
        const t = this.getSelection();
        if (t) {
          e.preventDefault();
          navigator.clipboard?.writeText(t).catch(() => {});
          this._clearSelection();
          return;
        }
      } else if (e.code === 'KeyV') {
        return; // no preventDefault: the browser fires 'paste' on the textarea
      }
    }
    if (e.metaKey && (e.code === 'KeyC' || e.code === 'KeyV')) return; // macOS Cmd+C / Cmd+V
    if (e.shiftKey && !e.ctrlKey && !e.altKey && !s.modes.altScreen) {
      const page = Math.max(1, s.rows - 1);
      let d = 0;
      if (e.key === 'PageUp') d = page; else if (e.key === 'PageDown') d = -page;
      else if (e.key === 'Home') d = s.buf.sbLength; else if (e.key === 'End') d = -s.buf.sbLength;
      if (d) { e.preventDefault(); s.scrollView(d); this._schedule(); return; }
    }
    const altGraph = typeof e.getModifierState === 'function' && e.getModifierState('AltGraph');
    const seq = encodeKey({
      key: e.key, code: e.code, ctrlKey: e.ctrlKey && !altGraph, altKey: e.altKey && !altGraph,
      shiftKey: e.shiftKey, metaKey: e.metaKey, altGraph,
    }, s.modes);
    if (seq === null) return;
    e.preventDefault();
    if (this._sel) this._clearSelection();
    this._input(seq);
  }

  // ---- mouse ---------------------------------------------------------------------

  _mouseReporting(e) { return this.screen.modes.mouse !== 0 && !e.shiftKey; }

  _report(button, cell, o) {
    const seq = encodeMouse(button, cell.col, cell.row, o, this.screen.modes);
    if (seq) this._emit(seq);
  }

  _mods(e) { return { shift: e.shiftKey, alt: e.altKey, ctrl: e.ctrlKey }; }

  _mousedown(e) {
    e.preventDefault();
    this.focus();
    const cell = this.renderer.cellAt(e.clientX, e.clientY);
    if (this._mouseReporting(e)) {
      if (e.button > 2) return;
      this._mouseDown = e.button;
      this._lastMouseCell = `${cell.col},${cell.row}`;
      this._report(e.button, cell, this._mods(e));
      return;
    }
    if (e.button !== 0) return;
    const pos = this._abs(cell);
    const mode = e.detail >= 3 ? 'line' : e.detail === 2 ? 'word' : 'char';
    this._clickStart = { x: e.clientX, y: e.clientY, link: (e.ctrlKey || e.metaKey) ? this._linkAt(pos) : null };
    this._sel = { anchor: pos, head: pos, mode, active: true, moved: mode !== 'char' };
    this._mouseDown = 0;
    this.screen.dirtyAll = true;
    this._schedule();
  }

  _abs(cell) {
    const col = cell.half && cell.col < this.screen.cols ? cell.col + 1 : cell.col;
    return { abs: this.screen.viewTop + cell.row, col: Math.min(col, this.screen.cols), cell: cell.col };
  }

  _mousemove(e) {
    if (this._mouseDown < 0 && !(this.screen.modes.mouse === 1003 && e.target === this.canvas)) return;
    const cell = this.renderer.cellAt(e.clientX, e.clientY);
    if (this._sel && this._sel.active) {
      // autoscroll when dragging past the edges
      if (cell.rawRow < 0) this.screen.scrollView(1);
      else if (cell.rawRow >= this.screen.rows) this.screen.scrollView(-1);
      const pos = this._abs(cell);
      if (pos.abs !== this._sel.head.abs || pos.col !== this._sel.head.col) {
        this._sel.head = pos;
        this._sel.moved = true;
        this.screen.dirtyAll = true;
        this._schedule();
      }
      return;
    }
    const m = this.screen.modes.mouse;
    if (m === 1003 || (m === 1002 && this._mouseDown >= 0)) {
      const key = `${cell.col},${cell.row}`;
      if (key === this._lastMouseCell) return;
      this._lastMouseCell = key;
      this._report(this._mouseDown >= 0 ? this._mouseDown : 3, cell, { ...this._mods(e), motion: true });
    }
  }

  _mouseup(e) {
    if (this._mouseDown < 0) return;
    const cell = this.renderer.cellAt(e.clientX, e.clientY);
    if (this._sel && this._sel.active) {
      this._sel.active = false;
      const cs = this._clickStart;
      if (!this._sel.moved) {
        this._clearSelection();
        if (cs && cs.link) window.open(cs.link, '_blank', 'noopener,noreferrer');
      } else if (this.opts.copyOnSelect) {
        const t = this.getSelection();
        if (t) navigator.clipboard?.writeText(t).catch(() => {});
      }
      this._mouseDown = -1;
      return;
    }
    const m = this.screen.modes.mouse;
    if (m !== 0 && m !== 9) this._report(this._mouseDown, cell, { ...this._mods(e), release: true });
    this._mouseDown = -1;
  }

  _wheel(e) {
    e.preventDefault();
    const s = this.screen;
    let dy = e.deltaY;
    if (e.deltaMode === 1) dy *= this.renderer.ch / this.renderer.dpr;
    else if (e.deltaMode === 2) dy *= s.rows * this.renderer.ch / this.renderer.dpr;
    this._wheelAcc += dy;
    const unit = this.renderer.ch / this.renderer.dpr;
    const lines = Math.trunc(this._wheelAcc / unit);
    if (!lines) return;
    this._wheelAcc -= lines * unit;
    if (this._mouseReporting(e)) {
      const cell = this.renderer.cellAt(e.clientX, e.clientY);
      const n = Math.min(Math.abs(lines), 10);
      for (let i = 0; i < n; i++) this._report(lines < 0 ? 64 : 65, cell, this._mods(e));
      return;
    }
    if (s.modes.altScreen) {
      const key = lines < 0 ? 'A' : 'B';
      const seq = (s.modes.appCursor ? '\x1bO' : '\x1b[') + key;
      const n = Math.min(Math.abs(lines), 30);
      this._emit(seq.repeat(n));
      return;
    }
    s.scrollView(-lines);
    this._schedule();
  }

  _linkAt(pos) {
    const l = this.screen.lineAt(pos.abs);
    if (!l || pos.cell >= l.cols) return null;
    const id = l.ln[pos.cell];
    return id ? this.screen.links.get(id) || null : null;
  }

  // ---- selection -------------------------------------------------------------------

  _clearSelection() {
    if (this._sel) { this._sel = null; this.screen.dirtyAll = true; this._schedule(); }
  }

  _selRange() {
    const sel = this._sel;
    if (!sel || !sel.moved) return null;
    let a = sel.anchor, b = sel.head;
    if (a.abs > b.abs || (a.abs === b.abs && a.col > b.col)) [a, b] = [b, a];
    let start = { abs: a.abs, col: a.col }, end = { abs: b.abs, col: b.col };
    if (sel.mode === 'word') {
      start = this._wordEdge(a.abs, Math.min(a.cell ?? a.col, this.screen.cols - 1), -1);
      end = this._wordEdge(b.abs, Math.min(b.cell ?? b.col, this.screen.cols - 1), 1);
    } else if (sel.mode === 'line') {
      start = { abs: a.abs, col: 0 };
      end = { abs: b.abs, col: this.screen.cols };
    }
    if (start.abs === end.abs && start.col >= end.col) return null;
    return { start, end };
  }

  _wordEdge(abs, col, dir) {
    const l = this.screen.lineAt(abs);
    if (!l) return { abs, col: dir < 0 ? 0 : this.screen.cols };
    const isWord = (i) => i >= 0 && i < l.cols && (l.wd[i] === 0 || WORD_CHARS.test(l.ch[i] || ' '));
    if (!isWord(col)) return { abs, col: dir < 0 ? col : col + 1 };
    let i = col;
    if (dir < 0) { while (i > 0 && isWord(i - 1)) i--; return { abs, col: i }; }
    while (i < l.cols - 1 && isWord(i + 1)) i++;
    return { abs, col: i + 1 };
  }
}
