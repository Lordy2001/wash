// Smoke test of Terminal + CanvasRenderer against a minimal fake DOM, to
// catch runtime errors in the drawing and input paths without a browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const calls = { fillText: 0, drawImage: 0, fillRect: 0 };

function ctx2d() {
  return new Proxy({}, {
    get(t, k) {
      if (k in t) return t[k];
      if (k === 'measureText') {
        // metrics scale with the font (15px: 9 wide, 18 high)
        const fs = Number(/(\d+(?:\.\d+)?)px/.exec(t.font || '15px')?.[1] || 15);
        return () => ({ width: fs * 9 / 15, fontBoundingBoxAscent: fs * 14 / 15, fontBoundingBoxDescent: fs * 4 / 15 });
      }
      return (...a) => { if (k in calls) calls[k]++; };
    },
    set(t, k, v) { t[k] = v; return true; },
  });
}

class El {
  constructor(tag) {
    this.tag = tag; this.style = {}; this.children = []; this.listeners = {}; this.attrs = {};
    this.width = 0; this.height = 0; this.clientWidth = 900; this.clientHeight = 360; this.value = '';
  }
  appendChild(c) { this.children.push(c); c.parent = this; return c; }
  remove() {}
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(ev, fn) { (this.listeners[ev] ||= []).push(fn); }
  removeEventListener() {}
  dispatch(ev, e) { for (const fn of this.listeners[ev] || []) fn({ preventDefault() {}, ...e }); }
  getContext() { return (this._ctx ||= ctx2d()); }
  getBoundingClientRect() { return { left: 0, top: 0, width: 900, height: 360 }; }
  focus() {} blur() {}
}

let rafQ = [];
globalThis.document = { createElement: (t) => new El(t) };
globalThis.window = new El('window');
window.devicePixelRatio = 1;
window.open = () => {};
globalThis.getComputedStyle = () => ({ position: 'static' });
globalThis.ResizeObserver = class { observe() {} disconnect() {} };
globalThis.requestAnimationFrame = (fn) => { rafQ.push(fn); return rafQ.length; };
globalThis.cancelAnimationFrame = () => {};
globalThis.createImageBitmap = async () => ({ width: 10, height: 10, close() {} });
globalThis.ImageData = class { constructor(d, w, h) { this.data = d; this.width = w; this.height = h; } };
if (!globalThis.navigator) globalThis.navigator = {};
const flush = () => { const q = rafQ; rafQ = []; q.forEach((f) => f()); };

const { Terminal } = await import('../../static/term/terminal.js');

test('terminal renders, resizes and encodes input', async () => {
  const el = new El('div');
  const t = new Terminal(el, { fontSize: 15 });
  const sent = [];
  let size = null;
  t.onData = (u8) => sent.push(new TextDecoder().decode(u8));
  t.onResize = (c, r) => { size = [c, r]; };
  await Promise.resolve();
  assert.deepEqual(size, [100, 20]); // 900/9, 360/18
  t.write(new TextEncoder().encode('hi \x1b[1;31mred\x1b[0m ┌─┐ ▄█ 中😀\r\n\x1b[4:3mcurly\x1b[0m'));
  // raw RGBA 2x2 image
  const px = Buffer.from(new Uint8Array(16).fill(200)).toString('base64');
  t.write(`\x1b_Ga=T,f=32,s=2,v=2,c=2,r=1;${px}\x1b\\`);
  await new Promise((r) => setTimeout(r, 5));
  flush();
  assert.ok(calls.fillText > 5, 'text drawn');
  assert.ok(calls.drawImage >= 1, 'image drawn');
  // a split UTF-8 sequence across writes
  const bytes = new TextEncoder().encode('é');
  t.write(bytes.subarray(0, 1));
  t.write(bytes.subarray(1));
  assert.equal(t.screen.buf.lines[1].text().includes('é'), true);
  // typing
  const ta = t.textarea;
  ta.dispatch('keydown', { key: 'a', code: 'KeyA' });
  ta.dispatch('keydown', { key: 'ArrowUp', code: 'ArrowUp' });
  ta.dispatch('keydown', { key: 'c', code: 'KeyC', ctrlKey: true });
  ta.dispatch('paste', { clipboardData: { getData: () => 'x\ny' } });
  assert.deepEqual(sent, ['a', '\x1b[A', '\x03', 'x\ry']);
  // terminal query reply goes to onData (curly + 2-col image + é)
  t.write('\x1b[6n');
  assert.equal(sent.at(-1), '\x1b[2;9R');
  // resize
  el.clientWidth = 450;
  t.fit();
  assert.deepEqual(size, [50, 20]);
  flush();
  // selection by drag
  t.canvas.dispatch('mousedown', { button: 0, detail: 1, clientX: 1, clientY: 1 });
  window.dispatch('mousemove', { clientX: 20, clientY: 1 });
  window.dispatch('mouseup', { clientX: 20, clientY: 1 });
  assert.equal(t.getSelection(), 'hi');
  flush();
  // mouse reporting
  t.write('\x1b[?1000h\x1b[?1006h');
  t.canvas.dispatch('mousedown', { button: 0, detail: 1, clientX: 10, clientY: 20 });
  window.dispatch('mouseup', { button: 0, clientX: 10, clientY: 20 });
  assert.deepEqual(sent.slice(-2), ['\x1b[<0;2;2M', '\x1b[<0;2;2m']);
  // sync output defers rendering
  t.write('\x1b[?2026h');
  const before = calls.fillText;
  t.write('more text');
  flush();
  assert.equal(calls.fillText, before);
  t.write('\x1b[?2026l');
  flush();
  assert.ok(calls.fillText > before);
  t.dispose();
});

test('fixed grid (watching a shared session): font shrinks to fit, never grows', async () => {
  const el = new El('div'); // 900 x 360
  const t = new Terminal(el, { fontSize: 15 });
  let resized = 0;
  t.onResize = () => { resized++; };
  await Promise.resolve();
  resized = 0;
  t.setFixedSize({ cols: 200, rows: 50 }); // a big desktop session watched on a small screen
  assert.equal(t.cols, 200); assert.equal(t.rows, 50);
  assert.ok(t._font < 15, `font ${t._font}`);
  const g = t.renderer.gridSize(900, 360);
  assert.ok(g.cols >= 200 && g.rows >= 50, `grid ${g.cols}x${g.rows} holds 200x50`);
  t.setFixedSize({ cols: 40, rows: 12 }); // a phone session watched on a big screen
  assert.equal(t._font, 15, 'never larger than the chosen font');
  assert.equal(t.cols, 40);
  assert.equal(resized, 0, 'a fixed grid is not reported as our size');
  t.setFixedSize(null); // took control: fit this screen again
  assert.equal(t.cols, 100); assert.equal(t.rows, 20);
  assert.equal(resized, 1);
  t.dispose();
});

test('on-screen keyboard backspace (Android): a delete in the textarea is DEL', async () => {
  const el = new El('div');
  const t = new Terminal(el, { fontSize: 15 });
  const sent = [];
  t.onData = (u8) => sent.push(new TextDecoder().decode(u8));
  const ta = t.textarea;
  assert.ok(ta.value.length > 0, 'the textarea keeps text to delete');
  // Gboard: keydown is keyCode 229 (ignored), then the IME deletes a character
  ta.dispatch('keydown', { key: 'Unidentified', keyCode: 229 });
  ta.value = ta.value.slice(0, -1);
  ta.dispatch('input', { inputType: 'deleteContentBackward' });
  ta.value = ta.value.slice(0, -1);
  ta.dispatch('input', { inputType: 'deleteContentBackward' });
  ta.dispatch('input', { inputType: 'deleteWordBackward' });
  ta.dispatch('input', { inputType: 'insertText', data: 'x' });
  assert.deepEqual(sent, ['\x7f', '\x7f', '\x17', 'x']);
  assert.equal(ta.value, '  ', 'refilled after each edit');
  t.dispose();
});
