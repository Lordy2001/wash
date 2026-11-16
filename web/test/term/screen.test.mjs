import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Screen, PAL, RGB, BOLD, UL_SHIFT } from '../../static/term/screen.js';
import { Parser } from '../../static/term/parser.js';
import { encodeKey, encodeMouse, encodePaste } from '../../static/term/input.js';
import { wcwidth } from '../../static/term/wcwidth.js';

function mk(cols = 10, rows = 5, opts = {}) {
  const s = new Screen(cols, rows, { scrollback: 100, ...opts });
  s.replies = [];
  s.onReply = (r) => s.replies.push(r);
  return s;
}
const row = (s, y) => s.buf.lines[y].text().replace(/\s+$/, '');

test('parser splits CSI params, subparams and prefixes', () => {
  const got = [];
  const p = new Parser({
    print: (str, a, b) => got.push(['print', str.slice(a, b)]),
    execute: (c) => got.push(['exec', c]),
    esc: (i, f) => got.push(['esc', i, f]),
    csi: (pre, params, i, f) => got.push(['csi', pre, JSON.stringify(params), i, f]),
    osc: (x) => got.push(['osc', x]),
    dcs: (x) => got.push(['dcs', x]),
    apc: (x) => got.push(['apc', x]),
  });
  p.parse('ab\x1b[1;2H\x1b[?25l\x1b[38:2::1:2:3m\x1b]0;ti');
  p.parse('tle\x07\x1b_Gx\x1b');
  p.parse('\\\x1b(0\r\x1b[ q');
  assert.deepEqual(got, [
    ['print', 'ab'],
    ['csi', '', '[[1],[2]]', '', 'H'],
    ['csi', '?', '[[25]]', '', 'l'],
    ['csi', '', '[[38,2,-1,1,2,3]]', '', 'm'],
    ['osc', '0;title'],
    ['apc', 'Gx'],
    ['esc', '(', '0'],
    ['exec', 13],
    ['csi', '', '[]', ' ', 'q'],
  ]);
});

test('print, wrap with pending-wrap semantics', () => {
  const s = mk(5, 3);
  s.write('abcde');
  assert.equal(s.buf.x, 4);
  assert.equal(s.buf.wrapPending, true);
  s.write('f');
  assert.equal(row(s, 0), 'abcde');
  assert.equal(row(s, 1), 'f');
  assert.equal(s.buf.lines[0].wrapped, true);
  s.write('\x1b[?7l\x1b[2;1Hxxxxxxxyz');
  assert.equal(row(s, 1), 'xxxxz');
});

test('cursor movement and CUP clamping', () => {
  const s = mk(10, 5);
  s.write('\x1b[3;4H');
  assert.deepEqual([s.buf.x, s.buf.y], [3, 2]);
  s.write('\x1b[2A\x1b[10C');
  assert.deepEqual([s.buf.x, s.buf.y], [9, 0]);
  s.write('\x1b[99;99H');
  assert.deepEqual([s.buf.x, s.buf.y], [9, 4]);
  s.write('\x1b[G\x1b[3d');
  assert.deepEqual([s.buf.x, s.buf.y], [0, 2]);
  s.write('\r\x1b[2C\x08');
  assert.equal(s.buf.x, 1);
  s.write('\x1b[1;1H\tX');
  assert.equal(s.buf.lines[0].ch[8], 'X');
});

test('scrolling into scrollback and scroll regions', () => {
  const s = mk(5, 3);
  s.write('1\r\n2\r\n3\r\n4');
  assert.equal(row(s, 0), '2');
  assert.equal(row(s, 2), '4');
  assert.equal(s.buf.sbLength, 1);
  assert.equal(s.lineAt(s.buf.top - 1).text().trim(), '1');
  // region rows 2..3 of a 4-row screen
  const t = mk(5, 4);
  t.write('a\r\nb\r\nc\r\nd\x1b[2;3r\x1b[3;1H\n');
  assert.deepEqual([0, 1, 2, 3].map((y) => row(t, y)), ['a', 'c', '', 'd']);
  assert.equal(t.buf.sbLength, 0);
  t.write('\x1b[2;1H\x1bM');
  assert.deepEqual([0, 1, 2, 3].map((y) => row(t, y)), ['a', '', 'c', 'd']);
});

test('IL/DL/ICH/DCH/ECH', () => {
  const s = mk(6, 3);
  s.write('abcdef\r\n123456\x1b[1;3H\x1b[2@');
  assert.equal(row(s, 0), 'ab  cd');
  s.write('\x1b[2P');
  assert.equal(row(s, 0), 'abcd');
  s.write('\x1b[1X');
  assert.equal(row(s, 0), 'ab d');
  s.write('\x1b[1;1H\x1b[L');
  assert.equal(row(s, 0), '');
  assert.equal(row(s, 1), 'ab d');
  s.write('\x1b[M');
  assert.equal(row(s, 0), 'ab d');
});

test('ED / EL', () => {
  const s = mk(5, 3);
  s.write('aaaaa\r\nbbbbb\r\nccccc\x1b[2;3H\x1b[K');
  assert.equal(row(s, 1), 'bb');
  s.write('\x1b[1K');
  assert.equal(row(s, 1), '');
  s.write('\x1b[J');
  assert.equal(row(s, 2), '');
  assert.equal(row(s, 0), 'aaaaa');
  s.write('\x1b[1J');
  assert.equal(row(s, 0), '');
  s.write('x\x1b[2J');
  assert.ok([0, 1, 2].every((y) => row(s, y) === ''));
});

test('alternate screen keeps the main screen and cursor', () => {
  const s = mk(5, 3);
  s.write('main\x1b[?1049h');
  assert.equal(row(s, 0), '');
  s.write('alt');
  s.write('\x1b[?1049l');
  assert.equal(row(s, 0), 'main');
  assert.equal(s.buf.x, 4);
  assert.equal(s.modes.altScreen, false);
});

test('SGR colors: 16, 256, truecolor in ; and : forms, underline styles', () => {
  const s = mk(10, 2);
  s.write('\x1b[1;31ma\x1b[38;5;200mb\x1b[38;2;1;2;3mc\x1b[48:2::4:5:6md\x1b[38:2:7:8:9me\x1b[4:3mf\x1b[0mg');
  const l = s.buf.lines[0];
  assert.equal(l.fg[0], PAL | 1);
  assert.ok(l.fl[0] & BOLD);
  assert.equal(l.fg[1], PAL | 200);
  assert.equal(l.fg[2], RGB | 0x010203);
  assert.equal(l.bg[3], RGB | 0x040506);
  assert.equal(l.fg[4], RGB | 0x070809);
  assert.equal((l.fl[5] >> UL_SHIFT) & 7, 3);
  assert.equal(l.fg[6], 0);
  assert.equal(l.bg[6], 0);
  assert.equal(l.fl[6], 0);
});

test('wide characters and combining marks', () => {
  assert.equal(wcwidth(0x4e2d), 2);
  assert.equal(wcwidth(0x1f600), 2);
  assert.equal(wcwidth(0x301), 0);
  const s = mk(5, 2);
  s.write('中é');
  const l = s.buf.lines[0];
  assert.equal(l.ch[0], '中');
  assert.equal(l.wd[0], 2);
  assert.equal(l.wd[1], 0);
  assert.equal(l.ch[2], 'é');
  assert.equal(s.buf.x, 3);
  // wide char at the last column wraps
  s.write('\x1b[1;5H中');
  assert.equal(s.buf.lines[1].ch[0], '中');
  // overwriting half a wide char clears the other half
  s.write('\x1b[2;2Hx');
  assert.equal(s.buf.lines[1].ch[0], ' ');
  assert.equal(s.buf.lines[1].ch[1], 'x');
});

test('replies: DA1, DA2, DSR, DECRQM, kitty keyboard, XTWINOPS, OSC 11', () => {
  const s = mk(10, 5);
  s.write('\x1b[c\x1b[>c\x1b[3;4H\x1b[6n\x1b[5n\x1b[?2004$p\x1b[?u\x1b[18t');
  s.write('\x1b]11;?\x07');
  assert.deepEqual(s.replies.slice(0, 7), [
    '\x1b[?62;22c', '\x1b[>1;10;0c', '\x1b[3;4R', '\x1b[0n', '\x1b[?2004;2$y', '\x1b[?0u', '\x1b[8;5;10t',
  ]);
  assert.match(s.replies[7], /^\x1b\]11;rgb:[0-9a-f]{4}\/[0-9a-f]{4}\/[0-9a-f]{4}\x1b\\$/);
});

test('DSR respects origin mode', () => {
  const s = mk(10, 6);
  s.write('\x1b[2;5r\x1b[?6h\x1b[2;3H\x1b[6n');
  assert.equal(s.buf.y, 2);
  assert.deepEqual(s.replies, ['\x1b[2;3R']);
});

test('resize keeps cursor in bounds and pushes lines to scrollback', () => {
  const s = mk(10, 4);
  s.write('1\r\n2\r\n3\r\n4');
  s.resize(6, 2);
  assert.equal(s.rows, 2);
  assert.equal(row(s, 1), '4');
  assert.equal(s.buf.y, 1);
  assert.equal(s.buf.sbLength, 2);
  s.resize(12, 5);
  assert.equal(s.buf.lines.length, 5);
  assert.equal(s.buf.lines[0].cols, 12);
});

test('OSC title and hyperlinks; REP; DEC graphics', () => {
  const s = mk(10, 2);
  let title = '';
  s.onTitle = (t) => { title = t; };
  s.write('\x1b]2;hello\x1b\\\x1b]8;;https://x.y\x07L\x1b]8;;\x07M');
  assert.equal(title, 'hello');
  const l = s.buf.lines[0];
  assert.equal(s.links.get(l.ln[0]), 'https://x.y');
  assert.equal(l.ln[1], 0);
  s.write('z\x1b[3b\x1b(0q\x1b(B');
  assert.equal(row(s, 0), 'LMzzzz─');
});

test('key and mouse encoding', () => {
  const k = (key, o = {}, modes = {}) => encodeKey({ key, code: o.code || '', ctrlKey: !!o.ctrl, altKey: !!o.alt, shiftKey: !!o.shift, metaKey: false }, modes);
  assert.equal(k('ArrowUp'), '\x1b[A');
  assert.equal(k('ArrowUp', {}, { appCursor: true }), '\x1bOA');
  assert.equal(k('ArrowLeft', { ctrl: true }), '\x1b[1;5D');
  assert.equal(k('F5'), '\x1b[15~');
  assert.equal(k('Delete', { shift: true }), '\x1b[3;2~');
  assert.equal(k('c', { ctrl: true, code: 'KeyC' }), '\x03');
  assert.equal(k(' ', { ctrl: true, code: 'Space' }), '\x00');
  assert.equal(k('b', { alt: true }), '\x1bb');
  assert.equal(k('Tab', { shift: true }), '\x1b[Z');
  assert.equal(k('Backspace'), '\x7f');
  assert.equal(k('Shift'), null);
  assert.equal(encodeMouse(0, 4, 2, {}, { mouseSGR: true }), '\x1b[<0;5;3M');
  assert.equal(encodeMouse(0, 4, 2, { release: true }, { mouseSGR: true }), '\x1b[<0;5;3m');
  assert.equal(encodeMouse(0, 0, 0, {}, {}), '\x1b[M !!');
  assert.equal(encodePaste('a\nb', true), '\x1b[200~a\rb\x1b[201~');
});

test('throughput: 20 MB of text parses quickly', () => {
  const s = mk(120, 40);
  const chunk = 'y\r\n'.repeat(20000) + '\x1b[31mcolor\x1b[0m '.repeat(2000) + '\r\n';
  const t0 = Date.now();
  let n = 0;
  while (n < 20e6) { s.write(chunk); n += chunk.length; }
  const ms = Date.now() - t0;
  assert.ok(ms < 8000, `took ${ms}ms`);
});
