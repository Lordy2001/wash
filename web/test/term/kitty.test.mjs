import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Screen } from '../../static/term/screen.js';
import { parseKeys } from '../../static/term/kitty.js';

function png(w, h) {
  // just enough of a PNG for size sniffing: signature + IHDR header
  const b = new Uint8Array(33);
  b.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
  const dv = new DataView(b.buffer);
  dv.setUint32(16, w);
  dv.setUint32(20, h);
  return Buffer.from(b).toString('base64');
}

function mk(cols = 20, rows = 10) {
  const decoded = [];
  const s = new Screen(cols, rows, {
    scrollback: 100,
    decoder: async (img, bytes, info) => { decoded.push({ img, bytes, info }); return { bitmap: { stub: true }, width: info.width || 1, height: info.height || 1 }; },
  });
  s.cellW = 10; s.cellH = 20;
  s.replies = [];
  s.onReply = (r) => s.replies.push(r);
  s.decoded = decoded;
  return s;
}

const apc = (keys, data = '') => `\x1b_G${keys};${data}\x1b\\`;

test('parseKeys', () => {
  assert.deepEqual(parseKeys('a=T,f=100,i=7,z=-1,o=z'), { a: 'T', f: 100, i: 7, z: -1, o: 'z' });
});

test('query replies OK without storing; unsupported medium errors', () => {
  const s = mk();
  s.write(apc('a=q,i=31,s=1,v=1,t=d,f=24', 'AAAA'));
  assert.deepEqual(s.replies, ['\x1b_Gi=31;OK\x1b\\']);
  assert.equal(s.kitty.images.size, 0);
  s.write(apc('a=q,i=32,t=f,f=100', 'L3RtcC94'));
  assert.match(s.replies[1], /^\x1b_Gi=32;EBADF:/);
});

test('chunked transmission is assembled, then displayed with cursor movement', async () => {
  const s = mk();
  const data = png(25, 30); // 3 cols x 2 rows at 10x20 cells
  const a = data.slice(0, 8), b = data.slice(8, 20), c = data.slice(20);
  s.write('\x1b[2;3H');
  s.write(apc('a=T,f=100,i=5,m=1', a));
  s.write(apc('m=1', b));
  assert.equal(s.kitty.images.size, 0);
  s.write(apc('m=0', c));
  assert.deepEqual(s.replies, ['\x1b_Gi=5;OK\x1b\\']);
  const img = s.kitty.images.get(5);
  assert.equal(img.w, 25);
  assert.equal(img.h, 30);
  const pl = s.buf.placements[0];
  assert.equal(pl.cols, 3);
  assert.equal(pl.rows, 2);
  assert.equal(pl.col, 2);
  assert.equal(pl.abs, 1);
  // cursor: last row of the image, column after it
  assert.deepEqual([s.buf.x, s.buf.y], [5, 2]);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(s.decoded.length, 1);
  assert.equal(s.decoded[0].info.format, 100);
  assert.ok(img.bitmap);
});

test('C=1 keeps the cursor; c/r size in cells; q=1 suppresses OK', () => {
  const s = mk();
  s.write(apc('a=T,f=100,i=6,c=4,r=3,C=1,q=1', png(8, 8)));
  assert.deepEqual(s.replies, []);
  assert.deepEqual([s.buf.x, s.buf.y], [0, 0]);
  const pl = s.buf.placements[0];
  assert.equal(pl.cols, 4);
  assert.equal(pl.rows, 3);
});

test('raw RGB needs s/v and enough data; put by number; delete', () => {
  const s = mk();
  s.write(apc('a=t,f=24,i=9', 'AAAA'));
  assert.match(s.replies[0], /^\x1b_Gi=9;EINVAL:/);
  const rgb = Buffer.from(new Uint8Array(2 * 2 * 3)).toString('base64');
  s.write(apc('a=t,f=24,s=2,v=2,I=77', rgb));
  assert.match(s.replies[1], /^\x1b_Gi=\d+,I=77;OK\x1b\\$/);
  s.write(apc('a=p,I=77,p=3'));
  assert.equal(s.buf.placements.length, 1);
  s.write(apc('a=p,I=77,p=3')); // same placement id replaces
  assert.equal(s.buf.placements.length, 1);
  s.write(apc('a=p,i=12345'));
  assert.match(s.replies.at(-1), /^\x1b_Gi=12345;ENOENT:/);
  s.write(apc('a=d,d=A'));
  assert.equal(s.buf.placements.length, 0);
  assert.equal(s.kitty.images.size, 0);
});

test('placements scroll with text and are dropped with the alternate screen', () => {
  const s = mk(20, 4);
  s.write(apc('a=T,f=100,i=1,C=1', png(10, 20)));
  const pl = s.buf.placements[0];
  assert.equal(pl.abs, 0);
  s.write('\r\n\r\n\r\n\r\n\r\n');
  assert.equal(s.buf.top, 2); // two lines scrolled into scrollback
  assert.equal(s.buf.placements.length, 1);
  assert.equal(s.buf.placements[0].abs, 0);
  s.write('\x1b[?1049h');
  s.write(apc('a=T,f=100,i=2', png(10, 20)));
  assert.equal(s.alt.placements.length, 1);
  s.write('\x1b[?1049l');
  assert.equal(s.alt.placements.length, 0);
  assert.equal(s.normal.placements.length, 1);
});
