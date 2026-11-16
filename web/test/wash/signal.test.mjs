// In-band wosh signaling as the browser does it (web/static/wosh.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import { WoshSession, encodeInput, F } from '../../static/wosh.js';

const enc = new TextEncoder();
const osc = (m) => enc.encode('\x1b]5379;wosh;' + Buffer.from(JSON.stringify(m)).toString('base64') + '\x07');

function outFrame(off, bytes) {
  const b = new Uint8Array(9 + bytes.length);
  b[0] = F.OUTPUT; new DataView(b.buffer).setBigUint64(1, BigInt(off)); b.set(bytes, 9);
  return b;
}

function ack(off) {
  const b = new Uint8Array(9);
  b[0] = F.ACK; new DataView(b.buffer).setBigUint64(1, BigInt(off));
  return b;
}

function session() {
  const written = [];
  const term = { cols: 80, rows: 24, write: (d) => written.push(...d) };
  const ws = new WoshSession({ hello: {} }, 'aa', term);
  const signals = [];
  ws.onSignal = (m) => signals.push(m);
  return { ws, written, signals };
}

test('hello split across frames is stripped and delivered', () => {
  const { ws, written, signals } = session();
  const msg = osc({ t: 'hello', id: 'c0ffee', host: 'ca', token: 'tok' });
  const all = new Uint8Array([...enc.encode('before'), ...msg, ...enc.encode('after\x1b[0m')]);
  let off = 0;
  for (const cut of [3, 9, 17, 40, all.length]) { // arbitrary chunk boundaries
    ws.frame(outFrame(off, all.subarray(off, cut))); off = cut;
  }
  assert.equal(new TextDecoder().decode(new Uint8Array(written)), 'beforeafter\x1b[0m');
  assert.equal(signals.length, 1);
  assert.deepEqual([signals[0].t, signals[0].id, signals[0].host, signals[0].token], ['hello', 'c0ffee', 'ca', 'tok']);
});

test('info control frame sets the session token', () => {
  const { ws } = session();
  ws.frame(new Uint8Array([F.CONTROL, ...enc.encode('{"op":"info","token":"t0k"}')]));
  assert.equal(ws.token, 't0k');
});

test('relay types a WOSH: line and resolves on the OSC answer', async () => {
  const { ws } = session();
  const sent = [];
  ws.tr = { send: (b) => sent.push(b), close() {} };
  ws.frame(ack(0)); // link synced
  const p = ws.relay({ t: 'offer', id: 'beef', sdp: 'v=0' });
  const line = new TextDecoder().decode(sent[0].subarray(9));
  assert.match(line, /^WOSH:[A-Za-z0-9+/=]+\r$/);
  const m = JSON.parse(Buffer.from(line.slice(5, -1), 'base64').toString());
  assert.deepEqual([m.t, m.id, m.v], ['offer', 'beef', 2]);
  ws.frame(outFrame(0, osc({ t: 'answer', id: 'beef', sdp: 'v=0 answer' })));
  assert.equal((await p).sdp, 'v=0 answer');
  ws.close();
});

test('encodeInput matches wosh wire.EncodeInput format', () => {
  const s = new TextDecoder().decode(encodeInput({ t: 'bye', id: 'x' }));
  assert.ok(s.startsWith('WOSH:') && s.endsWith('\r'));
});
const inputs = (sent) => sent.filter((b) => b[0] === F.INPUT).map((b) => [Number(new DataView(b.buffer, b.byteOffset).getBigUint64(1)), new TextDecoder().decode(b.subarray(9))]);

test('fresh page on an existing session rebases input onto the daemon offset', () => {
  const { ws } = session();
  const sent = [];
  ws.tr = { send: (b) => sent.push(b), close() {} };
  ws.flushPending = true;
  ws.input(enc.encode('ls\r'));         // typed before the link's first ack: held
  assert.deepEqual(inputs(sent), []);
  ws.frame(ack(1234));                   // the session already had 1234 bytes of input
  assert.deepEqual(inputs(sent), [[1234, 'ls\r']]);
  ws.input(enc.encode('x'));
  assert.deepEqual(inputs(sent).at(-1), [1237, 'x']);
  ws.close();
});

test('reconnect after another browser typed rebases; normal reconnect resends the unacked tail', () => {
  const { ws } = session();
  const sent = [];
  ws.tr = { send: (b) => sent.push(b), close() {} };
  ws.flushPending = true;
  ws.frame(ack(10));
  ws.input(enc.encode('abc'));           // 10..13, unacked
  // link drops; new link; daemon got only 'a' from us
  ws.synced = false; ws.flushPending = true; sent.length = 0;
  ws.frame(ack(11));
  assert.deepEqual(inputs(sent), [[11, 'bc']]);
  // link drops again; meanwhile another browser typed 50 bytes
  ws.input(enc.encode('d'));             // 13
  ws.synced = false; ws.flushPending = true; sent.length = 0;
  ws.frame(ack(63));
  assert.deepEqual(inputs(sent), [[63, 'bcd']]);
  ws.close();
});

test('build stream: stamp, data, fin, close with sequence numbers', async () => {
  const { serveStream } = await import('../../static/wosh.js');
  const gz = new Uint8Array(40000).map((_, i) => i & 0xff);
  const half = Buffer.from(gz.subarray(0, 20000)).toString('base64');
  const rest = Buffer.from(gz.subarray(20000)).toString('base64');
  const mgr = { request: async (m) => { assert.deepEqual([m.t, m.name], ['build', 'linux-amd64']); return { stamp: '123-abc', chunks: [half, rest] }; } };
  const sent = [];
  const dc = { label: 's:{"k":"build","cmd":"linux-amd64","sid":"x"}', readyState: 'open', bufferedAmount: 0,
    send: (b) => sent.push(b), close() {}, addEventListener() {} };
  serveStream(mgr, dc);
  await new Promise((r) => setTimeout(r, 20));
  const msgs = sent.map((b) => ({ t: String.fromCharCode(b[0]), seq: Number(new DataView(b.buffer, b.byteOffset + 1).getBigUint64(0)), p: b.subarray(9) }));
  assert.deepEqual(msgs.map((m) => m.t).join(''), 'xdddf' + 'C');
  assert.deepEqual(msgs.map((m) => m.seq), [0, 1, 2, 3, 4, 5]);
  assert.equal(new TextDecoder().decode(msgs[0].p), '123-abc');
  const data = Buffer.concat(msgs.filter((m) => m.t === 'd').map((m) => Buffer.from(m.p)));
  assert.ok(data.equals(Buffer.from(gz)));
  // opener's close gets acked
  const c = new Uint8Array(9); c[0] = 0x43;
  dc.onmessage({ data: c.buffer });
  const a = sent.at(-1);
  assert.equal(a[0], 0x4b);
  assert.equal(Number(new DataView(a.buffer, a.byteOffset + 1).getBigUint64(0)), 1);
});

test('other stream kinds are refused fast', async () => {
  const { serveStream } = await import('../../static/wosh.js');
  const sent = [];
  serveStream({}, { label: 's:{"k":"agent"}', readyState: 'open', send: (b) => sent.push(b), close() {} });
  await new Promise((r) => setTimeout(r, 5));
  assert.deepEqual(sent.map((b) => String.fromCharCode(b[0])), ['!', 'C']);
});
