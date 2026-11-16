// WoshSession role switching (shared sessions) against a fake transport.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WoshSession, F } from '../../static/wosh.js';

const enc = new TextEncoder();
const u64 = (t, n) => { const b = new Uint8Array(9); b[0] = t; new DataView(b.buffer).setBigUint64(1, BigInt(n)); return b; };
const control = (o) => { const j = enc.encode(JSON.stringify(o)); const b = new Uint8Array(1 + j.length); b[0] = F.CONTROL; b.set(j, 1); return b; };
const output = (off, s) => { const d = enc.encode(s); const b = new Uint8Array(9 + d.length); b.set(u64(F.OUTPUT, off)); b.set(d, 9); return b; };

function session() {
  const sent = [];
  const term = { cols: 80, rows: 24, written: '', fixed: undefined,
    write(s) { this.written += typeof s === 'string' ? s : new TextDecoder().decode(s); },
    setFixedSize(sz) { this.fixed = sz; } };
  const ws = new WoshSession({ cid: 'tab1', hello: {} }, 'S', term);
  ws.open = async () => ({ kind: 'webrtc', send: (b) => sent.push(b), close() {} });
  return { ws, sent, term };
}
const inputs = (sent) => sent.filter((b) => b[0] === F.INPUT)
  .map((b) => [Number(new DataView(b.buffer, b.byteOffset).getBigUint64(1)), new TextDecoder().decode(b.subarray(9))]);

test('a watcher sees output, cannot type, and types after taking control', async () => {
  const { ws, sent, term } = session();
  await ws.connect();
  ws.frame(u64(F.ACK, 5));
  ws.frame(control({ op: 'role', role: 'view' }));
  ws.stopPing();
  assert.equal(ws.role, 'view');
  ws.frame(output(0, 'hello'));
  assert.match(term.written, /hello/);
  ws.input(enc.encode('x'));
  assert.deepEqual(inputs(sent), [], 'watcher input must not be sent');

  ws.takeControl();
  const take = sent.find((b) => b[0] === F.CONTROL);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(take.subarray(1))), { op: 'take' });

  ws.frame(control({ op: 'role', role: 'control' }));
  assert.ok(sent.some((b) => b[0] === F.RESIZE), 'resizes to this screen');
  assert.ok(sent.some((b) => b[0] === F.REDRAW), 'asks for a repaint');
  ws.input(enc.encode('a')); // typed before the daemon's ack: held, then sent
  assert.deepEqual(inputs(sent), []);
  ws.frame(u64(F.ACK, 42)); // input offset to continue from (another device typed meanwhile)
  ws.input(enc.encode('b'));
  assert.deepEqual(inputs(sent), [[42, 'a'], [43, 'b']]);

  ws.frame(control({ op: 'role', role: 'view' }));
  ws.input(enc.encode('c'));
  assert.deepEqual(inputs(sent).length, 2, 'demoted: typing stops');
  ws.close();
});

test('an old daemon never sends roles: always in control', async () => {
  const { ws, sent } = session();
  await ws.connect();
  ws.stopPing();
  ws.frame(u64(F.ACK, 0));
  ws.input(enc.encode('z'));
  assert.deepEqual(inputs(sent), [[0, 'z']]);
  ws.close();
});

test('watching draws the controller\'s grid; control fits this screen', async () => {
  const { ws, term } = session();
  await ws.connect();
  ws.stopPing();
  ws.frame(control({ op: 'role', role: 'view' }));
  ws.frame(control({ op: 'size', cols: 132, rows: 40 }));
  assert.deepEqual(term.fixed, { cols: 132, rows: 40 });
  ws.frame(control({ op: 'size', cols: 45, rows: 30 })); // the controller rotated its phone
  assert.deepEqual(term.fixed, { cols: 45, rows: 30 });
  ws.frame(control({ op: 'role', role: 'control' }));
  assert.equal(term.fixed, null);
  ws.frame(control({ op: 'size', cols: 80, rows: 24 })); // our own size echoed back: stays fitted
  assert.equal(term.fixed, null);
  ws.close();
});
