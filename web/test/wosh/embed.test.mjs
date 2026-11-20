// Embedding the browser client without washd: WoshSession with a signal
// function, and the files an embedder copies (wosh.js, term/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WoshSession, VERSION } from '../../static/wosh.js';
import * as term from '../../static/term/index.js';

const staticDir = fileURLToPath(new URL('../../static/', import.meta.url));

test('signal option: offers go to the embedder, with cid and size', async () => {
  const offers = [];
  const termStub = { cols: 100, rows: 30, write() {} };
  const ws = new WoshSession(null, 'abc', termStub, {
    cid: 'tab9',
    signal: async (o) => { offers.push(o); return 'ANSWER-SDP'; },
  });
  assert.equal(ws.mode, 'webrtc', 'no washd: no bridge');
  assert.deepEqual(ws.iceConfig(), { ice: [], relay: false }, 'host candidates only by default');
  const sdp = await ws.signal('OFFER-SDP');
  assert.equal(sdp, 'ANSWER-SDP');
  assert.deepEqual(offers, [{ sdp: 'OFFER-SDP', cols: 100, rows: 30, rx_out: 0, cid: 'tab9', take: false }]);
});

test('signal option: embedder ICE servers win, and a "gone" error ends the session', async () => {
  const ice = [{ urls: ['turn:example.invalid'], username: 'u', credential: 'p' }];
  let exit = null;
  const ws = new WoshSession(null, 'abc', { write() {} }, {
    ice,
    signal: async () => { throw new Error('session gone'); },
    onExit: (code, why) => { exit = why; },
  });
  assert.deepEqual(ws.iceConfig().ice, ice);
  ws.open = async () => { await ws.signal('x'); };
  await ws.connect();
  assert.equal(exit, 'session gone');
});

test('a session needs a manager or a signal function', () => {
  assert.throws(() => new WoshSession(null, 'abc', { write() {} }), /signal/);
});

test('one version for wosh.js and term/', () => {
  assert.match(VERSION, /^\d+\.\d+\.\d+$/);
  assert.equal(term.VERSION, VERSION);
  assert.equal(typeof term.Terminal, 'function');
});

test('vendorable files only import each other (no build step)', () => {
  const files = ['wosh.js', ...readdirSync(staticDir + 'term').filter((f) => f.endsWith('.js')).map((f) => 'term/' + f)];
  for (const f of files) {
    const src = readFileSync(staticDir + f, 'utf8');
    for (const m of src.matchAll(/(?:^|\n)\s*(?:import|export)\b[^'"\n]*?from\s*['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      assert.ok(spec.startsWith('./') || spec.startsWith('../'), `${f} imports ${spec}`);
      if (f.startsWith('term/')) assert.ok(spec.startsWith('./'), `${f} reaches outside term/: ${spec}`);
    }
    assert.doesNotMatch(src, /\bimport\s*\(/, `${f} uses a dynamic import`);
  }
});
