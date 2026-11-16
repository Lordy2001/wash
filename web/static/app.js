// wash browser app: passkey sign-in / creation, session tabs, terminals.
import { Terminal } from './term/terminal.js';
import { ManagerConn, WoshSession, b64bytes, randomHex } from './wosh.js';

const $ = (s, el = document) => el.querySelector(s);
const show = (id) => { for (const v of document.querySelectorAll('.view')) v.hidden = v.id !== id; };
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch {} },
};

// --- WebAuthn JSON <-> binary ---------------------------------------------------

const b64u = {
  enc(buf) {
    const b = new Uint8Array(buf); let s = '';
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s); const b = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
    return b.buffer;
  },
};

function creationOptions(o) {
  const pk = o.publicKey;
  if (PublicKeyCredential.parseCreationOptionsFromJSON) return PublicKeyCredential.parseCreationOptionsFromJSON(pk);
  return {
    ...pk,
    challenge: b64u.dec(pk.challenge),
    user: { ...pk.user, id: b64u.dec(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) })),
  };
}

function requestOptions(o) {
  const pk = o.publicKey;
  if (PublicKeyCredential.parseRequestOptionsFromJSON) return PublicKeyCredential.parseRequestOptionsFromJSON(pk);
  return {
    ...pk,
    challenge: b64u.dec(pk.challenge),
    allowCredentials: (pk.allowCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) })),
  };
}

function credentialJSON(c) {
  if (typeof c.toJSON === 'function') { try { return c.toJSON(); } catch {} }
  const r = c.response;
  const out = { id: c.id, rawId: b64u.enc(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults() };
  if (r.attestationObject) {
    out.response = { clientDataJSON: b64u.enc(r.clientDataJSON), attestationObject: b64u.enc(r.attestationObject),
      transports: r.getTransports ? r.getTransports() : [] };
  } else {
    out.response = { clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData),
      signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null };
  }
  return out;
}

async function api(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), credentials: 'same-origin' });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || `${r.status} ${r.statusText}`);
  return j;
}

// --- auth views -----------------------------------------------------------------

let config = {};

function setMsg(el, text, kind = '') { el.textContent = text; el.className = 'msg ' + kind; }

async function signIn(ev) {
  ev && ev.preventDefault();
  const msg = $('#login-msg');
  const user = $('#login-user').value.trim();
  if (!user) { setMsg(msg, 'Enter your user name.', 'err'); return; }
  store.set('wash.user', user);
  setMsg(msg, 'Waiting for your passkey…');
  $('#login-btn').disabled = true;
  try {
    const begin = await api('api/login/begin', { user });
    const cred = await navigator.credentials.get({ publicKey: requestOptions(begin.options) });
    setMsg(msg, 'Verifying with the website and your shell manager…');
    const fin = await api(`api/login/finish?id=${begin.id}`, credentialJSON(cred));
    setMsg(msg, 'Connecting…');
    await startApp(fin.ticket);
  } catch (e) {
    setMsg(msg, e.name === 'NotAllowedError' ? 'Passkey request was cancelled or timed out. No passkey for this user here? Create one, then approve it with `wash keys approve ID` on the host.'
      : e.name === 'SecurityError' ? 'The browser blocked passkeys here (untrusted certificate?). Install the wash CA below, then reload.' : e.message, 'err');
  } finally {
    $('#login-btn').disabled = false;
  }
}

async function createPasskey(ev) {
  ev.preventDefault();
  const msg = $('#reg-msg');
  const user = $('#reg-user').value.trim();
  const name = $('#reg-name').value.trim() || defaultDeviceName();
  if (!user) { setMsg(msg, 'Enter the unix user this passkey is for.', 'err'); return; }
  store.set('wash.user', user);
  $('#reg-btn').disabled = true;
  setMsg(msg, 'Follow your browser’s prompt to create the passkey…');
  try {
    const begin = await api('api/register/begin', { user, name });
    const cred = await navigator.credentials.create({ publicKey: creationOptions(begin.options) });
    const fin = await api(`api/register/finish?id=${begin.id}`, credentialJSON(cred));
    $('#pending-id').textContent = fin.id;
    $('#pending-cmd').textContent = `wash keys approve ${fin.id}`;
    $('#pending-user').textContent = fin.user;
    $('#pending-ttl').textContent = fin.expires_in.replace(/0s$/, '').replace(/0m$/, '') || fin.expires_in;
    show('pending');
  } catch (e) {
    setMsg(msg, e.name === 'NotAllowedError' ? 'Passkey creation was cancelled or timed out.'
      : e.name === 'SecurityError' ? 'The browser blocked passkeys here (untrusted certificate?). Install the wash CA, then reload.' : e.message, 'err');
  } finally {
    $('#reg-btn').disabled = false;
  }
}

function defaultDeviceName() {
  const ua = navigator.userAgent;
  const os = /Mac/.test(ua) ? 'Mac' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'device';
  const br = /Firefox/.test(ua) ? 'Firefox' : /Edg/.test(ua) ? 'Edge' : /Chrome/.test(ua) ? 'Chrome' : /Safari/.test(ua) ? 'Safari' : 'browser';
  return `${br} on ${os}`;
}

// --- main app -------------------------------------------------------------------

const app = {
  mgr: null,
  sessions: [],  // from washd
  open: new Map(), // id -> view {id, box, layers: [{ws, term, el, status, host}]}
  mods: { ctrl: 0, alt: 0 }, // sticky Ctrl/Alt from the extra-keys bar (shared by all terminals)
  active: null,
};

const theme = {
  background: '#101317', foreground: '#d8dee9', cursor: '#f0c674', selection: 'rgba(120,160,220,0.35)',
  ansi: ['#1d2127', '#e06c75', '#98c379', '#e5c07b', '#61afef', '#c678dd', '#56b6c2', '#abb2bf',
    '#5c6370', '#ff7b86', '#b5e890', '#ffd68a', '#82c4ff', '#de9bf0', '#7fd6e0', '#ffffff'],
};

async function startApp(ticket) {
  const mgr = new ManagerConn();
  mgr.onSessions = (list) => { app.sessions = list; renderTabs(); };
  mgr.onState = (s) => { $('#mgr-state').textContent = s === 'connected' ? '' : s; };
  mgr.onAuthLost = (reason) => { teardown(); show('login'); setMsg($('#login-msg'), `Signed out: ${reason}`, 'err'); };
  await mgr.connect(ticket);
  app.mgr = mgr;
  $('#who').textContent = $('#menu-who').textContent = `${mgr.hello.user}@${mgr.hello.host}`;
  show('main');
  const want = store.get('wash.active');
  const ids = app.sessions.map((s) => s.id);
  if (want && ids.includes(want)) activate(want);
  else if (ids.length) activate(ids[ids.length - 1]);
  else newSession();
}

// A tab ("view") is a stack of layers: the washd session at the bottom and
// chained hops (`wosh HOST` typed inside it) above. Each layer has its own
// terminal; only the top one is shown and gets the keyboard.
const top = (o) => o.layers[o.layers.length - 1];

function teardown() {
  for (const o of app.open.values()) for (const l of o.layers) { l.ws.close(); l.term.dispose(); l.el.remove(); }
  app.open.clear(); app.active = null;
  if (app.mgr) app.mgr.close();
  app.mgr = null;
}

function tabLabel(s) {
  const o = app.open.get(s.id);
  const hops = o ? o.layers.slice(1).map((l) => l.host) : (s.hops || []).map((h) => h.host);
  return [s.name, ...hops].join(' → ');
}

function renderTabs() {
  const bar = $('#tabs');
  bar.textContent = '';
  for (const s of app.sessions) {
    const t = document.createElement('div');
    t.className = 'tab' + (s.id === app.active ? ' active' : '');
    t.dataset.id = s.id;
    const where = s.remote ? `on ${s.remote.host} via ssh ${s.remote.route.map((h) => h.join(' ')).join(' → ')}` : `pid ${s.pid}`;
    t.title = `${s.name}\nid ${s.id}\n${where}\nstarted ${new Date(s.created).toLocaleString()}\ndouble-click to rename`;
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = tabLabel(s);
    t.append(name);
    const st = document.createElement('span');
    st.className = 'st';
    const o = app.open.get(s.id);
    st.textContent = o ? top(o).status || '' : '';
    t.append(st);
    const x = document.createElement('button');
    x.className = 'x'; x.textContent = '×'; x.title = 'kill session';
    x.onclick = (e) => { e.stopPropagation(); killSession(s); };
    // control: this device types into the session (others watch)
    const mine = o && hasControl(top(o));
    const k = document.createElement('button');
    k.className = 'ctl' + (mine ? ' mine' : '');
    k.textContent = '⌨';
    k.title = mine ? 'this device has control' : 'take control (the other device keeps watching)';
    k.onclick = (e) => { e.stopPropagation(); confirmTake(s.id); };
    t.append(k, x);
    t.onclick = () => activate(s.id);
    t.ondblclick = () => renameSession(s);
    bar.append(t);
  }
  // keep the active tab in sight (the tab strip scrolls sideways on phones)
  const act = bar.querySelector('.tab.active');
  if (act && act.scrollIntoView) act.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  // sessions killed elsewhere
  for (const [id, o] of [...app.open]) {
    if (!o.adopting && !app.sessions.some((s) => s.id === id)) closeView(id, false);
  }
}

function setStatus(o, layer) {
  if (layer !== top(o)) return;
  const tab = document.querySelector(`.tab[data-id="${o.id}"] .st`);
  if (tab) tab.textContent = layer.status;
  const k = document.querySelector(`.tab[data-id="${o.id}"] .ctl`);
  if (k) {
    const mine = hasControl(layer);
    k.classList.toggle('mine', mine);
    k.title = mine ? 'this device has control' : 'take control (the other device keeps watching)';
  }
}

function showTop(o) {
  for (const l of o.layers) l.el.hidden = l !== top(o);
  if (app.active === o.id) requestAnimationFrame(() => { top(o).term.fit(); top(o).term.focus(); });
}

// activate shows session id. Opening it here only gets control if no other
// device has it, unless take (the tab's ⌨ button): then this device gets
// control and the other keeps watching.
function activate(id, take = false) {
  app.active = id;
  store.set('wash.active', id);
  let o = app.open.get(id);
  if (!o) o = openView(id, take);
  else if (take) top(o).ws.takeControl();
  for (const [k, v] of app.open) v.box.hidden = k !== id;
  renderTabs();
  showTop(o);
}

function newLayer(o, label) {
  const el = document.createElement('div');
  el.className = 'term';
  o.box.append(el);
  const term = new Terminal(el, {
    fontSize: fontSize(), scrollback: 5000, theme, liveIME: touch,
    copyOnSelect: true, ctrlCopyPaste: true,
  });
  term.mods = app.mods; // the key bar's Ctrl/Alt apply to whichever terminal you type in
  term.onMods = renderKeys;
  term.onTitle = (t) => { if (app.active === o.id && top(o).term === term) document.title = t ? `${t} — wash` : `${label} — wash`; };
  return { el, term, status: '…' };
}

const statusText = (s) => s.state === 'up' ? (s.transport === 'webrtc' ? 'p2p' : 'ws') + (s.rtt != null ? ` ${Math.round(s.rtt)}ms` : '')
  : s.state === 'connecting' ? '…' : '⚠';

function openView(id, take = false) {
  const box = document.createElement('div');
  box.className = 'view-box';
  $('#terms').append(box);
  const o = { id, box, layers: [] };
  const sess = app.sessions.find((x) => x.id === id);
  const root = newLayer(o, sess ? sess.name : id);
  root.ws = new WoshSession(app.mgr, id, root.term, {
    transport: app.mgr.hello.transport,
    onState: (s) => {
      root.status = statusText(s);
      if (s.error) console.warn('wash session', id, s.error);
      if (root.ws.role === 'view') root.status += ' · view';
      setStatus(o, root);
      if (s.state === 'up' && !root.restored) { root.restored = true; restoreHops(o); }
    },
    onExit: (code, why) => {
      root.term.write(`\r\n\x1b[2m[session ended${code != null ? ` with status ${code}` : ''}${why ? `: ${why}` : ''}]\x1b[0m\r\n`);
      root.status = 'exited';
      while (o.layers.length > 1) popLayer(o, false);
      const sess = app.sessions.find((x) => x.id === o.id);
      if (sess && sess.remote) app.mgr.request({ t: 'kill', id: o.id }).catch(() => {}); // drop the record
    },
  });
  root.ws.take = take;
  root.ws.onSignal = (m) => onSignal(o, root, m);
  o.layers.push(root);
  app.open.set(id, o);
  root.term.fit();
  root.ws.connect();
  return o;
}

// hasControl: this device is connected to the layer's session and controls it.
const hasControl = (l) => l.ws.role === 'control' && /^(p2p|ws)/.test(l.status || '');

// takeControl makes this device the one that types into session id.
function takeControl(id) {
  const o = app.open.get(id);
  if (!o) { activate(id, true); return; }
  top(o).ws.takeControl();
  if (app.active !== id) activate(id);
  else top(o).term.focus();
}

// confirmTake asks before taking control of session id (the tab's ⌨ button):
// "Take control" takes it; a tap anywhere else keeps watching.
function confirmTake(id) {
  const o = app.open.get(id);
  if (o && hasControl(top(o))) return; // already ours
  const sess = app.sessions.find((x) => x.id === id);
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  const box = document.createElement('div');
  box.className = 'modal';
  box.setAttribute('role', 'dialog');
  const p = document.createElement('p');
  p.textContent = `Take control of “${sess ? sess.name : id}”?`;
  const hint = document.createElement('p');
  hint.className = 'hint';
  hint.textContent = 'The device that has it now keeps watching.';
  const b = document.createElement('button');
  b.textContent = 'Take control';
  box.append(p, hint, b);
  bg.append(box);
  const close = () => {
    bg.remove();
    document.removeEventListener('keydown', onKey, true);
    const t = activeTerm();
    if (t) t.focus();
  };
  const onKey = (e) => { if (e.key === 'Escape') { e.preventDefault(); close(); } };
  bg.addEventListener('pointerdown', (e) => { if (e.target === bg) { e.preventDefault(); close(); } });
  b.onclick = () => { close(); takeControl(id); };
  document.addEventListener('keydown', onKey, true);
  document.body.append(bg);
  b.focus();
}

// --- chained hops ------------------------------------------------------------

function onSignal(o, layer, m) {
  if (m.t === 'typeahead') {
    // keys that reached the relay in this terminal belong to the hop
    const child = o.layers.find((l) => l.ws.id === m.id);
    if (child && m.text) child.ws.input(b64bytes(m.text));
    return;
  }
  if (m.t !== 'hello' || !m.id) return;
  if (layer !== top(o)) { console.warn('wash: ignoring hello from a background session'); return; }
  const name = (m.user ? m.user + '@' : '') + (m.host || m.id);
  // `wosh HOST` inside this session proves itself with the session token;
  // anything else that prints a hello (`wosh up`, a stray cat) must ask
  const trusted = m.token && layer.ws.token && m.token === layer.ws.token;
  if (!trusted && !confirm(`Connect this tab directly to ${name}?`)) {
    layer.ws.say({ t: 'bye', id: m.id });
    return;
  }
  const hop = { id: m.id, parent: layer.ws.id, host: m.host || m.id, user: m.user || '', key: randomHex(24) };
  // a chained hop (`wosh HOST`) says how its parent reached HOST: once we are
  // connected, washd takes over signaling through that ssh route and the
  // intermediate session ends, as in wosh. Hellos without a route (`wosh up`)
  // keep the parent parked as their signaling path.
  const adopt = trusted && Array.isArray(m.hop) && m.hop.length && layer === o.layers[0]
    ? { sock: m.sock || '', route: m.hop } : null;
  pushHop(o, hop, !adopt, adopt);
}

// adoptHop: the hop is connected; washd makes it a remote session (signaled
// over ssh) and ends the parent. The tab becomes the hop.
async function adoptHop(o, l, hop, adopt) {
  const parent = o.layers[0];
  o.adopting = true; // the session list may drop the parent before our reply
  try {
    const r = await app.mgr.request({ t: 'adopt', id: parent.ws.id, hop, sock: adopt.sock, route: adopt.route });
    const oldId = o.id;
    parent.ws.close(); parent.term.dispose(); parent.el.remove(); // washd ends it; no bye
    o.layers = o.layers.filter((x) => x !== parent);
    l.ws.parent = null;                       // signaling now via washd (ssh route)
    l.ws.mode = app.mgr.hello.transport;      // and washd can bridge if WebRTC fails
    l.root = true;
    app.open.delete(oldId);
    o.id = r.session.id;
    app.open.set(o.id, o);
    if (!app.sessions.some((x) => x.id === o.id)) app.sessions.push(r.session);
    if (app.active === oldId) { app.active = o.id; store.set('wash.active', o.id); }
  } catch (e) {
    console.warn('wash: adopt failed, keeping the parent as signaling path:', e.message);
    // say why this hop is not "direct" in the wosh sense (its parent stays up)
    const why = e.message.replace(/^ssh route not usable non-interactively \((.*)\); keeping.*$/s, '$1');
    l.term.write(`\r\n\x1b[2m[wash: keeping ${parent.host || 'the parent session'} as the link to ${hop.host}: ` +
      `washd cannot reach it on its own (${why}). Every ssh hop must work non-interactively (keys or agent, known host keys).]\x1b[0m\r\n`);
    app.mgr.request({ t: 'hop.add', id: o.id, hop }).catch(() => {});
  } finally {
    o.adopting = false;
    renderTabs();
    showTop(o);
  }
}

function pushHop(o, hop, isNew, adopt = null) {
  const parent = o.layers.find((l) => l.ws.id === hop.parent);
  if (!parent) return;
  const l = newLayer(o, hop.host);
  l.host = hop.host;
  l.ws = new WoshSession(app.mgr, hop.id, l.term, {
    parent: parent.ws, key: hop.key,
    onState: (s) => {
      l.status = statusText(s) + (l.ws.role === 'view' ? ' · view' : '') + (l.root ? '' : ' ↪');
      setStatus(o, l);
      if (s.state === 'up' && adopt && !l.adopted) { l.adopted = true; adoptHop(o, l, hop, adopt); }
    },
    onExit: (code, why) => {
      if (l.root) { // adopted: it is the tab's session now
        l.term.write(`\r\n\x1b[2m[session ended${code != null ? ` with status ${code}` : ''}${why ? `: ${why}` : ''}]\x1b[0m\r\n`);
        l.status = 'exited';
        app.mgr.request({ t: 'kill', id: o.id }).catch(() => {}); // forget the remote record
        return;
      }
      if (why) console.warn('wash hop', hop.host, why);
      // no bye when nothing is parked in the parent: it would be typed into its shell
      popLayer(o, true, l, !/relay .*gone|parent session ended/.test(why || ''));
    },
  });
  l.ws.onSignal = (m) => onSignal(o, l, m);
  o.layers.push(l);
  if (isNew) app.mgr.request({ t: 'hop.add', id: o.id, hop }).catch((e) => console.warn('hop.add', e.message));
  renderTabs();
  showTop(o);
  l.ws.connect();
}

// popLayer removes a hop (default: the top one) and returns to its parent.
function popLayer(o, notify, l = top(o), bye = notify) {
  const i = o.layers.indexOf(l);
  if (i <= 0) return;
  for (const x of o.layers.splice(i)) {
    x.ws.close(); x.term.dispose(); x.el.remove();
    if (bye && x === l) {
      // let the relay parked in the parent's terminal exit
      const parent = o.layers[o.layers.length - 1];
      parent.ws.say({ t: 'bye', id: x.ws.id });
      setTimeout(() => parent.ws.redraw(), 300);
    }
  }
  if (notify) app.mgr.request({ t: 'hop.del', id: o.id, name: l.ws.id }).catch(() => {});
  renderTabs();
  showTop(o);
}

// after a reload: hops washd remembers are still parked in their parents
function restoreHops(o) {
  const s = app.sessions.find((x) => x.id === o.id);
  for (const h of (s && s.hops) || []) {
    if (!o.layers.some((l) => l.ws.id === h.id)) pushHop(o, h, false);
  }
}

function closeView(id, kill) {
  const o = app.open.get(id);
  if (!o) return;
  if (kill) o.layers[0].ws.kill();
  for (const l of o.layers) { l.ws.close(); l.term.dispose(); }
  o.box.remove();
  app.open.delete(id);
  if (app.active === id) {
    app.active = null;
    const next = app.sessions.find((s) => s.id !== id);
    if (next) activate(next.id);
  }
}

async function newSession() {
  const o = app.active && app.open.get(app.active);
  const cols = o ? top(o).term.cols : 80, rows = o ? top(o).term.rows : 24;
  try {
    const r = await app.mgr.request({ t: 'new', cols, rows });
    if (!app.sessions.some((s) => s.id === r.session.id)) app.sessions.push(r.session);
    activate(r.session.id);
  } catch (e) { alert(`Could not start a session: ${e.message}`); }
}

async function killSession(s) {
  if (!confirm(`Kill session “${s.name}”? Its processes get SIGHUP.`)) return;
  try { await app.mgr.request({ t: 'kill', id: s.id }); closeView(s.id, false); } catch (e) { alert(e.message); }
}

async function renameSession(s) {
  const name = prompt('Session name', s.name);
  if (!name || name === s.name) return;
  try { await app.mgr.request({ t: 'rename', id: s.id, name }); } catch (e) { alert(e.message); }
}

// --- touch screens: extra keys, on-screen keyboard -------------------------------

const touch = typeof matchMedia === 'function' && matchMedia('(pointer: coarse)').matches;

function activeTerm() {
  const o = app.active && app.open.get(app.active);
  return o ? top(o).term : null;
}

// renderKeys shows the sticky modifiers: armed (next key) or locked.
function renderKeys() {
  for (const b of document.querySelectorAll('#keys [data-mod]')) {
    const st = app.mods[b.dataset.mod];
    b.classList.toggle('armed', st === 1);
    b.classList.toggle('locked', st === 2);
  }
}

// setupKeys wires the extra-keys bar. Buttons never take the focus (so the
// on-screen keyboard stays up); keys repeat while held; Ctrl/Alt: tap for
// the next key, tap again to lock, again to release.
function setupKeys() {
  const bar = $('#keys');
  document.body.classList.toggle('touch', touch);
  let timer = 0, rep = 0;
  const stop = () => { clearTimeout(timer); clearInterval(rep); timer = rep = 0; };
  bar.addEventListener('pointerdown', (e) => {
    const b = e.target.closest('button');
    e.preventDefault(); // keep the terminal focused
    if (!b) return;
    const t = activeTerm();
    if (!t) return;
    if (b.dataset.mod) {
      const k = b.dataset.mod;
      t.setMod(k, (app.mods[k] + 1) % 3);
      return;
    }
    const key = b.dataset.key;
    t.pressKey(key);
    stop();
    timer = setTimeout(() => { rep = setInterval(() => t.pressKey(key), 70); }, 400);
  });
  for (const ev of ['pointerup', 'pointercancel', 'pointerleave']) bar.addEventListener(ev, stop);
  bar.addEventListener('contextmenu', (e) => e.preventDefault());
}

// fitViewport keeps the page inside the visible area, so the on-screen
// keyboard never covers the bottom of the terminal (the terminal refits to
// the smaller space). Browsers that honour interactive-widget=resizes-content
// already shrink the layout; this covers the rest (and iOS).
function fitViewport() {
  const vv = window.visualViewport;
  const main = $('#main');
  if (!vv || !main) return;
  const covered = window.innerHeight - vv.height;
  main.style.top = `${vv.offsetTop}px`;
  main.style.height = `${vv.height}px`;
  main.style.bottom = 'auto';
  document.body.classList.toggle('kbd-open', covered > 120);
}

// fontSize: this device's choice (A−/A+), else smaller on phone-sized screens.
function fontSize() {
  const chosen = Number(store.get('wash.fontSize'));
  if (chosen) return chosen;
  const w = Math.min(window.innerWidth || 1e4, (window.screen && window.screen.width) || 1e4);
  return w < 480 ? 10 : w < 800 ? 12 : 15;
}

function menu(open) {
  const m = $('#menu');
  if (m.hidden === !open) return;
  m.hidden = !open;
  $('#menu-btn').setAttribute('aria-expanded', String(open));
  $('#m-size').textContent = `${fontSize()}px`;
  if (!open && app.active && app.open.get(app.active)) top(app.open.get(app.active)).term.focus();
}

function zoom(d) {
  const cur = fontSize();
  const n = Math.max(6, Math.min(32, cur + d));
  store.set('wash.fontSize', String(n));
  $('#m-size').textContent = `${n}px`;
  for (const o of app.open.values()) for (const l of o.layers) l.term.setOptions({ fontSize: n });
}

// --- boot -----------------------------------------------------------------------

async function boot() {
  setupKeys();
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', fitViewport);
    window.visualViewport.addEventListener('scroll', fitViewport);
    fitViewport();
  }
  $('#login-user').value = store.get('wash.user') || '';
  $('#reg-user').value = store.get('wash.user') || '';
  $('#reg-name').placeholder = defaultDeviceName();
  $('#login-form').onsubmit = signIn;
  $('#reg-form').onsubmit = createPasskey;
  $('#to-reg').onclick = (e) => { e.preventDefault(); $('#reg-user').value = $('#login-user').value; show('register'); };
  for (const b of document.querySelectorAll('.to-login')) b.onclick = (e) => { e.preventDefault(); show('login'); };
  $('#new-btn').onclick = () => newSession();
  $('#zoom-in').onclick = () => zoom(1);
  $('#zoom-out').onclick = () => zoom(-1);
  const signOut = async () => { menu(false); teardown(); await api('api/logout', {}).catch(() => {}); show('login'); setMsg($('#login-msg'), 'Signed out.'); };
  $('#logout').onclick = signOut;
  // phones: text size and sign out live in the ☰ menu
  $('#menu-btn').onclick = (e) => { e.stopPropagation(); menu($('#menu').hidden); };
  $('#m-zoom-in').onclick = () => zoom(1);
  $('#m-zoom-out').onclick = () => zoom(-1);
  $('#m-logout').onclick = signOut;
  $('#menu').onclick = (e) => e.stopPropagation();
  document.addEventListener('click', () => menu(false));
  document.addEventListener('keydown', (e) => {
    if (!e.ctrlKey || !e.shiftKey || !app.mgr) return;
    if (e.code === 'KeyT') { e.preventDefault(); newSession(); }
    if (e.code === 'PageDown' || e.code === 'PageUp') {
      e.preventDefault();
      const i = app.sessions.findIndex((s) => s.id === app.active);
      const n = app.sessions.length; if (!n) return;
      activate(app.sessions[(i + (e.code === 'PageDown' ? 1 : n - 1)) % n].id);
    }
  }, true);

  try { config = await (await fetch('api/config')).json(); } catch {}
  // passkeys are bound to a host name: an IP address can never work
  const isIP = /^[\d.]+$/.test(location.hostname) || location.hostname.startsWith('[');
  if (isIP) {
    show('login');
    $('#login-form').hidden = true; $('#to-reg').hidden = true;
    const msg = $('#login-msg');
    msg.className = 'msg err';
    msg.textContent = 'Passkeys cannot be used on an IP address. Open this site by host name: ';
    for (const o of config.origins || []) {
      const a = document.createElement('a');
      a.href = o + location.pathname; a.textContent = o;
      msg.append(a, ' ');
    }
    return;
  }
  if (config.ca) $('#ca-hint').hidden = false;
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    show('login');
    setMsg($('#login-msg'), 'Passkeys need a secure context: open this site over https with a host name (not an IP address).', 'err');
    $('#login-btn').disabled = true;
    return;
  }
  if (!config.registration) $('#to-reg').hidden = true;
  if (config.registration === 'request') $('#reg-open-hint').hidden = false;
  show('login');
  // every page load signs in with a passkey: the shell manager verifies it too
  if ($('#login-user').value) $('#login-btn').focus(); else $('#login-user').focus();
}

boot();
