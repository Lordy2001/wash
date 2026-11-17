// Player for recordings published with `wash watch host`, in the spirit of
// asciinema's player: big play button, seekable progress bar, speed, cutting
// long pauses, keyboard shortcuts. The recording (asciicast v2) is drawn by
// wash's own canvas terminal at the recorded size.
import { Terminal } from './term/terminal.js';

const $ = (id) => document.getElementById(id);
const player = $('player');
const castURL = location.pathname.replace(/\/+$/, '') + '/cast';
const SPEEDS = [0.25, 0.5, 1, 1.5, 2, 3, 4, 8, 16];

// clipboard: false: a recorded OSC 52 (e.g. a yank in vim or tmux) must not
// set the viewer's clipboard. mouseReporting: false: clicks select text even
// where the recorded program had turned on mouse reporting. ctrlCopyPaste:
// Ctrl+C copies the selection.
const term = new Terminal($('term'), { fontSize: 15, clipboard: false, mouseReporting: false, ctrlCopyPaste: true });
if (term.textarea) { term.textarea.readOnly = true; term.textarea.inputMode = 'none'; }
term.onData = null;

let header = null, events = [], at = [], dur = 0;
let next = 0, pos = 0, playing = false, speed = 2, idleOn = true, idle = 2;
let wallStart = 0, posStart = 0, raf = 0;

function fmt(s) {
  s = Math.max(0, Math.round(s));
  const h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, ss = s % 60;
  const two = (n) => String(n).padStart(2, '0');
  return h ? `${h}:${two(m)}:${two(ss)}` : `${two(m)}:${two(ss)}`;
}

function timeline() {
  at = new Array(events.length);
  let prev = 0, acc = 0;
  for (let i = 0; i < events.length; i++) {
    let d = Math.max(0, events[i][0] - prev);
    if (idleOn && d > idle) d = idle;
    acc += d; at[i] = acc; prev = events[i][0];
  }
  dur = acc;
}

function resetTerm() {
  term.reset();
  term.setFixedSize({ cols: header.width, rows: header.height });
  next = 0;
}

// seek applies events up to t (from the start if t is behind).
function seek(t) {
  t = Math.min(Math.max(t, 0), dur);
  if (t < pos && (next === 0 || t < at[next - 1])) resetTerm();
  let buf = '';
  while (next < events.length && at[next] <= t) {
    const [, type, data] = events[next++];
    if (type === 'o') buf += data;
    else if (type === 'r') {
      const m = /^(\d+)x(\d+)$/.exec(data);
      if (m) { if (buf) { term.write(buf); buf = ''; } term.setFixedSize({ cols: +m[1], rows: +m[2] }); }
    }
  }
  if (buf) term.write(buf);
  pos = t;
  ui();
}

function ui() {
  $('time').textContent = `${fmt(pos)} / ${fmt(dur)}`;
  const pct = dur ? (pos / dur) * 100 : 0;
  $('done').style.width = pct + '%';
  $('knob').style.left = pct + '%';
  $('track').setAttribute('aria-valuenow', Math.round(pct));
  player.classList.toggle('playing', playing);
  $('speed').textContent = SPEEDS[speed] + 'x';
  $('idle').classList.toggle('off', !idleOn);
}

function frame(now) {
  if (!playing) return;
  const t = posStart + ((now - wallStart) / 1000) * SPEEDS[speed];
  if (t >= dur) { seek(dur); pause(); return; }
  seek(t);
  raf = requestAnimationFrame(frame);
}

function playFrom() { wallStart = performance.now(); posStart = pos; }

function play() {
  if (!header) return;
  player.classList.add('started');
  if (pos >= dur) seek(0);
  playing = true; playFrom();
  cancelAnimationFrame(raf);
  raf = requestAnimationFrame(frame);
  ui();
}
function pause() { playing = false; cancelAnimationFrame(raf); ui(); }
function toggle() { playing ? pause() : play(); }
function jump(t) { player.classList.add('started'); seek(t); if (playing) playFrom(); }
function setSpeed(i) { speed = Math.min(Math.max(i, 0), SPEEDS.length - 1); if (playing) playFrom(); ui(); }
function toggleIdle() {
  const real = next > 0 ? events[next - 1][0] : 0; // stay on the same event
  idleOn = !idleOn;
  timeline();
  let i = events.findIndex((e) => e[0] >= real);
  if (i < 0) i = events.length - 1;
  pos = at[i] ?? 0;
  if (playing) playFrom();
  ui();
}
function step(dir) {
  pause(); player.classList.add('started');
  if (dir > 0 && next < events.length) seek(at[next]);
  else if (dir < 0) seek(next >= 2 ? at[next - 2] : 0);
}

// --- progress bar: click or drag to seek, hover shows the time ---------------------
const track = $('track');
function trackTime(e) {
  const r = track.getBoundingClientRect();
  return Math.min(Math.max((e.clientX - r.left) / r.width, 0), 1) * dur;
}
track.addEventListener('pointerdown', (e) => {
  track.setPointerCapture(e.pointerId);
  const was = playing; pause();
  jump(trackTime(e));
  const move = (ev) => jump(trackTime(ev));
  const up = () => {
    track.removeEventListener('pointermove', move);
    track.removeEventListener('pointerup', up);
    if (was) play();
  };
  track.addEventListener('pointermove', move);
  track.addEventListener('pointerup', up);
});
track.addEventListener('pointermove', (e) => {
  const tip = $('tip');
  tip.hidden = false;
  tip.textContent = fmt(trackTime(e));
  tip.style.left = (e.clientX - track.getBoundingClientRect().left) + 'px';
});
track.addEventListener('pointerleave', () => { $('tip').hidden = true; });

$('pp').onclick = toggle;
$('big-play').onclick = play;
// The screen is for reading and selecting text (Ctrl+C copies); play and
// pause are the buttons, the space bar and k.
$('speed').onclick = (e) => setSpeed(e.shiftKey ? speed - 1 : (speed + 1) % SPEEDS.length);
$('idle').onclick = toggleIdle;
$('fs').onclick = () => (document.fullscreenElement ? document.exitFullscreen() : player.requestFullscreen()).catch(() => {});
$('dl').href = castURL;

// keyboard (the same keys as asciinema's player where they overlap)
window.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && !e.altKey && e.code === 'KeyC') {
    // copy the selection wherever the focus is (the terminal does it too when focused)
    const t = term.getSelection();
    if (t) { e.preventDefault(); e.stopPropagation(); navigator.clipboard?.writeText(t).catch(() => {}); }
    return;
  }
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  const k = e.key;
  let handled = true;
  if (k === ' ' || k === 'k') toggle();
  else if (k === 'ArrowRight' || k === 'l') jump(pos + (e.shiftKey ? dur / 10 : 5));
  else if (k === 'ArrowLeft' || k === 'h') jump(pos - (e.shiftKey ? dur / 10 : 5));
  else if (k === 'Home') jump(0);
  else if (k === 'End') jump(dur);
  else if (/^[0-9]$/.test(k)) jump((dur * +k) / 10);
  else if (k === '.') step(1);
  else if (k === ',') step(-1);
  else if (k === '+' || k === '=' || k === '>') setSpeed(speed + 1);
  else if (k === '-' || k === '_' || k === '<') setSpeed(speed - 1);
  else if (k === 'i') toggleIdle();
  else if (k === 'f') $('fs').click();
  else handled = false;
  if (handled) { e.preventDefault(); e.stopPropagation(); }
}, true);

// --- load -------------------------------------------------------------------------
function parse(text) {
  const lines = text.split('\n');
  const h = JSON.parse(lines[0]);
  if (h.version !== 2) throw new Error(`asciicast version ${h.version} is not supported`);
  const ev = [];
  for (let i = 1; i < lines.length; i++) {
    if (!lines[i]) continue;
    try {
      const e = JSON.parse(lines[i]);
      if (Array.isArray(e) && e.length >= 3 && typeof e[0] === 'number') ev.push(e);
    } catch { /* a cut-off last line */ }
  }
  return { h, ev };
}

function message(s) { const m = $('msg'); m.textContent = s; m.hidden = !s; }

async function load() {
  message('loading…');
  try {
    const r = await fetch(castURL, { cache: 'no-cache' });
    if (!r.ok) throw new Error(r.status === 404 ? 'This recording is no longer available.' : `HTTP ${r.status}`);
    const { h, ev } = parse(await r.text());
    header = { width: h.width || 80, height: h.height || 24 };
    events = ev;
    if (h.idle_time_limit > 0) idle = h.idle_time_limit;
    $('idle').textContent = `idle ≤${idle}s`;
    const title = h.title || 'terminal recording';
    const when = h.timestamp ? new Date(h.timestamp * 1000).toLocaleString() : '';
    document.title = `${title} · wash playback`;
    $('title').innerHTML = '';
    const b = document.createElement('b');
    b.textContent = title;
    $('title').append(b, document.createTextNode(`  ${header.width}x${header.height}${when ? '  ·  ' + when : ''}`));
    timeline();
    resetTerm();
    message('');
    seek(0);
    player.focus();
    const t = /[#&]t=([\d.]+)/.exec(location.hash);
    if (t) jump(+t[1]);
  } catch (err) {
    message(err.message || String(err));
  }
}
load();
