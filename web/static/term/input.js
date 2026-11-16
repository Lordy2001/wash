// Keyboard and mouse encoding (xterm conventions), DOM-free.

const CSI = '\x1b[';
const SS3 = '\x1bO';

const CURSOR = { ArrowUp: 'A', ArrowDown: 'B', ArrowRight: 'C', ArrowLeft: 'D', Home: 'H', End: 'F' };
const TILDE = { Insert: 2, Delete: 3, PageUp: 5, PageDown: 6, F5: 15, F6: 17, F7: 18, F8: 19, F9: 20, F10: 21, F11: 23, F12: 24 };
const PF = { F1: 'P', F2: 'Q', F3: 'R', F4: 'S' };

function modParam(e) {
  return 1 + (e.shiftKey ? 1 : 0) + (e.altKey ? 2 : 0) + (e.ctrlKey ? 4 : 0) + (e.metaKey ? 8 : 0);
}

/**
 * encodeKey maps a keydown-like event ({key, code, ctrlKey, altKey,
 * shiftKey, metaKey, altGraph}) to the bytes (as a string) a terminal
 * sends, or null when the key produces nothing (or should be left to the
 * browser).
 */
export function encodeKey(e, modes = {}) {
  const key = e.key;
  const mod = modParam(e);
  if (key in CURSOR) {
    const f = CURSOR[key];
    if (mod > 1) return `${CSI}1;${mod}${f}`;
    return (modes.appCursor ? SS3 : CSI) + f;
  }
  if (key in PF) {
    if (mod > 1) return `${CSI}1;${mod}${PF[key]}`;
    return SS3 + PF[key];
  }
  if (key in TILDE) {
    const n = TILDE[key];
    return mod > 1 ? `${CSI}${n};${mod}~` : `${CSI}${n}~`;
  }
  switch (key) {
    case 'Enter': {
      const s = modes.lnm ? '\r\n' : '\r';
      return e.altKey ? '\x1b' + s : s;
    }
    case 'Tab':
      if (e.ctrlKey || e.metaKey) return null;
      return e.shiftKey ? `${CSI}Z` : (e.altKey ? '\x1b\t' : '\t');
    case 'Backspace': {
      const s = e.ctrlKey ? '\x08' : '\x7f';
      return e.altKey ? '\x1b' + s : s;
    }
    case 'Escape': return e.altKey ? '\x1b\x1b' : '\x1b';
  }
  if (e.metaKey) return null;
  if (key.length === 0) return null;
  const chars = [...key];
  if (chars.length !== 1) return null; // named keys (Shift, Dead, ...)
  if (e.altGraph) return key; // AltGr combinations produce characters
  if (e.ctrlKey) {
    let c = null;
    const k = key.length === 1 ? key : '';
    const code = e.code || '';
    let letter = /^[a-z]$/i.test(k) ? k.toUpperCase() : (code.startsWith('Key') ? code.slice(3) : '');
    if (letter) c = String.fromCharCode(letter.charCodeAt(0) - 64);
    else if (k === ' ' || k === '@' || k === '2' || code === 'Space') c = '\x00';
    else if (k === '[' || k === '3') c = '\x1b';
    else if (k === '\\' || k === '4') c = '\x1c';
    else if (k === ']' || k === '5') c = '\x1d';
    else if (k === '^' || k === '6' || k === '~') c = '\x1e';
    else if (k === '_' || k === '-' || k === '/' || k === '7') c = '\x1f';
    else if (k === '8' || k === '?') c = '\x7f';
    if (c === null) return null;
    return e.altKey ? '\x1b' + c : c;
  }
  if (e.altKey) return '\x1b' + key;
  return key;
}

/**
 * encodeMouse builds a mouse report.
 * @param {number} button 0 left, 1 middle, 2 right, 3 release (X10 encoding), 64/65 wheel
 * @param {number} col 0-based
 * @param {number} row 0-based
 * @param {{motion?: boolean, release?: boolean, shift?: boolean, alt?: boolean, ctrl?: boolean}} o
 * @param {{mouseSGR?: boolean}} modes
 */
export function encodeMouse(button, col, row, o, modes) {
  let b = button;
  if (o.motion) b += 32;
  if (o.shift) b += 4;
  if (o.alt) b += 8;
  if (o.ctrl) b += 16;
  if (modes.mouseSGR) {
    return `${CSI}<${b};${col + 1};${row + 1}${o.release ? 'm' : 'M'}`;
  }
  if (o.release) b = (b & ~3) | 3;
  const enc = (v) => String.fromCharCode(Math.min(255, v + 32));
  if (col + 1 > 223 || row + 1 > 223) return null;
  return `${CSI}M${enc(b)}${enc(col + 1)}${enc(row + 1)}`;
}

/** Prepares pasted text for the pty. */
export function encodePaste(text, bracketed) {
  let t = text.replace(/\r\n/g, '\r').replace(/\n/g, '\r');
  if (bracketed) {
    t = t.replace(/\x1b\[20[01]~/g, '');
    return `\x1b[200~${t}\x1b[201~`;
  }
  return t;
}
