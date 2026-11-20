// Links in terminal output: which ones may be opened.

// safeURL returns the URL to open, or null: only http: and https: links are
// opened. Terminal output is untrusted (a `cat` of a hostile file), and a
// javascript: or data: URL would run in the page's origin.
export function safeURL(s) {
  if (typeof s !== 'string' || !s) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null;
}

const URL_RE = /\bhttps?:\/\/[^\s<>"'`\x00-\x1f\x7f]+/gi;
const PAIRS = { ')': '(', ']': '[', '}': '{' };

// trimURL drops trailing punctuation that belongs to the sentence, keeping
// a closing bracket that matches one inside the URL (wiki links).
function trimURL(s) {
  for (;;) {
    const c = s[s.length - 1];
    if ('.,;:!?*'.includes(c)) { s = s.slice(0, -1); continue; }
    const open = PAIRS[c];
    if (open && s.split(open).length < s.split(c).length) { s = s.slice(0, -1); continue; }
    return s;
  }
}

// urlAt finds a plain http(s) URL in text that covers index i, or null.
export function urlAt(text, i) {
  for (const m of text.matchAll(URL_RE)) {
    const s = trimURL(m[0]);
    if (i >= m.index && i < m.index + s.length) return safeURL(s);
    if (m.index > i) break;
  }
  return null;
}
