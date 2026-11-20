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
