import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeURL, urlAt } from '../../static/term/links.js';

test('safeURL opens only http and https', () => {
  assert.equal(safeURL('https://example.com/a?b=1#c'), 'https://example.com/a?b=1#c');
  assert.equal(safeURL('http://localhost:8080'), 'http://localhost:8080/');
  assert.equal(safeURL('HTTPS://EXAMPLE.COM'), 'https://example.com/');
  for (const bad of ['javascript:alert(1)', 'JavaScript:alert(1)', ' javascript:alert(1)', 'data:text/html,<script>1</script>',
    'file:///etc/passwd', 'vbscript:x', 'blob:https://x/1', 'ftp://example.com', '//example.com', 'example.com', '', null, undefined]) {
    assert.equal(safeURL(bad), null, String(bad));
  }
});

test('urlAt finds plain URLs and drops sentence punctuation', () => {
  const t = 'see https://example.com/a_(b) and (http://x.io/p?q=1).';
  assert.equal(urlAt(t, 4), 'https://example.com/a_(b)');
  assert.equal(urlAt(t, 28), 'https://example.com/a_(b)', 'last char of the URL');
  assert.equal(urlAt(t, 29), null, 'the space after it');
  assert.equal(urlAt(t, t.indexOf('x.io')), 'http://x.io/p?q=1', 'the closing paren and period are not part of it');
  assert.equal(urlAt(t, 1), null);
  assert.equal(urlAt('go to javascript:alert(1)', 8), null, 'only http(s) is detected');
  assert.equal(urlAt('"https://a.b/c",', 3), 'https://a.b/c');
});
