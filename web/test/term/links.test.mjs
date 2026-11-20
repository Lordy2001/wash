import { test } from 'node:test';
import assert from 'node:assert/strict';
import { safeURL } from '../../static/term/links.js';

test('safeURL opens only http and https', () => {
  assert.equal(safeURL('https://example.com/a?b=1#c'), 'https://example.com/a?b=1#c');
  assert.equal(safeURL('http://localhost:8080'), 'http://localhost:8080/');
  assert.equal(safeURL('HTTPS://EXAMPLE.COM'), 'https://example.com/');
  for (const bad of ['javascript:alert(1)', 'JavaScript:alert(1)', ' javascript:alert(1)', 'data:text/html,<script>1</script>',
    'file:///etc/passwd', 'vbscript:x', 'blob:https://x/1', 'ftp://example.com', '//example.com', 'example.com', '', null, undefined]) {
    assert.equal(safeURL(bad), null, String(bad));
  }
});
