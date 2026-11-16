import { Terminal } from './term/terminal.js';

const t = new Terminal(document.getElementById('term'), { fontSize: 15 });
window.term = t;
let fontSize = 15;
t.onResize = (c, r) => { document.getElementById('size').textContent = `${c}x${r}`; };
t.onTitle = (s) => { document.title = s || 'wash terminal demo'; };
t.onData = (u8) => {
  const hex = [...u8].map((b) => b.toString(16).padStart(2, '0')).join(' ');
  const shown = [...new TextDecoder().decode(u8)].map((c) => (c < ' ' || c === '\x7f') ? '·' : c).join('');
  t.write(`\x1b[2m[${hex}]\x1b[0m ${shown}\r\n`);
};

async function pngBase64() {
  const c = document.createElement('canvas');
  c.width = 160; c.height = 80;
  const g = c.getContext('2d');
  const grad = g.createLinearGradient(0, 0, 160, 80);
  grad.addColorStop(0, '#e06c75'); grad.addColorStop(0.5, '#e5c07b'); grad.addColorStop(1, '#61afef');
  g.fillStyle = grad; g.fillRect(0, 0, 160, 80);
  g.fillStyle = '#101317'; g.font = 'bold 28px sans-serif'; g.fillText('kitty ✓', 22, 52);
  const blob = await new Promise((r) => c.toBlob(r, 'image/png'));
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function demo() {
  t.reset();
  const w = (s) => t.write(s);
  w('\x1b]2;wash terminal demo\x07');
  w('\x1b[1mwash\x1b[0m canvas terminal — \x1b[3mitalic\x1b[0m \x1b[4munderline\x1b[0m \x1b[4:3mcurly\x1b[0m \x1b[21mdouble\x1b[0m \x1b[9mstrike\x1b[0m \x1b[2mdim\x1b[0m \x1b[7minverse\x1b[0m \x1b[53moverline\x1b[0m\r\n\r\n');
  let s = '';
  for (let i = 0; i < 16; i++) s += `\x1b[48;5;${i}m  `;
  w(s + '\x1b[0m\r\n');
  for (let r = 0; r < 6; r++) {
    s = '';
    for (let c = 0; c < 36; c++) s += `\x1b[48;5;${16 + r * 36 + c}m `;
    w(s + '\x1b[0m\r\n');
  }
  s = '';
  for (let i = 232; i < 256; i++) s += `\x1b[48;5;${i}m `;
  w(s + '\x1b[0m\r\n');
  s = '';
  for (let i = 0; i < 72; i++) {
    const r = Math.round(255 * Math.max(0, Math.sin(i / 72 * Math.PI)));
    const g = Math.round(255 * i / 72), b = 255 - g;
    s += `\x1b[48:2::${r}:${g}:${b}m `;
  }
  w(s + '\x1b[0m\r\n\r\n');
  w('┌──────┬──────┐  ╔══════╦══════╗  ┏━━━━━━┳━━━━━━┓  ╭──────╮\r\n');
  w('│ box  │ draw │  ║ dbl  ║ line ║  ┃ heavy┃      ┃  │ arcs │\r\n');
  w('├──────┼──────┤  ╠══════╬══════╣  ┣━━━━━━╋━━━━━━┫  ╰──────╯\r\n');
  w('└──────┴──────┘  ╚══════╩══════╝  ┗━━━━━━┻━━━━━━┛  ▁▂▃▄▅▆▇█ ░▒▓ ▖▗▘▙▚▛▜▝▞▟\r\n\r\n');
  w('wide: 中文字符 日本語 한국어  emoji: 😀 🚀 👍🏽  combining: é ä ñ\r\n');
  w('\x1b]8;;https://sw.kovidgoyal.net/kitty/graphics-protocol/\x07ctrl-click this hyperlink\x1b]8;;\x07\r\n\r\n');
  w('kitty graphics (PNG, chunked):\r\n');
  const b64 = await pngBase64();
  const chunks = b64.match(/.{1,4096}/g);
  chunks.forEach((c, i) => {
    const more = i < chunks.length - 1 ? 1 : 0;
    w(i === 0 ? `\x1b_Ga=T,f=100,q=2,m=${more};${c}\x1b\\` : `\x1b_Gm=${more};${c}\x1b\\`);
  });
  w('  ← image, cursor continues after it\r\n');
  const raw = new Uint8Array(32 * 16 * 3);
  for (let y = 0; y < 16; y++) for (let x = 0; x < 32; x++) {
    const o = (y * 32 + x) * 3; raw[o] = x * 8; raw[o + 1] = y * 16; raw[o + 2] = 160;
  }
  let bin = '';
  for (const b of raw) bin += String.fromCharCode(b);
  w(`raw RGB scaled to 8x2 cells: \x1b_Ga=T,f=24,s=32,v=16,c=8,r=2,q=2;${btoa(bin)}\x1b\\\r\n\r\n`);
  w('Type to see key encodings. Shift+PageUp scrolls back. Drag to select, Ctrl+Shift+C copies.\r\n');
}

document.getElementById('again').onclick = () => { demo(); t.focus(); };
document.getElementById('bigger').onclick = () => { t.setOptions({ fontSize: ++fontSize }); t.focus(); };
document.getElementById('smaller').onclick = () => { t.setOptions({ fontSize: Math.max(8, --fontSize) }); t.focus(); };
demo();
t.focus();
