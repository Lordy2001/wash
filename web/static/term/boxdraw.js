// Procedural box drawing (U+2500-257F) and block elements (U+2580-259F),
// so lines join seamlessly regardless of the font.

// URDL weights per character: 0 none, 1 light, 2 heavy, 3 double.
const LINES = {
  0x2500: '0101', 0x2501: '0202', 0x2502: '1010', 0x2503: '2020',
  0x2504: '0101', 0x2505: '0202', 0x2506: '1010', 0x2507: '2020',
  0x2508: '0101', 0x2509: '0202', 0x250a: '1010', 0x250b: '2020',
  0x250c: '0110', 0x250d: '0210', 0x250e: '0120', 0x250f: '0220',
  0x2510: '0011', 0x2511: '0012', 0x2512: '0021', 0x2513: '0022',
  0x2514: '1100', 0x2515: '1200', 0x2516: '2100', 0x2517: '2200',
  0x2518: '1001', 0x2519: '1002', 0x251a: '2001', 0x251b: '2002',
  0x251c: '1110', 0x251d: '1210', 0x251e: '2110', 0x251f: '1120',
  0x2520: '2120', 0x2521: '2210', 0x2522: '1220', 0x2523: '2220',
  0x2524: '1011', 0x2525: '1012', 0x2526: '2011', 0x2527: '1021',
  0x2528: '2021', 0x2529: '2012', 0x252a: '1022', 0x252b: '2022',
  0x252c: '0111', 0x252d: '0112', 0x252e: '0211', 0x252f: '0212',
  0x2530: '0121', 0x2531: '0122', 0x2532: '0221', 0x2533: '0222',
  0x2534: '1101', 0x2535: '1102', 0x2536: '1201', 0x2537: '1202',
  0x2538: '2101', 0x2539: '2102', 0x253a: '2201', 0x253b: '2202',
  0x253c: '1111', 0x253d: '1112', 0x253e: '1211', 0x253f: '1212',
  0x2540: '2111', 0x2541: '1121', 0x2542: '2121', 0x2543: '2112',
  0x2544: '2211', 0x2545: '1122', 0x2546: '1221', 0x2547: '2212',
  0x2548: '1222', 0x2549: '2122', 0x254a: '2221', 0x254b: '2222',
  0x254c: '0101', 0x254d: '0202', 0x254e: '1010', 0x254f: '2020',
  0x2550: '0303', 0x2551: '3030', 0x2552: '0310', 0x2553: '0130',
  0x2554: '0330', 0x2555: '0013', 0x2556: '0031', 0x2557: '0033',
  0x2558: '1300', 0x2559: '3100', 0x255a: '3300', 0x255b: '1003',
  0x255c: '3001', 0x255d: '3003', 0x255e: '1310', 0x255f: '3130',
  0x2560: '3330', 0x2561: '1013', 0x2562: '3031', 0x2563: '3033',
  0x2564: '0313', 0x2565: '0131', 0x2566: '0333', 0x2567: '1303',
  0x2568: '3101', 0x2569: '3303', 0x256a: '1313', 0x256b: '3131',
  0x256c: '3333',
  0x2574: '0001', 0x2575: '1000', 0x2576: '0100', 0x2577: '0010',
  0x2578: '0002', 0x2579: '2000', 0x257a: '0200', 0x257b: '0020',
  0x257c: '0201', 0x257d: '1020', 0x257e: '0102', 0x257f: '2010',
};

const ARCS = { 0x256d: 'rd', 0x256e: 'ld', 0x256f: 'lu', 0x2570: 'ru' };

export function isBoxChar(cp) { return cp >= 0x2500 && cp <= 0x259f; }

/**
 * drawBox draws cp into the cell (x, y, w, h) with the current fillStyle /
 * strokeStyle. Returns false if the character is not handled.
 */
export function drawBox(ctx, cp, x, y, w, h, lw) {
  if (cp >= 0x2580) return drawBlock(ctx, cp, x, y, w, h);
  const spec = LINES[cp];
  const cx = x + Math.floor(w / 2), cy = y + Math.floor(h / 2);
  const light = lw, heavy = Math.max(lw + 1, lw * 2);
  const thick = (wt) => (wt === 1 ? light : wt === 2 ? heavy : wt === 3 ? light * 3 : 0);
  if (spec) {
    const [u, r, d, l] = [...spec].map(Number);
    const vt = Math.max(thick(u), thick(d)), ht = Math.max(thick(l), thick(r));
    const hseg = (x0, x1, wt) => {
      if (wt === 3) {
        ctx.fillRect(x0, cy - light - Math.floor(light / 2), x1 - x0, light);
        ctx.fillRect(x0, cy + light - Math.floor(light / 2), x1 - x0, light);
        return;
      }
      const t = thick(wt);
      ctx.fillRect(x0, cy - Math.floor(t / 2), x1 - x0, t);
    };
    const vseg = (y0, y1, wt) => {
      if (wt === 3) {
        ctx.fillRect(cx - light - Math.floor(light / 2), y0, light, y1 - y0);
        ctx.fillRect(cx + light - Math.floor(light / 2), y0, light, y1 - y0);
        return;
      }
      const t = thick(wt);
      ctx.fillRect(cx - Math.floor(t / 2), y0, t, y1 - y0);
    };
    const ve = Math.ceil(vt / 2), he = Math.ceil(ht / 2);
    if (l) hseg(x, cx + (u || d ? ve : 0), l);
    if (r) hseg(cx - (u || d ? ve : 0), x + w, r);
    if (u) vseg(y, cy + (l || r ? he : 0), u);
    if (d) vseg(cy - (l || r ? he : 0), y + h, d);
    if (!l && !r && !u && !d) return false;
    return true;
  }
  const arc = ARCS[cp];
  if (arc) {
    const rad = Math.min(w, h) / 2;
    ctx.save();
    ctx.lineWidth = light;
    ctx.strokeStyle = ctx.fillStyle;
    ctx.beginPath();
    const ox = cx + (light % 2 ? 0.5 : 0), oy = cy + (light % 2 ? 0.5 : 0);
    const ex = arc[0] === 'r' ? x + w : x;
    const ey = arc[1] === 'd' ? y + h : y;
    ctx.moveTo(ex, oy);
    ctx.arcTo(ox, oy, ox, ey, rad);
    ctx.lineTo(ox, ey);
    ctx.stroke();
    ctx.restore();
    return true;
  }
  if (cp >= 0x2571 && cp <= 0x2573) {
    ctx.save();
    ctx.lineWidth = light;
    ctx.strokeStyle = ctx.fillStyle;
    ctx.beginPath();
    if (cp !== 0x2572) { ctx.moveTo(x + w, y); ctx.lineTo(x, y + h); }
    if (cp !== 0x2571) { ctx.moveTo(x, y); ctx.lineTo(x + w, y + h); }
    ctx.stroke();
    ctx.restore();
    return true;
  }
  return false;
}

function drawBlock(ctx, cp, x, y, w, h) {
  const R = (x0, y0, x1, y1) => {
    const a = Math.round(x + x0 * w), b = Math.round(y + y0 * h);
    ctx.fillRect(a, b, Math.round(x + x1 * w) - a, Math.round(y + y1 * h) - b);
  };
  if (cp === 0x2580) R(0, 0, 1, 0.5);
  else if (cp >= 0x2581 && cp <= 0x2588) R(0, 1 - (cp - 0x2580) / 8, 1, 1);
  else if (cp >= 0x2589 && cp <= 0x258f) R(0, 0, (0x2590 - cp) / 8, 1);
  else if (cp === 0x2590) R(0.5, 0, 1, 1);
  else if (cp >= 0x2591 && cp <= 0x2593) {
    const a = ctx.globalAlpha;
    ctx.globalAlpha = a * (cp - 0x2590) * 0.25;
    R(0, 0, 1, 1);
    ctx.globalAlpha = a;
  } else if (cp === 0x2594) R(0, 0, 1, 1 / 8);
  else if (cp === 0x2595) R(7 / 8, 0, 1, 1);
  else {
    // quadrants: UL UR LL LR bits
    const Q = { 0x2596: 4, 0x2597: 8, 0x2598: 1, 0x2599: 1 | 4 | 8, 0x259a: 1 | 8, 0x259b: 1 | 2 | 4, 0x259c: 1 | 2 | 8, 0x259d: 2, 0x259e: 2 | 4, 0x259f: 2 | 4 | 8 }[cp];
    if (!Q) return false;
    if (Q & 1) R(0, 0, 0.5, 0.5);
    if (Q & 2) R(0.5, 0, 1, 0.5);
    if (Q & 4) R(0, 0.5, 0.5, 1);
    if (Q & 8) R(0.5, 0.5, 1, 1);
  }
  return true;
}
