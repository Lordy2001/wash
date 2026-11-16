// VT500-style escape sequence parser working on decoded (UTF-16) strings.
//
// The handler receives:
//   print(str, start, end)         run of printable characters
//   execute(code)                  C0 control
//   esc(intermediates, final)      ESC sequence
//   csi(prefix, params, inter, final)
//        prefix: '' or one of '<=>?'; params: array of arrays, each
//        [value, ...colonSubparams] with -1 for an omitted value
//   osc(str)                       OSC payload (without terminator)
//   dcs(str)                       DCS payload (everything after ESC P)
//   apc(str)                       APC payload (everything after ESC _)

const GROUND = 0, ESCAPE = 1, CSI = 2, CSI_IGNORE = 3, STRING = 4;
const MAX_STRING = 32 << 20;

export class Parser {
  constructor(handler) {
    this.h = handler;
    this.reset();
  }

  reset() {
    this.state = GROUND;
    this.inter = '';
    this.prefix = '';
    this.params = [];
    this.cur = null; // current param array
    this.num = -1;
    this.strKind = '';
    this.strParts = [];
    this.strLen = 0;
    this.strEsc = false;
  }

  _beginCSI() {
    this.state = CSI;
    this.prefix = '';
    this.inter = '';
    this.params = [];
    this.cur = null;
    this.num = -1;
  }

  _pushNum() {
    if (this.cur === null) this.cur = [this.num];
    else this.cur.push(this.num);
    this.num = -1;
  }

  _beginString(kind) {
    this.state = STRING;
    this.strKind = kind;
    this.strParts = [];
    this.strLen = 0;
    this.strEsc = false;
  }

  _endString() {
    const s = this.strParts.join('');
    const k = this.strKind;
    this.strParts = [];
    this.state = GROUND;
    if (k === 'osc') this.h.osc(s);
    else if (k === 'dcs') this.h.dcs(s);
    else if (k === 'apc') this.h.apc(s);
  }

  /** Feed a decoded string. */
  parse(s) {
    const h = this.h;
    const n = s.length;
    let i = 0;
    while (i < n) {
      const c = s.charCodeAt(i);
      switch (this.state) {
        case GROUND: {
          if (c >= 0x20 && c !== 0x7f && !(c >= 0x80 && c < 0xa0)) {
            let j = i + 1;
            while (j < n) {
              const d = s.charCodeAt(j);
              if (d < 0x20 || d === 0x7f || (d >= 0x80 && d < 0xa0)) break;
              j++;
            }
            h.print(s, i, j);
            i = j;
            continue;
          }
          if (c === 0x1b) { this.state = ESCAPE; this.inter = ''; }
          else if (c < 0x20) h.execute(c);
          else if (c === 0x9b) this._beginCSI();
          else if (c === 0x9d) this._beginString('osc');
          else if (c === 0x90) this._beginString('dcs');
          else if (c === 0x9f) this._beginString('apc');
          else if (c === 0x98 || c === 0x9e) this._beginString('ign');
          break;
        }
        case ESCAPE: {
          if (c < 0x20) {
            if (c === 0x18 || c === 0x1a) this.state = GROUND;
            else if (c === 0x1b) this.inter = '';
            else h.execute(c);
          } else if (c >= 0x20 && c <= 0x2f) {
            this.inter += s[i];
          } else if (this.inter === '' && c === 0x5b) this._beginCSI();
          else if (this.inter === '' && c === 0x5d) this._beginString('osc');
          else if (this.inter === '' && c === 0x50) this._beginString('dcs');
          else if (this.inter === '' && c === 0x5f) this._beginString('apc');
          else if (this.inter === '' && (c === 0x58 || c === 0x5e)) this._beginString('ign');
          else if (c >= 0x30 && c <= 0x7e) {
            this.state = GROUND;
            h.esc(this.inter, s[i]);
          } else {
            this.state = GROUND;
          }
          break;
        }
        case CSI: {
          if (c >= 0x30 && c <= 0x39) {
            this.num = (this.num < 0 ? 0 : this.num * 10) + (c - 0x30);
            if (this.num > 0x7fffffff) this.num = 0x7fffffff;
          } else if (c === 0x3b) {
            this._pushNum();
            this.params.push(this.cur);
            this.cur = null;
          } else if (c === 0x3a) {
            this._pushNum();
          } else if (c >= 0x3c && c <= 0x3f) {
            if (this.params.length === 0 && this.cur === null && this.num < 0 && this.prefix === '' && this.inter === '') this.prefix = s[i];
            else this.state = CSI_IGNORE;
          } else if (c >= 0x20 && c <= 0x2f) {
            this.inter += s[i];
          } else if (c >= 0x40 && c <= 0x7e) {
            if (this.num >= 0 || this.cur !== null || this.params.length > 0) {
              this._pushNum();
              this.params.push(this.cur);
            }
            this.state = GROUND;
            h.csi(this.prefix, this.params, this.inter, s[i]);
          } else if (c === 0x1b) {
            this.state = ESCAPE; this.inter = '';
          } else if (c === 0x18 || c === 0x1a) {
            this.state = GROUND;
          } else if (c < 0x20) {
            h.execute(c);
          } else {
            this.state = CSI_IGNORE;
          }
          break;
        }
        case CSI_IGNORE: {
          if (c >= 0x40 && c <= 0x7e) this.state = GROUND;
          else if (c === 0x1b) { this.state = ESCAPE; this.inter = ''; }
          else if (c === 0x18 || c === 0x1a) this.state = GROUND;
          else if (c < 0x20) h.execute(c);
          break;
        }
        case STRING: {
          if (this.strEsc) {
            this.strEsc = false;
            this._endString();
            if (c === 0x5c) break; // ST
            // ESC + something else: the string was cut short; reprocess
            this.state = ESCAPE; this.inter = '';
            continue;
          }
          // fast path: copy everything up to the next terminator candidate
          let j = i;
          while (j < n) {
            const d = s.charCodeAt(j);
            if (d === 0x1b || d === 0x07 || d === 0x9c || d === 0x18 || d === 0x1a) break;
            j++;
          }
          if (j > i) {
            if (this.strLen < MAX_STRING) {
              this.strParts.push(s.slice(i, j));
              this.strLen += j - i;
            }
            i = j;
            continue;
          }
          if (c === 0x1b) this.strEsc = true;
          else if (c === 0x07 || c === 0x9c) this._endString();
          else { this.state = GROUND; this.strParts = []; } // CAN / SUB
          break;
        }
      }
      i++;
    }
  }
}
