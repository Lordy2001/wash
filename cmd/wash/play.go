package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
	"golang.org/x/term"

	"wash/internal/cast"
)

// `wash watch play`: a terminal player for asciicast recordings. The
// recording runs in a virtual terminal (charmbracelet/x/vt) drawn inside a
// frame with a title bar, a progress bar and key help, so the controls never
// get in the recording's way. --raw instead writes the recording straight to
// this terminal, as `asciinema play` does (exact rendering, kitty images,
// but no frame; the terminal should be at least the recording's size).

var speeds = []float64{0.25, 0.5, 1, 1.5, 2, 3, 4, 8, 16}

func play(args []string) error {
	raw := has(args, "--raw")
	speedArg, args := flagVal(args, "--speed")
	idleArg, args := flagVal(args, "--idle")
	var pos []string
	for _, a := range args {
		if a != "--raw" {
			pos = append(pos, a)
		}
	}
	if len(pos) != 1 {
		return errors.New("usage: wash watch play FILE_ID|FILE.cast [--raw] [--speed N] [--idle SECONDS|0]")
	}
	path, id, err := recordingFile(pos[0])
	if err != nil {
		return err
	}
	c, err := cast.ReadFile(path)
	if err != nil {
		return err
	}
	if len(c.Events) == 0 {
		return errors.New("the recording is empty")
	}
	p := &player{c: c, id: id, speed: 2, idle: c.Header.IdleLimit, out: os.Stdout}
	if p.idle <= 0 {
		p.idle = 2
	}
	p.idleOn = true
	if idleArg != "" {
		v, err := strconv.ParseFloat(idleArg, 64)
		if err != nil || v < 0 {
			return fmt.Errorf("bad --idle %q", idleArg)
		}
		p.idle, p.idleOn = v, v > 0
		if v == 0 {
			p.idle = 2
		}
	}
	if speedArg != "" {
		v, err := strconv.ParseFloat(speedArg, 64)
		if err != nil || v <= 0 {
			return fmt.Errorf("bad --speed %q", speedArg)
		}
		p.speed = -1
		p.customSpeed = v
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("wash watch play needs a terminal")
	}
	if raw {
		return p.runRaw()
	}
	return p.run()
}

type player struct {
	c           *cast.Cast
	id          string
	out         io.Writer
	at          []float64 // event times with long pauses cut to idle
	dur         float64
	idle        float64
	idleOn      bool
	speed       int // index into speeds; -1: customSpeed
	customSpeed float64

	em         *vt.Emulator
	next       int     // next event to apply
	pos        float64 // playback position (seconds, on the at timeline)
	cols, rows int     // recording's terminal size now
	playing    bool
	title      string // OSC title set by the recording

	w, h     int
	panX     int
	panY     int
	prev     []string // last frame, by screen row
	flash    string
	flashEnd time.Time
}

func (p *player) rate() float64 {
	if p.speed < 0 {
		return p.customSpeed
	}
	return speeds[p.speed]
}

func (p *player) timeline() {
	p.at = make([]float64, len(p.c.Events))
	prev, acc := 0.0, 0.0
	for i, e := range p.c.Events {
		d := max(e.T-prev, 0)
		if p.idleOn && d > p.idle {
			d = p.idle
		}
		acc += d
		p.at[i] = acc
		prev = e.T
	}
	p.dur = acc
}

func (p *player) reset() {
	if p.em != nil {
		_ = p.em.Close()
	}
	p.cols, p.rows = max(p.c.Header.Width, 1), max(p.c.Header.Height, 1)
	p.em = vt.NewEmulator(p.cols, p.rows)
	p.em.SetCallbacks(vt.Callbacks{Title: func(s string) { p.title = s }})
	go func(em *vt.Emulator) { _, _ = io.Copy(io.Discard, em) }(p.em) // replies to queries
	p.next = 0
	p.title = ""
}

// seek applies events up to t (from the start if t is behind).
func (p *player) seek(t float64) {
	t = min(max(t, 0), p.dur)
	if p.em == nil || t < p.pos && (p.next == 0 || t < p.at[p.next-1]) {
		p.reset()
	}
	for p.next < len(p.c.Events) && p.at[p.next] <= t {
		e := p.c.Events[p.next]
		switch e.Type {
		case "o":
			_, _ = p.em.WriteString(e.Data)
		case "r":
			if c, r, ok := e.Size(); ok {
				p.em.Resize(c, r)
				p.cols, p.rows = c, r
			}
		}
		p.next++
	}
	p.pos = t
}

func (p *player) say(s string) {
	p.flash, p.flashEnd = s, time.Now().Add(1500*time.Millisecond)
}

func (p *player) run() error {
	fd := int(os.Stdin.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, old)
	fmt.Fprint(p.out, "\x1b[?1049h\x1b[?25l\x1b[2J")
	defer fmt.Fprint(p.out, "\x1b[0m\x1b[?25h\x1b[?1049l")

	keys := make(chan string, 16)
	go readKeys(keys)
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)

	p.timeline()
	p.seek(0)
	p.playing = true
	p.size()
	p.draw()
	tick := time.NewTicker(33 * time.Millisecond)
	defer tick.Stop()
	last := time.Now()
	for {
		select {
		case k, ok := <-keys:
			if !ok || !p.key(k) {
				return nil
			}
			p.draw()
		case <-winch:
			p.size()
			p.draw()
		case now := <-tick.C:
			if p.playing {
				t := p.pos + now.Sub(last).Seconds()*p.rate()
				if t >= p.dur {
					t, p.playing = p.dur, false
				}
				p.seek(t)
			}
			last = now
			p.draw()
		}
	}
}

// key handles one key; false quits.
func (p *player) key(k string) bool {
	jump := func(t float64) {
		p.seek(t)
		if p.pos >= p.dur {
			p.playing = false
		}
	}
	switch k {
	case "q", "Q", "\x03", "\x1b":
		return false
	case " ", "p", "k":
		if !p.playing && p.pos >= p.dur {
			p.seek(0)
		}
		p.playing = !p.playing
	case "\x1b[C", "l": // right
		jump(p.pos + 5)
	case "\x1b[D", "h": // left
		jump(p.pos - 5)
	case "\x1b[A": // up
		jump(p.pos + 30)
	case "\x1b[B": // down
		jump(p.pos - 30)
	case "\x1b[H", "\x1b[1~", "g":
		jump(0)
	case "\x1b[F", "\x1b[4~", "G":
		jump(p.dur)
	case ".": // one event forward (paused)
		p.playing = false
		if p.next < len(p.at) {
			jump(p.at[p.next])
		}
	case ",": // one event back
		p.playing = false
		if p.next >= 2 {
			jump(p.at[p.next-2])
		} else {
			jump(0)
		}
	case "+", "=", ">":
		if p.speed < 0 {
			p.speed = 2
		}
		p.speed = min(p.speed+1, len(speeds)-1)
		p.say(fmt.Sprintf("speed %gx", p.rate()))
	case "-", "_", "<":
		if p.speed < 0 {
			p.speed = 2
		}
		p.speed = max(p.speed-1, 0)
		p.say(fmt.Sprintf("speed %gx", p.rate()))
	case "i":
		// keep the position on the same event when the timeline changes
		at := 0.0
		if p.next > 0 {
			at = p.c.Events[p.next-1].T
		}
		p.idleOn = !p.idleOn
		p.timeline()
		for i, e := range p.c.Events {
			if e.T >= at {
				p.pos = p.at[i]
				break
			}
		}
		p.seek(p.pos)
		if p.idleOn {
			p.say(fmt.Sprintf("pauses cut to %gs", p.idle))
		} else {
			p.say("real time pauses")
		}
	default:
		if len(k) == 1 && k[0] >= '0' && k[0] <= '9' {
			jump(p.dur * float64(k[0]-'0') / 10)
		}
	}
	return true
}

func (p *player) size() {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w < 20 || h < 8 {
		w, h = max(w, 20), max(h, 8)
	}
	p.w, p.h = w, h
	p.prev = nil
	fmt.Fprint(p.out, "\x1b[2J")
}

// readKeys sends key presses (an escape sequence is one key). Strings the
// terminal sends on its own (OSC/DCS/APC replies, e.g. to a colour or
// clipboard query in a raw playback) are dropped, so their bytes never act
// as keys.
func readKeys(ch chan<- string) {
	defer close(ch)
	buf := make([]byte, 256)
	inString, esc := false, false // inside a terminal reply string; its last byte was ESC
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			return
		}
		s := string(buf[:n])
		for s != "" {
			if inString {
				c := s[0]
				s = s[1:]
				switch {
				case c == 0x07 || esc && c == '\\':
					inString, esc = false, false
				default:
					esc = c == 0x1b
				}
				continue
			}
			if s[0] == 0x1b && len(s) >= 2 && strings.IndexByte("]P_^", s[1]) >= 0 {
				inString, esc, s = true, false, s[2:]
				continue
			}
			k := s[:1]
			if s[0] == 0x1b && len(s) >= 3 && (s[1] == '[' || s[1] == 'O') {
				i := 2
				for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
					i++
				}
				k = s[:min(i+1, len(s))]
				if s[1] == 'O' { // SS3 arrows: same as CSI
					k = "\x1b[" + k[2:]
				}
			}
			ch <- k
			s = s[len(k):] // an SS3 key was rewritten to CSI of the same length
		}
	}
}

// osc52Filter drops OSC 52 (clipboard) sequences from recorded output, so
// playing a recording never sets or reads this machine's clipboard. A
// sequence may be split across events.
type osc52Filter struct {
	in   bool   // inside an OSC 52
	esc  bool   // ...and its last byte was ESC
	hold string // a possible start of one at the end of the last chunk
}

const osc52 = "\x1b]52;"

func (f *osc52Filter) filter(s string) string {
	s = f.hold + s
	f.hold = ""
	var out strings.Builder
	for s != "" {
		if f.in {
			i := 0
			for ; i < len(s); i++ {
				c := s[i]
				if c == 0x07 || f.esc && c == '\\' {
					f.in, f.esc = false, false
					break
				}
				f.esc = c == 0x1b
			}
			s = s[min(i+1, len(s)):]
			continue
		}
		i := strings.Index(s, osc52)
		if i < 0 {
			// keep a tail that may begin an OSC 52 for the next chunk
			for k := min(len(osc52)-1, len(s)); k > 0; k-- {
				if strings.HasPrefix(osc52, s[len(s)-k:]) {
					f.hold = s[len(s)-k:]
					s = s[:len(s)-k]
					break
				}
			}
			out.WriteString(s)
			break
		}
		out.WriteString(s[:i])
		f.in, f.esc = true, false
		s = s[i+len(osc52):]
	}
	return out.String()
}

// Styles (256 colours: work on any modern terminal).
const (
	stBar    = "\x1b[0;48;5;236;38;5;252m"
	stAccent = "\x1b[0;48;5;236;38;5;75;1m"
	stBorder = "\x1b[0;38;5;240m"
	stDim    = "\x1b[0;38;5;244m"
	stKey    = "\x1b[0;48;5;238;38;5;81;1m"
	stDone   = "\x1b[0;38;5;75m"
	stReset  = "\x1b[0m"
)

func pad(s string, w int) string {
	if sw := ansi.StringWidth(s); sw < w {
		return s + strings.Repeat(" ", w-sw)
	}
	return ansi.Truncate(s, w, "…")
}

func (p *player) draw() {
	W, H := p.w, p.h
	lines := make([]string, H)
	// title bar
	state := "▶"
	if !p.playing {
		state = "⏸"
		if p.pos >= p.dur {
			state = "■"
		}
	}
	name := p.c.Header.Title
	if p.title != "" {
		name += " · " + p.title
	}
	left := fmt.Sprintf(" %s%s wash playback %s %s · %s", stAccent, state, stBar, p.id, name)
	right := fmt.Sprintf("%dx%d ", p.cols, p.rows)
	lines[0] = stBar + pad(left, W-ansi.StringWidth(right)) + right + stReset

	// the recording's screen, framed, centered or cropped to follow the cursor
	vw, vh := W-2, H-5
	cw, ch := min(p.cols, vw), min(p.rows, vh)
	x0 := (W - (cw + 2)) / 2
	y0 := 1 + (vh-ch)/2
	cur := p.em.CursorPosition()
	if p.cols > vw {
		if cur.X < p.panX {
			p.panX = cur.X
		} else if cur.X >= p.panX+vw {
			p.panX = cur.X - vw + 1
		}
		p.panX = min(max(p.panX, 0), p.cols-vw)
	} else {
		p.panX = 0
	}
	if p.rows > vh {
		if cur.Y < p.panY {
			p.panY = cur.Y
		} else if cur.Y >= p.panY+vh {
			p.panY = cur.Y - vh + 1
		}
		p.panY = min(max(p.panY, 0), p.rows-vh)
	} else {
		p.panY = 0
	}
	screen := strings.Split(strings.ReplaceAll(p.em.Render(), "\r", ""), "\n")
	indent := strings.Repeat(" ", x0)
	crop := ""
	if p.cols > vw || p.rows > vh {
		crop = fmt.Sprintf(" cropped: terminal smaller than %dx%d ", p.cols, p.rows)
	}
	top := "╭" + strings.Repeat("─", cw) + "╮"
	if crop != "" && ansi.StringWidth(crop) < cw-2 {
		top = "╭─" + crop + strings.Repeat("─", cw-1-ansi.StringWidth(crop)) + "╮"
	}
	lines[y0] = indent + stBorder + top + stReset
	for r := 0; r < ch; r++ {
		y := p.panY + r
		row := ""
		if y < len(screen) {
			row = ansi.Cut(screen[y], p.panX, p.panX+cw)
		}
		// the recorded cursor, drawn as a block
		if !p.em.CursorHidden() && cur.Y == y && cur.X >= p.panX && cur.X < p.panX+cw {
			if cell := p.em.CellAt(cur.X, cur.Y); cell != nil {
				glyph := cell.Content
				if glyph == "" || glyph == "\x00" {
					glyph = " "
				}
				before := ansi.Cut(row, 0, cur.X-p.panX)
				after := ansi.Cut(row, cur.X-p.panX+max(cell.Width, 1), cw)
				row = pad(before, cur.X-p.panX) + stReset + "\x1b[7m" + glyph + stReset + after
			}
		}
		lines[y0+1+r] = indent + stBorder + "│" + stReset + pad(row, cw) + stReset + stBorder + "│" + stReset
	}
	lines[y0+1+ch] = indent + stBorder + "╰" + strings.Repeat("─", cw) + "╯" + stReset

	// progress bar
	tl := fmt.Sprintf(" %s %s ", state, clock(p.pos))
	tr := fmt.Sprintf(" %s  %gx ", clock(p.dur), p.rate())
	if p.flash != "" && time.Now().Before(p.flashEnd) {
		tr = " " + p.flash + "  " + tr
	}
	bw := max(W-ansi.StringWidth(tl)-ansi.StringWidth(tr), 4)
	done := 0
	if p.dur > 0 {
		done = int(float64(bw-1) * p.pos / p.dur)
	}
	bar := stDone + strings.Repeat("━", done) + "\x1b[1m●" + stReset + stDim + strings.Repeat("─", bw-1-done) + stReset
	lines[H-2] = stAccent + tl + stReset + bar + stDim + tr + stReset

	// key help, textual style
	help := []struct{ k, v string }{{"q", "quit"}, {"space", "play/pause"}, {"←→", "5s"}, {"↑↓", "30s"}, {"0-9", "jump"},
		{",.", "step"}, {"+-", "speed"}, {"i", "idle"}}
	var hb strings.Builder
	for _, x := range help {
		hb.WriteString(stKey + " " + x.k + " " + stReset + stDim + " " + x.v + "  ")
	}
	lines[H-1] = pad(hb.String(), W) + stReset

	var out strings.Builder
	out.WriteString("\x1b[?2026h")
	if len(p.prev) != H {
		p.prev = make([]string, H)
		out.WriteString("\x1b[2J")
	}
	for i, l := range lines {
		if l == p.prev[i] && l != "" {
			continue
		}
		fmt.Fprintf(&out, "\x1b[%d;1H%s\x1b[0m\x1b[K", i+1, l)
		p.prev[i] = l
	}
	out.WriteString("\x1b[?2026l")
	_, _ = io.WriteString(p.out, out.String())
}

// runRaw plays straight to this terminal, like `asciinema play`.
func (p *player) runRaw() error {
	fd := int(os.Stdin.Fd())
	if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil && (w < p.c.Header.Width || h < p.c.Header.Height) {
		fmt.Fprintf(os.Stderr, "note: the recording is %dx%d, this terminal %dx%d; it may not look right\n", p.c.Header.Width, p.c.Header.Height, w, h)
		time.Sleep(1500 * time.Millisecond)
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, old)
	defer fmt.Fprint(p.out, "\x1b[0m\x1b[?25h\r\n")
	keys := make(chan string, 16)
	go readKeys(keys)
	p.timeline()
	var clip osc52Filter
	paused := false
	start := time.Now()
	base := 0.0 // position when start was taken
	for i := 0; i < len(p.c.Events); {
		e := p.c.Events[i]
		wait := time.Duration((p.at[i]-base)/p.rate()*float64(time.Second)) - time.Since(start)
		if paused {
			wait = time.Hour
		}
		select {
		case k, ok := <-keys:
			switch {
			case !ok || k == "q" || k == "\x03":
				return nil
			case k == " ":
				if paused {
					start, base = time.Now(), p.at[max(i-1, 0)]
				}
				paused = !paused
			case k == "." && paused:
				if e.Type == "o" {
					_, _ = io.WriteString(p.out, clip.filter(e.Data))
				}
				i++
			}
			continue
		case <-time.After(max(wait, 0)):
		}
		if e.Type == "o" {
			_, _ = io.WriteString(p.out, clip.filter(e.Data))
		}
		i++
	}
	return nil
}
