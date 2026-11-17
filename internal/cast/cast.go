// Package cast reads and writes asciicast v2 recordings, the format of
// asciinema (https://docs.asciinema.org/manual/asciicast/v2/): a JSON header
// line, then one JSON array per event: [seconds, "o", text] for output,
// [seconds, "r", "COLSxROWS"] for a resize, [seconds, "m", label] for a marker.
// Recordings made by washd play in asciinema's own tools as well.
package cast

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Header is the first line of a cast.
type Header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp,omitempty"`
	Title     string            `json:"title,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	IdleLimit float64           `json:"idle_time_limit,omitempty"`
}

// Event is one line after the header.
type Event struct {
	T    float64
	Type string // o, r, m (i is ignored by players)
	Data string
}

// Size parses an "r" event's data.
func (e Event) Size() (cols, rows int, ok bool) {
	c, r, found := strings.Cut(e.Data, "x")
	if !found {
		return 0, 0, false
	}
	cols, err1 := strconv.Atoi(c)
	rows, err2 := strconv.Atoi(r)
	return cols, rows, err1 == nil && err2 == nil && cols > 0 && rows > 0
}

// Writer appends events to a cast. Output is UTF-8 text in JSON, so a
// multi-byte character split across two writes is carried to the next one.
type Writer struct {
	w     io.Writer
	carry []byte
}

// NewWriter writes the header (if h is not nil) and returns a writer.
func NewWriter(w io.Writer, h *Header) (*Writer, error) {
	cw := &Writer{w: w}
	if h != nil {
		h.Version = 2
		b, err := json.Marshal(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return nil, err
		}
	}
	return cw, nil
}

func (cw *Writer) event(t float64, typ, data string) error {
	d, _ := json.Marshal(data) // invalid UTF-8 becomes U+FFFD
	line := fmt.Sprintf("[%.6f, %q, %s]\n", t, typ, d)
	_, err := io.WriteString(cw.w, line)
	return err
}

// Output records terminal output at t seconds.
func (cw *Writer) Output(t float64, p []byte) error {
	if len(cw.carry) > 0 {
		p = append(cw.carry, p...)
		cw.carry = nil
	}
	if cut := incompleteTail(p); cut > 0 {
		cw.carry = append([]byte(nil), p[len(p)-cut:]...)
		p = p[:len(p)-cut]
	}
	if len(p) == 0 {
		return nil
	}
	return cw.event(t, "o", string(p))
}

// Resize records a terminal size change.
func (cw *Writer) Resize(t float64, cols, rows int) error {
	return cw.event(t, "r", fmt.Sprintf("%dx%d", cols, rows))
}

// Marker records a marker (asciinema players can jump to them).
func (cw *Writer) Marker(t float64, label string) error { return cw.event(t, "m", label) }

// incompleteTail returns how many bytes at the end of p start a UTF-8
// sequence that is not complete yet (0 if none).
func incompleteTail(p []byte) int {
	for i := 1; i <= 3 && i <= len(p); i++ {
		b := p[len(p)-i]
		if b < 0x80 {
			return 0 // ASCII: nothing pending
		}
		if utf8.RuneStart(b) {
			if !utf8.FullRune(p[len(p)-i:]) {
				return i
			}
			return 0
		}
	}
	return 0
}

// Cast is a whole recording in memory.
type Cast struct {
	Header Header
	Events []Event
}

// Duration is the time of the last event.
func (c *Cast) Duration() float64 {
	if len(c.Events) == 0 {
		return 0
	}
	return c.Events[len(c.Events)-1].T
}

// Read parses a cast. A truncated last line (a recording still being
// written) is ignored.
func Read(r io.Reader) (*Cast, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	first, err := br.ReadBytes('\n')
	if err != nil && len(first) == 0 {
		return nil, errors.New("empty recording")
	}
	c := &Cast{}
	if err := json.Unmarshal(first, &c.Header); err != nil {
		return nil, fmt.Errorf("not an asciicast: %w", err)
	}
	if c.Header.Version != 2 {
		return nil, fmt.Errorf("asciicast version %d not supported (want 2)", c.Header.Version)
	}
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			var raw []json.RawMessage
			if json.Unmarshal(line, &raw) == nil && len(raw) == 3 {
				var e Event
				if json.Unmarshal(raw[0], &e.T) == nil && json.Unmarshal(raw[1], &e.Type) == nil && json.Unmarshal(raw[2], &e.Data) == nil {
					c.Events = append(c.Events, e)
				}
			}
		}
		if err != nil {
			break
		}
	}
	return c, nil
}

// ReadFile reads a cast file.
func ReadFile(path string) (*Cast, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Stat reads only what `wash watch list` shows: the header and the time of the
// last event (from the file's tail).
func Stat(path string) (Header, float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return Header{}, 0, err
	}
	defer f.Close()
	var h Header
	first, err := bufio.NewReader(f).ReadBytes('\n')
	if err != nil || json.Unmarshal(first, &h) != nil {
		return h, 0, errors.New("no header")
	}
	st, _ := f.Stat()
	off := max(st.Size()-64<<10, 0)
	buf := make([]byte, st.Size()-off)
	_, _ = f.ReadAt(buf, off)
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		var raw []json.RawMessage
		var t float64
		if json.Unmarshal([]byte(lines[i]), &raw) == nil && len(raw) == 3 && json.Unmarshal(raw[0], &t) == nil {
			return h, t, nil
		}
	}
	return h, 0, nil
}
