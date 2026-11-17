package manager

import (
	"encoding/binary"
	"testing"
	"time"

	"wash/internal/wosh"
)

type sent [][]byte

func (s *sent) Send(b []byte) error { *s = append(*s, append([]byte(nil), b...)); return nil }

func out(off uint64, data string) []byte {
	b := inputFrame(off, data)
	b[0] = wosh.FOutput
	return b
}

func TestAnswerStartup(t *testing.T) {
	frames := make(chan []byte, 8)
	ack := make([]byte, 9)
	ack[0] = wosh.FAck
	binary.BigEndian.PutUint64(ack[1:], 5)
	frames <- ack
	// fish: queries, DA1 split across two frames, then a second DA1 as ESC [ 0 c
	frames <- out(0, "\x1b[?u\x1b[>0q\x1b")
	frames <- out(10, "[c prompt \x1b[0c")
	var s sent
	start := time.Now()
	answerStartup(&s, frames, time.Second, 50*time.Millisecond, 2*time.Second)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("waited %s after output went quiet", d)
	}
	if len(s) != 2 {
		t.Fatalf("%d replies, want 2", len(s))
	}
	for i, f := range s {
		off := binary.BigEndian.Uint64(f[1:9])
		if f[0] != wosh.FInput || string(f[9:]) != da1Reply || off != 5+uint64(i*len(da1Reply)) {
			t.Fatalf("reply %d: %q at %d", i, f, off)
		}
	}
	if countDA1([]byte("x\x1b[c"), 4) != 0 {
		t.Fatal("a query already seen was counted again")
	}
}
