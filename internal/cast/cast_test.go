package cast

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, &Header{Width: 100, Height: 30, Title: "t"})
	if err != nil {
		t.Fatal(err)
	}
	euro := []byte("€") // 3 bytes, split across writes
	_ = w.Output(0.5, append([]byte("a"), euro[:1]...))
	_ = w.Output(0.6, append(euro[1:], 'b'))
	_ = w.Resize(1, 90, 20)
	_ = w.Output(1.5, []byte("\x1b[31mred\x1b[0m\r\n"))
	buf.WriteString(`[2.0, "o", "trunc`) // a recording still being written
	c, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if c.Header.Version != 2 || c.Header.Width != 100 || len(c.Events) != 4 {
		t.Fatalf("%+v", c)
	}
	if c.Events[0].Data != "a" || c.Events[1].Data != "€b" {
		t.Fatalf("utf-8 carry: %q %q", c.Events[0].Data, c.Events[1].Data)
	}
	if cols, rows, ok := c.Events[2].Size(); !ok || cols != 90 || rows != 20 {
		t.Fatal("resize")
	}
	if !strings.Contains(c.Events[3].Data, "\x1b[31m") || c.Duration() != 1.5 {
		t.Fatalf("%q %v", c.Events[3].Data, c.Duration())
	}
}

// A recording resumed after a washd restart is two gzip members, the last
// one possibly cut off (still being written).
func TestGzipMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.cast.gz")
	f, _ := os.Create(path)
	z1 := gzip.NewWriter(f)
	w, _ := NewWriter(z1, &Header{Width: 80, Height: 24})
	_ = w.Output(1, []byte("one\r\n"))
	z1.Close()
	z2 := gzip.NewWriter(f)
	w, _ = NewWriter(z2, nil)
	_ = w.Output(2, []byte("two\r\n"))
	io.WriteString(z2, `[3.0, "o", "cut`)
	z2.Flush() // no trailer: still recording
	f.Close()
	c, err := ReadFile(path)
	if err != nil || len(c.Events) != 2 || c.Events[1].Data != "two\r\n" {
		t.Fatalf("%v %+v", err, c)
	}
	var buf bytes.Buffer
	n, err := Compress(&buf, path)
	if err != nil || n == 0 {
		t.Fatal(n, err)
	}
	zr, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(zr)
	if err != nil || int64(len(all)) != n || strings.Contains(string(all), "cut") || !strings.Contains(string(all), "two") {
		t.Fatalf("compressed: %v %q", err, all)
	}
}
