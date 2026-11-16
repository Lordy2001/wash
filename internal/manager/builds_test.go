package manager

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The stamp washd computes must be the one wosh reports for itself.
func TestWoshBuildStamp(t *testing.T) {
	bin := os.Getenv("WASH_TEST_WOSH")
	if bin == "" {
		bin, _ = filepath.Abs("../../../wosh/bin/wosh")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no wosh binary")
	}
	out, err := exec.Command(bin, "_proto").Output()
	if err != nil {
		t.Skip("wosh _proto:", err)
	}
	m := &Manager{cfg: Config{Wosh: bin}}
	b, err := m.woshBuild(runtime.GOOS + "-" + runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), b.stamp) {
		t.Fatalf("stamp %s not in `wosh _proto` output %q", b.stamp, out)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b.gz))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(zr)
	want, _ := os.ReadFile(bin)
	if !bytes.Equal(raw, want) {
		t.Fatal("gzip does not round-trip to the binary")
	}
	if _, err := m.woshBuild("linux-amd64.xz"); err == nil {
		t.Fatal("xz should be refused")
	}
	if _, err := m.woshBuild("../etc"); err == nil {
		t.Fatal("bad key accepted")
	}
}
