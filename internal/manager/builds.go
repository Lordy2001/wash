package manager

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// wosh builds for chained hops.
//
// A host in the middle of a chained hop (`wosh HOST` inside a web session)
// that has no wosh build for HOST's platform asks its client for one over a
// "build" stream. In wash the client is the browser, which asks washd: washd
// serves the per-platform builds next to its wosh binary (`make dist` in the
// wosh repo: <dir>/dist/wosh-<os>-<arch>), from $WOSH_DIST, or from
// ~/.cache/wosh, exactly where wosh itself looks. Stamp and gzip match
// wosh's internal/build and internal/client/push.go.

var buildKeyRE = regexp.MustCompile(`^[a-z0-9]+-[a-z0-9]+$`)

type woshBuild struct {
	stamp string
	gz    []byte
}

var (
	buildMu    sync.Mutex
	buildCache = map[string]*woshBuild{} // path+mtime -> build
)

func (m *Manager) woshBuild(key string) (*woshBuild, error) {
	if strings.HasSuffix(key, ".xz") {
		return nil, errors.New("no xz build ready") // wosh falls back to gzip
	}
	if !buildKeyRE.MatchString(key) {
		return nil, fmt.Errorf("bad build key %q", key)
	}
	goos, arch, _ := strings.Cut(key, "-")
	var cands []string
	if p, err := m.config().WoshPath(); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		if goos == runtime.GOOS && arch == runtime.GOARCH {
			cands = append(cands, p)
		}
		cands = append(cands, filepath.Join(filepath.Dir(p), "dist", "wosh-"+key), filepath.Join(filepath.Dir(p), "wosh-"+key))
	}
	if d := os.Getenv("WOSH_DIST"); d != "" {
		cands = append(cands, filepath.Join(d, "wosh-"+key))
	}
	if home, err := os.UserHomeDir(); err == nil {
		cands = append(cands, filepath.Join(home, ".cache", "wosh", "wosh-"+key))
	}
	for _, p := range cands {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		ck := fmt.Sprintf("%s@%d", p, st.ModTime().UnixNano())
		buildMu.Lock()
		b := buildCache[ck]
		buildMu.Unlock()
		if b != nil {
			return b, nil
		}
		bi, err := buildinfo.ReadFile(p)
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var t int64
		for _, s := range bi.Settings {
			if s.Key == "vcs.time" {
				if tt, err := time.Parse(time.RFC3339, s.Value); err == nil {
					t = tt.Unix()
				}
			}
		}
		h := sha256.Sum256(raw)
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = io.Copy(zw, bytes.NewReader(raw))
		_ = zw.Close()
		b = &woshBuild{stamp: fmt.Sprintf("%d-%s", t, hex.EncodeToString(h[:])[:12]), gz: buf.Bytes()}
		buildMu.Lock()
		buildCache[ck] = b
		buildMu.Unlock()
		return b, nil
	}
	return nil, fmt.Errorf("no wosh build for %s on the wash host (looked in %s; run `make dist` in the wosh repo)", key, strings.Join(cands, ", "))
}
