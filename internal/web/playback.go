package web

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"wash/internal/link"
)

// Published recordings (`wash watch host`). washd uploads an asciicast over
// its link; anyone with the link can watch it at /playback/UUID (the UUID is
// the only secret). Files live in Config.PlaybackDir as UUID.cast with a
// UUID.json sidecar naming the user that owns it.

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const maxPlaybacksPerUser = 200

type playbackMeta struct {
	User    string    `json:"user"`
	Title   string    `json:"title,omitempty"`
	Size    int64     `json:"size"`
	Created time.Time `json:"created"`
}

type upload struct {
	user string
	f    *os.File
	next int
	size int64
	at   time.Time
}

func (s *Server) playbackPath(uuid, ext string) string {
	return filepath.Join(s.cfg.PlaybackDir, uuid+ext)
}

func (s *Server) playbackMeta(uuid string) (playbackMeta, error) {
	var pm playbackMeta
	if !uuidRE.MatchString(uuid) || s.cfg.PlaybackDir == "" {
		return pm, os.ErrNotExist
	}
	b, err := os.ReadFile(s.playbackPath(uuid, ".json"))
	if err != nil {
		return pm, err
	}
	return pm, json.Unmarshal(b, &pm)
}

func (s *Server) countPlaybacks(user string) int {
	n := 0
	ents, _ := os.ReadDir(s.cfg.PlaybackDir)
	for _, e := range ents {
		if uuid, ok := strings.CutSuffix(e.Name(), ".json"); ok {
			if pm, err := s.playbackMeta(uuid); err == nil && pm.User == user {
				n++
			}
		}
	}
	return n
}

func (s *Server) playbackPut(user string, data json.RawMessage) (any, error) {
	if s.cfg.PlaybackDir == "" {
		return nil, errors.New("this wash-web does not host recordings")
	}
	var ch link.PlaybackChunk
	if err := json.Unmarshal(data, &ch); err != nil || !uuidRE.MatchString(ch.UUID) {
		return nil, errors.New("bad playback chunk")
	}
	if err := os.MkdirAll(s.cfg.PlaybackDir, 0o700); err != nil {
		return nil, err
	}
	old, oerr := s.playbackMeta(ch.UUID)
	if oerr == nil && old.User != user {
		return nil, errors.New("playback id taken")
	}
	s.mu.Lock()
	up := s.uploads[ch.UUID]
	if ch.Seq == 0 {
		if up != nil {
			up.f.Close()
			os.Remove(up.f.Name())
		}
		if oerr != nil && s.countPlaybacks(user) >= maxPlaybacksPerUser {
			s.mu.Unlock()
			return nil, fmt.Errorf("at most %d hosted recordings per user", maxPlaybacksPerUser)
		}
		f, err := os.CreateTemp(s.cfg.PlaybackDir, ".up-*")
		if err != nil {
			s.mu.Unlock()
			return nil, err
		}
		up = &upload{user: user, f: f}
		s.uploads[ch.UUID] = up
	}
	if up == nil || up.user != user || up.next != ch.Seq {
		s.mu.Unlock()
		return nil, errors.New("playback upload out of order")
	}
	up.next++
	up.at = time.Now()
	s.mu.Unlock()

	abort := func(err error) (any, error) {
		s.mu.Lock()
		if s.uploads[ch.UUID] == up {
			delete(s.uploads, ch.UUID)
		}
		s.mu.Unlock()
		up.f.Close()
		os.Remove(up.f.Name())
		return nil, err
	}
	up.size += int64(len(ch.Data))
	if s.cfg.PlaybackMax > 0 && up.size > s.cfg.PlaybackMax {
		return abort(fmt.Errorf("recording too large (limit %d MiB, WASH_PLAYBACK_MAX_MB)", s.cfg.PlaybackMax>>20))
	}
	if _, err := up.f.Write(ch.Data); err != nil {
		return abort(err)
	}
	if !ch.Last {
		return struct{}{}, nil
	}
	s.mu.Lock()
	delete(s.uploads, ch.UUID)
	s.mu.Unlock()
	if err := up.f.Close(); err != nil {
		return abort(err)
	}
	pm := playbackMeta{User: user, Title: ch.Title, Size: up.size, Created: time.Now()}
	if oerr == nil {
		pm.Created = old.Created
	}
	mb, _ := json.Marshal(pm)
	if err := os.WriteFile(s.playbackPath(ch.UUID, ".json.tmp"), mb, 0o600); err != nil {
		return abort(err)
	}
	if err := os.Rename(up.f.Name(), s.playbackPath(ch.UUID, ".cast")); err != nil {
		return abort(err)
	}
	if err := os.Rename(s.playbackPath(ch.UUID, ".json.tmp"), s.playbackPath(ch.UUID, ".json")); err != nil {
		return nil, err
	}
	log.Printf("playback %s published by %s (%d bytes)", ch.UUID, user, up.size)
	path := "/playback/" + ch.UUID
	info := link.PlaybackInfo{UUID: ch.UUID, Path: path, Size: up.size}
	if s.cfg.PublicURL != "" {
		info.URL = strings.TrimRight(s.cfg.PublicURL, "/") + path
	}
	return info, nil
}

func (s *Server) playbackDel(user string, data json.RawMessage) (any, error) {
	var ref link.PlaybackRef
	if err := json.Unmarshal(data, &ref); err != nil {
		return nil, err
	}
	pm, err := s.playbackMeta(ref.UUID)
	if errors.Is(err, os.ErrNotExist) {
		return struct{}{}, nil // already gone
	}
	if err != nil {
		return nil, err
	}
	if pm.User != user {
		return nil, errors.New("not your playback")
	}
	_ = os.Remove(s.playbackPath(ref.UUID, ".json")) // first: the page 404s at once
	if err := os.Remove(s.playbackPath(ref.UUID, ".cast")); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	log.Printf("playback %s removed by %s", ref.UUID, user)
	return struct{}{}, nil
}

// expireUploads drops uploads that stalled (called by the janitor).
func (s *Server) expireUploadsLocked(now time.Time) {
	for k, up := range s.uploads {
		if now.Sub(up.at) > 10*time.Minute {
			up.f.Close()
			os.Remove(up.f.Name())
			delete(s.uploads, k)
		}
	}
}

// RemovePlaybacks deletes every playback of user in dir (wash-web unenroll).
func RemovePlaybacks(dir, user string) int {
	n := 0
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		uuid, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !uuidRE.MatchString(uuid) {
			continue
		}
		var pm playbackMeta
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err != nil || json.Unmarshal(b, &pm) != nil || pm.User != user {
			continue
		}
		os.Remove(filepath.Join(dir, uuid+".json"))
		os.Remove(filepath.Join(dir, uuid+".cast"))
		n++
	}
	return n
}

// handlePlaybackPage serves the player for /playback/UUID.
func (s *Server) handlePlaybackPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	if _, err := s.playbackMeta(r.PathValue("id")); err != nil {
		http.Error(w, "no such recording", http.StatusNotFound)
		return
	}
	page, err := fs.ReadFile(s.cfg.Static, "playback.html")
	if err != nil {
		http.Error(w, "player missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(page)
}

// handlePlaybackCast serves the recording itself (asciicast v2).
func (s *Server) handlePlaybackCast(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	uuid := r.PathValue("id")
	if _, err := s.playbackMeta(uuid); err != nil {
		http.Error(w, "no such recording", http.StatusNotFound)
		return
	}
	f, err := os.Open(s.playbackPath(uuid, ".cast"))
	if err != nil {
		http.Error(w, "no such recording", http.StatusNotFound)
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", "application/x-asciicast")
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Disposition", `inline; filename="`+uuid[:8]+`.cast"`)
	h.Set("Vary", "Accept-Encoding")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		_, _ = io.Copy(gz, f)
		return
	}
	st, _ := f.Stat()
	http.ServeContent(w, r, "", st.ModTime(), f)
}
