package manager

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"wash/internal/cast"
	"wash/internal/link"
	"wash/internal/paths"
	"wash/internal/wosh"
)

// Recordings (`wash watch`). washd records a session by joining it as a
// passive wosh peer: it receives the same output frames a watching browser
// does, can never take control, and writes them as an asciicast v2 file.
// Output is addressed by byte offset, so a recorder that reconnects (or a
// washd restart) continues exactly where it stopped, with no gap or repeat.

// Recording is one recording's state (recordings.json).
type Recording struct {
	ID      string    `json:"id"`
	Session string    `json:"session"`
	Name    string    `json:"name"`
	Started time.Time `json:"started"`
	Stopped time.Time `json:"stopped,omitzero"`
	State   string    `json:"state"`            // recording | stopped
	Reason  string    `json:"reason,omitempty"` // why it stopped, or the last connection error
	Off     uint64    `json:"off"`              // next session output offset to record
	Dur     float64   `json:"dur"`              // seconds recorded
	Cols    int       `json:"cols,omitempty"`
	Rows    int       `json:"rows,omitempty"`
	Hosted  *Hosted   `json:"hosted,omitempty"`
}

// Hosted: the recording is published on wash-web for playback.
type Hosted struct {
	UUID string    `json:"uuid"`
	URL  string    `json:"url"`
	At   time.Time `json:"at"`
	Size int64     `json:"size"` // bytes published (less than the file while still recording)
}

// RecordingInfo is what `wash watch list` shows.
type RecordingInfo struct {
	Recording
	Size int64  `json:"size"`
	Path string `json:"path"`
}

const (
	recIdleLimit = 2.0 // header hint: players shorten pauses to this (they can turn it off)
	recSaveEvery = 5 * time.Second
)

type recorder struct {
	id   string
	stop chan struct{}
	done chan struct{}
}

var errOldDaemon = errors.New("this session's wosh daemon cannot record without taking control: update wosh and start a new session")

func (m *Manager) loadRecordings() {
	var rs []*Recording
	_ = readJSON(paths.RecordingsFile(), &rs)
	m.mu.Lock()
	for _, r := range rs {
		m.recs[r.ID] = r
	}
	m.mu.Unlock()
}

func (m *Manager) saveRecordingsLocked() {
	rs := []*Recording{}
	for _, r := range m.recs {
		rs = append(rs, r)
	}
	if err := writeJSON(paths.RecordingsFile(), rs); err != nil {
		log.Printf("save recordings: %v", err)
	}
}

// resumeRecordings restarts the recorders that were running when washd stopped.
func (m *Manager) resumeRecordings() {
	m.mu.Lock()
	var ids []string
	for id, r := range m.recs {
		if r.State == "recording" {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	for _, id := range ids {
		m.startRecorder(id)
	}
}

func (m *Manager) getRec(id string) (*Recording, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.recs[id]; r != nil {
		return r, nil
	}
	var hit *Recording
	for k, r := range m.recs {
		if len(id) >= 3 && strings.HasPrefix(k, id) {
			if hit != nil {
				return nil, fmt.Errorf("recording id %s is ambiguous", id)
			}
			hit = r
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("no recording %s", id)
	}
	return hit, nil
}

func (m *Manager) recInfoLocked(r *Recording) RecordingInfo {
	ri := RecordingInfo{Recording: *r, Path: paths.RecordingFile(r.ID)}
	if r.Hosted != nil {
		h := *r.Hosted
		ri.Hosted = &h
	}
	if st, err := os.Stat(ri.Path); err == nil {
		ri.Size = st.Size()
	}
	return ri
}

// Recordings lists recordings, oldest first.
func (m *Manager) Recordings() []RecordingInfo {
	m.mu.Lock()
	out := []RecordingInfo{}
	for _, r := range m.recs {
		out = append(out, m.recInfoLocked(r))
	}
	m.mu.Unlock()
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Started.Before(out[j-1].Started); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// StartRecording starts recording a session as a passive viewer.
func (m *Manager) StartRecording(sessionID string) (RecordingInfo, error) {
	s, err := m.get(sessionID)
	if err != nil {
		return RecordingInfo{}, err
	}
	m.mu.Lock()
	for _, r := range m.recs {
		if r.Session == s.ID && r.State == "recording" {
			m.mu.Unlock()
			return RecordingInfo{}, fmt.Errorf("session %s is already being recorded (%s)", s.ID, r.ID)
		}
	}
	r := &Recording{ID: randHex(4), Session: s.ID, Name: s.Name, Started: time.Now(), State: "recording"}
	for m.recs[r.ID] != nil {
		r.ID = randHex(4)
	}
	m.recs[r.ID] = r
	m.saveRecordingsLocked()
	m.mu.Unlock()
	m.startRecorder(r.ID)
	// report the first connection's outcome (e.g. a daemon too old to record)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		state, reason, cols := r.State, r.Reason, r.Cols
		m.mu.Unlock()
		if state != "recording" {
			return RecordingInfo{}, errors.New(reason)
		}
		if cols > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("recording %s of session %s (%s) started", r.ID, s.ID, s.Name)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recInfoLocked(r), nil
}

// StopRecording stops the recording of a session (by session or recording id).
func (m *Manager) StopRecording(id string) (RecordingInfo, error) {
	var r *Recording
	if s, err := m.get(id); err == nil {
		m.mu.Lock()
		for _, x := range m.recs {
			if x.Session == s.ID && x.State == "recording" {
				r = x
			}
		}
		m.mu.Unlock()
	}
	if r == nil {
		x, err := m.getRec(id)
		if err != nil {
			return RecordingInfo{}, fmt.Errorf("no recording in progress for %s", id)
		}
		r = x
	}
	m.mu.Lock()
	rr := m.recorders[r.ID]
	state := r.State
	m.mu.Unlock()
	if state != "recording" {
		return RecordingInfo{}, fmt.Errorf("recording %s is not running", r.ID)
	}
	if rr != nil {
		close(rr.stop)
		<-rr.done
	} else {
		m.finishRecording(r, "stopped")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recInfoLocked(r), nil
}

// finishRecording marks r stopped and refreshes a published copy.
func (m *Manager) finishRecording(r *Recording, reason string) {
	m.mu.Lock()
	if r.State != "recording" {
		m.mu.Unlock()
		return
	}
	r.State, r.Reason, r.Stopped = "stopped", reason, time.Now()
	hosted := r.Hosted != nil
	m.saveRecordingsLocked()
	m.mu.Unlock()
	log.Printf("recording %s stopped: %s", r.ID, reason)
	if hosted {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			if _, err := m.Host(ctx, r.ID); err != nil {
				log.Printf("recording %s: update published copy: %v", r.ID, err)
			}
		}()
	}
}

// RemoveRecording deletes a recording (stopping and unpublishing it first).
func (m *Manager) RemoveRecording(ctx context.Context, id string) error {
	r, err := m.getRec(id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	running, hosted := r.State == "recording", r.Hosted != nil
	m.mu.Unlock()
	if running {
		if _, err := m.StopRecording(r.ID); err != nil {
			return err
		}
	}
	if hosted {
		if err := m.Unhost(ctx, r.ID); err != nil {
			return fmt.Errorf("unpublish first: %w", err)
		}
	}
	m.mu.Lock()
	delete(m.recs, r.ID)
	m.saveRecordingsLocked()
	m.mu.Unlock()
	if err := os.Remove(paths.RecordingFile(r.ID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	log.Printf("recording %s removed", r.ID)
	return nil
}

func (m *Manager) startRecorder(id string) {
	rr := &recorder{id: id, stop: make(chan struct{}), done: make(chan struct{})}
	m.mu.Lock()
	if m.recorders[id] != nil {
		m.mu.Unlock()
		return
	}
	m.recorders[id] = rr
	r := m.recs[id]
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			delete(m.recorders, id)
			m.mu.Unlock()
			close(rr.done)
		}()
		m.runRecorder(r, rr)
	}()
}

// runRecorder keeps a recorder connected until it is stopped, the session
// ends, or washd quits (then the recording resumes on the next start).
func (m *Manager) runRecorder(r *Recording, rr *recorder) {
	f, err := os.OpenFile(paths.RecordingFile(r.ID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		m.finishRecording(r, err.Error())
		return
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 64<<10)
	defer bw.Flush()
	st, _ := f.Stat()
	w := &recWriter{m: m, r: r, bw: bw, hasHeader: st.Size() > 0}
	m.mu.Lock()
	w.base = time.Now().Add(-time.Duration(r.Dur * float64(time.Second)))
	m.mu.Unlock()

	backoff := time.Second
	for {
		s, err := m.get(r.Session)
		if err != nil {
			m.finishRecording(r, "session ended")
			return
		}
		why, err := m.recordOnce(s, r, rr, w)
		_ = bw.Flush()
		m.saveRecordings()
		switch {
		case why == "stopped" || why == "session ended":
			m.finishRecording(r, why)
			return
		case why == "washd stopped":
			return // resumes when washd starts again
		case errors.Is(err, errOldDaemon):
			m.finishRecording(r, err.Error())
			return
		}
		if err != nil {
			m.mu.Lock()
			r.Reason = err.Error()
			m.mu.Unlock()
			if s.Remote != nil && strings.Contains(err.Error(), wosh.ErrNoSession) {
				m.finishRecording(r, "session ended")
				return
			}
			log.Printf("recording %s: %v (retry in %s)", r.ID, err, backoff)
		} else {
			backoff = time.Second // was connected: reconnect soon
		}
		select {
		case <-rr.stop:
			m.finishRecording(r, "stopped")
			return
		case <-m.quit:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (m *Manager) saveRecordings() {
	m.mu.Lock()
	m.saveRecordingsLocked()
	m.mu.Unlock()
}

// recWriter turns wosh frames into cast events.
type recWriter struct {
	m         *Manager
	r         *Recording
	bw        *bufio.Writer
	cw        *cast.Writer
	base      time.Time
	hasHeader bool
	queue     [][]byte // output that arrived before the terminal size (no header yet)
}

func (w *recWriter) now() float64 { return time.Since(w.base).Seconds() }

func (w *recWriter) header(cols, rows int) error {
	if w.cw != nil {
		return nil
	}
	var h *cast.Header
	if !w.hasHeader {
		w.m.mu.Lock()
		h = &cast.Header{Width: cols, Height: rows, Timestamp: w.r.Started.Unix(), Title: w.r.Name,
			IdleLimit: recIdleLimit, Env: map[string]string{"TERM": w.m.cfg.term()}}
		w.m.mu.Unlock()
	}
	cw, err := cast.NewWriter(w.bw, h)
	if err != nil {
		return err
	}
	w.cw, w.hasHeader = cw, true
	for _, p := range w.queue {
		if err := w.output(p); err != nil {
			return err
		}
	}
	w.queue = nil
	return nil
}

func (w *recWriter) size(cols, rows int) error {
	w.m.mu.Lock()
	same := cols == w.r.Cols && rows == w.r.Rows
	w.r.Cols, w.r.Rows = cols, rows
	w.m.mu.Unlock()
	if w.cw == nil {
		if !w.hasHeader {
			return w.header(cols, rows)
		}
		if err := w.header(cols, rows); err != nil {
			return err
		}
	}
	if same {
		return nil
	}
	return w.cw.Resize(w.now(), cols, rows)
}

// output records an FOutput frame (offset + bytes), skipping what is
// already recorded.
func (w *recWriter) output(frame []byte) error {
	if w.cw == nil {
		w.queue = append(w.queue, frame)
		return nil
	}
	off, data, ok := parseOffset(frame)
	if !ok {
		return nil
	}
	w.m.mu.Lock()
	have := w.r.Off
	w.m.mu.Unlock()
	end := off + uint64(len(data))
	if end <= have {
		return nil
	}
	if off < have {
		data = data[have-off:]
	}
	t := w.now()
	if err := w.cw.Output(t, data); err != nil {
		return err
	}
	w.m.mu.Lock()
	w.r.Off, w.r.Dur = end, t
	w.m.mu.Unlock()
	return nil
}

func parseOffset(b []byte) (uint64, []byte, bool) {
	if len(b) < 9 {
		return 0, nil, false
	}
	var off uint64
	for _, c := range b[1:9] {
		off = off<<8 | uint64(c)
	}
	return off, b[9:], true
}

// recordOnce connects to the session daemon and records until the
// connection ends. why: stopped | session ended | washd stopped | "" (lost).
func (m *Manager) recordOnce(s *Session, r *Recording, rr *recorder, w *recWriter) (string, error) {
	frames := make(chan []byte, 4096)
	closed := make(chan struct{})
	var once sync.Once
	onClose := func() { once.Do(func() { close(closed) }) }
	m.mu.Lock()
	off := r.Off
	m.mu.Unlock()
	offer := m.offerFor(s, 80, 24, off, m.config())
	offer.CID, offer.Join, offer.Watch = "rec-"+r.ID, true, true
	if s.Remote == nil {
		offer.ICE, offer.Relay = nil, false // same host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pc, _, err := dialDaemon(ctx, m.signal(s), offer, func(p []byte) {
		select {
		case frames <- append([]byte(nil), p...):
		case <-closed:
		}
	}, onClose)
	cancel()
	if err != nil {
		if s.Remote == nil && !wosh.Alive(s.sock()) {
			return "session ended", nil
		}
		return "", err
	}
	defer pc.Close()
	m.mu.Lock()
	r.Reason = ""
	m.mu.Unlock()
	// output that arrives before the size: write the header after a moment anyway
	hdrWait := time.After(2 * time.Second)
	save := time.NewTicker(recSaveEvery)
	defer save.Stop()
	handle := func(b []byte) (string, error) {
		if len(b) == 0 {
			return "", nil
		}
		switch b[0] {
		case wosh.FOutput:
			return "", w.output(b)
		case wosh.FControl:
			var c struct {
				Op, Role   string
				Cols, Rows int
			}
			if json.Unmarshal(b[1:], &c) != nil {
				return "", nil
			}
			switch {
			case c.Op == "size" && c.Cols > 0 && c.Rows > 0:
				return "", w.size(c.Cols, c.Rows)
			case c.Op == "role" && c.Role == "control":
				// a daemon without passive watchers made us the controller
				return "", errOldDaemon
			}
		case wosh.FExit:
			return "session ended", nil
		}
		return "", nil
	}
	for {
		select {
		case b := <-frames:
			if why, err := handle(b); why != "" || err != nil {
				return why, err
			}
		case <-hdrWait:
			if w.cw == nil {
				if err := w.header(80, 24); err != nil {
					return "", err
				}
			}
		case <-save.C:
			_ = w.bw.Flush()
			m.saveRecordings()
		case <-closed:
			// record what already arrived
			for drained := false; !drained; {
				select {
				case b := <-frames:
					if why, err := handle(b); why != "" || err != nil {
						return why, err
					}
				default:
					drained = true
				}
			}
			if w.cw == nil && len(w.queue) > 0 {
				_ = w.header(80, 24)
			}
			if s.Remote == nil && !wosh.Alive(s.sock()) {
				return "session ended", nil
			}
			return "", nil
		case <-rr.stop:
			return "stopped", nil
		case <-m.quit:
			return "washd stopped", nil
		}
	}
}

// --- publishing ---------------------------------------------------------------

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Host publishes a recording on wash-web (again, if it already is: the
// published copy is replaced by the current file). A recording still in
// progress is published as it is now, and again when it stops.
func (m *Manager) Host(ctx context.Context, id string) (RecordingInfo, error) {
	r, err := m.getRec(id)
	if err != nil {
		return RecordingInfo{}, err
	}
	p, err := m.web()
	if err != nil {
		return RecordingInfo{}, err
	}
	m.mu.Lock()
	uuid, title := "", r.Name
	if r.Hosted != nil {
		uuid = r.Hosted.UUID
	}
	m.mu.Unlock()
	if uuid == "" {
		uuid = newUUID()
	}
	f, err := os.Open(paths.RecordingFile(r.ID))
	if err != nil {
		return RecordingInfo{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return RecordingInfo{}, err
	}
	if st.Size() == 0 {
		return RecordingInfo{}, errors.New("nothing recorded yet")
	}
	// a recording in progress: publish whole lines only
	size := st.Size()
	tail := make([]byte, min(size, 64<<10))
	if _, err := f.ReadAt(tail, size-int64(len(tail))); err == nil {
		if i := strings.LastIndexByte(string(tail), '\n'); i >= 0 {
			size = size - int64(len(tail)) + int64(i) + 1
		}
	}
	var info link.PlaybackInfo
	src := io.LimitReader(f, size)
	buf := make([]byte, link.PlaybackChunkSize)
	for seq, sent := 0, int64(0); ; seq++ {
		n, rerr := io.ReadFull(src, buf)
		sent += int64(n)
		last := sent >= size || rerr != nil
		ch := link.PlaybackChunk{UUID: uuid, Seq: seq, Data: buf[:n], Last: last, Title: title}
		if err := p.Call(ctx, link.OpPlaybackPut, ch, &info); err != nil {
			return RecordingInfo{}, fmt.Errorf("publish: %w", err)
		}
		if last {
			break
		}
	}
	url := info.URL
	if url == "" {
		url = strings.TrimRight(m.creds.URL, "/") + info.Path
	}
	m.mu.Lock()
	r.Hosted = &Hosted{UUID: uuid, URL: url, At: time.Now(), Size: size}
	m.saveRecordingsLocked()
	ri := m.recInfoLocked(r)
	m.mu.Unlock()
	log.Printf("recording %s published at %s", r.ID, url)
	return ri, nil
}

// Unhost removes a recording from wash-web.
func (m *Manager) Unhost(ctx context.Context, id string) error {
	r, err := m.getRec(id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	h := r.Hosted
	m.mu.Unlock()
	if h == nil {
		return fmt.Errorf("recording %s is not hosted", r.ID)
	}
	p, err := m.web()
	if err != nil {
		return err
	}
	if err := p.Call(ctx, link.OpPlaybackDel, link.PlaybackRef{UUID: h.UUID}, nil); err != nil {
		return err
	}
	m.mu.Lock()
	r.Hosted = nil
	m.saveRecordingsLocked()
	m.mu.Unlock()
	log.Printf("recording %s unpublished", r.ID)
	return nil
}
