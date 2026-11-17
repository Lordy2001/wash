package manager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"wash/internal/paths"
	"wash/internal/wosh"
)

// Session is one wosh daemon washd started. The daemon process outlives
// washd (own process group); washd finds it again through sessions.json
// and its control socket.
type Session struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Key     string    `json:"key"` // wosh session key, never leaves washd
	Created time.Time `json:"created"`
	PID     int       `json:"pid"`
	// SockPath: a wosh daemon on this host that washd did not start (a
	// chained hop that came back here); empty = washd's own session dir.
	SockPath string  `json:"sock_path,omitempty"`
	Hops     []Hop   `json:"hops,omitempty"`
	Remote   *Remote `json:"remote,omitempty"`
}

// Remote marks a session on another host: a chained hop that was adopted
// after the browser connected to it directly. Its intermediate sessions are
// gone (as in wosh); washd signals reconnects by ssh'ing through Route
// (Route[0] runs here, Route[1] on that host, ...) to the daemon's Sock.
type Remote struct {
	Host  string     `json:"host"`
	User  string     `json:"user,omitempty"`
	Route [][]string `json:"route"`
	Sock  string     `json:"sock,omitempty"`
}

// signal sends wosh offers to s's daemon (local socket, or its ssh route).
func (m *Manager) signal(s *Session) signalFunc {
	return func(ctx context.Context, msg wosh.Msg) (wosh.Msg, error) {
		if s.Remote != nil {
			return wosh.RouteRequest(ctx, s.Remote.Route, s.Remote.Sock, msg, m.routeOpts())
		}
		return wosh.Request(ctx, s.sock(), msg)
	}
}

// routeOpts: washd's ssh uses the user's agent (handed over by `wash up` /
// `wash agent`) and forwards it through intermediate hops if configured.
func (m *Manager) routeOpts() wosh.RouteOptions {
	m.mu.Lock()
	agent, fwd := m.agentSock, m.cfg.ForwardAgent
	m.mu.Unlock()
	var o wosh.RouteOptions
	if agent != "" {
		if st, err := os.Stat(agent); err == nil && st.Mode()&os.ModeSocket != 0 {
			o.Env = []string{"SSH_AUTH_SOCK=" + agent}
			o.ForwardAgent = fwd
		}
	}
	return o
}

// SetAgent records the user's ssh-agent socket for washd's own ssh.
func (m *Manager) SetAgent(sock string) error {
	if sock != "" {
		st, err := os.Stat(sock)
		if err != nil || st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s is not an ssh-agent socket", sock)
		}
		if sameOwner(st) != nil {
			return fmt.Errorf("%s is not owned by you", sock)
		}
	}
	m.mu.Lock()
	m.agentSock = sock
	m.mu.Unlock()
	log.Printf("ssh agent: %q", sock)
	return nil
}

// candidateRoutes lists ways washd might reach a hop's daemon, shortest
// first: straight from here with the args the parent used or by the target's
// host name (shortcuts past intermediate hosts whose keys need a
// passphrase), then every suffix of the chain, then the full chain.
func candidateRoutes(parentRoute [][]string, hopArgs []string, host string) [][][]string {
	full := append(append([][]string{}, parentRoute...), hopArgs)
	var out [][][]string
	seen := map[string]bool{}
	add := func(r [][]string) {
		k := wosh.RouteString(r)
		if len(r) > 0 && !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	add([][]string{hopArgs})
	if host != "" && validHost(host) {
		add([][]string{{host}})
	}
	for i := len(full) - 2; i >= 0; i-- {
		add(full[i:])
	}
	return out
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

func validHost(h string) bool { return hostRE.MatchString(h) }

// pickRoute probes candidates in parallel and returns the first (shortest)
// that reaches the hop's daemon. A probe only succeeds on the host and
// account where that daemon's socket and session id exist, so a shortcut
// cannot land somewhere else.
func (m *Manager) pickRoute(cands [][][]string, sock, id string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	errs := make([]error, len(cands))
	var wg sync.WaitGroup
	for i, r := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = wosh.RouteProbe(ctx, r, sock, id, m.routeOpts())
		}()
	}
	wg.Wait()
	var why []string
	for i, r := range cands {
		if errs[i] == nil {
			return r, nil
		}
		why = append(why, fmt.Sprintf("%s: %v", wosh.RouteString(r), errs[i]))
	}
	return nil, errors.New(strings.Join(why, "; "))
}

// Hop is a chained wosh session (`wosh HOST` typed inside this session)
// that a browser connected to directly. Its signaling path is the parked
// `wosh` process in the parent's terminal, so washd only remembers it for
// browsers to reattach after a reload.
type Hop struct {
	ID     string `json:"id"`
	Parent string `json:"parent"` // session or hop id whose terminal relays signaling
	Host   string `json:"host"`
	User   string `json:"user,omitempty"`
	Key    string `json:"key"` // the hop session's wosh key (chosen by the browser)
}

// SessionInfo is what browsers and the CLI see.
type SessionInfo struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Created  time.Time `json:"created"`
	PID      int       `json:"pid"`
	Alive    bool      `json:"alive"`
	Attached int       `json:"attached"` // browser connections using it via washd
	Hops     []Hop     `json:"hops,omitempty"`
	Remote   *Remote   `json:"remote,omitempty"`
}

func (s *Session) sock() string {
	if s.SockPath != "" {
		return s.SockPath
	}
	return filepath.Join(paths.SessionDir(), s.ID+".sock")
}

// isLocalDaemon is localDaemon (tests that simulate far hosts with local
// daemons turn it off).
var isLocalDaemon = localDaemon

// localDaemon reports whether a hop's daemon socket is on this host, ours:
// the hop came back to the machine washd runs on, so no ssh is needed. The
// path ends in the hop's random session id and must be a live socket owned
// by this user, so it cannot be some other daemon.
func localDaemon(sock, id string) bool {
	if sock == "" || !filepath.IsAbs(sock) || filepath.Base(sock) != id+".sock" {
		return false
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode()&os.ModeSocket == 0 || sameOwner(st) != nil {
		return false
	}
	return wosh.Alive(sock)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var nameRE = regexp.MustCompile(`[^\w .:@+-]`)

func cleanName(s string) string {
	s = strings.TrimSpace(nameRE.ReplaceAllString(s, ""))
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func (m *Manager) loadSessions() {
	var ss []*Session
	_ = readJSON(paths.SessionsFile(), &ss)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range ss {
		if s.Remote != nil || wosh.Alive(s.sock()) {
			m.sessions[s.ID] = s
		}
	}
	m.saveSessionsLocked()
}

func (m *Manager) saveSessionsLocked() {
	ss := []*Session{}
	for _, s := range m.sessions {
		ss = append(ss, s)
	}
	if err := writeJSON(paths.SessionsFile(), ss); err != nil {
		log.Printf("save sessions: %v", err)
	}
}

// prune drops sessions whose daemon is gone; returns true if any changed.
func (m *Manager) prune() bool {
	m.mu.Lock()
	var all []*Session
	for _, s := range m.sessions {
		all = append(all, s)
	}
	m.mu.Unlock()
	changed := false
	for _, s := range all {
		if s.Remote == nil && !wosh.Alive(s.sock()) {
			m.mu.Lock()
			delete(m.sessions, s.ID)
			changed = true
			m.mu.Unlock()
			log.Printf("session %s (%s) ended", s.ID, s.Name)
		}
	}
	if changed {
		m.mu.Lock()
		m.saveSessionsLocked()
		m.mu.Unlock()
	}
	return changed
}

// List returns the sessions, oldest first.
func (m *Manager) List() []SessionInfo {
	m.prune()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []SessionInfo{}
	for _, s := range m.sessions {
		out = append(out, SessionInfo{ID: s.ID, Name: s.Name, Created: s.Created, PID: s.PID,
			Alive: true, Attached: m.attached[s.ID], Hops: append([]Hop(nil), s.Hops...), Remote: s.Remote})
	}
	sortSessions(out)
	return out
}

func sortSessions(s []SessionInfo) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Created.Before(s[j-1].Created); j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (m *Manager) get(id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil {
		return s, nil
	}
	// unique prefix
	var hit *Session
	for k, s := range m.sessions {
		if len(id) >= 3 && strings.HasPrefix(k, id) {
			if hit != nil {
				return nil, fmt.Errorf("session id %s is ambiguous", id)
			}
			hit = s
		}
	}
	if hit == nil {
		return nil, fmt.Errorf("no session %s", id)
	}
	return hit, nil
}

// New starts a wosh daemon and its shell. The shell starts on the first
// offer, so washd connects once itself (warm start); the session then keeps
// running with nobody attached.
func (m *Manager) New(ctx context.Context, name string, cols, rows uint16) (SessionInfo, error) {
	m.prune()
	cfg := m.config()
	m.mu.Lock()
	n := len(m.sessions)
	m.mu.Unlock()
	if n >= cfg.maxSessions() {
		return SessionInfo{}, fmt.Errorf("session limit reached (%d; `wash config set max_sessions N`)", cfg.maxSessions())
	}
	bin, err := cfg.WoshPath()
	if err != nil {
		return SessionInfo{}, err
	}
	s := &Session{ID: randHex(8), Key: randHex(24), Created: time.Now(), Name: cleanName(name)}
	if s.Name == "" {
		s.Name = fmt.Sprintf("shell %d", m.nextNumber())
	}
	if err := m.spawn(bin, s, cfg); err != nil {
		return SessionInfo{}, err
	}
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.saveSessionsLocked()
	m.mu.Unlock()
	if cols == 0 || rows == 0 {
		cols, rows = 80, 24
	}
	if err := warmStart(ctx, s, m.offerFor(s, cols, rows, 0, cfg), m.signal(s)); err != nil {
		log.Printf("session %s warm start: %v", s.ID, err)
		_ = m.Kill(s.ID)
		return SessionInfo{}, fmt.Errorf("start session: %w", err)
	}
	log.Printf("session %s (%s) started, pid %d", s.ID, s.Name, s.PID)
	m.changed()
	return SessionInfo{ID: s.ID, Name: s.Name, Created: s.Created, PID: s.PID, Alive: true}, nil
}

func (m *Manager) nextNumber() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	used := map[string]bool{}
	for _, s := range m.sessions {
		used[s.Name] = true
	}
	for i := 1; ; i++ {
		if !used[fmt.Sprintf("shell %d", i)] {
			return i
		}
	}
}

// spawn runs `wosh _daemon --id ID` detached, like wosh's own relay does.
func (m *Manager) spawn(bin string, s *Session, cfg Config) error {
	logf, err := os.OpenFile(filepath.Join(paths.SessionDir(), s.ID+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	args := []string{"_daemon", "--id", s.ID, "--linger", "0s"}
	if len(cfg.Command) > 0 {
		args = append(append(args, "--"), cfg.Command...)
	}
	cmd := exec.Command(bin, args...)
	cmd.Args[0] = "wosh"
	cmd.Env = append(sessionEnv(os.Environ()),
		"WOSH_RUNTIME_DIR="+paths.SessionDir(),
		"WOSH_LOOPBACK=1", // lets washd's bridge reach the daemon on hosts without a LAN address
	)
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		w.Close()
		return err
	}
	w.Close()
	s.PID = cmd.Process.Pid
	go cmd.Wait()
	ready := make(chan error, 1)
	go func() {
		b := make([]byte, 1)
		_, err := r.Read(b)
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			return fmt.Errorf("wosh daemon failed to start (see %s)", logf.Name())
		}
		return nil
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		return errors.New("wosh daemon start timeout")
	}
}

// terminalEnv lists variables that describe the terminal (or multiplexer)
// washd happened to be started from. A wash session runs in the browser's
// terminal, so they are wrong there, and some break programs: herdr refuses
// to start when it sees HERDR_ENV ("nested herdr"), tmux and zellij think
// they are nested, and so on. Names ending in "_" are prefixes.
var terminalEnv = []string{
	"HERDR_", "TMUX", "TMUX_PANE", "STY", "WINDOW", "ZELLIJ", "ZELLIJ_", "BYOBU_",
	"TERM_PROGRAM", "TERM_PROGRAM_VERSION", "TERM_SESSION_ID", "LC_TERMINAL", "LC_TERMINAL_VERSION",
	"COLORTERM", "COLORFGBG", "VTE_VERSION", "WT_SESSION", "WT_PROFILE_ID",
	"KITTY_", "WEZTERM_", "ALACRITTY_", "ITERM_", "KONSOLE_", "GNOME_TERMINAL_", "GHOSTTY_",
	"SSH_TTY", "SSH_CONNECTION", "SSH_CLIENT", "WASH_SESSION",
	// a wosh session's own (its settings, WOSH_PUSH, WOSH_STUN, ..., stay)
	"WOSH_SESSION", "WOSH_SOCK", "WOSH_TOKEN", "WOSH_AGENT_SOCK", "WOSH_BIN_DIR", "WOSH_SRC", "WOSH_HOP_SSH",
}

// sessionEnv drops terminalEnv from washd's environment for a new session
// (the offer sets TERM, COLORTERM and TERM_PROGRAM for the browser terminal).
func sessionEnv(env []string) []string {
	out := env[:0:0]
outer:
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		for _, t := range terminalEnv {
			if name == t || strings.HasSuffix(t, "_") && strings.HasPrefix(name, t) {
				continue outer
			}
		}
		out = append(out, kv)
	}
	return out
}

// offerFor builds the wosh offer for a session (SDP filled in by the caller).
func (m *Manager) offerFor(s *Session, cols, rows uint16, rxOut uint64, cfg Config) wosh.Msg {
	return wosh.Msg{
		T: wosh.TOffer, ID: s.ID, Key: s.Key, User: m.user,
		Term: cfg.term(), Cols: cols, Rows: rows, RxOut: rxOut,
		ICE: cfg.ice(), Relay: cfg.Relay,
		Env: map[string]string{
			"COLORTERM":            "truecolor",
			"TERM_PROGRAM":         "wash",
			"TERM_PROGRAM_VERSION": Version,
			"WASH_SESSION":         s.ID,
		},
	}
}

// Kill hangs up a session: SIGHUP to the daemon, which hangs up the shell's
// process group and exits.
func (m *Manager) Kill(id string) error {
	s, err := m.get(id)
	if err != nil {
		return err
	}
	if s.Remote != nil || (s.SockPath != "" && s.PID == 0) {
		// not a process we started: hang it up over the wosh protocol (best
		// effort; the record goes either way)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := hangUp(ctx, m.signal(s), m.offerFor(s, 80, 24, ^uint64(0)>>1, m.config())); err != nil {
			log.Printf("session %s (%s): hang up via route: %v", s.ID, s.Name, err)
		}
		cancel()
	} else if s.PID > 0 && isOurDaemon(s.PID, s.ID) {
		_ = syscall.Kill(s.PID, syscall.SIGHUP)
		for i := 0; i < 30 && wosh.Alive(s.sock()); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		if wosh.Alive(s.sock()) {
			_ = syscall.Kill(s.PID, syscall.SIGKILL)
		}
	} else if wosh.Alive(s.sock()) {
		return fmt.Errorf("session %s: daemon pid unknown; cannot kill", s.ID)
	}
	if s.Remote == nil && s.SockPath == "" {
		_ = os.Remove(s.sock())
	}
	m.Forget(s.ID)
	log.Printf("session %s (%s) killed", s.ID, s.Name)
	return nil
}

// Forget drops a session record (a remote session that ended).
func (m *Manager) Forget(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.saveSessionsLocked()
	m.mu.Unlock()
	m.changed()
}

// Adopt turns a chained hop the browser has connected to into a remote
// session reached through its ssh route, then ends the intermediate
// session: the same "spin down" wosh does after a chained hop.
func (m *Manager) Adopt(parentID string, h Hop, sock string, hopArgs []string) (SessionInfo, error) {
	parent, err := m.get(parentID)
	if err != nil {
		return SessionInfo{}, err
	}
	if !hexRE.MatchString(h.ID) || len(h.Key) < 16 || len(h.Key) > 128 || len(hopArgs) == 0 || len(hopArgs) > 32 {
		return SessionInfo{}, errors.New("bad hop")
	}
	for _, a := range hopArgs {
		if len(a) > 1024 {
			return SessionInfo{}, errors.New("bad hop args")
		}
	}
	s := &Session{ID: h.ID, Name: cleanName(h.Host), Key: h.Key, Created: parent.Created}
	if isLocalDaemon(sock, h.ID) {
		// the hop came back to this host: talk to its socket, no ssh
		s.SockPath = sock
	} else {
		var parentRoute [][]string
		if parent.Remote != nil {
			parentRoute = parent.Remote.Route
		}
		// only spin the parent down if washd can reach the hop on its own
		route, err := m.pickRoute(candidateRoutes(parentRoute, hopArgs, h.Host), sock, h.ID)
		if err != nil {
			log.Printf("adopt %s: no usable route, keeping %s as its signaling path: %v", h.ID, parent.ID, err)
			return SessionInfo{}, fmt.Errorf("ssh route not usable non-interactively (%v); keeping the parent session as the signaling path", err)
		}
		s.Remote = &Remote{Host: cleanName(h.Host), User: cleanName(h.User), Route: route, Sock: sock}
	}
	if s.Name == "" {
		s.Name = h.ID[:8]
	}
	m.mu.Lock()
	if _, dup := m.sessions[s.ID]; dup {
		m.mu.Unlock()
		return SessionInfo{}, errors.New("session exists")
	}
	m.sessions[s.ID] = s
	m.saveSessionsLocked()
	m.mu.Unlock()
	via := "local socket " + s.SockPath
	if s.Remote != nil {
		via = "ssh " + wosh.RouteString(s.Remote.Route)
	}
	log.Printf("session %s (%s) adopted via %s; ending %s (%s)", s.ID, s.Name, via, parent.ID, parent.Name)
	go func() {
		time.Sleep(300 * time.Millisecond) // let the browser's reply go out first
		if err := m.Kill(parent.ID); err != nil {
			log.Printf("end intermediate %s: %v", parent.ID, err)
		}
	}()
	return SessionInfo{ID: s.ID, Name: s.Name, Created: s.Created, Alive: true, Remote: s.Remote}, nil
}

// Rename changes a session's display name.
func (m *Manager) Rename(id, name string) error {
	s, err := m.get(id)
	if err != nil {
		return err
	}
	if name = cleanName(name); name == "" {
		return errors.New("empty name")
	}
	m.mu.Lock()
	s.Name = name
	m.saveSessionsLocked()
	m.mu.Unlock()
	m.changed()
	return nil
}

var hexRE = regexp.MustCompile(`^[0-9a-f]{1,64}$`)

// AddHop records a chained hop under session id.
func (m *Manager) AddHop(id string, h Hop) error {
	s, err := m.get(id)
	if err != nil {
		return err
	}
	if !hexRE.MatchString(h.ID) || !hexRE.MatchString(h.Parent) || len(h.Key) < 16 || len(h.Key) > 128 {
		return errors.New("bad hop")
	}
	h.Host, h.User = cleanName(h.Host), cleanName(h.User)
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := s.Hops[:0]
	for _, x := range s.Hops {
		if x.ID != h.ID {
			keep = append(keep, x)
		}
	}
	if len(keep) >= 16 {
		return errors.New("too many hops")
	}
	s.Hops = append(keep, h)
	m.saveSessionsLocked()
	return nil
}

// DelHop forgets a hop (and hops chained from it).
func (m *Manager) DelHop(id, hop string) error {
	s, err := m.get(id)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	gone := map[string]bool{hop: true}
	for changed := true; changed; {
		changed = false
		for _, x := range s.Hops {
			if gone[x.Parent] && !gone[x.ID] {
				gone[x.ID], changed = true, true
			}
		}
	}
	keep := s.Hops[:0]
	for _, x := range s.Hops {
		if !gone[x.ID] {
			keep = append(keep, x)
		}
	}
	s.Hops = keep
	m.saveSessionsLocked()
	return nil
}

// isOurDaemon guards against pid reuse: the process must be a wosh daemon
// for this session id.
func isOurDaemon(pid int, id string) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		// no procfs (not Linux): fall back to "process exists"
		return syscall.Kill(pid, 0) == nil && !dirExists("/proc/self")
	}
	return strings.Contains(string(b), "_daemon\x00--id\x00"+id+"\x00")
}

func dirExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}
