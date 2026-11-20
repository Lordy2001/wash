package manager

import (
	"context"
	"fmt"
	"log"
	"time"

	"wash/internal/wosh"
)

// Sessions on other hosts.
//
// `new` with a host starts the session there instead of here: washd runs
// `ssh HOST wosh server` (pushing its own wosh build when HOST has no
// compatible one), warm-starts the shell through that relay, and records a
// remote session reached by the attach stub over ssh, like an adopted
// chained hop with a one-hop route. The browser then connects to that
// daemon directly over WebRTC, or through washd's bridge.
//
// Only hosts on washd's list can be chosen (`wash config set hosts`; empty
// by default), so a browser cannot pass ssh options of its own.

// hosts lists the ssh hosts a new session may start on: only the ones the
// user listed (`wash config set hosts`); none by default.
func (c Config) hosts() []string { return c.Hosts }

func (m *Manager) allowedHost(host string) bool {
	if !validHost(host) {
		return false
	}
	for _, h := range m.config().hosts() {
		if h == host {
			return true
		}
	}
	return false
}

// newRemote starts a session on host.
func (m *Manager) newRemote(ctx context.Context, host, name string, cols, rows uint16) (SessionInfo, error) {
	if !m.allowedHost(host) {
		return SessionInfo{}, fmt.Errorf("host %q is not on washd's list (`wash config set hosts`)", host)
	}
	cfg := m.config()
	srv, err := wosh.StartServer(ctx, host, m.routeOpts(), func(key string) (string, []byte, error) {
		b, err := m.woshBuild(key)
		if err != nil {
			return "", nil, err
		}
		return b.stamp, b.gz, nil
	})
	if err != nil {
		return SessionInfo{}, fmt.Errorf("start session on %s: %w", host, err)
	}
	defer srv.Close()
	h := srv.Hello
	if !hexRE.MatchString(h.ID) {
		return SessionInfo{}, fmt.Errorf("%s: bad session id %q", host, h.ID)
	}
	s := &Session{ID: h.ID, Key: randHex(24), Created: time.Now(), Name: cleanName(name)}
	if s.Name == "" {
		s.Name = m.nextName(host)
	}
	s.Remote = &Remote{Host: cleanName(h.Host), User: cleanName(h.User), Route: [][]string{{host}}}
	if s.Remote.Host == "" {
		s.Remote.Host = host
	}
	if srv.Perl {
		s.Remote.Sock = h.Sock // reattach with the perl stub: no wosh binary needed there
	}
	if cols == 0 || rows == 0 {
		cols, rows = 80, 24
	}
	// the first offer must go through the relay that started the daemon
	answered := false
	first := func(ctx context.Context, msg wosh.Msg) (wosh.Msg, error) {
		if answered {
			return m.signal(s)(ctx, msg)
		}
		ans, err := srv.Request(ctx, msg)
		answered = err == nil
		return ans, err
	}
	if err := warmStart(ctx, s, m.offerFor(s, cols, rows, 0, cfg), first); err != nil {
		if !answered {
			return SessionInfo{}, fmt.Errorf("start session on %s: %w", host, err)
		}
		// the shell runs; only washd's own WebRTC to it failed. Browsers
		// may still reach it directly, so keep it.
		log.Printf("session %s on %s: warm start: %v", s.ID, host, err)
	}
	m.mu.Lock()
	m.sessions[s.ID] = s
	m.saveSessionsLocked()
	m.mu.Unlock()
	log.Printf("session %s (%s) started on %s (%s@%s, %s)", s.ID, s.Name, host, h.User, h.Host, srv.How)
	m.changed()
	return SessionInfo{ID: s.ID, Name: s.Name, Created: s.Created, Alive: true, Remote: s.Remote}, nil
}

// nextName: "HOST", then "HOST 2", ... for sessions on another host.
func (m *Manager) nextName(host string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	used := map[string]bool{}
	for _, s := range m.sessions {
		used[s.Name] = true
	}
	name := cleanName(host)
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s %d", cleanName(host), i)
	}
	return name
}
