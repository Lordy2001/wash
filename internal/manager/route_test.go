package manager

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wash/internal/wosh"
)

// fakeSSH runs the remote command locally: ssh [-T] [-o X]... HOST CMD
const fakeSSH = `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in -T) shift ;; -o) shift 2 ;; *) break ;; esac
done
shift # host
exec sh -c "$1"
`

// farHosts makes local daemons count as being on other hosts.
func farHosts(t *testing.T) {
	isLocalDaemon = func(string, string) bool { return false }
	t.Cleanup(func() { isLocalDaemon = localDaemon })
}

func TestAdoptAndRoute(t *testing.T) {
	farHosts(t)
	bin, _ := filepath.Abs("../../../wosh/bin/wosh")
	if p := os.Getenv("WASH_TEST_WOSH"); p != "" {
		bin = p
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no wosh binary")
	}
	root, _ := os.MkdirTemp("", "washr")
	t.Cleanup(func() { os.RemoveAll(root) })
	for k, v := range map[string]string{"XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/s",
		"WASH_RUNTIME_DIR": root + "/r", "SHELL": "/bin/sh"} {
		t.Setenv(k, v)
	}
	ssh := filepath.Join(root, "ssh")
	if err := os.WriteFile(ssh, []byte(fakeSSH), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WASH_SSH", ssh)
	t.Setenv("WOSH_HOP_SSH", ssh) // used by wosh's hop stub on "intermediate hosts"

	m := &Manager{user: "t", cfg: Config{Wosh: bin, ICE: []wosh.ICEServer{}}, sessions: map[string]*Session{},
		attached: map[string]int{}, nonces: map[string]time.Time{}, tickets: map[string]*ticket{},
		conns: map[*browserConn]bool{}, quit: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a, err := m.New(ctx, "a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.New(ctx, "b", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	bs, _ := m.get(b.ID)
	key, sock := bs.Key, bs.sock()
	m.Forget(b.ID) // b now plays a session on another host that only a route reaches

	si, err := m.Adopt(a.ID, Hop{ID: b.ID, Host: "far", Key: key}, sock, []string{"hostX"})
	if err != nil {
		t.Fatal(err)
	}
	if si.Remote == nil || len(si.Remote.Route) != 1 || si.Remote.Route[0][0] != "hostX" {
		t.Fatalf("adopted: %+v", si)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		ss := m.List()
		if len(ss) == 1 && ss[0].ID == b.ID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("intermediate not ended: %+v", ss)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// two-hop route: ssh hostX -> (hop stub) ssh hostY -> attach stub -> daemon
	rs, _ := m.get(b.ID)
	rs.Remote.Route = [][]string{{"hostX"}, {"hostY"}}

	var mu sync.Mutex
	var out strings.Builder
	offer := m.offerFor(rs, 80, 24, 0, m.config())
	pc, dc, err := dialDaemon(ctx, m.signal(rs), offer, func(p []byte) {
		if len(p) > 9 && p[0] == wosh.FOutput {
			mu.Lock()
			out.Write(p[9:])
			mu.Unlock()
		}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// input offset must continue where the session is: take it from the first ack
	in := []byte("echo route-$((6*7))\r")
	f := make([]byte, 9+len(in))
	f[0] = wosh.FInput
	binary.BigEndian.PutUint64(f[1:], 0)
	copy(f[9:], in)
	_ = dc.Send(f)
	for !strings.Contains(func() string { mu.Lock(); defer mu.Unlock(); return out.String() }(), "route-42") {
		if ctx.Err() != nil {
			t.Fatalf("no output over the route; got %q", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	pc.Close()

	// kill via the route: FKill over the wosh protocol
	if err := m.Kill(b.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && wosh.Alive(sock); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if wosh.Alive(sock) {
		t.Fatal("remote session still running after kill")
	}
	if len(m.List()) != 0 {
		t.Fatal("record not dropped")
	}
	// a gone session reports wosh's "no such session"
	_, err = wosh.RouteRequest(ctx, [][]string{{"hostX"}}, sock, wosh.Msg{T: wosh.TOffer, ID: b.ID}, wosh.RouteOptions{})
	if err == nil || !strings.Contains(err.Error(), wosh.ErrNoSession) {
		t.Fatalf("gone session: %v", err)
	}
}

func TestAdoptRefusedWhenRouteFails(t *testing.T) {
	bin, _ := filepath.Abs("../../../wosh/bin/wosh")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no wosh binary")
	}
	root, _ := os.MkdirTemp("", "washr")
	t.Cleanup(func() { os.RemoveAll(root) })
	for k, v := range map[string]string{"XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/s",
		"WASH_RUNTIME_DIR": root + "/r", "SHELL": "/bin/sh"} {
		t.Setenv(k, v)
	}
	ssh := filepath.Join(root, "ssh")
	_ = os.WriteFile(ssh, []byte("#!/bin/sh\necho 'Host key verification failed.' >&2\nexit 255\n"), 0o755)
	t.Setenv("WASH_SSH", ssh)
	m := &Manager{user: "t", cfg: Config{Wosh: bin, ICE: []wosh.ICEServer{}}, sessions: map[string]*Session{},
		attached: map[string]int{}, conns: map[*browserConn]bool{}, quit: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := m.New(ctx, "a", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Kill(a.ID)
	_, err = m.Adopt(a.ID, Hop{ID: "abcdef0123", Host: "far", Key: strings.Repeat("k", 32)}, "/nonexistent.sock", []string{"far"})
	if err == nil || !strings.Contains(err.Error(), "Host key verification failed") {
		t.Fatalf("adopt with a broken route: %v", err)
	}
	if ss := m.List(); len(ss) != 1 || ss[0].ID != a.ID {
		t.Fatalf("parent must survive: %+v", ss)
	}
}

func TestCandidateRoutes(t *testing.T) {
	got := candidateRoutes([][]string{{"ca-mini"}, {"ca"}}, []string{"ca-data"}, "box")
	var s []string
	for _, r := range got {
		s = append(s, wosh.RouteString(r))
	}
	want := "ca-data | box | ca -> ca-data | ca-mini -> ca -> ca-data"
	if strings.Join(s, " | ") != want {
		t.Fatalf("candidates: %s", strings.Join(s, " | "))
	}
	if r := candidateRoutes(nil, []string{"x"}, "bad host;rm"); len(r) != 1 {
		t.Fatalf("unsafe host name used: %v", r)
	}
}

func TestRouteForwardAgent(t *testing.T) {
	args, _ := wosh.RouteArgs([][]string{{"a"}, {"b"}, {"c"}}, "/s", "id", wosh.RouteOptions{ForwardAgent: true})
	j := strings.Join(args, " ")
	if !strings.Contains(j, "-o ForwardAgent=yes a ") {
		t.Fatalf("first hop not forwarding: %s", j)
	}
	args, _ = wosh.RouteArgs([][]string{{"a"}}, "/s", "id", wosh.RouteOptions{ForwardAgent: true})
	if strings.Contains(strings.Join(args, " "), "ForwardAgent") {
		t.Fatal("agent forwarded into the final host")
	}
}

// A hop reached through a host whose ssh needs a passphrase: washd finds the
// direct shortcut and skips that host.
func TestAdoptShortcut(t *testing.T) {
	farHosts(t)
	bin, _ := filepath.Abs("../../../wosh/bin/wosh")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no wosh binary")
	}
	root, _ := os.MkdirTemp("", "washr")
	t.Cleanup(func() { os.RemoveAll(root) })
	for k, v := range map[string]string{"XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/s",
		"WASH_RUNTIME_DIR": root + "/r", "SHELL": "/bin/sh"} {
		t.Setenv(k, v)
	}
	// "locked" hosts cannot ssh onwards non-interactively; "alias" does not
	// resolve from here; "target" does
	ssh := filepath.Join(root, "ssh")
	_ = os.WriteFile(ssh, []byte(`#!/bin/sh
while [ $# -gt 0 ]; do case "$1" in -T) shift ;; -o) shift 2 ;; *) break ;; esac; done
host=$1; shift
case "$host" in alias) echo "ssh: Could not resolve hostname alias" >&2; exit 255 ;; esac
[ -n "$LOCKED" ] && { echo "Permission denied (publickey)." >&2; exit 255; }
case "$host" in locked) export LOCKED=1 ;; esac
exec sh -c "$1"
`), 0o755)
	t.Setenv("WASH_SSH", ssh)
	t.Setenv("WOSH_HOP_SSH", ssh)
	m := &Manager{user: "t", cfg: Config{Wosh: bin, ICE: []wosh.ICEServer{}}, sessions: map[string]*Session{},
		attached: map[string]int{}, conns: map[*browserConn]bool{}, quit: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, _ := m.New(ctx, "parent", 80, 24)
	b, _ := m.New(ctx, "far", 80, 24)
	bs, _ := m.get(b.ID)
	key, sock := bs.Key, bs.sock()
	m.Forget(b.ID)
	// the parent is a remote session behind "locked"
	ps, _ := m.get(p.ID)
	ps.Remote = &Remote{Host: "locked", Route: [][]string{{"locked"}}}
	si, err := m.Adopt(p.ID, Hop{ID: b.ID, Host: "target", Key: key}, sock, []string{"alias"})
	if err != nil {
		t.Fatal(err)
	}
	if got := wosh.RouteString(si.Remote.Route); got != "target" {
		t.Fatalf("route %s, want the direct shortcut", got)
	}
	_ = m.Kill(b.ID)
}

// A hop that comes back to washd's own host is attached through its local
// socket: no ssh (which may not even trust its own host key).
func TestAdoptLocalDaemon(t *testing.T) {
	bin, _ := filepath.Abs("../../../wosh/bin/wosh")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no wosh binary")
	}
	root, _ := os.MkdirTemp("", "washr")
	t.Cleanup(func() { os.RemoveAll(root) })
	for k, v := range map[string]string{"XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/s",
		"WASH_RUNTIME_DIR": root + "/r", "SHELL": "/bin/sh"} {
		t.Setenv(k, v)
	}
	ssh := filepath.Join(root, "ssh")
	_ = os.WriteFile(ssh, []byte("#!/bin/sh\necho 'Host key verification failed.' >&2\nexit 255\n"), 0o755)
	t.Setenv("WASH_SSH", ssh)
	m := &Manager{user: "t", cfg: Config{Wosh: bin, ICE: []wosh.ICEServer{}}, sessions: map[string]*Session{},
		attached: map[string]int{}, conns: map[*browserConn]bool{}, quit: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, _ := m.New(ctx, "parent", 80, 24)
	b, _ := m.New(ctx, "back-here", 80, 24)
	bs, _ := m.get(b.ID)
	key, sock := bs.Key, bs.sock()
	m.Forget(b.ID)
	ps, _ := m.get(p.ID)
	ps.Remote = &Remote{Host: "far", Route: [][]string{{"far"}}}
	si, err := m.Adopt(p.ID, Hop{ID: b.ID, Host: "ca-data", Key: key}, sock, []string{"ca-data"})
	if err != nil {
		t.Fatal(err)
	}
	if si.Remote != nil {
		t.Fatalf("local daemon adopted as remote: %+v", si.Remote)
	}
	s, _ := m.get(b.ID)
	if s.SockPath != sock {
		t.Fatalf("sock path %q", s.SockPath)
	}
	// signaling works over the socket
	pc, _, err := dialDaemon(ctx, m.signal(s), m.offerFor(s, 80, 24, 0, m.config()), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if err := m.Kill(b.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && wosh.Alive(sock); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if wosh.Alive(sock) {
		t.Fatal("not hung up")
	}
	// a socket that is not ours / not this id is never taken as local
	if localDaemon(sock, "deadbeef") || localDaemon("relative.sock", b.ID) {
		t.Fatal("localDaemon too permissive")
	}
}
