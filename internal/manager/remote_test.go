package manager

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wash/internal/wosh"
)

// TestNewRemote starts sessions "on another host" through a fake ssh that
// runs the remote command locally: once with no wosh there (washd pushes
// its build, run from memory) and once with one installed (used as is).
// Later signaling goes through the attach stub, as for an adopted hop.
func TestNewRemote(t *testing.T) {
	farHosts(t)
	bin, _ := filepath.Abs("../../../wosh/bin/wosh")
	if p := os.Getenv("WASH_TEST_WOSH"); p != "" {
		bin = p
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skip("no wosh binary")
	}
	for _, installed := range []bool{false, true} {
		name := map[bool]string{false: "push", true: "installed"}[installed]
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			for k, v := range map[string]string{"XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/s",
				"WASH_RUNTIME_DIR": root + "/r", "WOSH_RUNTIME_DIR": root + "/w", "SHELL": "/bin/sh",
				"HOME": home, "PATH": "/usr/bin:/bin"} {
				t.Setenv(k, v)
			}
			if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if installed {
				raw, err := os.ReadFile(bin)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, "bin", "wosh"), raw, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			ssh := filepath.Join(root, "ssh")
			if err := os.WriteFile(ssh, []byte(fakeSSH), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("WASH_SSH", ssh)

			m := &Manager{user: "t", cfg: Config{Wosh: bin, ICE: []wosh.ICEServer{}, Hosts: []string{"far"}},
				sessions: map[string]*Session{}, attached: map[string]int{}, nonces: map[string]time.Time{},
				tickets: map[string]*ticket{}, conns: map[*browserConn]bool{}, quit: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			if _, err := m.New(ctx, "elsewhere", "", 80, 24); err == nil || !strings.Contains(err.Error(), "not on washd's list") {
				t.Fatalf("host not on the list: %v", err)
			}
			if _, err := m.New(ctx, "-oProxyCommand=x", "", 80, 24); err == nil {
				t.Fatal("ssh option as host accepted")
			}
			si, err := m.New(ctx, "far", "", 80, 24)
			if err != nil {
				t.Fatal(err)
			}
			if si.Name != "far" || si.Remote == nil || wosh.RouteString(si.Remote.Route) != "far" || si.Remote.Sock == "" {
				t.Fatalf("session: %+v %+v", si, si.Remote)
			}
			if si2, err := m.New(ctx, "far", "", 80, 24); err != nil || si2.Name != "far 2" {
				t.Fatalf("second: %+v %v", si2, err)
			} else if err := m.Kill(si2.ID); err != nil {
				t.Fatal(err)
			}

			// reattach the way a browser does: an offer through the ssh route
			s, _ := m.get(si.ID)
			out := make(chan []byte, 64)
			pc, _, err := dialDaemon(ctx, m.signal(s), m.offerFor(s, 80, 24, 0, m.config()),
				func(p []byte) { out <- append([]byte(nil), p...) }, nil)
			if err != nil {
				t.Fatalf("reattach via route: %v", err)
			}
			select {
			case <-out:
			case <-time.After(10 * time.Second):
				t.Fatal("no output after reattach")
			}
			pc.Close()

			if err := m.Kill(si.ID); err != nil {
				t.Fatal(err)
			}
			if n := len(m.List()); n != 0 {
				t.Fatalf("%d sessions left", n)
			}
			// the daemon is gone: its socket disappears
			deadline := time.Now().Add(5 * time.Second)
			for wosh.Alive(s.Remote.Sock) {
				if time.Now().After(deadline) {
					t.Fatal("remote daemon still running after kill")
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func TestDecidePush(t *testing.T) {
	build := func(key string) (string, []byte, error) {
		if key != "linux-amd64" {
			return "", nil, os.ErrNotExist
		}
		return "100-abc", []byte{0x1f, 0x8b}, nil
	}
	cases := []struct {
		line, want string
	}{
		{"WOSHPUSH linux x86_64 1", "MEM 2 g"},
		{"WOSHPUSH linux x86_64 1 /a/wosh|1|1/50-old /b/wosh|0|2/100-abc", "USE /b/wosh"},
		{"WOSHPUSH linux x86_64 1 /a/wosh|1|2/50-old", "USE /a/wosh"},
		{"WOSHPUSH darwin arm64 1 /a/wosh|1|2/50-old", "USE /a/wosh"},
		{"WOSHPUSH darwin arm64 1 /a/wosh|1|1/50-old", "error"},
		{"WOSHPUSH linux x86_64 1 /a/wosh|1|-", "MEM 2 g"},
	}
	for _, c := range cases {
		reply, _, _, err := wosh.DecidePush(strings.Fields(c.line), build)
		got := strings.TrimSpace(reply)
		if err != nil {
			got = "error"
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.line, got, c.want)
		}
	}
}

func TestSSHConfigHosts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_ = os.MkdirAll(filepath.Join(home, ".ssh", "conf.d"), 0o700)
	_ = os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(
		"Include conf.d/*\nHost ca ca-prox\n  HostName x\nHost *.lan !bad\nhost=mini\nHost ca\n"), 0o600)
	_ = os.WriteFile(filepath.Join(home, ".ssh", "conf.d", "w"), []byte("Host work\n"), 0o600)
	if got := strings.Join(sshConfigHosts(), ","); got != "work,ca,mini" {
		t.Fatalf("hosts %q", got)
	}
}

// TestNewRemoteReal starts a session on a real ssh host:
// WASH_TEST_HOST=myhost go test ./internal/manager -run Real
func TestNewRemoteReal(t *testing.T) {
	host := os.Getenv("WASH_TEST_HOST")
	if host == "" {
		t.Skip("WASH_TEST_HOST not set")
	}
	bin, _ := filepath.Abs("../../../wosh/bin/wosh")
	root := t.TempDir()
	t.Setenv("XDG_STATE_HOME", root+"/s")
	t.Setenv("XDG_CONFIG_HOME", root+"/c")
	m := &Manager{user: "t", cfg: Config{Wosh: bin, Hosts: []string{host}},
		sessions: map[string]*Session{}, attached: map[string]int{}, nonces: map[string]time.Time{},
		tickets: map[string]*ticket{}, conns: map[*browserConn]bool{}, quit: make(chan struct{})}
	if a := os.Getenv("SSH_AUTH_SOCK"); a != "" {
		m.agentSock = a
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	si, err := m.New(ctx, host, "", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("remote: %+v", *si.Remote)
	s, _ := m.get(si.ID)
	out := make(chan []byte, 64)
	pc, _, err := dialDaemon(ctx, m.signal(s), m.offerFor(s, 80, 24, 0, m.config()),
		func(p []byte) { out <- append([]byte(nil), p...) }, nil)
	if err != nil {
		t.Fatalf("reattach: %v", err)
	}
	select {
	case <-out:
	case <-time.After(15 * time.Second):
		t.Error("no output after reattach")
	}
	pc.Close()
	if err := m.Kill(si.ID); err != nil {
		t.Fatal(err)
	}
}
