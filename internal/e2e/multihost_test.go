package e2e

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"wash/internal/link"
	"wash/internal/manager"
	"wash/internal/passkey"
	"wash/internal/web"
	"wash/internal/wosh"
	webui "wash/web"
)

// fakeWashd is a second washd of the same user on another host, speaking
// the link protocol: nonces, verification against the mixed challenge,
// attach with a dial-back that says hello, and revocations.
type fakeWashd struct {
	t       *testing.T
	base    string
	token   string
	mu      sync.Mutex
	nonces  map[string]bool
	revoked []string
	hosts   []string // hosts named in attaches
}

func (f *fakeWashd) dial(ctx context.Context, path string) (*websocket.Conn, error) {
	u := strings.Replace(f.base, "http", "ws", 1) + path
	c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPHeader: http.Header{
		"Authorization": {"Bearer " + f.token}, link.HostHeader: {"spoofed"}}})
	return c, err
}

func (f *fakeWashd) run(ctx context.Context) {
	c, err := f.dial(ctx, "/api/link")
	if err != nil {
		f.t.Errorf("fake washd link: %v", err)
		return
	}
	p := link.NewPeer(c, func(ctx context.Context, op string, data json.RawMessage) (any, error) {
		switch op {
		case link.OpChallenge:
			n := make([]byte, passkey.NonceLen)
			_, _ = rand.Read(n)
			f.mu.Lock()
			f.nonces[string(n)] = true
			f.mu.Unlock()
			return link.Nonce{Nonce: n}, nil
		case link.OpVerify:
			var req link.VerifyReq
			_ = json.Unmarshal(data, &req)
			if len(req.Nonces) < 2 {
				return nil, errors.New("expected a mixed challenge")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, n := range req.Nonces {
				if f.nonces[string(n)] {
					delete(f.nonces, string(n))
					return link.Ticket{Ticket: "fake-ticket"}, nil
				}
			}
			return nil, errors.New("not my nonce")
		case link.OpAttach:
			var req link.AttachReq
			_ = json.Unmarshal(data, &req)
			if req.Ticket != "fake-ticket" {
				return nil, errors.New("bad ticket")
			}
			go func() {
				c, err := f.dial(context.Background(), "/api/link/conn?sid="+req.SID)
				if err != nil {
					f.t.Errorf("dial back: %v", err)
					return
				}
				b, _ := json.Marshal(map[string]any{"t": "hello", "user": "alice", "host": "two"})
				_ = c.Write(context.Background(), websocket.MessageText, b)
				time.Sleep(2 * time.Second)
				c.CloseNow()
			}()
			return struct{}{}, nil
		case link.OpKeyRevoked:
			var ref link.KeyRef
			_ = json.Unmarshal(data, &ref)
			f.mu.Lock()
			f.revoked = append(f.revoked, ref.ID)
			f.mu.Unlock()
			return struct{}{}, nil
		}
		return nil, errors.New("unknown op " + op)
	})
	_ = p.Run(ctx)
}

// TestMultiHost: one user, two washds on different hosts behind one
// wash-web. One passkey sign-in gives a ticket for each; each browser
// socket goes to the washd it names; a revocation reaches both.
func TestMultiHost(t *testing.T) {
	bin := woshBin(t)
	root, err := os.MkdirTemp("", "washm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	for k, v := range map[string]string{
		"HOME": root, "XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/st", "XDG_DATA_HOME": root + "/d",
		"WASH_RUNTIME_DIR": root + "/r", "SHELL": "/bin/sh",
	} {
		t.Setenv(k, v)
	}
	db, err := web.OpenDB(filepath.Join(root, "wash.db"))
	if err != nil {
		t.Fatal(err)
	}
	srv := web.New(web.Config{Static: webui.Static(), Version: "test"}, db)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	base := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	jar, _ := cookiejar.New(nil)
	e := &env{t: t, url: base, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}, db: db}

	enroll := func(host string) string {
		code, _ := db.NewEnrollCode("alice")
		st, out := e.post("/api/enroll", map[string]string{"code": code, "host": host})
		if st != 200 {
			t.Fatalf("enroll %s: %d %v", host, st, out)
		}
		return out["token"].(string)
	}
	tokOne := enroll("one")
	tokTwo := enroll("two")
	if st, _ := e.post("/api/enroll", map[string]string{"code": "x", "host": "-bad host"}); st != 400 {
		t.Fatalf("bad host name accepted: %d", st)
	}
	if err := manager.SaveCreds(manager.Creds{URL: base, User: "alice", Token: tokOne, Host: "one"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SaveConfig(manager.Config{Wosh: bin, ICE: []wosh.ICEServer{}, Hosts: []string{}}); err != nil {
		t.Fatal(err)
	}
	m, err := manager.New()
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = m.Run() }()
	defer func() {
		_ = manager.Call(manager.Request{Op: "stop", All: true}, nil)
		time.Sleep(300 * time.Millisecond)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fake := &fakeWashd{t: t, base: base, token: tokTwo, nonces: map[string]bool{}}
	go fake.run(ctx)
	waitFor(t, "washd link", func() bool {
		var s manager.Status
		return manager.Call(manager.Request{Op: "status"}, &s) == nil && s.Linked
	})
	rows, _ := db.Managers()
	if len(rows) != 2 || rows[0].Host != "one" || rows[1].Host != "two" {
		t.Fatalf("managers: %+v (the enrolled host name wins over the header)", rows)
	}

	// a passkey, approved on washd "one" (the fake accepts any)
	if err := manager.Call(manager.Request{Op: "keys.open", Val: "10m"}, nil); err != nil {
		t.Fatal(err)
	}
	auth := newAuthenticator()
	st, begin := e.post("/api/register/begin", map[string]string{"user": "alice", "name": "k"})
	if st != 200 {
		t.Fatalf("register begin: %d %v", st, begin)
	}
	st, fin := e.post("/api/register/finish?id="+begin["id"].(string), auth.create(challengeOf(begin), "localhost", base))
	if st != 200 {
		t.Fatalf("register finish: %d %v", st, fin)
	}
	keyID := fin["id"].(string)
	if err := manager.Call(manager.Request{Op: "keys.approve", ID: keyID}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both links", func() bool {
		st, b := e.post("/api/login/begin", map[string]string{"user": "alice"})
		if st != 200 {
			return false
		}
		_ = b
		fake.mu.Lock()
		n := len(fake.nonces)
		fake.mu.Unlock()
		return n > 0
	})

	st, begin = e.post("/api/login/begin", map[string]string{"user": "alice"})
	if st != 200 {
		t.Fatalf("login begin: %d %v", st, begin)
	}
	st, fin = e.post("/api/login/finish?id="+begin["id"].(string), auth.get(challengeOf(begin), "localhost", base))
	if st != 200 {
		t.Fatalf("login: %d %v", st, fin)
	}
	tickets := map[string]string{}
	for _, x := range fin["managers"].([]any) {
		r := x.(map[string]any)
		if tk, _ := r["ticket"].(string); tk != "" {
			tickets[r["host"].(string)] = tk
		} else {
			t.Errorf("washd %v refused: %v", r["host"], r["err"])
		}
	}
	if len(tickets) != 2 || tickets["two"] != "fake-ticket" || fin["ticket"] != tickets["one"] {
		t.Fatalf("login result: %v", fin)
	}

	hello := func(host, tk string) map[string]any {
		u := strings.Replace(base, "http", "ws", 1) + "/api/ws?host=" + host + "&ticket=" + tk
		c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: e.client, HTTPHeader: http.Header{"Origin": {base}}})
		if err != nil {
			t.Fatal(err)
		}
		defer c.CloseNow()
		for {
			typ, b, err := c.Read(ctx)
			if err != nil {
				t.Fatalf("socket to %s: %v", host, err)
			}
			var h map[string]any
			if typ == websocket.MessageText && json.Unmarshal(b, &h) == nil && h["t"] == "hello" {
				return h
			}
		}
	}
	if h := hello("one", tickets["one"]); h["host"] != "one" || h["user"] != "alice" {
		t.Fatalf("hello from one: %v", h)
	}
	if h := hello("two", tickets["two"]); h["host"] != "two" {
		t.Fatalf("hello from two: %v", h)
	}
	// no host with two washds: refused, not guessed
	{
		u := strings.Replace(base, "http", "ws", 1) + "/api/ws?ticket=x"
		c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: e.client, HTTPHeader: http.Header{"Origin": {base}}})
		if err == nil {
			_, _, rerr := c.Read(ctx)
			if websocket.CloseStatus(rerr) != 4503 {
				t.Fatalf("ws without host: %v", rerr)
			}
		}
	}

	// revoking on one tells the other
	if err := manager.Call(manager.Request{Op: "keys.revoke", ID: keyID}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revocation at the other washd", func() bool {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return len(fake.revoked) == 1 && fake.revoked[0] == keyID
	})
}
