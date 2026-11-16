// End-to-end test: wash-web (in process, plain HTTP) + washd (in process) +
// real wosh daemons, driven by a software passkey authenticator.
//
// Needs a wosh binary: $WASH_TEST_WOSH, or ../wosh/bin/wosh next to this repo.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/fxamacker/cbor/v2"

	"wash/internal/link"
	"wash/internal/manager"
	"wash/internal/web"
	"wash/internal/wosh"
	webui "wash/web"
)

var b64 = base64.RawURLEncoding

// authenticator is a minimal software passkey (ES256, "none" attestation).
type authenticator struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newAuthenticator() *authenticator {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &authenticator{key: k, id: id}
}

func (a *authenticator) authData(rpID string, withCred bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	var b bytes.Buffer
	b.Write(h[:])
	flags := byte(0x05) // UP | UV
	if withCred {
		flags |= 0x40 // AT
	}
	b.WriteByte(flags)
	a.count++
	_ = binary.Write(&b, binary.BigEndian, a.count)
	if withCred {
		b.Write(make([]byte, 16)) // aaguid
		_ = binary.Write(&b, binary.BigEndian, uint16(len(a.id)))
		b.Write(a.id)
		pad := func(x []byte) []byte { return append(make([]byte, 32-len(x)), x...) }
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
			-2: pad(a.key.PublicKey.X.Bytes()), -3: pad(a.key.PublicKey.Y.Bytes())})
		b.Write(cose)
	}
	return b.Bytes()
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (a *authenticator) create(challenge, rpID, origin string) []byte {
	cd := clientData("webauthn.create", challenge, origin)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(rpID, true)})
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att)},
	})
	return out
}

func (a *authenticator) get(challenge, rpID, origin string) []byte {
	cd := clientData("webauthn.get", challenge, origin)
	ad := a.authData(rpID, false)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	out, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.id), "rawId": b64.EncodeToString(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig)},
	})
	return out
}

type env struct {
	t      *testing.T
	url    string // http://localhost:PORT
	client *http.Client
	db     *web.DB
}

func (e *env) post(path string, body any) (int, map[string]any) {
	var rd io.Reader
	switch b := body.(type) {
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest("POST", e.url+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", e.url)
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func allowOf(opts map[string]any) []any {
	l, _ := opts["options"].(map[string]any)["publicKey"].(map[string]any)["allowCredentials"].([]any)
	return l
}

func challengeOf(opts map[string]any) string {
	return opts["options"].(map[string]any)["publicKey"].(map[string]any)["challenge"].(string)
}

func woshBin(t *testing.T) string {
	if p := os.Getenv("WASH_TEST_WOSH"); p != "" {
		return p
	}
	p, _ := filepath.Abs("../../../wosh/bin/wosh")
	if _, err := os.Stat(p); err != nil {
		t.Skip("no wosh binary (set WASH_TEST_WOSH)")
	}
	return p
}

func TestEndToEnd(t *testing.T) {
	bin := woshBin(t)
	// short paths: unix socket names are limited to ~108 bytes
	root, err := os.MkdirTemp("", "wash")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	for k, v := range map[string]string{
		"HOME": root, "XDG_CONFIG_HOME": root + "/c", "XDG_STATE_HOME": root + "/st",
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

	// --- enroll washd -----------------------------------------------------------
	code, _ := db.NewEnrollCode("alice")
	st, out := e.post("/api/enroll", map[string]string{"code": code})
	if st != 200 {
		t.Fatalf("enroll: %d %v", st, out)
	}
	if st, _ := e.post("/api/enroll", map[string]string{"code": code}); st == 200 {
		t.Fatal("enroll code reused")
	}
	if err := manager.SaveCreds(manager.Creds{URL: base, User: "alice", Token: out["token"].(string)}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SaveConfig(manager.Config{Wosh: bin, ICE: []wosh.ICEServer{}}); err != nil {
		t.Fatal(err)
	}

	// login/begin does not reveal users, passkeys or managers: a user without
	// approved passkeys gets a stable decoy, shaped like a real challenge
	decoys := map[string]any{}
	for _, u := range []string{"alice", "nosuchuser", "alice"} {
		st, out := e.post("/api/login/begin", map[string]string{"user": u})
		if st != 200 || len(allowOf(out)) != 1 {
			t.Fatalf("login begin %s: %d %v", u, st, out)
		}
		id := allowOf(out)[0].(map[string]any)["id"]
		if prev, ok := decoys[u]; ok && prev != id {
			t.Fatalf("decoy for %s changed: %v -> %v", u, prev, id)
		}
		decoys[u] = id
	}
	if decoys["alice"] == decoys["nosuchuser"] {
		t.Fatal("decoys are not per user")
	}
	// every sign-in request takes at least the floor, so timing tells nothing
	t0 := time.Now()
	if st, out := e.post("/api/login/begin", map[string]string{"user": "root"}); st != 200 || len(allowOf(out)) != 1 {
		t.Fatalf("login begin root: %d %v", st, out)
	}
	if d := time.Since(t0); d < 100*time.Millisecond {
		t.Fatalf("login begin answered in %s, under the 100ms floor", d)
	}
	t0 = time.Now()
	if st, _ := e.post("/api/login/finish?id=nope", map[string]string{}); st != 400 || time.Since(t0) < 100*time.Millisecond {
		t.Fatalf("login finish: %d in %s", st, time.Since(t0))
	}

	// root, default and service accounts never get in
	rootCode, _ := db.NewEnrollCode("root")
	if st, out := e.post("/api/enroll", map[string]string{"code": rootCode}); st != 403 {
		t.Fatalf("enroll root: %d %v", st, out)
	}
	srv.OpenRegistration("ubuntu", time.Minute)
	if st, out := e.post("/api/register/begin", map[string]string{"user": "ubuntu"}); st != 403 ||
		!strings.Contains(fmt.Sprint(out["error"]), "cannot use wash") {
		t.Fatalf("register ubuntu: %d %v", st, out)
	}
	srv.ResetRateLimitsForTest()
	if n, _ := e.db.Keys("nosuchuser"); len(n) != 0 {
		t.Fatal("login begin stored something for an unknown user")
	}

	m, err := manager.New()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := m.Run(); err != nil {
			t.Errorf("washd: %v", err)
		}
	}()
	defer func() {
		_ = manager.Call(manager.Request{Op: "stop", All: true}, nil)
		time.Sleep(300 * time.Millisecond)
	}()
	waitFor(t, "washd link", func() bool {
		var s manager.Status
		return manager.Call(manager.Request{Op: "status"}, &s) == nil && s.Linked
	})

	// --- register a passkey (pending) -----------------------------------------------
	// passkey creation is closed until the user opens it from the host
	if st, out := e.post("/api/register/begin", map[string]string{"user": "alice", "name": "x"}); st != 403 ||
		!strings.Contains(fmt.Sprint(out["error"]), "wash keys open") {
		t.Fatalf("register while closed: %d %v", st, out)
	}
	var rw link.RegWindow
	if err := manager.Call(manager.Request{Op: "keys.open", Val: "5h"}, &rw); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(rw.Until); d < 59*time.Minute || d > time.Hour {
		t.Fatalf("registration window %s, want capped at 1h", d)
	}
	auth := newAuthenticator()
	register := func(a *authenticator, user string) string {
		st, begin := e.post("/api/register/begin", map[string]string{"user": user, "name": "test key"})
		if st != 200 {
			t.Fatalf("register begin: %d %v", st, begin)
		}
		st, fin := e.post("/api/register/finish?id="+begin["id"].(string), a.create(challengeOf(begin), "localhost", base))
		if st != 200 {
			t.Fatalf("register finish: %d %v", st, fin)
		}
		return fin["id"].(string)
	}
	keyID := register(auth, "alice")

	login := func(a *authenticator) (int, map[string]any) {
		st, begin := e.post("/api/login/begin", map[string]string{"user": "alice"})
		if st != 200 {
			return st, begin
		}
		return e.post("/api/login/finish?id="+begin["id"].(string), a.get(challengeOf(begin), "localhost", base))
	}
	if st, out := login(auth); st == 200 {
		t.Fatalf("login with pending key succeeded: %v", out)
	}

	var keys []manager.KeyView
	if err := manager.Call(manager.Request{Op: "keys.list"}, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != keyID || keys[0].Approved || keys[0].Expires.IsZero() {
		t.Fatalf("keys before approve: %+v", keys)
	}
	if d := time.Until(keys[0].Expires); d < 59*time.Minute || d > time.Hour {
		t.Fatalf("pending ttl %s", d)
	}

	// another user's key cannot be approved by alice's washd
	if st, _ := e.post("/api/register/begin", map[string]string{"user": "bob"}); st != 403 {
		t.Fatal("alice's window opened registration for bob")
	}
	srv.OpenRegistration("bob", time.Minute)
	bobKey := register(newAuthenticator(), "bob")
	if err := manager.Call(manager.Request{Op: "keys.approve", ID: bobKey}, nil); err == nil {
		t.Fatal("alice approved bob's key")
	}

	var ki link.KeyInfo
	if err := manager.Call(manager.Request{Op: "keys.approve", ID: keyID[:6]}, &ki); err != nil {
		t.Fatal(err)
	}

	// --- dual verification ----------------------------------------------------------
	// a key approved on the web side only (e.g. a tampered DB) is refused by washd
	rogue := newAuthenticator()
	rogueID := register(rogue, "alice")
	if err := db.Approve("alice", rogueID); err != nil {
		t.Fatal(err)
	}
	if st, out := login(rogue); st != 403 || !strings.Contains(fmt.Sprint(out["error"]), "not approved on this host") {
		t.Fatalf("rogue login: %d %v", st, out)
	}

	st, fin := login(auth)
	if st != 200 {
		t.Fatalf("login: %d %v", st, fin)
	}
	ticket := fin["ticket"].(string)

	// --- browser socket ---------------------------------------------------------------
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dialWS := func(tk string) (*websocket.Conn, map[string]any) {
		u := strings.Replace(base, "http", "ws", 1) + "/api/ws?ticket=" + tk
		c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: e.client, HTTPHeader: http.Header{"Origin": {base}}})
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadLimit(1 << 20)
		for {
			typ, b, err := c.Read(ctx)
			if err != nil {
				t.Fatalf("socket: %v", err)
			}
			if typ == websocket.MessageText {
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				if m["t"] == "hello" {
					return c, m
				}
			}
		}
	}
	ctl, hello := dialWS(ticket)
	defer ctl.CloseNow()
	if hello["user"] != "alice" || hello["resume"] == "" {
		t.Fatalf("hello: %v", hello)
	}
	// tickets are single use
	{
		u := strings.Replace(base, "http", "ws", 1) + "/api/ws?ticket=" + ticket
		c, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{HTTPClient: e.client, HTTPHeader: http.Header{"Origin": {base}}})
		if err == nil {
			_, _, rerr := c.Read(ctx)
			if websocket.CloseStatus(rerr) != 4403 {
				t.Fatalf("reused ticket: %v", rerr)
			}
		}
	}

	rid := 0
	request := func(c *websocket.Conn, m map[string]any) map[string]any {
		rid++
		m["rid"] = rid
		b, _ := json.Marshal(m)
		if err := c.Write(ctx, websocket.MessageText, b); err != nil {
			t.Fatal(err)
		}
		for {
			typ, b, err := c.Read(ctx)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if typ != websocket.MessageText {
				continue
			}
			var r map[string]any
			_ = json.Unmarshal(b, &r)
			if r["rid"] == float64(rid) {
				if r["t"] == "err" {
					t.Fatalf("%v: %v", m["t"], r["err"])
				}
				return r
			}
		}
	}
	created := request(ctl, map[string]any{"t": "new", "name": "e2e", "cols": 100, "rows": 30})
	sid := created["session"].(map[string]any)["id"].(string)

	var ss []manager.SessionInfo
	if err := manager.Call(manager.Request{Op: "sessions.list"}, &ss); err != nil || len(ss) != 1 || ss[0].Name != "e2e" {
		t.Fatalf("sessions: %v %+v", err, ss)
	}

	// --- bridge: wosh frames over the WebSocket ------------------------------------------
	sub := request(ctl, map[string]any{"t": "ticket"})["ticket"].(string)
	br, _ := dialWS(sub)
	defer br.CloseNow()
	request(br, map[string]any{"t": "bridge", "id": sid, "cols": 100, "rows": 30})
	frame := func(t0 byte, off uint64, data []byte) []byte {
		b := make([]byte, 9+len(data))
		b[0] = t0
		binary.BigEndian.PutUint64(b[1:], off)
		copy(b[9:], data)
		return b
	}
	in := []byte("echo wash-$((6*7))\r")
	if err := br.Write(ctx, websocket.MessageBinary, frame(wosh.FInput, 0, in)); err != nil {
		t.Fatal(err)
	}
	var outBuf bytes.Buffer
	var rx uint64
	acked := false
	for !strings.Contains(outBuf.String(), "wash-42") || !acked {
		typ, b, err := br.Read(ctx)
		if err != nil {
			t.Fatalf("bridge read: %v (output so far %q)", err, outBuf.String())
		}
		if typ != websocket.MessageBinary || len(b) < 9 {
			continue
		}
		switch b[0] {
		case wosh.FOutput:
			off := binary.BigEndian.Uint64(b[1:9])
			if off != rx {
				t.Fatalf("output offset %d, want %d", off, rx)
			}
			rx += uint64(len(b) - 9)
			outBuf.Write(b[9:])
		case wosh.FAck:
			if binary.BigEndian.Uint64(b[1:9]) == uint64(len(in)) {
				acked = true
			}
		}
	}
	br.CloseNow()

	// a second bridge resumes at rx_out: only new output arrives
	sub = request(ctl, map[string]any{"t": "ticket"})["ticket"].(string)
	br2, _ := dialWS(sub)
	defer br2.CloseNow()
	request(br2, map[string]any{"t": "bridge", "id": sid, "cols": 100, "rows": 30, "rx_out": rx})
	in2 := []byte("echo again-$((7*6))\r")
	_ = br2.Write(ctx, websocket.MessageBinary, frame(wosh.FInput, uint64(len(in)), in2))
	outBuf.Reset()
	for !strings.Contains(outBuf.String(), "again-42") {
		typ, b, err := br2.Read(ctx)
		if err != nil {
			t.Fatalf("bridge2 read: %v", err)
		}
		if typ == websocket.MessageBinary && len(b) >= 9 && b[0] == wosh.FOutput {
			if off := binary.BigEndian.Uint64(b[1:9]); off < rx {
				t.Fatalf("replayed old output at %d (< %d)", off, rx)
			}
			outBuf.Write(b[9:])
		}
	}
	if strings.Contains(outBuf.String(), "wash-42") {
		t.Fatal("old output replayed")
	}

	// --- shared sessions: one tab controls, the others watch --------------------------------
	bridgeAs := func(cid string, take bool) *websocket.Conn {
		tk := request(ctl, map[string]any{"t": "ticket"})["ticket"].(string)
		c, _ := dialWS(tk)
		t.Cleanup(func() { c.CloseNow() })
		request(c, map[string]any{"t": "bridge", "id": sid, "cols": 100, "rows": 30, "cid": cid, "take": take, "rx_out": rx})
		return c
	}
	type view struct {
		c    *websocket.Conn
		out  bytes.Buffer
		role string
		ack  uint64
	}
	// pump reads v until done() or a read error (returned)
	pump := func(v *view, done func() bool) error {
		for !done() {
			typ, b, err := v.c.Read(ctx)
			if err != nil {
				return err
			}
			if typ != websocket.MessageBinary || len(b) == 0 {
				continue
			}
			switch b[0] {
			case wosh.FOutput:
				v.out.Write(b[9:])
			case wosh.FAck:
				v.ack = binary.BigEndian.Uint64(b[1:9])
			case wosh.FControl:
				var c struct{ Op, Role string }
				if json.Unmarshal(b[1:], &c) == nil && c.Op == "role" {
					v.role = c.Role
				}
			}
		}
		return nil
	}
	control := func(c *websocket.Conn, op string) {
		j, _ := json.Marshal(map[string]string{"op": op})
		if err := c.Write(ctx, websocket.MessageBinary, append([]byte{wosh.FControl}, j...)); err != nil {
			t.Fatal(err)
		}
	}
	// br2 is a legacy peer (no cid) in control: a tab joining only watches
	A := &view{c: bridgeAs("tabA", false)}
	if err := pump(A, func() bool { return A.role != "" }); err != nil || A.role != "view" {
		t.Fatalf("tabA joined as %q (%v), want view", A.role, err)
	}
	// a watcher's input goes nowhere
	_ = A.c.Write(ctx, websocket.MessageBinary, frame(wosh.FInput, A.ack, []byte("echo viewer-$((1+1))\r")))
	// taking control: tabA controls, the legacy peer is dropped as before roles
	A.ack = 0 // taking control is followed by an ack: the input offset to continue from
	control(A.c, "take")
	if err := pump(A, func() bool { return A.role == "control" }); err != nil {
		t.Fatal(err)
	}
	_ = pump(A, func() bool { return A.ack > 0 })
	if _, _, err := br2.Read(ctx); err == nil {
		// drain until the drop
		for err == nil {
			_, _, err = br2.Read(ctx)
		}
	}
	// tabB joins: watches; both see what tabA types
	B := &view{c: bridgeAs("tabB", false)}
	if err := pump(B, func() bool { return B.role != "" }); err != nil || B.role != "view" {
		t.Fatalf("tabB joined as %q (%v), want view", B.role, err)
	}
	_ = A.c.Write(ctx, websocket.MessageBinary, frame(wosh.FInput, A.ack, []byte("echo shared-$((5*5))\r")))
	for _, v := range []*view{A, B} {
		if err := pump(v, func() bool { return strings.Contains(v.out.String(), "shared-25") }); err != nil {
			t.Fatalf("output: %v (%q)", err, v.out.String())
		}
	}
	if strings.Contains(A.out.String()+B.out.String(), "viewer-2") {
		t.Fatal("a watcher's input reached the shell")
	}
	// tabB takes control: tabA is told it watches (and stays connected)
	B.ack = 0 // taking control is followed by an ack: the input offset to continue from
	control(B.c, "take")
	if err := pump(B, func() bool { return B.role == "control" }); err != nil {
		t.Fatal(err)
	}
	if err := pump(A, func() bool { return A.role == "view" }); err != nil {
		t.Fatalf("tabA after tabB took control: %v", err)
	}
	_ = pump(B, func() bool { return B.ack > 0 })
	_ = B.c.Write(ctx, websocket.MessageBinary, frame(wosh.FInput, B.ack, []byte("echo second-$((3*3))\r")))
	if err := pump(A, func() bool { return strings.Contains(A.out.String(), "second-9") }); err != nil {
		t.Fatalf("tabA watching: %v", err)
	}
	// a reconnect of the same tab keeps control; a page reload asking to take wins
	B2 := &view{c: bridgeAs("tabB", false)}
	if err := pump(B2, func() bool { return B2.role != "" }); err != nil || B2.role != "control" {
		t.Fatalf("tabB reconnect: %q %v", B2.role, err)
	}

	// --- kill from the CLI side -----------------------------------------------------------
	if err := manager.Call(manager.Request{Op: "sessions.kill", ID: sid}, nil); err != nil {
		t.Fatal(err)
	}
	if err := manager.Call(manager.Request{Op: "sessions.list"}, &ss); err != nil || len(ss) != 0 {
		t.Fatalf("after kill: %v %+v", err, ss)
	}

	// --- revoke closes the browser and blocks login ---------------------------------------
	if err := manager.Call(manager.Request{Op: "keys.revoke", ID: keyID}, nil); err != nil {
		t.Fatal(err)
	}
	for {
		_, _, err := ctl.Read(ctx)
		if err != nil {
			break
		}
	}
	if st, _ := login(auth); st == 200 {
		t.Fatal("login after revoke")
	}

	// --- pending keys are purged after the TTL ----------------------------------------------
	srv.ResetRateLimitsForTest() // the test is one client making many sign-in requests
	pend := register(newAuthenticator(), "alice")
	db.ExpirePendingForTest()
	if _, err := db.Key("alice", pend); err == nil {
		t.Fatal("expired pending key still present")
	}

	// --- wash keys close ----------------------------------------------------------------------
	var closed link.RegWindow
	if err := manager.Call(manager.Request{Op: "keys.open"}, &closed); err != nil || !closed.Until.IsZero() {
		t.Fatalf("keys close: %v %+v", err, closed)
	}
	if st, _ := e.post("/api/register/begin", map[string]string{"user": "alice"}); st != 403 {
		t.Fatal("registration still open after close")
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	for i := 0; i < 100; i++ {
		if f() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
