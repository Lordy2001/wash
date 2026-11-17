// Package manager is washd: one persistent process per unix user that owns
// that user's wosh sessions, keeps a link to wash-web, verifies passkeys on
// its own, and serves browser connections handed over by wash-web.
package manager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"wash/internal/link"
	"wash/internal/passkey"
	"wash/internal/pin"
	"wash/internal/userpolicy"
)

// Version is washd's version (set by the build).
var Version = "0.1.0-dev"

const (
	nonceTTL    = 3 * time.Minute
	loginTTL    = time.Minute      // ticket from a passkey login: open the first socket
	subTTL      = time.Minute      // ticket for extra sockets of a logged-in page
	resumeTTL   = 30 * time.Minute // ticket to reconnect after a network drop
	maxNonces   = 64
	ticketBytes = 32
)

type ticket struct {
	expires time.Time
	kind    string // login | sub | resume
	key     string // passkey ShortID used
}

// Manager is the washd state.
type Manager struct {
	user  string
	creds Creds

	mu        sync.Mutex
	cfg       Config
	sessions  map[string]*Session
	attached  map[string]int
	nonces    map[string]time.Time // hex nonce -> expiry
	tickets   map[string]*ticket   // sha256 hex -> ticket
	conns     map[*browserConn]bool
	recs      map[string]*Recording // `wash watch` recordings
	recorders map[string]*recorder  // ...the running ones
	peer      *link.Peer
	agentSock string // user's ssh-agent for washd's own ssh (routes)
	linkErr   string
	linkedAt  time.Time
	started   time.Time
	quit      chan struct{}
	quitOnce  sync.Once
}

// New loads state; it does not start anything.
func New() (*Manager, error) {
	creds, err := LoadCreds()
	if err != nil {
		return nil, err
	}
	if err := userpolicy.CheckLocal(creds.User); err != nil {
		return nil, err
	}
	m := &Manager{
		user: creds.User, creds: creds, cfg: LoadConfig(),
		sessions: map[string]*Session{}, attached: map[string]int{},
		nonces: map[string]time.Time{}, tickets: map[string]*ticket{},
		conns: map[*browserConn]bool{}, started: time.Now(), quit: make(chan struct{}),
		recs: map[string]*Recording{}, recorders: map[string]*recorder{},
	}
	m.agentSock = os.Getenv("SSH_AUTH_SOCK") // from `wash up`; `wash agent` updates it
	m.loadSessions()
	m.loadRecordings()
	return m, nil
}

func (m *Manager) config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Stop ends Run.
func (m *Manager) Stop() { m.quitOnce.Do(func() { close(m.quit) }) }

// Run keeps the link up and serves the CLI socket until Stop.
func (m *Manager) Run() error {
	ln, err := m.listenControl()
	if err != nil {
		return err
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.linkLoop(ctx)
	m.resumeRecordings()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-m.quit:
			m.mu.Lock()
			for c := range m.conns {
				c.close("washd stopped")
			}
			if m.peer != nil {
				m.peer.Close("washd stopped")
			}
			rs := make([]*recorder, 0, len(m.recorders))
			for _, r := range m.recorders {
				rs = append(rs, r)
			}
			m.mu.Unlock()
			for _, r := range rs { // flush their files; they resume on the next start
				select {
				case <-r.done:
				case <-time.After(3 * time.Second):
				}
			}
			return nil
		case <-t.C:
			if m.prune() {
				m.changed()
			}
			m.expire()
		}
	}
}

func (m *Manager) expire() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, e := range m.nonces {
		if now.After(e) {
			delete(m.nonces, k)
		}
	}
	for k, t := range m.tickets {
		if now.After(t.expires) {
			delete(m.tickets, k)
		}
	}
}

// --- link to wash-web ------------------------------------------------------------

func (m *Manager) httpClient() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: pin.Config(m.creds.Fingerprint), Proxy: http.ProxyFromEnvironment}}
}

func wsURL(base, path string) string {
	u, _ := url.Parse(strings.TrimRight(base, "/") + path)
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	return u.String()
}

func (m *Manager) dial(ctx context.Context, path string) (*websocket.Conn, error) {
	c, resp, err := websocket.Dial(ctx, wsURL(m.creds.URL, path), &websocket.DialOptions{
		HTTPClient: m.httpClient(),
		HTTPHeader: http.Header{"Authorization": {"Bearer " + m.creds.Token}},
	})
	if err != nil && resp != nil && resp.StatusCode == http.StatusUnauthorized {
		return nil, errors.New("wash-web rejected our token (enroll again: `wash enroll`)")
	}
	return c, err
}

func (m *Manager) linkLoop(ctx context.Context) {
	backoff := time.Second
	for {
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := m.dial(dctx, "/api/link")
		cancel()
		if err == nil {
			backoff = time.Second
			p := link.NewPeer(c, m.handleLink)
			m.mu.Lock()
			m.peer, m.linkErr, m.linkedAt = p, "", time.Now()
			m.mu.Unlock()
			log.Printf("linked to %s as %s", m.creds.URL, m.user)
			err = p.Run(ctx)
			m.mu.Lock()
			m.peer = nil
			m.mu.Unlock()
		}
		m.mu.Lock()
		if err != nil {
			m.linkErr = err.Error()
		}
		m.mu.Unlock()
		log.Printf("link: %v (retry in %s)", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-m.quit:
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// web returns the live link (or an error explaining why there is none).
func (m *Manager) web() (*link.Peer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peer == nil {
		if m.linkErr != "" {
			return nil, fmt.Errorf("not connected to %s: %s", m.creds.URL, m.linkErr)
		}
		return nil, fmt.Errorf("not connected to %s yet", m.creds.URL)
	}
	return m.peer, nil
}

func (m *Manager) handleLink(ctx context.Context, op string, data json.RawMessage) (any, error) {
	switch op {
	case link.OpChallenge:
		return m.newNonce()
	case link.OpVerify:
		var req link.VerifyReq
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		tk, key, err := m.verify(req.Assertion)
		if err != nil {
			log.Printf("login from %s rejected: %v", req.Remote, err)
			return nil, err
		}
		log.Printf("login from %s with passkey %s verified", req.Remote, key)
		return link.Ticket{Ticket: tk}, nil
	case link.OpAttach:
		var req link.AttachReq
		if err := json.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		t, err := m.takeTicket(req.Ticket)
		if err != nil {
			log.Printf("attach from %s refused: %v", req.Remote, err)
			return nil, err
		}
		go m.serveBrowser(req.SID, req.Remote, t)
		return struct{}{}, nil
	}
	return nil, fmt.Errorf("unknown op %q", op)
}

// --- passkey verification ---------------------------------------------------------

func (m *Manager) newNonce() (link.Nonce, error) {
	n := make([]byte, passkey.NonceLen)
	_, _ = rand.Read(n)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.nonces) >= maxNonces {
		return link.Nonce{}, errors.New("too many logins in progress")
	}
	m.nonces[hex.EncodeToString(n)] = time.Now().Add(nonceTTL)
	return link.Nonce{Nonce: n}, nil
}

// verify checks an assertion against keys.json and a nonce we issued; on
// success it returns a single-use login ticket.
func (m *Manager) verify(assertion []byte) (string, string, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertion)
	if err != nil {
		return "", "", fmt.Errorf("bad assertion: %w", err)
	}
	ch, err := passkey.ClientChallenge(parsed)
	if err != nil {
		return "", "", err
	}
	nk := hex.EncodeToString(ch[passkey.NonceLen:])
	m.mu.Lock()
	exp, ok := m.nonces[nk]
	delete(m.nonces, nk)
	m.mu.Unlock()
	if !ok || time.Now().After(exp) {
		return "", "", errors.New("unknown or expired manager challenge")
	}
	keys, err := loadKeys()
	if err != nil {
		return "", "", err
	}
	var lk *LocalKey
	for i := range keys {
		var c webauthn.Credential
		if json.Unmarshal(keys[i].Credential, &c) == nil && subtle.ConstantTimeCompare(c.ID, parsed.RawID) == 1 {
			lk = &keys[i]
		}
	}
	if lk == nil {
		return "", "", errors.New("passkey not approved on this host (`wash keys approve ID`)")
	}
	var cred webauthn.Credential
	_ = json.Unmarshal(lk.Credential, &cred)
	wa, err := passkey.New(lk.RPID, []string{lk.Origin})
	if err != nil {
		return "", "", err
	}
	u := &passkey.User{Handle: lk.UserHandle, Name: m.user, Creds: []webauthn.Credential{cred}}
	updated, err := passkey.Verify(wa, u, parsed, ch)
	if err != nil {
		return "", "", err
	}
	lk.Credential, _ = json.Marshal(updated)
	lk.LastUsed = time.Now()
	if err := saveKeys(keys); err != nil {
		log.Printf("save keys: %v", err)
	}
	return m.issue("login", lk.ID, loginTTL), lk.ID, nil
}

func (m *Manager) issue(kind, key string, ttl time.Duration) string {
	b := make([]byte, ticketBytes)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(tok))
	m.mu.Lock()
	m.tickets[hex.EncodeToString(h[:])] = &ticket{expires: time.Now().Add(ttl), kind: kind, key: key}
	m.mu.Unlock()
	return tok
}

func (m *Manager) takeTicket(tok string) (*ticket, error) {
	h := sha256.Sum256([]byte(tok))
	k := hex.EncodeToString(h[:])
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.tickets[k]
	delete(m.tickets, k)
	if t == nil || time.Now().After(t.expires) {
		return nil, errors.New("invalid or expired ticket: sign in with your passkey again")
	}
	// a ticket of a revoked key is useless
	if keys, err := loadKeys(); err == nil {
		for _, lk := range keys {
			if lk.ID == t.key {
				return t, nil
			}
		}
	}
	return nil, errors.New("passkey was revoked")
}

// --- keys (CLI) -----------------------------------------------------------------

// KeyView merges the web side's list with keys.json.
type KeyView struct {
	link.KeyInfo
	Local bool   `json:"local"` // in keys.json (washd accepts it)
	Note  string `json:"note,omitempty"`
}

func (m *Manager) Keys(ctx context.Context) ([]KeyView, error) {
	local, err := loadKeys()
	if err != nil {
		return nil, err
	}
	have := map[string]*LocalKey{}
	for i := range local {
		have[local[i].ID] = &local[i]
	}
	out := []KeyView{}
	p, werr := m.web()
	var remote []link.KeyInfo
	if werr == nil {
		werr = p.Call(ctx, link.OpKeysList, nil, &remote)
	}
	seen := map[string]bool{}
	for _, k := range remote {
		v := KeyView{KeyInfo: k}
		if lk := have[k.ID]; lk != nil {
			v.Local = true
			if !lk.LastUsed.IsZero() {
				v.LastUsed = lk.LastUsed
			}
		}
		if k.Approved && !v.Local {
			v.Note = "approved on web only: washd rejects it until you approve it here"
		}
		seen[k.ID] = true
		out = append(out, v)
	}
	for _, lk := range local {
		if !seen[lk.ID] {
			v := KeyView{KeyInfo: lk.KeyInfo, Local: true}
			if werr == nil {
				v.Note = "unknown to wash-web (deleted there?)"
			} else {
				v.Note = "web unreachable: " + werr.Error()
			}
			out = append(out, v)
		}
	}
	if werr != nil && len(out) == 0 {
		return nil, werr
	}
	return out, nil
}

// Approve copies a pending key from wash-web into keys.json, then marks it
// approved there. Only keys registered for this washd's user are visible.
func (m *Manager) Approve(ctx context.Context, id string) (link.KeyInfo, error) {
	p, err := m.web()
	if err != nil {
		return link.KeyInfo{}, err
	}
	var rec link.KeyRecord
	if err := p.Call(ctx, link.OpKeysGet, link.KeyRef{ID: id}, &rec); err != nil {
		return link.KeyInfo{}, err
	}
	if rec.User != m.user {
		return link.KeyInfo{}, fmt.Errorf("passkey %s belongs to %s, not %s", rec.ID, rec.User, m.user)
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(rec.Credential, &cred); err != nil || len(cred.PublicKey) == 0 {
		return link.KeyInfo{}, errors.New("wash-web sent an unusable credential")
	}
	if passkey.ShortID(cred.ID) != rec.ID {
		return link.KeyInfo{}, errors.New("wash-web sent a credential that does not match its id")
	}
	keys, err := loadKeys()
	if err != nil {
		return link.KeyInfo{}, err
	}
	found := false
	rec.Approved, rec.Expires = true, time.Time{}
	for i := range keys {
		if keys[i].ID == rec.ID {
			keys[i].KeyRecord, found = rec, true
		}
	}
	if !found {
		keys = append(keys, LocalKey{KeyRecord: rec, ApprovedAt: time.Now()})
	}
	if err := saveKeys(keys); err != nil {
		return link.KeyInfo{}, err
	}
	if err := p.Call(ctx, link.OpKeysApprove, link.KeyRef{ID: rec.ID}, nil); err != nil {
		return link.KeyInfo{}, fmt.Errorf("approved locally, but wash-web failed: %w", err)
	}
	log.Printf("passkey %s (%s) approved", rec.ID, rec.Name)
	return rec.KeyInfo, nil
}

// OpenRegistration lets this user create passkeys on the website for d (wash-web
// caps it at one hour); d == 0 closes passkey creation again.
func (m *Manager) OpenRegistration(ctx context.Context, d time.Duration) (link.RegWindow, error) {
	p, err := m.web()
	if err != nil {
		return link.RegWindow{}, err
	}
	var out link.RegWindow
	if err := p.Call(ctx, link.OpKeysOpen, link.RegWindow{For: d}, &out); err != nil {
		return out, err
	}
	if d > 0 {
		log.Printf("passkey creation on the website open until %s", out.Until.Format(time.Kitchen))
	} else {
		log.Printf("passkey creation on the website closed")
	}
	return out, nil
}

// Revoke removes a key locally (immediately effective for washd) and on
// wash-web; open browser connections that logged in with it are closed.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	keys, err := loadKeys()
	if err != nil {
		return err
	}
	var keep []LocalKey
	full := ""
	for _, k := range keys {
		if strings.HasPrefix(k.ID, id) && len(id) >= 4 {
			full = k.ID
			continue
		}
		keep = append(keep, k)
	}
	if full != "" {
		if err := saveKeys(keep); err != nil {
			return err
		}
		m.mu.Lock()
		for c := range m.conns {
			if c.key == full {
				c.close("passkey revoked")
			}
		}
		m.mu.Unlock()
	}
	p, werr := m.web()
	if werr == nil {
		ref := id
		if full != "" {
			ref = full
		}
		werr = p.Call(ctx, link.OpKeysRevoke, link.KeyRef{ID: ref}, nil)
	}
	if full == "" && werr != nil {
		return werr
	}
	if werr != nil {
		log.Printf("revoke %s on wash-web: %v", full, werr)
	}
	return nil
}

// Status is `wash status`.
type Status struct {
	User     string        `json:"user"`
	URL      string        `json:"url"`
	Linked   bool          `json:"linked"`
	LinkErr  string        `json:"link_err,omitempty"`
	Since    time.Time     `json:"since"`
	PID      int           `json:"pid"`
	Version  string        `json:"version"`
	Sessions []SessionInfo `json:"sessions"`
	Browsers int           `json:"browsers"`
	Agent    string        `json:"agent,omitempty"`
}

func (m *Manager) Status() Status {
	ss := m.List()
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{User: m.user, URL: m.creds.URL, Linked: m.peer != nil, LinkErr: m.linkErr,
		Since: m.started, PID: os.Getpid(), Version: Version, Sessions: ss, Browsers: len(m.conns), Agent: m.agentSock}
}
