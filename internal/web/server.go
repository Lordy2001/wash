// Package web is wash-web: the HTTPS site (listening on 0.0.0.0 inside its
// container) that authenticates passkeys and hands browser WebSockets to the
// user's washd over the manager link.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"wash/internal/link"
	"wash/internal/passkey"
	"wash/internal/userpolicy"
)

// Config configures the server.
type Config struct {
	Listen       string   // 0.0.0.0:8443
	Origins      []string // allowed browser origins; empty = derive from Host
	Registration bool     // always allow creating passkeys (else only in windows opened by `wash keys open`)
	Static       fs.FS
	Version      string
	TrustProxy   bool            // take client IP and scheme from X-Forwarded-For/-Proto
	Proxies      []netip.Prefix  // ... but only from these peers (empty: from any peer)
	CAFile       string          // wash-web's own CA, served at /ca.crt for users to trust
	DenyUsers    map[string]bool // refused on top of userpolicy.Reserved (WASH_DENY_USERS)
	PlaybackDir  string          // published recordings (`wash watch host`); "" = off
	PlaybackMax  int64           // largest published recording in bytes (0 = no limit)
	PublicURL    string          // public base URL (WASH_PUBLIC_URL), for playback links
}

// MaxRegWindow is the longest `wash keys open` window.
const MaxRegWindow = time.Hour

// Server is the web front end.
type Server struct {
	cfg Config
	db  *DB

	mu         sync.Mutex
	ceremonies map[string]*ceremony
	sessions   map[string]*webSession
	links      map[string]map[string]*link.Peer // user -> washd host -> link
	waiters    map[string]*waiter               // sid -> pending dial-back
	limits     map[string]*bucket
	regOpen    map[string]time.Time // user -> passkey creation allowed until
	secret     []byte               // keys decoy login challenges
	uploads    map[string]*upload   // playback uuid -> upload in progress
}

type ceremony struct {
	kind     string // reg | login
	user     string
	name     string
	rpID     string
	origin   string
	session  webauthn.SessionData
	expires  time.Time
	attempts int
	decoy    bool // login for a user without approved passkeys: always fails
	// managers: the washds asked for a nonce at /begin (login), in the order
	// their nonces went into the challenge
	managers []managerNonce
}

type managerNonce struct {
	host  string
	peer  *link.Peer
	nonce []byte
}

type webSession struct {
	user    string
	expires time.Time
}

type waiter struct {
	user string
	host string // the washd that must dial back
	ch   chan *dialBack
}

type dialBack struct {
	c    *websocket.Conn
	done chan struct{}
}

const (
	cookieName  = "wash_session"
	sessionTTL  = 12 * time.Hour
	ceremonyTTL = 3 * time.Minute
)

var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// New returns a server.
func New(cfg Config, db *DB) *Server {
	secret, err := db.Secret()
	if err != nil {
		log.Printf("server secret: %v (using a random one until restart)", err)
		secret = make([]byte, 32)
		_, _ = rand.Read(secret)
	}
	return &Server{
		cfg: cfg, db: db, secret: secret,
		regOpen:    map[string]time.Time{},
		ceremonies: map[string]*ceremony{},
		sessions:   map[string]*webSession{},
		links:      map[string]map[string]*link.Peer{},
		waiters:    map[string]*waiter{},
		limits:     map[string]*bucket{},
		uploads:    map[string]*upload{},
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", s.static())
	mux.HandleFunc("GET /api/config", s.handleConfig)
	mux.HandleFunc("GET /ca.crt", s.handleCA)
	mux.HandleFunc("POST /api/register/begin", s.limited(s.handleRegisterBegin))
	mux.HandleFunc("POST /api/register/finish", s.limited(s.handleRegisterFinish))
	mux.HandleFunc("POST /api/login/begin", s.limited(floor(loginFloor, s.handleLoginBegin)))
	mux.HandleFunc("POST /api/login/finish", s.limited(floor(loginFloor, s.handleLoginFinish)))
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/ws", s.handleBrowserWS)
	mux.HandleFunc("POST /api/enroll", s.limited(s.handleEnroll))
	mux.HandleFunc("GET /api/link", s.handleLink)
	mux.HandleFunc("GET /api/link/conn", s.handleLinkConn)
	mux.HandleFunc("GET /playback/{id}", s.handlePlaybackPage)
	mux.HandleFunc("GET /playback/{id}/cast", s.handlePlaybackCast)
	return securityHeaders(mux)
}

// Run serves until ctx ends; also purges expired state.
func (s *Server) Janitor(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if n := s.db.Purge(); n > 0 {
			log.Printf("purged %d unapproved passkey(s) older than %s", n, PendingTTL)
		}
		now := time.Now()
		s.mu.Lock()
		for k, c := range s.ceremonies {
			if now.After(c.expires) {
				delete(s.ceremonies, k)
			}
		}
		for k, v := range s.sessions {
			if now.After(v.expires) {
				delete(s.sessions, k)
			}
		}
		for k, b := range s.limits {
			if now.Sub(b.last) > 10*time.Minute {
				delete(s.limits, k)
			}
		}
		s.expireUploadsLocked(now)
		for k, until := range s.regOpen {
			if now.After(until) {
				delete(s.regOpen, k)
			}
		}
		s.mu.Unlock()
	}
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Content-Security-Policy", "default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) static() http.Handler {
	fsrv := http.FileServerFS(s.cfg.Static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fsrv.ServeHTTP(w, r)
	})
}

// --- helpers -----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(v)
}

func newID() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func peerIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

var prefixRE = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)

// basePath is the path prefix the site is served under: X-Forwarded-Prefix
// from a trusted proxy (e.g. "/wash" behind Caddy's handle_path), else "".
// The page itself only uses relative URLs; this scopes the session cookie,
// so other apps on the same host name never receive it.
func (s *Server) basePath(r *http.Request) string {
	if !s.viaProxy(r) {
		return ""
	}
	p := strings.TrimRight(r.Header.Get("X-Forwarded-Prefix"), "/")
	if !prefixRE.MatchString(p) || strings.Contains(p, "/.") {
		return ""
	}
	return p
}

// trustedProxy reports whether ip is one of the configured proxies.
func (s *Server) trustedProxy(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range s.cfg.Proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// viaProxy reports whether the request's X-Forwarded-* headers can be believed.
func (s *Server) viaProxy(r *http.Request) bool {
	return s.cfg.TrustProxy && (len(s.cfg.Proxies) == 0 || s.trustedProxy(peerIP(r)))
}

// clientIP is the address rate limits and logs use. Behind a trusted proxy it
// is the right-most X-Forwarded-For entry that is not itself a trusted proxy:
// entries to the left of that were written by the client and can be anything.
func (s *Server) clientIP(r *http.Request) string {
	peer := peerIP(r)
	if !s.viaProxy(r) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		if len(s.cfg.Proxies) > 0 && s.trustedProxy(h) {
			continue
		}
		return h
	}
	return peer
}

// rp returns the WebAuthn instance for this request's origin.
func (s *Server) rp(r *http.Request) (*webauthn.WebAuthn, string, error) {
	origin := r.Header.Get("Origin")
	if h, _, err := net.SplitHostPort(r.Host); (err == nil && net.ParseIP(h) != nil) || net.ParseIP(r.Host) != nil {
		msg := "passkeys cannot be used on an IP address; open this site by host name"
		if len(s.cfg.Origins) > 0 {
			msg += ": " + strings.Join(s.cfg.Origins, " or ")
		}
		return nil, "", errors.New(msg)
	}
	if len(s.cfg.Origins) > 0 {
		ok := false
		for _, o := range s.cfg.Origins {
			if o == origin {
				ok = true
			}
		}
		if !ok {
			return nil, "", fmt.Errorf("origin %q not allowed (WASH_ORIGIN)", origin)
		}
	} else {
		scheme := "https"
		if r.TLS == nil && !(s.viaProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https") {
			scheme = "http"
		}
		want := scheme + "://" + r.Host
		if origin != "" && origin != want {
			return nil, "", fmt.Errorf("origin %q does not match host %q", origin, want)
		}
		origin = want
	}
	rpID, err := passkey.RPFromOrigin(origin)
	if err != nil {
		return nil, "", err
	}
	if net.ParseIP(rpID) != nil {
		return nil, "", errors.New("passkeys need a host name, not an IP address: open this site by name (e.g. https://localhost:8443 or a DNS name)")
	}
	wa, err := passkey.New(rpID, []string{origin})
	return wa, origin, err
}

// ResetRateLimitsForTest forgets all rate limit buckets.
func (s *Server) ResetRateLimitsForTest() {
	s.mu.Lock()
	s.limits = map[string]*bucket{}
	s.mu.Unlock()
}

// loginFloor is the least time a sign-in request takes, whatever happened.
// Real users cost a database lookup and a round trip to their washd; decoys
// cost nothing. Padding both to the same time hides which one ran (random
// jitter would not: it averages out over many requests).
const loginFloor = 100 * time.Millisecond

func floor(d time.Duration, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deadline := time.Now().Add(d)
		h(&delayed{ResponseWriter: w, until: deadline, ctx: r.Context()}, r)
	}
}

// delayed holds the response back until its deadline, so the time to the
// first byte does not depend on the code path.
type delayed struct {
	http.ResponseWriter
	until time.Time
	ctx   context.Context
	slept bool
}

func (d *delayed) wait() {
	if d.slept {
		return
	}
	d.slept = true
	t := time.NewTimer(time.Until(d.until))
	defer t.Stop()
	select {
	case <-t.C:
	case <-d.ctx.Done():
	}
}

func (d *delayed) WriteHeader(code int) { d.wait(); d.ResponseWriter.WriteHeader(code) }

func (d *delayed) Write(b []byte) (int, error) { d.wait(); return d.ResponseWriter.Write(b) }

// denied reports whether user may never use wash (root, defaults, service accounts).
func (s *Server) denied(user string) bool { return userpolicy.Denied(user, s.cfg.DenyUsers) }

type bucket struct {
	tokens float64
	last   time.Time
}

// limited applies a per-IP rate limit (burst 20, 1 request / 3 s).
func (s *Server) limited(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		s.mu.Lock()
		b := s.limits[ip]
		now := time.Now()
		if b == nil {
			b = &bucket{tokens: 20, last: now}
			s.limits[ip] = b
		}
		b.tokens = min(20, b.tokens+now.Sub(b.last).Seconds()/3)
		b.last = now
		ok := b.tokens >= 1
		if ok {
			b.tokens--
		}
		s.mu.Unlock()
		if !ok {
			fail(w, http.StatusTooManyRequests, "too many requests; slow down")
			return
		}
		h(w, r)
	}
}

func (s *Server) sessionUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.sessions[c.Value]
	if v == nil || time.Now().After(v.expires) {
		return "", false
	}
	return v.user, true
}

// hostLink is one connected washd of a user.
type hostLink struct {
	host string
	peer *link.Peer
}

// linksFor lists user's connected washds, by host name.
func (s *Server) linksFor(user string) []hostLink {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []hostLink
	for h, p := range s.links[user] {
		out = append(out, hostLink{h, p})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].host < out[j].host })
	return out
}

// linkFor finds user's washd on host; "" picks the only one.
func (s *Server) linkFor(user, host string) (string, *link.Peer) {
	ls := s.linksFor(user)
	if host == "" && len(ls) == 1 {
		return ls[0].host, ls[0].peer
	}
	for _, l := range ls {
		if l.host == host {
			return l.host, l.peer
		}
	}
	return "", nil
}

func (s *Server) takeCeremony(id, kind string) (*ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.ceremonies[id]
	delete(s.ceremonies, id)
	if c == nil || c.kind != kind || time.Now().After(c.expires) {
		return nil, false
	}
	return c, true
}

// --- API ---------------------------------------------------------------------

// servesCA: visitors that reach wash-web directly see its own CA (they need to
// trust it). Behind a proxy the browser sees the proxy's public certificate,
// so the hint would be wrong, and the CA (name-constrained to the internal
// names) would only tell the public those names.
func (s *Server) servesCA(r *http.Request) bool {
	return s.cfg.CAFile != "" && !s.viaProxy(r)
}

// handleCA serves the CA certificate (public) so devices can trust the site:
// browsers refuse passkeys on pages with certificate errors.
func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if !s.servesCA(r) {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(s.cfg.CAFile)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="wash-ca.crt"`)
	_, _ = w.Write(b)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(r)
	out := map[string]any{
		"ca":           s.servesCA(r),
		"registration": map[bool]string{true: "open", false: "request"}[s.cfg.Registration],
		"pending_ttl":  PendingTTL.String(),
		"user":         user,
		"logged_in":    ok,
	}
	// The host names are only needed to send someone who opened the site by IP
	// address to a name that works. Everyone else (e.g. the public, coming in by
	// the public name) must not learn the internal names.
	if byIP(r.Host) {
		out["origins"] = s.cfg.Origins
	}
	if ok {
		out["version"] = s.cfg.Version
	}
	writeJSON(w, 200, out)
}

func byIP(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

// OpenRegistration lets user create passkeys on the website for d (at most
// MaxRegWindow); d <= 0 closes the window. It returns when the window closes.
func (s *Server) OpenRegistration(user string, d time.Duration) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d <= 0 {
		delete(s.regOpen, user)
		return time.Time{}
	}
	until := time.Now().Add(min(d, MaxRegWindow))
	s.regOpen[user] = until
	return until
}

func (s *Server) registrationOpen(user string) bool {
	if s.cfg.Registration {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Now().Before(s.regOpen[user])
}

const regClosed = "passkey creation is closed. Run `wash keys open` as that user on the host, then try again"

func (s *Server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ User, Name string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	in.User = strings.TrimSpace(in.User)
	in.Name = strings.TrimSpace(in.Name)
	if !userRE.MatchString(in.User) {
		fail(w, 400, "user must be a unix user name")
		return
	}
	if s.denied(in.User) {
		fail(w, 403, userpolicy.ErrDenied.Error())
		return
	}
	if !s.registrationOpen(in.User) {
		fail(w, 403, regClosed)
		return
	}
	if in.Name == "" {
		in.Name = "passkey"
	}
	if len(in.Name) > 64 {
		in.Name = in.Name[:64]
	}
	wa, origin, err := s.rp(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	handle, err := s.db.UserHandle(in.User)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	existing, _ := s.db.Keys(in.User)
	u := &passkey.User{Handle: handle, Name: in.User}
	var excl []protocol.CredentialDescriptor
	for _, k := range existing {
		excl = append(excl, k.cred.Descriptor())
	}
	opts, sess, err := wa.BeginRegistration(u,
		webauthn.WithExclusions(excl),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	id := newID()
	s.mu.Lock()
	s.ceremonies[id] = &ceremony{kind: "reg", user: in.User, name: in.Name, rpID: wa.Config.RPID,
		origin: origin, session: *sess, expires: time.Now().Add(ceremonyTTL)}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"id": id, "options": opts})
}

func (s *Server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	c, ok := s.takeCeremony(r.URL.Query().Get("id"), "reg")
	if !ok {
		fail(w, 400, "registration expired; try again")
		return
	}
	if !s.registrationOpen(c.user) {
		fail(w, 403, regClosed)
		return
	}
	wa, origin, err := s.rp(r)
	if err != nil || origin != c.origin {
		fail(w, 400, "origin changed during registration")
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		fail(w, 400, "bad credential: "+err.Error())
		return
	}
	handle, err := s.db.UserHandle(c.user)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	cred, err := wa.CreateCredential(&passkey.User{Handle: handle, Name: c.user}, c.session, parsed)
	if err != nil {
		fail(w, 400, "passkey rejected: "+err.Error())
		return
	}
	short, err := s.db.AddPending(c.user, c.name, c.rpID, c.origin, cred)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	log.Printf("new pending passkey %s for %s (%q) from %s", short, c.user, c.name, s.clientIP(r))
	writeJSON(w, 200, map[string]any{"id": short, "user": c.user, "expires_in": PendingTTL.String()})
}

// decoy returns a stable fake credential and user handle for user on rpID.
// Login for a user without approved passkeys gets a challenge for it, so the
// answer to /api/login/begin does not tell whether a user exists, has
// passkeys, or runs a shell manager.
func (s *Server) decoy(rpID, user string) (webauthn.Credential, []byte) {
	mac := func(kind string) []byte {
		m := hmac.New(sha256.New, s.secret)
		m.Write([]byte(kind + "\x00" + rpID + "\x00" + user))
		return m.Sum(nil)
	}
	return webauthn.Credential{ID: mac("cred")}, mac("handle")
}

const loginFailed = "sign-in failed. New here? Create a passkey, then approve it on the host with `wash keys approve ID`"

func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var in struct{ User string }
	if err := readJSON(r, &in); err != nil || !userRE.MatchString(strings.TrimSpace(in.User)) {
		fail(w, 400, "enter your user name")
		return
	}
	user := strings.TrimSpace(in.User)
	wa, origin, err := s.rp(r)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	var creds []credRow
	if !s.denied(user) { // refused users only ever get the decoy
		if creds, err = s.db.Approved(user); err != nil {
			fail(w, 500, "database error")
			return
		}
	}
	lu := &passkey.User{Name: user}
	var allow []protocol.CredentialDescriptor
	for _, c := range creds {
		if c.rpID == wa.Config.RPID {
			allow = append(allow, c.cred.Descriptor())
			lu.Creds = append(lu.Creds, c.cred)
		}
	}
	// webNonce ‖ managerNonce: the nonce of the user's washd, or with several
	// washds (one per host) a hash of all their nonces (link.MixNonces). Without
	// a manager (or for a decoy) the second half stays random: the login then
	// fails at /finish, after the passkey.
	challenge := make([]byte, 2*passkey.NonceLen)
	_, _ = rand.Read(challenge)
	decoy := len(allow) == 0
	var managers []managerNonce
	if decoy {
		cred, handle := s.decoy(wa.Config.RPID, user)
		lu.Handle, lu.Creds = handle, []webauthn.Credential{cred}
		allow = []protocol.CredentialDescriptor{cred.Descriptor()}
	} else {
		if lu.Handle, err = s.db.UserHandle(user); err != nil {
			fail(w, 500, "database error")
			return
		}
		managers = s.managerNonces(r.Context(), user)
		switch len(managers) {
		case 0:
		case 1:
			copy(challenge[passkey.NonceLen:], managers[0].nonce)
		default:
			var ns [][]byte
			for _, mn := range managers {
				ns = append(ns, mn.nonce)
			}
			copy(challenge[passkey.NonceLen:], link.MixNonces(ns))
		}
	}
	opts, sess, err := wa.BeginLogin(lu,
		webauthn.WithChallenge(challenge),
		webauthn.WithAllowedCredentials(allow),
		webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	id := newID()
	s.mu.Lock()
	s.ceremonies[id] = &ceremony{kind: "login", user: user, rpID: wa.Config.RPID, origin: origin,
		session: *sess, expires: time.Now().Add(ceremonyTTL), decoy: decoy, managers: managers}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"id": id, "options": opts})
}

func (s *Server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	c, ok := s.takeCeremony(r.URL.Query().Get("id"), "login")
	if !ok {
		fail(w, 400, "login expired; try again")
		return
	}
	wa, origin, err := s.rp(r)
	if err != nil || origin != c.origin {
		fail(w, 400, "origin changed during login")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		fail(w, 400, "bad request")
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		fail(w, 400, "bad assertion: "+err.Error())
		return
	}
	rows, err := s.db.Approved(c.user)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	handle, _ := s.db.UserHandle(c.user)
	u := &passkey.User{Handle: handle, Name: c.user}
	for _, row := range rows {
		if row.rpID == wa.Config.RPID {
			u.Creds = append(u.Creds, row.cred)
		}
	}
	challenge, err := passkey.ClientChallenge(parsed)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	wantCh, _ := decodeB64URL(c.session.Challenge)
	if subtle.ConstantTimeCompare(challenge, wantCh) != 1 {
		fail(w, 400, "challenge mismatch")
		return
	}
	if c.decoy || s.denied(c.user) {
		fail(w, 403, loginFailed)
		return
	}
	cred, err := passkey.Verify(wa, u, parsed, challenge)
	if err != nil {
		log.Printf("login %s from %s: web verification failed: %v", c.user, s.clientIP(r), err)
		fail(w, 403, loginFailed)
		return
	}
	s.db.Used(cred)
	// every washd verifies the same assertion against its own key store; the
	// ones that accept it give this browser a ticket to connect to them
	if len(c.managers) == 0 {
		fail(w, 503, fmt.Sprintf("no shell manager is running for %s (run `wash up` on the host)", c.user))
		return
	}
	var nonces [][]byte
	if len(c.managers) > 1 {
		for _, mn := range c.managers {
			nonces = append(nonces, mn.nonce)
		}
	}
	type result struct {
		Host   string `json:"host"`
		Ticket string `json:"ticket,omitempty"`
		Err    string `json:"err,omitempty"`
	}
	results := make([]result, len(c.managers))
	var wg sync.WaitGroup
	for i, mn := range c.managers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			defer cancel()
			results[i].Host = mn.host
			var t link.Ticket
			if err := mn.peer.Call(ctx, link.OpVerify, link.VerifyReq{Assertion: body, Remote: s.clientIP(r), Nonces: nonces}, &t); err != nil {
				log.Printf("login %s from %s: shell manager on %s rejected: %v", c.user, s.clientIP(r), mn.host, err)
				results[i].Err = err.Error()
				return
			}
			results[i].Ticket = t.Ticket
		}()
	}
	wg.Wait()
	var first string
	var why []string
	for _, res := range results {
		if res.Ticket != "" && first == "" {
			first = res.Ticket
		}
		if res.Err != "" {
			why = append(why, res.Host+": "+res.Err)
		}
	}
	if first == "" {
		fail(w, 403, "shell manager rejected the passkey: "+strings.Join(why, "; "))
		return
	}
	tok := newID()
	s.mu.Lock()
	s.sessions[tok] = &webSession{user: c.user, expires: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: s.basePath(r) + "/", HttpOnly: true,
		Secure: strings.HasPrefix(origin, "https:"), SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	log.Printf("login %s from %s with passkey %s", c.user, s.clientIP(r), passkey.ShortID(cred.ID))
	// ticket: the first washd's (pages from before multi-host use only that)
	writeJSON(w, 200, map[string]any{"user": c.user, "ticket": first, "managers": results})
}

// managerNonces asks each of user's washds for a login nonce (in parallel);
// a washd that does not answer is left out of this login.
func (s *Server) managerNonces(ctx context.Context, user string) []managerNonce {
	ls := s.linksFor(user)
	out := make([]managerNonce, len(ls))
	var wg sync.WaitGroup
	for i, l := range ls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var mn link.Nonce
			if err := l.peer.Call(ctx, link.OpChallenge, nil, &mn); err != nil || len(mn.Nonce) != passkey.NonceLen {
				log.Printf("login %s: shell manager on %s gave no challenge: %v", user, l.host, err)
				return
			}
			out[i] = managerNonce{host: l.host, peer: l.peer, nonce: mn.Nonce}
		}()
	}
	wg.Wait()
	keep := out[:0]
	for _, mn := range out {
		if mn.peer != nil {
			keep = append(keep, mn)
		}
	}
	return keep
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: s.basePath(r) + "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{})
}

// handleBrowserWS hands an authenticated browser WebSocket to washd (?host=
// picks which of the user's washds; optional when there is one). Two
// checks: this server's login cookie, and a ticket only that washd can
// validate (issued by it after it verified the passkey assertion itself).
func (s *Server) handleBrowserWS(w http.ResponseWriter, r *http.Request) {
	user, ok := s.sessionUser(r)
	c, err := websocket.Accept(w, r, nil) // same-origin only
	if err != nil {
		return
	}
	if !ok {
		_ = c.Close(4401, "not logged in")
		return
	}
	host, lk := s.linkFor(user, r.URL.Query().Get("host"))
	if lk == nil {
		_ = c.Close(4503, "no shell manager running for "+user)
		return
	}
	sid := newID()
	wt := &waiter{user: user, host: host, ch: make(chan *dialBack, 1)}
	s.mu.Lock()
	s.waiters[sid] = wt
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.waiters, sid)
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	err = lk.Call(ctx, link.OpAttach, link.AttachReq{SID: sid, Ticket: r.URL.Query().Get("ticket"), Remote: s.clientIP(r)}, nil)
	if err != nil {
		cancel()
		_ = c.Close(4403, "shell manager refused: "+err.Error())
		return
	}
	var db *dialBack
	select {
	case db = <-wt.ch:
	case <-ctx.Done():
	}
	cancel()
	if db == nil {
		_ = c.Close(4504, "shell manager did not connect")
		return
	}
	defer close(db.done)
	link.Splice(context.Background(), c, db.c)
}

// --- manager side ------------------------------------------------------------

// manager resolves a washd's bearer token to its user and host name.
func (s *Server) manager(r *http.Request) (user, host string, ok bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return "", "", false
	}
	claim := r.Header.Get(link.HostHeader)
	if !hostRE.MatchString(claim) {
		claim = ""
	}
	user, host, ok = s.db.ManagerFor(tok, claim)
	if ok && s.denied(user) {
		log.Printf("refused manager link for %s: %v", user, userpolicy.ErrDenied)
		return "", "", false
	}
	return user, host, ok
}

// hostRE: a washd's host name (as enrolled, or reported by an older token).
var hostRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in struct{ Code, Host string }
	if err := readJSON(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	// Host: the washd's host name (an older wash sends none: its washd
	// names itself on its first link)
	if in.Host != "" && !hostRE.MatchString(in.Host) {
		fail(w, 400, "bad host name")
		return
	}
	user, token, err := s.db.Enroll(strings.TrimSpace(in.Code), in.Host, s.denied)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	log.Printf("manager enrolled for %s on %q from %s", user, in.Host, s.clientIP(r))
	writeJSON(w, 200, map[string]string{"user": user, "token": token})
}

func (s *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	user, host, ok := s.manager(r)
	if !ok {
		http.Error(w, "bad manager token", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}) // not a browser
	if err != nil {
		return
	}
	p := link.NewPeer(c, s.managerHandler(user, host))
	s.mu.Lock()
	if s.links[user] == nil {
		s.links[user] = map[string]*link.Peer{}
	}
	old := s.links[user][host]
	s.links[user][host] = p
	s.mu.Unlock()
	if old != nil {
		old.Close("replaced by a new manager connection")
	}
	log.Printf("manager for %s on %q connected from %s", user, host, s.clientIP(r))
	_ = p.Run(context.Background())
	s.mu.Lock()
	if s.links[user][host] == p {
		delete(s.links[user], host)
		if len(s.links[user]) == 0 {
			delete(s.links, user)
		}
	}
	s.mu.Unlock()
	log.Printf("manager for %s on %q disconnected", user, host)
}

func (s *Server) handleLinkConn(w http.ResponseWriter, r *http.Request) {
	user, host, ok := s.manager(r)
	if !ok {
		http.Error(w, "bad manager token", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	wt := s.waiters[r.URL.Query().Get("sid")]
	s.mu.Unlock()
	if wt == nil || wt.user != user || wt.host != host {
		http.Error(w, "unknown connection", http.StatusNotFound)
		return
	}
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	db := &dialBack{c: c, done: make(chan struct{})}
	select {
	case wt.ch <- db:
		<-db.done
	default:
		_ = c.Close(websocket.StatusPolicyViolation, "duplicate")
	}
}

func (s *Server) managerHandler(user, host string) link.Handler {
	return func(ctx context.Context, op string, data json.RawMessage) (any, error) {
		var ref link.KeyRef
		_ = json.Unmarshal(data, &ref)
		switch op {
		case link.OpInfo:
			return link.Info{User: user, Host: host, Version: s.cfg.Version}, nil
		case link.OpPlaybackPut:
			return s.playbackPut(user, data)
		case link.OpPlaybackDel:
			return s.playbackDel(user, data)
		case link.OpKeysList:
			rows, err := s.db.Keys(user)
			if err != nil {
				return nil, err
			}
			out := []link.KeyInfo{}
			for _, k := range rows {
				out = append(out, k.info())
			}
			return out, nil
		case link.OpKeysGet:
			k, err := s.db.Key(user, ref.ID)
			if err != nil {
				return nil, err
			}
			handle, _ := s.db.UserHandle(user)
			cj, _ := json.Marshal(k.cred)
			return link.KeyRecord{KeyInfo: k.info(), UserHandle: handle, RPID: k.rpID, Credential: cj}, nil
		case link.OpKeysApprove:
			if err := s.db.Approve(user, ref.ID); err != nil {
				return nil, err
			}
			log.Printf("passkey %s approved by %s", ref.ID, user)
			return struct{}{}, nil
		case link.OpKeysOpen:
			var rw link.RegWindow
			if err := json.Unmarshal(data, &rw); err != nil {
				return nil, err
			}
			until := s.OpenRegistration(user, rw.For)
			if until.IsZero() {
				log.Printf("passkey creation closed by %s", user)
			} else {
				log.Printf("passkey creation opened by %s until %s", user, until.Format(time.RFC3339))
			}
			return link.RegWindow{Until: until, Always: s.cfg.Registration}, nil
		case link.OpKeysRevoke:
			if err := s.db.Revoke(user, ref.ID); err != nil {
				return nil, err
			}
			log.Printf("passkey %s revoked by %s on %q", ref.ID, user, host)
			// the user's other washds drop it too (and close its browsers)
			for _, l := range s.linksFor(user) {
				if l.host == host {
					continue
				}
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					if err := l.peer.Call(ctx, link.OpKeyRevoked, ref, nil); err != nil {
						log.Printf("passkey %s: tell %s on %q: %v", ref.ID, user, l.host, err)
					}
				}()
			}
			return struct{}{}, nil
		}
		return nil, fmt.Errorf("unknown op %q", op)
	}
}
