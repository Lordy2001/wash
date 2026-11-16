package web

import (
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	cidr := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.1/32")}
	cases := []struct {
		name    string
		trust   bool
		proxies []netip.Prefix
		peer    string
		xff     []string
		want    string
	}{
		{"off ignores header", false, nil, "203.0.113.9:1", []string{"1.2.3.4"}, "203.0.113.9"},
		{"any peer: right-most entry", true, nil, "127.0.0.1:1", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"any peer: spoofed first header ignored", true, nil, "127.0.0.1:1", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"any peer: no header", true, nil, "127.0.0.1:1", nil, "127.0.0.1"},
		{"list: untrusted peer ignored", true, cidr, "203.0.113.9:1", []string{"1.2.3.4"}, "203.0.113.9"},
		{"list: skips trusted hops", true, cidr, "127.0.0.1:1", []string{"6.6.6.6, 198.51.100.7, 10.1.2.3"}, "198.51.100.7"},
		{"list: all trusted", true, cidr, "127.0.0.1:1", []string{"10.0.0.1"}, "127.0.0.1"},
		{"list: mapped peer", true, cidr, "[::ffff:127.0.0.1]:1", []string{"198.51.100.7"}, "198.51.100.7"},
	}
	for _, c := range cases {
		s := &Server{cfg: Config{TrustProxy: c.trust, Proxies: c.proxies}}
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := s.clientIP(r); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestForwardedProtoNeedsTrustedPeer(t *testing.T) {
	s := &Server{cfg: Config{TrustProxy: true, Proxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.9:1"
	r.Header.Set("X-Forwarded-Proto", "https")
	if s.viaProxy(r) {
		t.Fatal("believed X-Forwarded-Proto from an untrusted peer")
	}
	r.RemoteAddr = "127.0.0.1:1"
	if !s.viaProxy(r) {
		t.Fatal("ignored the trusted proxy")
	}
}

func TestConfigHidesOriginsAndVersion(t *testing.T) {
	s := &Server{cfg: Config{Origins: []string{"https://internal.example:8443"}, Version: "9.9"}}
	for host, want := range map[string]bool{"internal.example:8443": false, "public.example": false,
		"192.0.2.1:8443": true, "[2001:db8::1]:8443": true, "192.0.2.1": true} {
		r := httptest.NewRequest("GET", "/api/config", nil)
		r.Host = host
		w := httptest.NewRecorder()
		s.handleConfig(w, r)
		body := w.Body.String()
		if got := strings.Contains(body, "internal.example"); got != want {
			t.Errorf("host %s: origins shown=%v, want %v (%s)", host, got, want, body)
		}
		if strings.Contains(body, "9.9") {
			t.Errorf("host %s: version shown before sign-in", host)
		}
	}
}

func TestBasePath(t *testing.T) {
	s := &Server{cfg: Config{TrustProxy: true, Proxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}}
	for _, c := range []struct{ peer, prefix, want string }{
		{"10.0.0.1:1", "/wash", "/wash"},
		{"10.0.0.1:1", "/wash/", "/wash"},
		{"10.0.0.1:1", "/a/b", "/a/b"},
		{"10.0.0.1:1", "", ""},
		{"10.0.0.1:1", "/../x", ""},
		{"10.0.0.1:1", "/wash;x", ""},
		{"10.0.0.1:1", "wash", ""},
		{"203.0.113.9:1", "/wash", ""}, // not from the proxy
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		r.Header.Set("X-Forwarded-Prefix", c.prefix)
		if got := s.basePath(r); got != c.want {
			t.Errorf("%s %q: got %q, want %q", c.peer, c.prefix, got, c.want)
		}
	}
}

func TestCAOnlyForDirectVisitors(t *testing.T) {
	ca := t.TempDir() + "/ca.crt"
	if err := os.WriteFile(ca, []byte("PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{CAFile: ca, TrustProxy: true, Proxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}}}
	for peer, want := range map[string]int{"100.64.0.4:1": 200, "10.0.0.1:1": 404} {
		r := httptest.NewRequest("GET", "/ca.crt", nil)
		r.RemoteAddr = peer
		w := httptest.NewRecorder()
		s.handleCA(w, r)
		if w.Code != want {
			t.Errorf("%s: /ca.crt %d, want %d", peer, w.Code, want)
		}
		w = httptest.NewRecorder()
		s.handleConfig(w, r)
		if got := strings.Contains(w.Body.String(), `"ca":true`); got != (want == 200) {
			t.Errorf("%s: config ca=%v", peer, got)
		}
	}
}
