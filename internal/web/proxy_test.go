package web

import (
	"net/http/httptest"
	"net/netip"
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
