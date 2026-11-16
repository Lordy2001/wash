package web

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"wash/internal/pin"
)

func chain(t *testing.T, cert, key string) []*x509.Certificate {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for _, d := range pair.Certificate {
		c, _ := x509.ParseCertificate(d)
		out = append(out, c)
	}
	return out
}

func TestSelfSignedCA(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := SelfSigned(dir, []string{"ca-data.tailnet.local"})
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := Fingerprint(cert, key)
	c := chain(t, cert, key)
	if len(c) != 2 || !c[1].IsCA {
		t.Fatalf("want leaf+CA, got %d", len(c))
	}
	if err := pin.Verify(c, fp, "ca-data.tailnet.local"); err != nil {
		t.Fatal(err)
	}
	if err := pin.Verify(c, fp, "evil.example"); err == nil {
		t.Fatal("pin accepted a name outside the certificate")
	}
	// browsers: the CA verifies the leaf by name
	roots := x509.NewCertPool()
	roots.AddCert(c[1])
	if _, err := c[0].Verify(x509.VerifyOptions{DNSName: "ca-data.tailnet.local", Roots: roots}); err != nil {
		t.Fatal(err)
	}
	// a new host inside nothing the CA permits: new CA; a leaf-only change keeps the pin
	os.Remove(filepath.Join(dir, "cert.pem"))
	cert, key, _ = SelfSigned(dir, []string{"ca-data.tailnet.local"})
	if fp2, _ := Fingerprint(cert, key); fp2 != fp {
		t.Fatal("leaf reissue changed the pin")
	}
	cert, key, _ = SelfSigned(dir, []string{"ca-data.tailnet.local", "other.example"})
	if fp3, _ := Fingerprint(cert, key); fp3 == fp {
		t.Fatal("CA not replaced for a name outside its constraints")
	}
	// the name constraint holds: a CA for these names cannot vouch for others
	c = chain(t, cert, key)
	roots = x509.NewCertPool()
	roots.AddCert(c[1])
	if _, err := c[0].Verify(x509.VerifyOptions{DNSName: "other.example", Roots: roots}); err != nil {
		t.Fatal(err)
	}
}
