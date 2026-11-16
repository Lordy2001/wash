package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func decodeB64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// SelfSigned manages wash-web's own TLS in dir:
//
//	ca.pem, ca-key.pem   private CA, name-constrained to the server's names
//	cert.pem, key.pem    leaf signed by it (served chain: leaf + CA)
//
// Browsers only allow passkeys on pages without certificate errors, so users
// import ca.pem once (served at /ca.crt) and the site is trusted. The name
// constraint limits what that imported CA can vouch for to these hosts.
// The leaf is reissued when it nears expiry or the host list grows; the CA
// (what washd pins) only when the host list leaves its constraint.
func SelfSigned(dir string, hosts []string) (certFile, keyFile string, err error) {
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	caFile, caKeyFile := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	names := hostList(hosts)

	ca, caKey, err := loadPair(caFile, caKeyFile)
	if err != nil || !caCovers(ca, names) {
		if ca != nil {
			log.Printf("tls: host list %v is outside the CA's names; creating a new CA (users must re-import /ca.crt and re-run `wash enroll`)", names)
		}
		if ca, caKey, err = newCA(names); err != nil {
			return "", "", err
		}
		if err := writePair(caFile, caKeyFile, ca, caKey); err != nil {
			return "", "", err
		}
		_ = os.Remove(certFile) // reissue under the new CA
	}
	leaf, _, lerr := loadPair(certFile, keyFile)
	if lerr == nil && leaf.CheckSignatureFrom(ca) == nil && time.Until(leaf.NotAfter) > 30*24*time.Hour && covers(leaf, names) {
		return certFile, keyFile, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(397 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	addNames(tpl, names)
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	leaf, _ = x509.ParseCertificate(der)
	if err := writePair(certFile, keyFile, leaf, key, ca); err != nil {
		return "", "", err
	}
	log.Printf("tls: issued certificate for %s", strings.Join(names, ", "))
	return certFile, keyFile, nil
}

// CAFile is the CA users import (empty if the TLS dir has none).
func CAFile(dir string) string {
	p := filepath.Join(dir, "ca.pem")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func hostList(hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	for _, h := range hosts {
		add(h)
	}
	// not os.Hostname(): in a container that is the container id, new on every
	// restart, which would replace the CA (and break every pin) each time
	for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
		add(h)
	}
	return out
}

func addNames(tpl *x509.Certificate, names []string) {
	for _, h := range names {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func newCA(names []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "wash local CA (" + names[0] + ")", Organization: []string{"wash"}},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
	}
	for _, h := range names {
		if ip := net.ParseIP(h); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			} else {
				ip = ip.To4()
			}
			tpl.PermittedIPRanges = append(tpl.PermittedIPRanges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		} else {
			tpl.PermittedDNSDomains = append(tpl.PermittedDNSDomains, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

// caCovers: every name is inside the CA's constraints.
func caCovers(ca *x509.Certificate, names []string) bool {
	if ca == nil || !ca.IsCA {
		return false
	}
	for _, h := range names {
		ok := false
		if ip := net.ParseIP(h); ip != nil {
			for _, r := range ca.PermittedIPRanges {
				ok = ok || r.Contains(ip)
			}
		} else {
			for _, d := range ca.PermittedDNSDomains {
				ok = ok || h == d || strings.HasSuffix(h, "."+d)
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func covers(c *x509.Certificate, names []string) bool {
	for _, h := range names {
		if c.VerifyHostname(h) != nil {
			return false
		}
	}
	return true
}

func loadPair(certFile, keyFile string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, err
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, err
	}
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return nil, nil, errors.New("bad pem")
	}
	c, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParseECPrivateKey(kp.Bytes)
	return c, k, err
}

func writePair(certFile, keyFile string, c *x509.Certificate, k *ecdsa.PrivateKey, chain ...*x509.Certificate) error {
	kb, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(keyFile+".tmp", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	var cb []byte
	for _, x := range append([]*x509.Certificate{c}, chain...) {
		cb = append(cb, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: x.Raw})...)
	}
	if err := os.WriteFile(certFile+".tmp", cb, 0o644); err != nil {
		return err
	}
	if err := os.Rename(keyFile+".tmp", keyFile); err != nil {
		return err
	}
	return os.Rename(certFile+".tmp", certFile)
}

// Fingerprint returns the SHA-256 (hex) `wash enroll` pins: the CA's when the
// chain has one, else the (self-signed) leaf's.
func Fingerprint(certFile, keyFile string) (string, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", err
	}
	// the pin is the CA (last in the served chain) when there is one
	h := sha256.Sum256(pair.Certificate[len(pair.Certificate)-1])
	return hex.EncodeToString(h[:]), nil
}
