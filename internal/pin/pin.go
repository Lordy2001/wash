// Package pin verifies wash-web's TLS certificate against the fingerprint
// `wash enroll` stored.
//
// wash-web's self-managed TLS is a small private CA (name-constrained to the
// server's host names) that signs a renewable leaf; the served chain is
// leaf + CA. The pin is the CA's SHA-256, so leaf renewals and new host names
// do not break enrolled washd's. A pin that matches the leaf itself (older
// self-signed setups) is accepted as is.
package pin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
)

// Of returns a certificate's SHA-256 (hex).
func Of(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}

// Verify checks a served chain: the leaf must be the pinned certificate, or
// chain (for host) to a pinned CA that is part of the served chain.
func Verify(chain []*x509.Certificate, fp, host string) error {
	fp = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	if len(chain) == 0 {
		return errors.New("no server certificate")
	}
	if Of(chain[0]) == fp {
		return nil
	}
	for _, c := range chain[1:] {
		if Of(c) != fp {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(c)
		inter := x509.NewCertPool()
		for _, i := range chain[1:] {
			if i != c {
				inter.AddCert(i)
			}
		}
		_, err := chain[0].Verify(x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: inter})
		return err
	}
	return errors.New("server certificate does not match the pinned fingerprint (re-run `wash enroll` if the server's certificate authority changed)")
}

// Config returns a TLS config that trusts only the pin (empty pin = system roots).
func Config(fp string) *tls.Config {
	if fp == "" {
		return &tls.Config{}
	}
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return Verify(cs.PeerCertificates, fp, cs.ServerName)
		},
	}
}
