// Package passkey holds the WebAuthn verification shared by wash-web and
// washd. Both verify the *same* assertion independently:
//
//	challenge = webNonce(32) || managerNonce(32)
//
// wash-web checks the first half against its own nonce and the signature
// against its database; washd checks the second half against a nonce it
// issued and the signature against its own key store (keys the user
// approved with `wash keys approve`). A compromised web container alone
// cannot produce a valid assertion for a manager nonce, and a key the web
// container claims is approved but the user never approved locally is
// rejected by washd.
package passkey

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// NonceLen is the length of each half of the combined challenge.
const NonceLen = 32

// User adapts a credential list to webauthn.User.
type User struct {
	Handle []byte
	Name   string
	Creds  []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.Handle }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Creds }

// New returns a WebAuthn instance for an RP id and its allowed origins.
func New(rpID string, origins []string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "wash",
		RPOrigins:     origins,
	})
}

// RPFromOrigin derives the RP id (host name) from an origin URL.
func RPFromOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("bad origin %q", origin)
	}
	return u.Hostname(), nil
}

// ClientChallenge returns the raw challenge the browser signed.
func ClientChallenge(p *protocol.ParsedCredentialAssertionData) ([]byte, error) {
	s := p.Response.CollectedClientData.Challenge
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("bad challenge encoding")
	}
	if len(b) != 2*NonceLen {
		return nil, errors.New("challenge has wrong length")
	}
	return b, nil
}

// Verify checks a parsed assertion for user against the full challenge.
// It returns the matching credential with its sign counter updated.
func Verify(wa *webauthn.WebAuthn, user *User, p *protocol.ParsedCredentialAssertionData, challenge []byte) (*webauthn.Credential, error) {
	got, err := ClientChallenge(p)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(got, challenge) {
		return nil, errors.New("challenge mismatch")
	}
	var allowed [][]byte
	for _, c := range user.Creds {
		allowed = append(allowed, c.ID)
	}
	sess := webauthn.SessionData{
		Challenge:            base64.RawURLEncoding.EncodeToString(challenge),
		RelyingPartyID:       wa.Config.RPID,
		UserID:               user.Handle,
		AllowedCredentialIDs: allowed,
		UserVerification:     protocol.VerificationPreferred,
	}
	cred, err := wa.ValidateLogin(user, sess, p)
	if err != nil {
		return nil, describe(err)
	}
	if cred.Authenticator.CloneWarning {
		return nil, errors.New("authenticator sign counter went backwards (cloned key?)")
	}
	return cred, nil
}

// describe flattens go-webauthn's error (its Details carry the reason).
func describe(err error) error {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.Details != "" {
		if pe.DevInfo != "" {
			return fmt.Errorf("%s: %s", pe.Details, pe.DevInfo)
		}
		return errors.New(pe.Details)
	}
	return err
}

// ShortID is the human handle for a credential (shown by `wash keys`).
func ShortID(credID []byte) string {
	h := sha256.Sum256(credID)
	return hex.EncodeToString(h[:6])
}
