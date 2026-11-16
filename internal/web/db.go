package web

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"

	"wash/internal/link"
	"wash/internal/passkey"
)

// PendingTTL: a passkey created on the website is purged unless its user
// approves it (`wash keys approve`) within this time.
const PendingTTL = time.Hour

const (
	maxPendingPerUser = 5
	maxPendingTotal   = 200
)

const schema = `
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
	name    TEXT PRIMARY KEY,
	handle  BLOB NOT NULL UNIQUE,
	created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
	id        TEXT PRIMARY KEY,          -- base64url credential id
	short     TEXT NOT NULL UNIQUE,      -- passkey.ShortID
	user      TEXT NOT NULL,
	name      TEXT NOT NULL,
	rp_id     TEXT NOT NULL,
	origin    TEXT NOT NULL,
	cred      TEXT NOT NULL,             -- webauthn.Credential JSON
	approved  INTEGER NOT NULL DEFAULT 0,
	created   INTEGER NOT NULL,
	expires   INTEGER NOT NULL DEFAULT 0, -- pending only
	last_used INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS credentials_user ON credentials(user);
CREATE TABLE IF NOT EXISTS managers (
	user       TEXT PRIMARY KEY,
	token_hash BLOB NOT NULL UNIQUE,
	created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enroll_codes (
	code_hash BLOB PRIMARY KEY,
	user      TEXT NOT NULL,
	expires   INTEGER NOT NULL
);
`

// DB is wash-web's sqlite store.
type DB struct{ db *sql.DB }

// OpenDB opens (and migrates) the database.
func OpenDB(path string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error { return d.db.Close() }

func hash(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// UserHandle returns the WebAuthn user handle for name, creating it.
func (d *DB) UserHandle(name string) ([]byte, error) {
	var h []byte
	err := d.db.QueryRow(`SELECT handle FROM users WHERE name=?`, name).Scan(&h)
	if err == nil {
		return h, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	h = make([]byte, 32)
	_, _ = rand.Read(h)
	if _, err := d.db.Exec(`INSERT OR IGNORE INTO users(name, handle, created) VALUES(?,?,?)`, name, h, time.Now().Unix()); err != nil {
		return nil, err
	}
	return d.UserHandle(name)
}

// credRow is one stored credential.
type credRow struct {
	id, short, user, name, rpID, origin string
	cred                                webauthn.Credential
	approved                            bool
	created, expires, lastUsed          time.Time
}

func (r credRow) info() link.KeyInfo {
	k := link.KeyInfo{ID: r.short, User: r.user, Name: r.name, Approved: r.approved,
		Created: r.created, Origin: r.origin, LastUsed: r.lastUsed}
	if !r.approved {
		k.Expires = r.expires
	}
	if len(r.cred.Authenticator.AAGUID) == 16 {
		k.AAGUID = hex.EncodeToString(r.cred.Authenticator.AAGUID)
	}
	return k
}

func unix(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0)
}

func (d *DB) scan(where string, args ...any) ([]credRow, error) {
	rows, err := d.db.Query(`SELECT id, short, user, name, rp_id, origin, cred, approved, created, expires, last_used
		FROM credentials WHERE `+where+` ORDER BY created`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []credRow
	for rows.Next() {
		var r credRow
		var cj string
		var c, e, l int64
		if err := rows.Scan(&r.id, &r.short, &r.user, &r.name, &r.rpID, &r.origin, &cj, &r.approved, &c, &e, &l); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(cj), &r.cred); err != nil {
			continue
		}
		r.created, r.expires, r.lastUsed = unix(c), unix(e), unix(l)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AddPending stores a newly registered, not yet approved passkey.
func (d *DB) AddPending(user, name, rpID, origin string, cred *webauthn.Credential) (string, error) {
	d.Purge()
	var nUser, nAll int
	_ = d.db.QueryRow(`SELECT count(*) FROM credentials WHERE approved=0 AND user=?`, user).Scan(&nUser)
	_ = d.db.QueryRow(`SELECT count(*) FROM credentials WHERE approved=0`).Scan(&nAll)
	if nUser >= maxPendingPerUser {
		return "", fmt.Errorf("user %s already has %d passkeys waiting for approval", user, nUser)
	}
	if nAll >= maxPendingTotal {
		return "", errors.New("too many passkeys waiting for approval; try later")
	}
	cj, _ := json.Marshal(cred)
	short := passkey.ShortID(cred.ID)
	now := time.Now()
	_, err := d.db.Exec(`INSERT INTO credentials(id, short, user, name, rp_id, origin, cred, approved, created, expires)
		VALUES(?,?,?,?,?,?,?,0,?,?)`,
		base64.RawURLEncoding.EncodeToString(cred.ID), short, user, name, rpID, origin, string(cj),
		now.Unix(), now.Add(PendingTTL).Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return "", errors.New("this passkey is already registered")
		}
		return "", err
	}
	return short, nil
}

// Purge deletes pending passkeys older than PendingTTL.
func (d *DB) Purge() int64 {
	r, err := d.db.Exec(`DELETE FROM credentials WHERE approved=0 AND expires < ?`, time.Now().Unix())
	if err != nil {
		return 0
	}
	n, _ := r.RowsAffected()
	return n
}

// Keys lists a user's passkeys ("" = everyone).
func (d *DB) Keys(user string) ([]credRow, error) {
	d.Purge()
	if user == "" {
		return d.scan(`1=1`)
	}
	return d.scan(`user=?`, user)
}

// Key finds one of user's passkeys by short id (or unique prefix).
func (d *DB) Key(user, short string) (credRow, error) {
	d.Purge()
	if len(short) < 4 {
		return credRow{}, errors.New("key id too short")
	}
	rows, err := d.scan(`user=? AND short LIKE ? ESCAPE '\'`, user, escapeLike(short)+"%")
	if err != nil {
		return credRow{}, err
	}
	switch len(rows) {
	case 0:
		return credRow{}, fmt.Errorf("no passkey %s for user %s (pending keys expire after %s)", short, user, PendingTTL)
	case 1:
		return rows[0], nil
	}
	return credRow{}, fmt.Errorf("key id %s is ambiguous", short)
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Approve marks a passkey approved.
func (d *DB) Approve(user, short string) error {
	k, err := d.Key(user, short)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`UPDATE credentials SET approved=1, expires=0 WHERE id=? AND user=?`, k.id, user)
	return err
}

// Revoke deletes a passkey.
func (d *DB) Revoke(user, short string) error {
	k, err := d.Key(user, short)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`DELETE FROM credentials WHERE id=? AND user=?`, k.id, user)
	return err
}

// Approved returns a user's approved credentials.
func (d *DB) Approved(user string) ([]credRow, error) {
	return d.scan(`user=? AND approved=1`, user)
}

// Used records a successful login with the updated credential.
func (d *DB) Used(cred *webauthn.Credential) {
	cj, _ := json.Marshal(cred)
	_, _ = d.db.Exec(`UPDATE credentials SET cred=?, last_used=? WHERE id=?`,
		string(cj), time.Now().Unix(), base64.RawURLEncoding.EncodeToString(cred.ID))
}

// --- managers ------------------------------------------------------------------

// NewEnrollCode creates a one-time code (10 min) that lets a washd enroll as user.
func (d *DB) NewEnrollCode(user string) (string, error) {
	code := randToken(18)
	_, err := d.db.Exec(`INSERT INTO enroll_codes(code_hash, user, expires) VALUES(?,?,?)`,
		hash(code), user, time.Now().Add(10*time.Minute).Unix())
	return code, err
}

// Enroll redeems a code; returns the user and the manager's long-lived token
// (replacing any previous manager token of that user).
func (d *DB) Enroll(code string) (user, token string, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	var exp int64
	err = tx.QueryRow(`SELECT user, expires FROM enroll_codes WHERE code_hash=?`, hash(code)).Scan(&user, &exp)
	if err != nil || time.Now().Unix() > exp {
		return "", "", errors.New("invalid or expired enrollment code")
	}
	if _, err := tx.Exec(`DELETE FROM enroll_codes WHERE code_hash=? OR expires < ?`, hash(code), time.Now().Unix()); err != nil {
		return "", "", err
	}
	token = randToken(32)
	if _, err := tx.Exec(`INSERT INTO managers(user, token_hash, created) VALUES(?,?,?)
		ON CONFLICT(user) DO UPDATE SET token_hash=excluded.token_hash, created=excluded.created`,
		user, hash(token), time.Now().Unix()); err != nil {
		return "", "", err
	}
	return user, token, tx.Commit()
}

// ManagerUser resolves a manager token.
func (d *DB) ManagerUser(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	var u string
	if d.db.QueryRow(`SELECT user FROM managers WHERE token_hash=?`, hash(token)).Scan(&u) != nil {
		return "", false
	}
	return u, true
}

// Managers lists enrolled users.
func (d *DB) Managers() ([]string, error) {
	rows, err := d.db.Query(`SELECT user FROM managers ORDER BY user`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			out = append(out, u)
		}
	}
	return out, nil
}

// Unenroll removes a user's manager token.
func (d *DB) Unenroll(user string) error {
	_, err := d.db.Exec(`DELETE FROM managers WHERE user=?`, user)
	return err
}

// KeyInfos lists passkeys for the admin CLI ("" = everyone).
func (d *DB) KeyInfos(user string) ([]link.KeyInfo, error) {
	rows, err := d.Keys(user)
	if err != nil {
		return nil, err
	}
	var out []link.KeyInfo
	for _, r := range rows {
		out = append(out, r.info())
	}
	return out, nil
}

// ExpirePendingForTest backdates every pending key past its TTL.
func (d *DB) ExpirePendingForTest() {
	_, _ = d.db.Exec(`UPDATE credentials SET expires=? WHERE approved=0`, time.Now().Add(-time.Second).Unix())
}

// Backup writes a consistent copy of the live database (safe with WAL).
func (d *DB) Backup(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s exists", path)
	}
	_, err := d.db.Exec(`VACUUM INTO ?`, path)
	return err
}
