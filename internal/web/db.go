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
	"wash/internal/userpolicy"
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
CREATE TABLE IF NOT EXISTS managers (       -- one washd per user (before multi-host); migrated below
	user       TEXT PRIMARY KEY,
	token_hash BLOB NOT NULL UNIQUE,
	created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS manager_hosts (  -- one washd per user and host
	user       TEXT NOT NULL,
	host       TEXT NOT NULL,                 -- '' = enrolled before multi-host: named on first link
	token_hash BLOB NOT NULL UNIQUE,
	created    INTEGER NOT NULL,
	PRIMARY KEY (user, host)
);
INSERT OR IGNORE INTO manager_hosts(user, host, token_hash, created)
	SELECT user, '', token_hash, created FROM managers;
DELETE FROM managers;
CREATE TABLE IF NOT EXISTS meta (
	k TEXT PRIMARY KEY,
	v BLOB NOT NULL
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

// Secret returns the server's random 32-byte secret, creating it once.
func (d *DB) Secret() ([]byte, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	if _, err := d.db.Exec(`INSERT OR IGNORE INTO meta(k, v) VALUES('secret', ?)`, b); err != nil {
		return nil, err
	}
	var v []byte
	if err := d.db.QueryRow(`SELECT v FROM meta WHERE k='secret'`).Scan(&v); err != nil {
		return nil, err
	}
	if len(v) != 32 {
		return nil, errors.New("bad secret in meta table")
	}
	return v, nil
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

// Enroll redeems a code; returns the user and the long-lived token of that
// user's washd on host (replacing an earlier token of the same user and
// host only: each host's washd has its own).
// refuse (may be nil) vetoes the code's user; the code is used up either way.
func (d *DB) Enroll(code, host string, refuse func(user string) bool) (user, token string, err error) {
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
	if refuse != nil && refuse(user) {
		if err := tx.Commit(); err != nil {
			return "", "", err
		}
		return "", "", userpolicy.ErrDenied
	}
	token = randToken(32)
	if _, err := tx.Exec(`INSERT INTO manager_hosts(user, host, token_hash, created) VALUES(?,?,?,?)
		ON CONFLICT(user, host) DO UPDATE SET token_hash=excluded.token_hash, created=excluded.created`,
		user, host, hash(token), time.Now().Unix()); err != nil {
		return "", "", err
	}
	return user, token, tx.Commit()
}

// ManagerFor resolves a manager token to its user and host. A token from
// before multi-host has no host yet: it takes claim (the host name washd
// reports) unless that user already has a washd of that name.
func (d *DB) ManagerFor(token, claim string) (user, host string, ok bool) {
	if token == "" {
		return "", "", false
	}
	if d.db.QueryRow(`SELECT user, host FROM manager_hosts WHERE token_hash=?`, hash(token)).Scan(&user, &host) != nil {
		return "", "", false
	}
	if host == "" && claim != "" {
		if _, err := d.db.Exec(`UPDATE manager_hosts SET host=? WHERE token_hash=? AND host=''`, claim, hash(token)); err == nil {
			host = claim
		}
	}
	return user, host, true
}

// ManagerRow is one enrolled washd.
type ManagerRow struct {
	User, Host string
	Created    time.Time
}

// Managers lists enrolled washds.
func (d *DB) Managers() ([]ManagerRow, error) {
	rows, err := d.db.Query(`SELECT user, host, created FROM manager_hosts ORDER BY user, host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagerRow
	for rows.Next() {
		var r ManagerRow
		var c int64
		if rows.Scan(&r.User, &r.Host, &c) == nil {
			r.Created = time.Unix(c, 0)
			out = append(out, r)
		}
	}
	return out, nil
}

// Unenroll removes the manager token of user's washd on host ("" = all of
// user's); it reports how many were removed.
func (d *DB) Unenroll(user, host string) (int64, error) {
	q, args := `DELETE FROM manager_hosts WHERE user=?`, []any{user}
	if host != "" {
		q, args = q+` AND host=?`, append(args, host)
	}
	res, err := d.db.Exec(q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

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
