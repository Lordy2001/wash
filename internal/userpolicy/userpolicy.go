// Package userpolicy decides which accounts may use wash at all.
//
// wash gives a browser a shell, so it is only for people's own login
// accounts. Never root, never well-known default accounts (ubuntu, pi,
// ec2-user, ...), and never system or service accounts such as the rootless
// podman users this host runs its containers as.
//
// Both sides check: wash-web (in its container, by name only: Reserved plus
// WASH_DENY_USERS) and the host side (washd and the wash CLI: CheckLocal,
// which also reads the account from the host's passwd database).
package userpolicy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
)

// reserved are names wash refuses on every host: root, system accounts, the
// default users of cloud and distro images, and common service accounts.
var reserved = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`
		root toor daemon bin sys sync games man lp mail news uucp proxy www-data
		backup list irc gnats nobody nogroup nfsnobody operator adm halt shutdown
		messagebus syslog polkitd sshd dnsmasq avahi colord geoclue pulse rtkit
		saned usbmux tss uuidd tcpdump landscape pollinate fwupd-refresh dhcpcd
		chrony ntp postfix dovecot named bind unbound
		ubuntu debian admin administrator pi ec2-user centos fedora rocky
		almalinux cloud-user opc azureuser vagrant core alpine arch user guest
		test demo default oracle
		postgres mysql mariadb redis mongodb git gitlab jenkins www nginx apache
		httpd caddy podman docker containers dockremap
		wash`) {
		reserved[n] = true
	}
}

// Reserved reports whether name is never allowed, wherever it is checked.
func Reserved(name string) bool {
	return reserved[name] || strings.HasPrefix(name, "systemd-") || strings.HasPrefix(name, "_")
}

// Denied reports whether name is reserved or in extra (WASH_DENY_USERS).
func Denied(name string, extra map[string]bool) bool {
	return Reserved(name) || extra[name]
}

// ParseList parses a comma or space separated list of user names.
func ParseList(s string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		out[f] = true
	}
	return out
}

// Account is one passwd entry.
type Account struct {
	Name  string
	UID   int
	Shell string
}

// noShell are login shells that mean "no interactive logins".
var noShell = map[string]bool{
	"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/nologin": true, "/usr/bin/nologin": true,
	"/bin/false": true, "/usr/bin/false": true, "/bin/sync": true, "/usr/bin/sync": true,
}

// Check applies the host-side rules to an account: not reserved, not root,
// a uid in the login range of /etc/login.defs (UID_MIN..UID_MAX), and a real
// login shell. Service users (podman ones included) have nologin.
func Check(a Account) error {
	switch {
	case Reserved(a.Name):
		return fmt.Errorf("wash refuses the %q account: root, default and service accounts cannot have web shells", a.Name)
	case a.UID == 0:
		return fmt.Errorf("wash refuses %q: uid 0", a.Name)
	}
	lo, hi := uidRange()
	if a.UID < lo || a.UID > hi {
		return fmt.Errorf("wash refuses %q: uid %d is outside the login range %d-%d (system account)", a.Name, a.UID, lo, hi)
	}
	if noShell[a.Shell] || strings.HasSuffix(a.Shell, "/nologin") || strings.HasSuffix(a.Shell, "/false") {
		return fmt.Errorf("wash refuses %q: its login shell is %s (service account)", a.Name, a.Shell)
	}
	return nil
}

// CheckLocal checks the account this process runs as, and also name (the user
// washd is enrolled for), which may differ.
func CheckLocal(name string) error {
	me, err := user.Current()
	if err != nil {
		return err
	}
	acct, err := Lookup(me.Username)
	if err != nil {
		return err
	}
	if err := Check(acct); err != nil {
		return err
	}
	if name != "" && name != acct.Name {
		if Reserved(name) {
			return fmt.Errorf("wash refuses the %q account: root, default and service accounts cannot have web shells", name)
		}
		if other, err := Lookup(name); err == nil {
			return Check(other)
		}
	}
	return nil
}

// Lookup finds name in /etc/passwd, then through getent (LDAP, sssd, ...),
// and on macOS (whose people are not in /etc/passwd) in Directory Services.
func Lookup(name string) (Account, error) {
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		if a, ok := findPasswd(b, name); ok {
			return a, nil
		}
	}
	if out, err := exec.Command("getent", "passwd", name).Output(); err == nil {
		if a, ok := findPasswd(out, name); ok {
			return a, nil
		}
	}
	if runtime.GOOS == "darwin" && !strings.ContainsAny(name, "/ ") && name != "" {
		if out, err := exec.Command("dscl", ".", "-read", "/Users/"+name, "UniqueID", "UserShell").Output(); err == nil {
			if a, ok := parseDscl(out, name); ok {
				return a, nil
			}
		}
	}
	return Account{}, fmt.Errorf("no passwd entry for %q", name)
}

// parseDscl reads `dscl . -read /Users/NAME UniqueID UserShell`:
// "UniqueID: 501" and "UserShell: /bin/zsh" (a long value may wrap onto the
// next line after a bare "UserShell:").
func parseDscl(b []byte, name string) (Account, bool) {
	a := Account{Name: name, UID: -1}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" && i+1 < len(lines) {
			v = strings.TrimSpace(lines[i+1])
		}
		switch k {
		case "UniqueID":
			if n, err := strconv.Atoi(v); err == nil {
				a.UID = n
			}
		case "UserShell":
			a.Shell = v
		}
	}
	return a, a.UID >= 0 && a.Shell != ""
}

func findPasswd(b []byte, name string) (Account, bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) < 7 || f[0] != name {
			continue
		}
		uid, err := strconv.Atoi(f[2])
		if err != nil {
			return Account{}, false
		}
		return Account{Name: f[0], UID: uid, Shell: f[6]}, true
	}
	return Account{}, false
}

// uidRange reads UID_MIN and UID_MAX from /etc/login.defs (default 1000-60000;
// on macOS, which has no login.defs, people start at 501).
func uidRange() (int, int) {
	lo, hi := 1000, 60000
	if runtime.GOOS == "darwin" {
		lo = 501
	}
	b, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return lo, hi
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		if n, err := strconv.Atoi(f[1]); err == nil {
			switch f[0] {
			case "UID_MIN":
				lo = n
			case "UID_MAX":
				hi = n
			}
		}
	}
	return lo, hi
}

// ErrDenied is what wash-web answers for a refused user name.
var ErrDenied = errors.New("this account cannot use wash (root, default and service accounts are refused)")
