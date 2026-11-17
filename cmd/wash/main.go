// Command wash is the user's interface to washd (the shell manager) and,
// through it, to wash-web.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"wash/internal/link"
	"wash/internal/manager"
	"wash/internal/paths"
	"wash/internal/pin"
	"wash/internal/userpolicy"
)

var version = "0.1.0-dev"

const usage = `wash - manage your wash shell manager (washd), sessions and passkeys

manager:
  wash up                       start washd in the background
  wash down [--kill-sessions]   stop washd (sessions keep running unless --kill-sessions)
  wash restart                  stop and start washd
  wash status                   washd, link to the website, sessions
  wash logs [-n N]              last lines of the washd log
  wash enroll [URL [CODE]] [--fingerprint=SHA256] [--yes]
                                link washd to wash-web. Without CODE, wash gets the code
                                and certificate fingerprint from the web container itself
                                (podman: wash-web, wash-web-dev; else upod wash; or
                                $WASH_WEB_EXEC). URL defaults to https://$(hostname):8443
  wash web ARGS...              run wash-web admin commands in that container
                                (keys, managers, unenroll USER, fingerprint, backup FILE)
  wash service install|uninstall  systemd user unit for washd
  wash agent [SOCK|--clear]     give washd your ssh-agent ($SSH_AUTH_SOCK; "wash up" does
                                this too) for its ssh routes to chained-hop sessions

sessions:
  wash sessions                 list (alias: wash ls)
  wash sessions new [NAME]      start a session
  wash sessions kill ID...|--all
  wash sessions rename ID NAME

recordings (asciicast v2, playable with asciinema too):
  wash watch start SESSION_ID   record a session as a viewer (never takes control;
                                alias: wash watch record SESSION_ID)
  wash watch stop SESSION_ID    stop recording it
  wash watch list               recordings with their FILE_ID and status (alias: ls)
  wash watch play FILE_ID [--raw] [--speed N] [--idle SECONDS|0]
                                play in this terminal (--raw: straight to the terminal,
                                like asciinema play)
  wash watch host FILE_ID       publish on the website: prints a public link
                                (WASH_PUBLIC_URL/playback/UUID); anyone with it can watch
  wash watch unhost FILE_ID     remove it from the website
  wash watch rm FILE_ID...      delete recordings

passkeys (only your own user's):
  wash keys                     approved and pending passkeys
  wash keys open [DURATION]     allow creating a passkey for you on the website
                                (default and maximum 1h; closed again otherwise)
  wash keys close               stop allowing it before the time is up
  wash keys approve ID          approve a pending passkey (pending ones expire after 1h)
  wash keys revoke ID           remove a passkey (closes browsers that used it)

config:
  wash config                   show settings
  wash config set KEY VALUE     keys: wosh command stun turn relay transport max_sessions term
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"status"}
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "up", "start":
		err = up()
	case "down", "stop":
		err = down(has(rest, "--kill-sessions"))
	case "restart":
		if err = down(false); err == nil || errors.Is(err, manager.ErrNotRunning) {
			err = up()
		}
	case "status":
		err = status()
	case "logs":
		err = logs(rest)
	case "agent":
		err = agent(rest)
	case "web":
		if len(rest) >= 2 && rest[0] == "enroll" {
			// an admin issuing a code for someone: check that account on this host
			name := rest[len(rest)-1]
			if a, lerr := userpolicy.Lookup(name); lerr == nil {
				err = userpolicy.Check(a)
			} else if userpolicy.Reserved(name) {
				err = fmt.Errorf("%s: %w", name, userpolicy.ErrDenied)
			}
			if err != nil {
				break
			}
		}
		err = webExec(rest)
	case "enroll":
		err = enroll(rest)
	case "service":
		err = service(rest)
	case "sessions", "session", "ls":
		if cmd == "ls" {
			rest = nil
		}
		err = sessions(rest)
	case "watch", "rec", "recordings":
		err = watch(rest)
	case "keys", "key":
		err = keys(rest)
	case "config":
		err = config(rest)
	case "version", "--version":
		fmt.Println("wash", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wash:", err)
		os.Exit(1)
	}
}

func has(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func flagVal(args []string, name string) (string, []string) {
	var rest []string
	val := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			val = v
		} else if a == name && i+1 < len(args) {
			val = args[i+1]
			i++
		} else {
			rest = append(rest, a)
		}
	}
	return val, rest
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return t.Format("2006-01-02")
}

// --- washd lifecycle ---------------------------------------------------------------

func washdPath() (string, error) {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "washd")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath("washd")
}

func running() bool { return manager.Call(manager.Request{Op: "status"}, nil) == nil }

func up() error {
	if running() {
		fmt.Println("washd is already running")
		return nil
	}
	creds, err := manager.LoadCreds()
	if err != nil {
		return err
	}
	if err := userpolicy.CheckLocal(creds.User); err != nil {
		return err
	}
	bin, err := washdPath()
	if err != nil {
		return errors.New("washd binary not found next to wash or in PATH")
	}
	logf, err := os.OpenFile(paths.LogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	cmd := exec.Command(bin)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for i := 0; i < 50; i++ {
		select {
		case err := <-exited:
			return fmt.Errorf("washd exited: %v (see %s)", err, paths.LogFile())
		case <-time.After(100 * time.Millisecond):
		}
		if running() {
			break
		}
	}
	if !running() {
		return fmt.Errorf("washd did not come up (see %s)", paths.LogFile())
	}
	// give the link a moment so status is informative
	for i := 0; i < 20; i++ {
		var st manager.Status
		if manager.Call(manager.Request{Op: "status"}, &st) == nil && (st.Linked || st.LinkErr != "") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Printf("washd started (pid %d, log %s)\n", cmd.Process.Pid, paths.LogFile())
	return status()
}

func down(killSessions bool) error {
	if err := manager.Call(manager.Request{Op: "stop", All: killSessions}, nil); err != nil {
		return err
	}
	for i := 0; i < 50 && running(); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	if killSessions {
		fmt.Println("washd stopped; sessions killed")
	} else {
		fmt.Println("washd stopped (sessions keep running; `wash up` picks them up again)")
	}
	return nil
}

func status() error {
	var st manager.Status
	if err := manager.Call(manager.Request{Op: "status"}, &st); err != nil {
		if c, cerr := manager.LoadCreds(); cerr == nil {
			fmt.Printf("washd: not running   (enrolled with %s as %s)\n", c.URL, c.User)
		}
		return err
	}
	link := "connected"
	if !st.Linked {
		link = "DISCONNECTED"
		if st.LinkErr != "" {
			link += ": " + st.LinkErr
		}
	}
	fmt.Printf("washd %s  pid %d  up since %s  user %s\n", st.Version, st.PID, st.Since.Format("2006-01-02 15:04"), st.User)
	fmt.Printf("website  %s  %s\n", st.URL, link)
	fmt.Printf("browsers %d connected\n", st.Browsers)
	if st.Agent != "" {
		fmt.Printf("ssh-agent %s\n", st.Agent)
	} else {
		fmt.Println("ssh-agent none (run `wash agent` from a shell that has one)")
	}
	fmt.Println()
	printSessions(st.Sessions)
	return nil
}

func logs(args []string) error {
	n := 40
	if v, _ := flagVal(args, "-n"); v != "" {
		fmt.Sscan(v, &n)
	}
	b, err := os.ReadFile(paths.LogFile())
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	fmt.Println(strings.Join(lines, "\n"))
	return nil
}

// --- enroll ---------------------------------------------------------------------

func enroll(args []string) error {
	if err := userpolicy.CheckLocal(""); err != nil {
		return err
	}
	fp, args := flagVal(args, "--fingerprint")
	yes := has(args, "--yes")
	var pos []string
	for _, a := range args {
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
		}
	}
	if len(pos) > 2 {
		return errors.New("usage: wash enroll [URL [CODE]]")
	}
	if len(pos) == 0 {
		h, _ := os.Hostname()
		pos = append(pos, "https://"+h+":8443")
	}
	if len(pos) == 1 {
		// no code: ask the web container directly (local, trusted channel), which
		// also gives us the certificate fingerprint to pin without a prompt
		user := os.Getenv("USER")
		if user == "" {
			return errors.New("$USER is not set")
		}
		run, err := webRunner()
		if err != nil {
			return fmt.Errorf("%w\n(or get a CODE from an admin: wash-web enroll %s, then `wash enroll URL CODE`)", err, user)
		}
		fmt.Printf("getting an enrollment code from %s\n", strings.Join(run, " "))
		out, err := runWeb(run, "enroll", "-q", user)
		if err != nil {
			return err
		}
		pos = append(pos, strings.TrimSpace(out))
		if fp == "" {
			if out, err := runWeb(run, "fingerprint"); err == nil {
				fp = strings.TrimSpace(out)
			}
		}
	}
	base := strings.TrimRight(pos[0], "/")
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return fmt.Errorf("bad URL %q", pos[0])
	}
	fp = strings.ToLower(strings.ReplaceAll(fp, ":", ""))
	if u.Scheme == "https" {
		host := u.Host
		if u.Port() == "" {
			host = net.JoinHostPort(u.Hostname(), "443")
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host,
			&tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()})
		if err != nil {
			return err
		}
		certs := conn.ConnectionState().PeerCertificates
		conn.Close()
		// pin the CA when the server sends one (wash-web's own TLS), else the leaf
		got := pin.Of(certs[len(certs)-1])
		if len(certs) == 1 || certs[len(certs)-1].CheckSignatureFrom(certs[len(certs)-1]) != nil {
			got = pin.Of(certs[0])
		}
		pool, _ := x509.SystemCertPool()
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, verr := certs[0].Verify(x509.VerifyOptions{DNSName: u.Hostname(), Roots: pool, Intermediates: inter})
		switch {
		case fp != "":
			if err := pin.Verify(certs, fp, u.Hostname()); err != nil {
				return fmt.Errorf("certificate check failed: %v\n  expected %s\n  server   %s", err, fp, got)
			}
		case verr == nil:
			// publicly trusted: rely on normal verification, no pin
		default:
			fmt.Printf("The server's certificate is not publicly trusted (self-signed?).\nSHA-256: %s\n", got)
			fmt.Println("Compare with `wash-web fingerprint` in the web container (also printed by `wash-web enroll`).")
			if !yes && !confirm("Pin this certificate?") {
				return errors.New("aborted")
			}
			fp = got
		}
	}
	creds := manager.Creds{URL: base, Fingerprint: fp}
	client := pinnedClient(fp)
	body, _ := json.Marshal(map[string]string{"code": pos[1]})
	resp, err := client.Post(base+"/api/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct{ User, Token, Error string }
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out)
	if resp.StatusCode != 200 {
		return fmt.Errorf("enroll failed: %s", out.Error)
	}
	if me := os.Getenv("USER"); me != "" && me != out.User {
		fmt.Printf("note: the code was issued for user %q, you are %q\n", out.User, me)
	}
	if err := userpolicy.CheckLocal(out.User); err != nil {
		return err
	}
	creds.User, creds.Token = out.User, out.Token
	if err := manager.SaveCreds(creds); err != nil {
		return err
	}
	fmt.Printf("enrolled with %s as %s (%s)\n", base, out.User, paths.ManagerFile())
	if running() {
		fmt.Println("restarting washd to use the new link")
		if err := down(false); err != nil {
			return err
		}
	}
	return up()
}

// webRunner finds how to run commands in the wash-web container.
func webRunner() ([]string, error) {
	if v := strings.Fields(os.Getenv("WASH_WEB_EXEC")); len(v) > 0 {
		return v, nil
	}
	if out, err := exec.Command("podman", "ps", "--format", "{{.Names}}").Output(); err == nil {
		names := strings.Fields(string(out))
		for _, want := range []string{"wash-web", "wash-web-dev"} {
			for _, n := range names {
				if n == want {
					return []string{"podman", "exec", n}, nil
				}
			}
		}
	}
	if p, err := exec.LookPath("upod"); err == nil { // the wash service user (needs sudo)
		return []string{p, "wash", "exec", "wash-web"}, nil
	}
	return nil, errors.New("no wash-web container found (podman ps: wash-web, wash-web-dev; upod wash); set WASH_WEB_EXEC")
}

func runWeb(run []string, args ...string) (string, error) {
	cmd := exec.Command(run[0], append(append(run[1:], "/wash-web"), args...)...)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr // sudo may prompt
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", strings.Join(run, " "), err)
	}
	return string(out), nil
}

// webExec passes admin commands through to wash-web in its container.
func webExec(args []string) error {
	if len(args) == 0 {
		args = []string{"help"}
	}
	run, err := webRunner()
	if err != nil {
		return err
	}
	cmd := exec.Command(run[0], append(append(run[1:], "/wash-web"), args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Run()
}

func pinnedClient(fp string) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: pin.Config(fp)}}
}

func confirm(q string) bool {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false
	}
	fmt.Printf("%s [y/N] ", q)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// --- sessions ---------------------------------------------------------------------

func printSessions(ss []manager.SessionInfo) {
	if len(ss) == 0 {
		fmt.Println("no sessions")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSTARTED\tPID\tBROWSERS")
	for _, s := range ss {
		name := s.Name
		if s.Remote != nil {
			var via []string
			for _, h := range s.Remote.Route {
				via = append(via, strings.Join(h, " "))
			}
			name += " (" + s.Remote.Host + " via " + strings.Join(via, " → ") + ")"
		}
		for _, h := range s.Hops {
			name += " → " + h.Host // chained hops a browser connected to
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\n", s.ID, name, ago(s.Created), s.PID, s.Attached)
	}
	tw.Flush()
}

func sessions(args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "list", "ls":
		var ss []manager.SessionInfo
		if err := manager.Call(manager.Request{Op: "sessions.list"}, &ss); err != nil {
			return err
		}
		printSessions(ss)
	case "new":
		var s manager.SessionInfo
		if err := manager.Call(manager.Request{Op: "sessions.new", Name: strings.Join(args, " ")}, &s); err != nil {
			return err
		}
		fmt.Printf("started %s (%s), pid %d\n", s.ID, s.Name, s.PID)
	case "kill", "rm":
		if has(args, "--all") {
			var n int
			if err := manager.Call(manager.Request{Op: "sessions.kill", All: true}, &n); err != nil {
				return err
			}
			fmt.Printf("killed %d session(s)\n", n)
			return nil
		}
		if len(args) == 0 {
			return errors.New("usage: wash sessions kill ID...|--all")
		}
		var errs []error
		for _, id := range args {
			if err := manager.Call(manager.Request{Op: "sessions.kill", ID: id}, nil); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
			} else {
				fmt.Println("killed", id)
			}
		}
		return errors.Join(errs...)
	case "rename":
		if len(args) < 2 {
			return errors.New("usage: wash sessions rename ID NAME")
		}
		return manager.Call(manager.Request{Op: "sessions.rename", ID: args[0], Name: strings.Join(args[1:], " ")}, nil)
	default:
		return fmt.Errorf("unknown sessions command %q", sub)
	}
	return nil
}

// --- keys -------------------------------------------------------------------------

func keys(args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "list", "ls":
		var ks []manager.KeyView
		if err := manager.Call(manager.Request{Op: "keys.list"}, &ks); err != nil {
			return err
		}
		if len(ks) == 0 {
			fmt.Println("no passkeys. Run `wash keys open`, create one on the website, then `wash keys approve ID`.")
			return nil
		}
		sort.SliceStable(ks, func(i, j int) bool { return ks[i].Approved && !ks[j].Approved })
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSTATUS\tCREATED\tLAST USED\tORIGIN")
		var notes []string
		for _, k := range ks {
			st := "approved"
			switch {
			case !k.Approved && !k.Expires.IsZero():
				st = fmt.Sprintf("PENDING (purged in %s)", time.Until(k.Expires).Round(time.Minute))
			case !k.Approved:
				st = "PENDING"
			case !k.Local:
				st = "approved (web only)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", k.ID, k.Name, st, ago(k.Created), ago(k.LastUsed), k.Origin)
			if k.Note != "" {
				notes = append(notes, k.ID+": "+k.Note)
			}
		}
		tw.Flush()
		for _, n := range notes {
			fmt.Println("note", n)
		}
	case "approve":
		if len(args) != 1 {
			return errors.New("usage: wash keys approve ID")
		}
		var k link.KeyInfo
		if err := manager.Call(manager.Request{Op: "keys.approve", ID: args[0]}, &k); err != nil {
			return err
		}
		fmt.Printf("approved %s (%s, created %s from %s)\n", k.ID, k.Name, ago(k.Created), k.Origin)
	case "open":
		if len(args) > 1 {
			return errors.New("usage: wash keys open [DURATION]")
		}
		d := "1h"
		if len(args) == 1 {
			d = args[0]
		}
		var rw link.RegWindow
		if err := manager.Call(manager.Request{Op: "keys.open", Val: d}, &rw); err != nil {
			return err
		}
		if rw.Always {
			fmt.Println("note: this wash-web runs with WASH_REGISTRATION=open, so anyone can always create passkeys there")
		}
		fmt.Printf("passkey creation for you is open until %s (%s). Create the passkey on the website,\n",
			rw.Until.Format("15:04"), time.Until(rw.Until).Round(time.Minute))
		fmt.Println("then approve only the ID the website shows you: `wash keys approve ID`. Close early with `wash keys close`.")
	case "close":
		var rw link.RegWindow
		if err := manager.Call(manager.Request{Op: "keys.open"}, &rw); err != nil {
			return err
		}
		fmt.Println("passkey creation for you is closed")
	case "revoke", "rm", "delete":
		if len(args) != 1 {
			return errors.New("usage: wash keys revoke ID")
		}
		if err := manager.Call(manager.Request{Op: "keys.revoke", ID: args[0]}, nil); err != nil {
			return err
		}
		fmt.Println("revoked", args[0])
	default:
		return fmt.Errorf("unknown keys command %q", sub)
	}
	return nil
}

// --- config -----------------------------------------------------------------------

func config(args []string) error {
	cfg := manager.LoadConfig()
	if len(args) == 0 || args[0] == "list" || args[0] == "show" {
		var ks []string
		for k := range manager.ConfigKeys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, k := range ks {
			v, _ := cfg.Get(k)
			fmt.Fprintf(tw, "%s\t%s\t# %s\n", k, v, manager.ConfigKeys[k])
		}
		tw.Flush()
		if c, err := manager.LoadCreds(); err == nil {
			fmt.Printf("\nwebsite %s as %s (%s)\n", c.URL, c.User, paths.ManagerFile())
		}
		return nil
	}
	switch args[0] {
	case "get":
		if len(args) != 2 {
			return errors.New("usage: wash config get KEY")
		}
		v, err := cfg.Get(args[1])
		if err != nil {
			return err
		}
		fmt.Println(v)
	case "set":
		if len(args) < 2 {
			return errors.New("usage: wash config set KEY VALUE")
		}
		if err := cfg.Set(args[1], strings.Join(args[2:], " ")); err != nil {
			return err
		}
		if err := manager.SaveConfig(cfg); err != nil {
			return err
		}
		if err := manager.Call(manager.Request{Op: "config.reload"}, nil); err == nil {
			fmt.Println("saved; washd reloaded")
		} else {
			fmt.Println("saved")
		}
	default:
		return fmt.Errorf("unknown config command %q", args[0])
	}
	return nil
}

func agent(args []string) error {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if len(args) > 0 {
		sock = args[0]
	}
	if has(args, "--clear") {
		sock = ""
	}
	if err := manager.Call(manager.Request{Op: "agent", Val: sock}, nil); err != nil {
		return err
	}
	if sock == "" {
		fmt.Println("washd: no ssh-agent")
	} else {
		fmt.Println("washd uses ssh-agent", sock)
	}
	return nil
}

// --- systemd ----------------------------------------------------------------------

func service(args []string) error {
	if len(args) != 1 || (args[0] != "install" && args[0] != "uninstall") {
		return errors.New("usage: wash service install|uninstall")
	}
	home, _ := os.UserHomeDir()
	unit := filepath.Join(home, ".config", "systemd", "user", "washd.service")
	if args[0] == "uninstall" {
		_ = exec.Command("systemctl", "--user", "disable", "--now", "washd").Run()
		if err := os.Remove(unit); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("removed", unit)
		return nil
	}
	bin, err := washdPath()
	if err != nil {
		return errors.New("washd binary not found")
	}
	bin, _ = filepath.Abs(bin)
	if err := os.MkdirAll(filepath.Dir(unit), 0o755); err != nil {
		return err
	}
	content := fmt.Sprintf(`[Unit]
Description=wash shell manager (washd)
After=network-online.target

[Service]
ExecStart=%s
Restart=on-failure
RestartSec=5
# sessions are separate processes that must outlive washd restarts
KillMode=process

[Install]
WantedBy=default.target
`, bin)
	if err := os.WriteFile(unit, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", unit)
	fmt.Println("enable with:  systemctl --user daemon-reload && systemctl --user enable --now washd")
	fmt.Println("keep it running after logout:  loginctl enable-linger $USER")
	return nil
}
