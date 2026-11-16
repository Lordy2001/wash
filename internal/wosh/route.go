package wosh

// Route signaling: reaching a wosh daemon on another host by ssh'ing
// through the same hosts a chained hop went through, each hop with that
// host's own ssh config and keys. This is how wosh's client reconnects a
// chained hop after the intermediate sessions are gone (wosh
// internal/client: hopCommand, pushAttachStub, RemoteCommand, pipeWire);
// washd does it on behalf of the browser, which cannot ssh. The stubs are
// copied verbatim from wosh; keep them in sync.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// pushAttachStub (wosh internal/client/push.go): talks to a daemon's
// control socket with perl only (no wosh binary needed on the target).
const pushAttachStub = `use IO::Socket::UNIX;use MIME::Base64;$|=1;($k,$i)=@ARGV;` +
	`sub osc{print "\e]5379;wosh;".encode_base64($_[0],"")."\a"}` +
	`$s=IO::Socket::UNIX->new(Peer=>$k);unless($s){osc(qq({"t":"err","id":"$i","err":"no such session"}));exit 1}` +
	`osc(qq({"t":"hello","id":"$i","v":1}));$/="\r";` +
	`while(<STDIN>){if(/WOSH:([A-Za-z0-9+\/=]+)/){print $s decode_base64($1)."\n";` +
	`{local $/="\n";$r=<$s>}defined $r or exit 1;chomp $r;osc($r);exit 0 if $r=~/"t":"answer"/}}`

// hopStub (wosh): runs ssh on an intermediate host with that host's config.
const hopStub = `use MIME::Base64;exec {$ENV{WOSH_HOP_SSH}||"ssh"} "ssh",split(chr(0),decode_base64($ARGV[0]));` +
	`die "wosh: cannot run ssh: $^E\n"`

const remotePath = `$PATH:$HOME/bin:$HOME/.local/bin:$HOME/go/bin:/usr/local/bin`

// ErrNoSession is what the attach stub reports for a session that is gone.
const ErrNoSession = "no such session"

func quoteWord(w string) string {
	safe := w != ""
	for _, r := range w {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+=:,@%", r)) {
			safe = false
			break
		}
	}
	if safe {
		return w
	}
	return "'" + strings.NewReplacer("'", "", `\`, "").Replace(w) + "'"
}

func perlCommand(stub string, args ...string) string {
	parts := []string{"perl", "-e", "'" + stub + "'"}
	for _, a := range args {
		parts = append(parts, quoteWord(a))
	}
	return strings.Join(parts, " ")
}

// remoteCommand runs an installed wosh with args under any login shell.
func remoteCommand(args ...string) string {
	parts := []string{"sh", "-c", `'PATH="` + remotePath + `"; exec "$0" "$@"'`, "wosh"}
	for _, a := range args {
		parts = append(parts, quoteWord(a))
	}
	return strings.Join(parts, " ")
}

func hopCommand(hops [][]string, final string) string {
	if len(hops) == 0 {
		return final
	}
	argv := append([]string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}, hops[0]...)
	argv = append(argv, hopCommand(hops[1:], final))
	return perlCommand(hopStub, base64.StdEncoding.EncodeToString([]byte(strings.Join(argv, "\x00"))))
}

// RouteOptions tune how washd runs a route.
type RouteOptions struct {
	// Env is added to ssh's environment (SSH_AUTH_SOCK: the user's agent).
	Env []string
	// ForwardAgent forwards that agent through the intermediate hops so they
	// can use its keys for the next ssh (not to the final host).
	ForwardAgent bool
}

// RouteArgs is the local ssh command line that reaches session id on the
// last host of route (route[0] runs here, route[1] on that host, ...).
func RouteArgs(route [][]string, sock, id string, o RouteOptions) ([]string, error) {
	if len(route) == 0 || len(route[0]) == 0 {
		return nil, errors.New("empty route")
	}
	final := remoteCommand("attach", id)
	if sock != "" {
		final = perlCommand(pushAttachStub, sock, id)
	}
	hops := route
	if o.ForwardAgent {
		// every ssh except the one into the final host forwards the agent
		hops = make([][]string, len(route))
		for i, h := range route {
			if i < len(route)-1 {
				h = append([]string{"-o", "ForwardAgent=yes"}, h...)
			}
			hops[i] = h
		}
	}
	args := append([]string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}, hops[0]...)
	return append(args, hopCommand(hops[1:], final)), nil
}

// SSHProgram is the ssh binary used for routes ($WASH_SSH overrides; tests).
func SSHProgram() string {
	if p := os.Getenv("WASH_SSH"); p != "" {
		return p
	}
	return "ssh"
}

// RouteRequest sends one offer to a daemon reached through route and
// returns its answer (one ssh per signaling exchange, as wosh does).
func RouteRequest(ctx context.Context, route [][]string, sock string, m Msg, o RouteOptions) (Msg, error) {
	args, err := RouteArgs(route, sock, m.ID, o)
	if err != nil {
		return Msg{}, err
	}
	if m.V == 0 {
		m.V = Version
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, SSHProgram(), args...)
	if len(o.Env) > 0 {
		cmd.Env = append(os.Environ(), o.Env...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Msg{}, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Msg{}, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Msg{}, err
	}
	exited := make(chan struct{}) // closed after Wait (stderr complete)
	defer func() {
		_ = stdin.Close()
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}()
	msgs := make(chan Msg, 4)
	go func() {
		defer close(msgs)
		// Wait only after stdout hit EOF (os/exec rule), so stderr is complete
		// by the time a failure is reported
		defer func() { _ = cmd.Wait(); close(exited) }()
		var f oscFilter
		buf := make([]byte, 8192)
		for {
			n, err := stdout.Read(buf)
			for _, x := range f.write(buf[:n]) {
				msgs <- x
			}
			if err != nil {
				return
			}
		}
	}()
	recv := func() (Msg, error) {
		for {
			select {
			case x, ok := <-msgs:
				if !ok {
					why := strings.TrimSpace(stderr.String())
					if why == "" {
						why = "remote side closed before answering"
					}
					return Msg{}, fmt.Errorf("route %s: %s", routeString(route), why)
				}
				if x.ID == "" || x.ID == m.ID {
					return x, nil
				}
			case <-ctx.Done():
				return Msg{}, fmt.Errorf("route %s: %w", routeString(route), ctx.Err())
			}
		}
	}
	hello, err := recv()
	if err != nil {
		return Msg{}, err
	}
	if hello.T == TError {
		return Msg{}, errors.New(hello.Err)
	}
	if m.T == "" { // probe: the route reaches the daemon
		return hello, nil
	}
	b, _ := json.Marshal(m)
	if _, err := io.WriteString(stdin, "WOSH:"+base64.StdEncoding.EncodeToString(b)+"\r"); err != nil {
		return Msg{}, err
	}
	for {
		ans, err := recv()
		if err != nil {
			return Msg{}, err
		}
		switch ans.T {
		case TAnswer:
			return ans, nil
		case TError:
			return Msg{}, errors.New(ans.Err)
		}
	}
}

// RouteProbe checks that route reaches session id's daemon (non-interactive
// ssh at every hop, host keys known, daemon listening) without signaling.
func RouteProbe(ctx context.Context, route [][]string, sock, id string, o RouteOptions) error {
	_, err := RouteRequest(ctx, route, sock, Msg{ID: id}, o)
	return err
}

// RouteString renders a route for logs and errors.
func RouteString(route [][]string) string { return routeString(route) }

func routeString(route [][]string) string {
	var hs []string
	for _, h := range route {
		hs = append(hs, strings.Join(h, " "))
	}
	return strings.Join(hs, " -> ")
}

// oscFilter extracts wosh OSC messages (ESC ] 5379 ; wosh ; b64 BEL|ST).
type oscFilter struct {
	buf []byte
}

func (f *oscFilter) write(p []byte) []Msg {
	const pre = "\x1b]5379;wosh;"
	f.buf = append(f.buf, p...)
	var out []Msg
	for {
		i := bytes.Index(f.buf, []byte(pre))
		if i < 0 {
			if k := len(f.buf) - len(pre); k > 0 {
				f.buf = f.buf[k:] // keep a possible prefix only
			}
			return out
		}
		rest := f.buf[i+len(pre):]
		j := bytes.IndexAny(rest, "\a\x1b")
		if j < 0 {
			if len(rest) > 1<<20 {
				f.buf = nil
			}
			return out
		}
		var m Msg
		if b, err := base64.StdEncoding.DecodeString(string(rest[:j])); err == nil && json.Unmarshal(b, &m) == nil {
			out = append(out, m)
		}
		f.buf = rest[j+1:]
	}
}
