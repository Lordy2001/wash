package wosh

// Starting a session on another host. washd runs the remote relay over ssh
// the way wosh's client does for `wosh HOST` (wosh internal/client:
// startRemote, bootstrap, answerStub): a perl stub reports the platform and
// any installed wosh, washd answers USE <path> or sends a build for that
// platform to run from memory (MEM), and the relay (`wosh server`) starts a
// new daemon and prints its hello. The first offer goes through that relay;
// later ones use the attach stub over a fresh ssh (RouteRequest).
//
// Unlike wosh, washd never upgrades an installed wosh on the far host
// (no UPGRADE): it uses a protocol-compatible one or runs its own build
// from memory without installing anything.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// BuildFunc returns washd's gzipped wosh build for a platform key such as
// "linux-amd64", and its stamp (as `wosh _proto` prints it after "2/").
type BuildFunc func(key string) (stamp string, gz []byte, err error)

// Server is a `wosh server` relay on another host, reached over ssh. It
// started a new daemon there and relays offers to it until Close.
type Server struct {
	Hello Msg    // the relay's hello: session id, host, user, daemon socket
	How   string // what runs there: "installed /path" or "pushed linux-amd64 build"
	// Perl: the far host has perl, so later signaling can use the attach
	// stub on Hello.Sock (no wosh binary needed there, as with a pushed build).
	Perl bool

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	msgs   chan Msg
	stderr lockedBuf
	exited chan struct{}
	host   string
	once   sync.Once
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 64<<10 {
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.TrimSpace(l.b.String())
}

// StartServer runs `wosh server` on host (an ssh destination, e.g. a Host
// alias from ~/.ssh/config) and waits for its hello. ssh runs with
// BatchMode: keys or the agent in o must work without prompts.
func StartServer(ctx context.Context, host string, o RouteOptions, build BuildFunc) (*Server, error) {
	if host == "" || strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("bad host %q", host)
	}
	s, err := startServer(ctx, host, o, build, true)
	if err != nil && s != nil && s.exitCode() == 127 {
		// no perl there: an installed wosh is the only option
		s, err = startServer(ctx, host, o, nil, false)
	}
	return s, err
}

func startServer(ctx context.Context, host string, o RouteOptions, build BuildFunc, push bool) (*Server, error) {
	remote := remoteCommand("server")
	if push {
		remote = perlCommand(pushStub, "server")
	}
	args := []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host, remote}
	cmd := exec.Command(SSHProgram(), args...)
	if len(o.Env) > 0 {
		cmd.Env = append(os.Environ(), o.Env...)
	}
	s := &Server{cmd: cmd, msgs: make(chan Msg, 8), exited: make(chan struct{}), host: host, Perl: push}
	cmd.Stderr = &s.stderr
	var err error
	if s.stdin, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill() })
	defer stop()

	r := bufio.NewReaderSize(stdout, 64<<10)
	if push {
		line, err := pushLine(r)
		if err != nil {
			s.wait()
			return s, s.fail(err)
		}
		reply, payload, how, err := DecidePush(strings.Fields(line), build)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%s: %w", host, err)
		}
		s.How = how
		if _, err := io.WriteString(s.stdin, reply); err != nil {
			s.wait()
			return s, s.fail(err)
		}
		if _, err := s.stdin.Write(payload); err != nil {
			s.wait()
			return s, s.fail(err)
		}
	} else {
		s.How = "installed wosh (no perl)"
	}
	go func() {
		defer close(s.msgs)
		defer func() { _ = cmd.Wait(); close(s.exited) }()
		var f oscFilter
		buf := make([]byte, 8192)
		for {
			n, err := r.Read(buf)
			for _, x := range f.write(buf[:n]) {
				s.msgs <- x
			}
			if err != nil {
				return
			}
		}
	}()
	hello, err := s.recv(ctx, "")
	if err != nil {
		s.Close()
		return s, err
	}
	if hello.T == TError {
		s.Close()
		return nil, fmt.Errorf("%s: %s", host, hello.Err)
	}
	if hello.T != "hello" || hello.ID == "" {
		s.Close()
		return nil, fmt.Errorf("%s: unexpected %q from wosh server", host, hello.T)
	}
	s.Hello = hello
	return s, nil
}

// pushLine reads up to the stub's "WOSHPUSH ..." line (skipping anything a
// login shell printed first).
func pushLine(r *bufio.Reader) (string, error) {
	for i := 0; i < 200; i++ {
		line, err := r.ReadString('\n')
		if strings.HasPrefix(line, "WOSHPUSH ") {
			return strings.TrimSpace(line), nil
		}
		if err != nil {
			return "", errors.New("remote side closed before the push handshake")
		}
	}
	return "", errors.New("no push handshake")
}

// wait reaps a server whose reader goroutine never started.
func (s *Server) wait() {
	_ = s.stdin.Close()
	_ = s.cmd.Wait()
	close(s.exited)
}

func (s *Server) exitCode() int {
	select {
	case <-s.exited:
		if s.cmd.ProcessState != nil {
			return s.cmd.ProcessState.ExitCode()
		}
	default:
	}
	return -1
}

func (s *Server) fail(err error) error {
	if why := s.stderr.String(); why != "" {
		return fmt.Errorf("ssh %s: %s", s.host, why)
	}
	return fmt.Errorf("ssh %s: %w", s.host, err)
}

func (s *Server) recv(ctx context.Context, id string) (Msg, error) {
	for {
		select {
		case x, ok := <-s.msgs:
			if !ok {
				<-s.exited
				return Msg{}, s.fail(errors.New("remote side closed before answering"))
			}
			if id == "" || x.ID == "" || x.ID == id {
				return x, nil
			}
		case <-ctx.Done():
			return Msg{}, s.fail(ctx.Err())
		}
	}
}

// Request relays one offer to the new daemon and returns its answer.
func (s *Server) Request(ctx context.Context, m Msg) (Msg, error) {
	if m.V == 0 {
		m.V = Version
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	b, _ := json.Marshal(m)
	if _, err := io.WriteString(s.stdin, "WOSH:"+base64.StdEncoding.EncodeToString(b)+"\r"); err != nil {
		return Msg{}, s.fail(err)
	}
	for {
		ans, err := s.recv(ctx, m.ID)
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

// Close ends the relay (stdin EOF). A daemon that has answered an offer
// keeps running; one that never did is told to quit by its relay.
func (s *Server) Close() {
	s.once.Do(func() {
		_ = s.stdin.Close()
		select {
		case <-s.exited:
		case <-time.After(3 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.exited
		}
	})
}

// PlatformKey maps the stub's $^O and `uname -m` to a build key.
func PlatformKey(goos, arch string) string {
	goos = strings.ToLower(goos)
	switch strings.ToLower(arch) {
	case "x86_64", "amd64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	case "armv7l", "armv6l", "arm":
		arch = "arm"
	case "i386", "i686", "386":
		arch = "386"
	}
	return goos + "-" + strings.ToLower(arch)
}

// DecidePush answers the stub's "WOSHPUSH os arch caps [path|w|proto/stamp...]":
// an installed copy of washd's own build, else any protocol-compatible
// installed wosh, else washd's build run from memory.
func DecidePush(f []string, build BuildFunc) (reply string, payload []byte, how string, err error) {
	if len(f) < 4 {
		return "", nil, "", fmt.Errorf("bad push handshake %q", strings.Join(f, " "))
	}
	key := PlatformKey(f[1], f[2])
	var stamp string
	var gz []byte
	berr := errors.New("no builds")
	if build != nil {
		stamp, gz, berr = build(key)
	}
	type inst struct {
		path  string
		proto int
		stamp string
	}
	var found []inst
	for _, x := range f[4:] {
		p := strings.SplitN(x, "|", 3)
		if len(p) != 3 {
			continue
		}
		in := inst{path: p[0]}
		if pv, st, ok := strings.Cut(p[2], "/"); ok {
			in.proto, _ = strconv.Atoi(pv)
			in.stamp = st
		}
		found = append(found, in)
	}
	if berr == nil {
		for _, in := range found {
			if in.proto == Version && in.stamp == stamp {
				return "USE " + in.path + "\n", nil, "installed " + in.path, nil
			}
		}
	}
	for _, in := range found {
		if in.proto == Version {
			return "USE " + in.path + "\n", nil, "installed " + in.path, nil
		}
	}
	if berr != nil {
		return "", nil, "", fmt.Errorf("no compatible wosh installed there and none to push (%v)", berr)
	}
	codec, payload := "g", gz
	if !strings.HasPrefix(f[3], "1") { // perl cannot gunzip there
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			return "", nil, "", err
		}
		if payload, err = io.ReadAll(zr); err != nil {
			return "", nil, "", err
		}
		codec = "r"
	}
	return fmt.Sprintf("MEM %d %s\n", len(payload), codec), payload, "pushed " + key + " build", nil
}

// pushStub: copied verbatim from wosh internal/client/push.go; keep in sync.
const pushStub = `$|=1;$o=$^O;$m=` + "`uname -m`" + `;chomp $m;` +
	`$z=eval{require IO::Uncompress::Gunzip;1}?1:0;@f=();%s=();$X="";` +
	`for $c (split /:/,$ENV{PATH}){$X||="$c/xz" if -f "$c/xz" and -x "$c/xz"}$z.="x" if $X;` +
	`for $c ((split /:/,$ENV{PATH}),"$ENV{HOME}/bin","$ENV{HOME}/.local/bin","$ENV{HOME}/go/bin"){` +
	`$x="$c/wosh";next if $s{$x}++ or $x=~/[|\s]/;next unless -f $x and -x $x;` +
	`$pv=` + "`\"$x\" _proto 2>/dev/null`" + `;chomp $pv;$pv=~s/[|\s]//g;$pv="-" unless length $pv;` +
	`$w=(-w $x and -w $c)?1:0;push @f,"$x|$w|$pv"}` +
	`print "WOSHPUSH $o $m $z @f\n";binmode STDIN;$l=<STDIN>;defined $l or exit 1;chomp $l;` +
	`($q,$a,$l,$c)=split / /,$l;if($q eq "USE"){exec {$a} "wosh",@ARGV;die "wosh: exec $a failed\n"}` +
	`($l,$c)=($a,$l) if $q eq "MEM";` +
	`$d="";while(length($d)<$l){$r=read(STDIN,$d,$l-length($d),length($d));$r or die "wosh push: short read\n"}` +
	`if($c eq "x"){$p=open($h,"-|");defined $p or die "wosh push: fork: $^E\n";` +
	`unless($p){open($k,"|-",$X,"-dc") or exit 1;binmode $k;print $k $d;close $k or exit 1;exit 0}` +
	`binmode $h;{local $/;$d=<$h>}close $h or die "wosh push: xz failed\n"}` +
	`elsif($c eq "g"){$u="";IO::Uncompress::Gunzip::gunzip(\$d=>\$u) or die "wosh push: gunzip failed\n";$d=$u}` +
	`if($q eq "UPGRADE"){$t="$a.new.$$";if(open($h,">",$t)){binmode $h;print $h $d;close $h;chmod 0755,$t;` +
	`if(rename $t,$a){print STDERR "wosh: upgraded $a\n";exec {$a} "wosh",@ARGV}unlink $t}}` +
	`%n=(x86_64=>319,aarch64=>279);$nm="wosh";` +
	`if($o eq "linux" and $n{$m}){$f=syscall($n{$m},$nm,0);if($f>=0){open($h,">&=",$f) or die;binmode $h;$w=0;` +
	`while($w<length $d){$k=syswrite($h,$d,length($d)-$w,$w);defined $k or die "wosh push: write: $^E\n";$w+=$k}` +
	`exec {"/proc/self/fd/$f"} "wosh",@ARGV}}` +
	`for $t ("/dev/shm",$ENV{TMPDIR}||"/tmp","/tmp",$ENV{HOME}){next unless $t and -d $t;$p="$t/.wosh-$$";` +
	`open($h,">",$p) or next;binmode $h;print $h $d;close $h;chmod 0700,$p;$ENV{WOSH_UNLINK}=$p;` +
	`exec {$p} "wosh",@ARGV;unlink $p}die "wosh push: cannot execute pushed binary\n"`
