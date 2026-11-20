// Command wash-web is the wash website: passkey login and the hand-off of
// browser WebSockets to each user's washd. It runs in a podman container and
// listens on 0.0.0.0.
//
//	wash-web [serve]            run the server (default)
//	wash-web enroll [-q] USER   print a one-time code for `wash enroll` (-q: code only)
//	wash-web unenroll USER [HOST]  forget USER's washd token(s) (all hosts, or HOST's)
//	wash-web managers           list enrolled washds (user, host)
//	wash-web keys [USER]        list passkeys (approved and pending)
//	wash-web fingerprint        print the TLS fingerprint washd pins (the CA's)
//	wash-web ca                 print the CA certificate (also served at /ca.crt)
//	wash-web backup FILE        consistent copy of the database (VACUUM INTO)
//	wash-web health             exit 0 if the server answers (container healthcheck)
//
// Environment:
//
//	WASH_LISTEN        listen address (default 0.0.0.0:8443)
//	WASH_DATA          data dir: wash.db, tls/ (default /data; the quadlet uses /var/lib/wash)
//	WASH_ORIGIN        allowed origins, comma separated, e.g. https://wash.example.com:8443
//	                   (default: derived from each request's Host)
//	WASH_TLS           "auto" (self-signed in $WASH_DATA/tls, default), "off"
//	                   (plain HTTP behind a TLS proxy), or "CERT,KEY" file paths
//	WASH_TLS_HOSTS     extra names/IPs for the self-signed certificate
//	WASH_REGISTRATION  "closed" (default: each user opens passkey creation for up to
//	                   1h with `wash keys open`) or "open" (anyone, any time)
//	WASH_DENY_USERS    extra user names (comma separated) that may never use wash, on top
//	                   of the built-in list (root, ubuntu, pi, system and service names)
//	WASH_PUBLIC_URL    public base URL of the site, e.g. https://example.com/wash: the
//	                   links `wash watch host` prints are WASH_PUBLIC_URL/playback/UUID
//	WASH_PLAYBACK_MAX_MB  largest recording `wash watch host` may publish (default 512)
//	WASH_TRUST_PROXY   behind a reverse proxy: comma-separated proxy IPs/CIDRs whose
//	                   X-Forwarded-For/-Proto are believed, or 1 for any peer (then
//	                   publish the port on 127.0.0.1 only). Default: off
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	webui "wash/web"

	"wash/internal/userpolicy"
	"wash/internal/web"
)

var version = "0.1.0-dev"

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(log.LstdFlags)
	data := env("WASH_DATA", "/data")
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		serve(data)
		return
	case "health":
		os.Exit(health())
	}
	db, err := web.OpenDB(filepath.Join(data, "wash.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	switch cmd {
	case "enroll":
		quiet := len(args) == 2 && args[0] == "-q"
		if quiet {
			args = args[1:]
		}
		if len(args) != 1 {
			fatal("usage: wash-web enroll [-q] USER")
		}
		if userpolicy.Denied(args[0], denyUsers()) {
			fatal("%s: %v", args[0], userpolicy.ErrDenied)
		}
		code, err := db.NewEnrollCode(args[0])
		if err != nil {
			fatal("%v", err)
		}
		if quiet { // for `wash enroll`, which runs this through podman exec
			fmt.Println(code)
			return
		}
		fmt.Printf("Enrollment code for %s (valid 10 minutes, single use):\n\n  %s\n\n", args[0], code)
		fmt.Printf("As %s on the shell host run:\n\n  wash enroll https://HOST:PORT %s\n", args[0], code)
		if fp, err := tlsFingerprint(data); err == nil {
			fmt.Printf("\nServer certificate SHA-256 (compare when wash enroll asks):\n  %s\n", fp)
		}
	case "unenroll":
		if len(args) != 1 && len(args) != 2 {
			fatal("usage: wash-web unenroll USER [HOST]")
		}
		host := ""
		if len(args) == 2 {
			host = args[1]
		}
		n, err := db.Unenroll(args[0], host)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Printf("removed %d washd token(s) of %s\n", n, args[0])
		if host == "" { // the user is gone entirely
			if n := web.RemovePlaybacks(filepath.Join(data, "playback"), args[0]); n > 0 {
				fmt.Printf("removed %d hosted recording(s) of %s\n", n, args[0])
			}
		}
	case "managers":
		rows, err := db.Managers()
		if err != nil {
			fatal("%v", err)
		}
		for _, r := range rows {
			host := r.Host
			if host == "" {
				host = "(named on its next link)"
			}
			fmt.Printf("%-16s %-24s %s\n", r.User, host, r.Created.Format("2006-01-02"))
		}
	case "keys":
		user := ""
		if len(args) > 0 {
			user = args[0]
		}
		rows, err := db.KeyInfos(user)
		if err != nil {
			fatal("%v", err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tUSER\tNAME\tSTATUS\tCREATED\tORIGIN")
		for _, k := range rows {
			st := "approved"
			if !k.Approved {
				st = "pending (expires " + k.Expires.Format("15:04") + ")"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", k.ID, k.User, k.Name, st, k.Created.Format("2006-01-02 15:04"), k.Origin)
		}
		tw.Flush()
	case "backup":
		if len(args) != 1 {
			fatal("usage: wash-web backup FILE")
		}
		if err := db.Backup(args[0]); err != nil {
			fatal("%v", err)
		}
		fmt.Println("wrote", args[0])
	case "ca":
		if _, _, err := tlsFiles(data); err != nil {
			fatal("%v", err)
		}
		p := web.CAFile(filepath.Join(data, "tls"))
		if p == "" {
			fatal("no wash CA (WASH_TLS is not auto)")
		}
		b, err := os.ReadFile(p)
		if err != nil {
			fatal("%v", err)
		}
		os.Stdout.Write(b)
	case "fingerprint":
		fp, err := tlsFingerprint(data)
		if err != nil {
			fatal("%v", err)
		}
		fmt.Println(fp)
	default:
		fatal("unknown command %q (serve, enroll, unenroll, managers, keys, fingerprint, ca, backup, health)", cmd)
	}
}

// health probes the local listener (for HealthCmd; the image has no shell or curl).
func health() int {
	addr := env("WASH_LISTEN", "0.0.0.0:8443")
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	scheme := "https"
	if env("WASH_TLS", "auto") == "off" {
		scheme = "http"
	}
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} // loopback self-probe
	resp, err := c.Get(scheme + "://127.0.0.1:" + port + "/api/config")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "wash-web: "+f+"\n", a...)
	os.Exit(1)
}

func tlsFiles(data string) (cert, key string, err error) {
	mode := env("WASH_TLS", "auto")
	switch {
	case mode == "off":
		return "", "", nil
	case mode == "auto":
		return web.SelfSigned(filepath.Join(data, "tls"), strings.Split(os.Getenv("WASH_TLS_HOSTS"), ","))
	default:
		cert, key, ok := strings.Cut(mode, ",")
		if !ok {
			return "", "", errors.New("WASH_TLS must be auto, off or CERT,KEY")
		}
		return cert, key, nil
	}
}

func tlsFingerprint(data string) (string, error) {
	cert, key, err := tlsFiles(data)
	if err != nil {
		return "", err
	}
	if cert == "" {
		return "", errors.New("TLS is off")
	}
	return web.Fingerprint(cert, key)
}

func serve(data string) {
	if err := os.MkdirAll(data, 0o700); err != nil {
		log.Fatal(err)
	}
	db, err := web.OpenDB(filepath.Join(data, "wash.db"))
	if err != nil {
		log.Fatal(err)
	}
	var origins []string
	for _, o := range strings.Split(os.Getenv("WASH_ORIGIN"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			origins = append(origins, o)
		}
	}
	cert, key, err := tlsFiles(data)
	if err != nil {
		log.Fatal(err)
	}
	trust, proxies, err := trustedProxies(os.Getenv("WASH_TRUST_PROXY"))
	if err != nil {
		log.Fatal(err)
	}
	caFile := ""
	if env("WASH_TLS", "auto") == "auto" {
		caFile = web.CAFile(filepath.Join(data, "tls"))
	}
	srv := web.New(web.Config{
		Listen:       env("WASH_LISTEN", "0.0.0.0:8443"),
		Origins:      origins,
		Registration: registrationMode(),
		Static:       webui.Static(),
		Version:      version,
		TrustProxy:   trust,
		Proxies:      proxies,
		DenyUsers:    denyUsers(),
		CAFile:       caFile,
		PlaybackDir:  filepath.Join(data, "playback"),
		PlaybackMax:  playbackMax(),
		PublicURL:    strings.TrimRight(os.Getenv("WASH_PUBLIC_URL"), "/"),
	}, db)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Janitor(ctx)

	hs := &http.Server{
		Addr:              env("WASH_LISTEN", "0.0.0.0:8443"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	if len(origins) == 0 {
		log.Printf("WASH_ORIGIN not set: accepting the origin of each request's Host header")
	}
	if cert == "" {
		log.Printf("wash-web %s listening on http://%s (TLS off: put a TLS proxy in front; passkeys need https)", version, hs.Addr)
		err = hs.ListenAndServe()
	} else {
		fp, _ := web.Fingerprint(cert, key)
		log.Printf("wash-web %s listening on https://%s", version, hs.Addr)
		log.Printf("certificate SHA-256: %s", fp)
		err = hs.ListenAndServeTLS(cert, key)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func registrationMode() bool {
	switch v := env("WASH_REGISTRATION", "closed"); v {
	case "open":
		return true
	case "closed":
		return false
	default:
		log.Fatalf("WASH_REGISTRATION=%q: want open or closed", v)
		return false
	}
}

// trustedProxies parses WASH_TRUST_PROXY: "", "0" (off), "1" (any peer), or
// a comma-separated list of IPs and CIDRs.
func trustedProxies(v string) (bool, []netip.Prefix, error) {
	switch strings.TrimSpace(v) {
	case "", "0":
		return false, nil, nil
	case "1":
		return true, nil, nil
	}
	var out []netip.Prefix
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return false, nil, fmt.Errorf("WASH_TRUST_PROXY: %q is not an IP or CIDR", f)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return true, out, nil
}

func playbackMax() int64 {
	mb := int64(512)
	if v := os.Getenv("WASH_PLAYBACK_MAX_MB"); v != "" {
		if _, err := fmt.Sscan(v, &mb); err != nil || mb < 0 {
			log.Fatalf("WASH_PLAYBACK_MAX_MB=%q: want a number of MiB", v)
		}
	}
	return mb << 20
}

func denyUsers() map[string]bool { return userpolicy.ParseList(os.Getenv("WASH_DENY_USERS")) }
