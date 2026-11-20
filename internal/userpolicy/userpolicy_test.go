package userpolicy

import "testing"

func TestCheck(t *testing.T) {
	lo, _ := uidRange()
	cases := []struct {
		a  Account
		ok bool
	}{
		{Account{"alice", lo, "/bin/bash"}, true},
		{Account{"alice", lo, ""}, true}, // empty shell means /bin/sh
		{Account{"root", 0, "/bin/bash"}, false},
		{Account{"toor", 0, "/bin/bash"}, false},
		{Account{"ubuntu", lo, "/bin/bash"}, false},
		{Account{"ec2-user", lo, "/bin/bash"}, false},
		{Account{"systemd-network", lo, "/bin/bash"}, false},
		{Account{"alice", 0, "/bin/bash"}, false},
		{Account{"daemonish", lo - 1, "/bin/bash"}, false},
		{Account{"mealie", 5001, "/usr/sbin/nologin"}, false}, // rootless podman service user
		{Account{"svc", 5002, "/bin/false"}, false},
		{Account{"nobodyish", 65534, "/bin/bash"}, false},
	}
	for _, c := range cases {
		if err := Check(c.a); (err == nil) != c.ok {
			t.Errorf("%+v: err=%v, want ok=%v", c.a, err, c.ok)
		}
	}
}

func TestDenied(t *testing.T) {
	extra := ParseList("media, mealie wash")
	for _, n := range []string{"root", "pi", "_apt", "media", "mealie", "wash"} {
		if !Denied(n, extra) {
			t.Errorf("%s allowed", n)
		}
	}
	if Denied("alice", extra) {
		t.Error("alice denied")
	}
}

func TestFindPasswd(t *testing.T) {
	pw := []byte("root:x:0:0:root:/root:/bin/bash\nmealie:x:5001:5001::/home/mealie:/usr/sbin/nologin\n")
	a, ok := findPasswd(pw, "mealie")
	if !ok || a.UID != 5001 || a.Shell != "/usr/sbin/nologin" {
		t.Fatalf("%+v %v", a, ok)
	}
	if _, ok := findPasswd(pw, "nope"); ok {
		t.Fatal("found missing user")
	}
}

func TestParseDscl(t *testing.T) {
	a, ok := parseDscl([]byte("UniqueID: 501\nUserShell: /opt/homebrew/bin/fish\n"), "ca")
	if !ok || a.UID != 501 || a.Shell != "/opt/homebrew/bin/fish" || a.Name != "ca" {
		t.Fatalf("%+v %v", a, ok)
	}
	a, ok = parseDscl([]byte("UniqueID: 502\nUserShell:\n /bin/zsh\n"), "x")
	if !ok || a.UID != 502 || a.Shell != "/bin/zsh" {
		t.Fatalf("wrapped: %+v %v", a, ok)
	}
	if _, ok := parseDscl([]byte("No such key: UniqueID\n"), "x"); ok {
		t.Fatal("parsed garbage")
	}
}
