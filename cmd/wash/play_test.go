package main

import "testing"

func TestOSC52Filter(t *testing.T) {
	var f osc52Filter
	in := []string{"a\x1b]52;c;aGk=\x07b", "c\x1b]5", "2;c;", "aGk=\x1b", "\\d", "\x1b]0;title\x07e"}
	got := ""
	for _, s := range in {
		got += f.filter(s)
	}
	got += f.hold
	if want := "abcd\x1b]0;title\x07e"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}
