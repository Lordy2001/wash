package manager

import (
	"slices"
	"testing"
)

func TestSessionEnv(t *testing.T) {
	got := sessionEnv([]string{"HOME=/h", "HERDR_ENV=1", "HERDR_PANE_ID=w:p1", "TMUX=/tmp/x", "TERM_PROGRAM=herdr",
		"TERM_PROGRAM_VERSION=0.9.5", "PATH=/bin", "WOSH_SESSION=abc", "WOSH_PUSH=0", "SSH_AUTH_SOCK=/a", "TMUXIFIER=keep"})
	want := []string{"HOME=/h", "PATH=/bin", "WOSH_PUSH=0", "SSH_AUTH_SOCK=/a", "TMUXIFIER=keep"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}
