// Package paths locates washd's files for the current user.
//
//	~/.config/wash/manager.json   link credentials (url, token, pinned cert)  0600
//	~/.config/wash/config.json    manager settings                            0600
//	~/.config/wash/keys.json      passkeys this user approved                  0600
//	~/.local/state/wash/          sessions.json, recordings.json, washd.log
//	~/.local/share/wash/recordings/  session recordings (asciicast v2, gzip: ID.cast.gz)
//	$XDG_RUNTIME_DIR/wash/        washd.sock, washd.pid, s/ (wosh daemon sockets)
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func home() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return "/"
	}
	return h
}

func mk(dir string) string {
	_ = os.MkdirAll(dir, 0o700)
	return dir
}

// ConfigDir: ~/.config/wash
func ConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return mk(filepath.Join(x, "wash"))
	}
	return mk(filepath.Join(home(), ".config", "wash"))
}

// StateDir: ~/.local/state/wash
func StateDir() string {
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return mk(filepath.Join(x, "wash"))
	}
	return mk(filepath.Join(home(), ".local", "state", "wash"))
}

// DataDir: ~/.local/share/wash
func DataDir() string {
	if x := os.Getenv("XDG_DATA_HOME"); x != "" {
		return mk(filepath.Join(x, "wash"))
	}
	return mk(filepath.Join(home(), ".local", "share", "wash"))
}

// RecordingsDir holds `wash watch` recordings.
func RecordingsDir() string { return mk(filepath.Join(DataDir(), "recordings")) }

// RecordingFile is a recording's cast (gzip). An uncompressed ID.cast from
// before compression is used as long as it exists.
func RecordingFile(id string) string {
	plain := filepath.Join(RecordingsDir(), id+".cast")
	if _, err := os.Stat(plain); err == nil {
		return plain
	}
	return plain + ".gz"
}

// RecordingsFile lists the recordings and their state.
func RecordingsFile() string { return filepath.Join(StateDir(), "recordings.json") }

// RuntimeDir: $XDG_RUNTIME_DIR/wash (0700), or /tmp/wash-UID. On macOS
// (no XDG_RUNTIME_DIR, and a $TMPDIR that launchd jobs may not share with
// login shells) it is ~/.local/state/wash/run, so washd as a LaunchAgent and
// the CLI in a terminal find the same socket.
func RuntimeDir() string {
	dir := os.Getenv("WASH_RUNTIME_DIR")
	if dir == "" {
		if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
			dir = filepath.Join(x, "wash")
		} else if runtime.GOOS == "darwin" {
			dir = filepath.Join(StateDir(), "run")
		} else {
			dir = filepath.Join(os.TempDir(), fmt.Sprintf("wash-%d", os.Getuid()))
		}
	}
	mk(dir)
	_ = os.Chmod(dir, 0o700)
	return dir
}

// SessionDir is WOSH_RUNTIME_DIR for the wosh daemons washd starts (kept
// apart from the user's own wosh sessions).
func SessionDir() string { return mk(filepath.Join(RuntimeDir(), "s")) }

func Socket() string  { return filepath.Join(RuntimeDir(), "washd.sock") }
func PIDFile() string { return filepath.Join(RuntimeDir(), "washd.pid") }
func LogFile() string { return filepath.Join(StateDir(), "washd.log") }

func ManagerFile() string  { return filepath.Join(ConfigDir(), "manager.json") }
func ConfigFile() string   { return filepath.Join(ConfigDir(), "config.json") }
func KeysFile() string     { return filepath.Join(ConfigDir(), "keys.json") }
func SessionsFile() string { return filepath.Join(StateDir(), "sessions.json") }
