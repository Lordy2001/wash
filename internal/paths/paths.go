// Package paths locates washd's files for the current user.
//
//	~/.config/wash/manager.json   link credentials (url, token, pinned cert)  0600
//	~/.config/wash/config.json    manager settings                            0600
//	~/.config/wash/keys.json      passkeys this user approved                  0600
//	~/.local/state/wash/          sessions.json, washd.log
//	$XDG_RUNTIME_DIR/wash/        washd.sock, washd.pid, s/ (wosh daemon sockets)
package paths

import (
	"fmt"
	"os"
	"path/filepath"
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

// RuntimeDir: $XDG_RUNTIME_DIR/wash (0700), or /tmp/wash-UID.
func RuntimeDir() string {
	dir := os.Getenv("WASH_RUNTIME_DIR")
	if dir == "" {
		if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
			dir = filepath.Join(x, "wash")
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
