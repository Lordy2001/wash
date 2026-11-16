package manager

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"wash/internal/link"
	"wash/internal/paths"
	"wash/internal/wosh"
)

// Creds is the link enrollment (written by `wash enroll`).
type Creds struct {
	URL         string `json:"url"`                   // https://host:8443
	User        string `json:"user"`                  // user the web side knows us as
	Token       string `json:"token"`                 // bearer token
	Fingerprint string `json:"fingerprint,omitempty"` // pinned cert SHA-256 (hex); empty = system CAs
}

// Config is the manager's settings (`wash config`).
type Config struct {
	Wosh        string           `json:"wosh,omitempty"`         // wosh binary (default: PATH, ~/.local/bin, ~/go/bin)
	Command     []string         `json:"command,omitempty"`      // run instead of the login shell
	ICE         []wosh.ICEServer `json:"ice,omitempty"`          // STUN/TURN for browser <-> session WebRTC
	Relay       bool             `json:"relay,omitempty"`        // force TURN
	Transport   string           `json:"transport,omitempty"`    // auto (default) | webrtc | bridge
	MaxSessions int              `json:"max_sessions,omitempty"` // default 16
	Term        string           `json:"term,omitempty"`         // TERM for sessions (default xterm-256color)
	// ForwardAgent: washd's route ssh forwards the user's agent through
	// intermediate hops (so a hop can use local keys for the next ssh).
	ForwardAgent bool `json:"forward_agent,omitempty"`
}

// ConfigKeys documents the keys `wash config set` accepts.
var ConfigKeys = map[string]string{
	"wosh":          "path of the wosh binary",
	"command":       "command to run instead of the login shell (space separated; empty = login shell)",
	"stun":          "STUN servers, comma separated (stun:host:port); 'none' for host candidates only",
	"turn":          "TURN servers 'turn:host:port|user|pass', ';' separated",
	"relay":         "true: force the browser to use TURN",
	"transport":     "auto | webrtc | bridge (bridge = through washd over the WebSocket)",
	"max_sessions":  "maximum concurrent sessions",
	"term":          "TERM for new sessions",
	"forward_agent": "true: washd's ssh routes forward your agent through intermediate hops (root there can use it meanwhile)",
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSON writes atomically with 0600.
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func LoadCreds() (Creds, error) {
	var c Creds
	err := readJSON(paths.ManagerFile(), &c)
	if errors.Is(err, os.ErrNotExist) {
		return c, errors.New("not enrolled: run `wash enroll` (or `wash enroll URL CODE` with a code from an admin's `wash web enroll $USER`)")
	}
	return c, err
}

func SaveCreds(c Creds) error { return writeJSON(paths.ManagerFile(), c) }

func LoadConfig() Config {
	var c Config
	_ = readJSON(paths.ConfigFile(), &c)
	return c
}

func SaveConfig(c Config) error { return writeJSON(paths.ConfigFile(), c) }

func (c Config) maxSessions() int {
	if c.MaxSessions > 0 {
		return c.MaxSessions
	}
	return 16
}

func (c Config) ice() []wosh.ICEServer {
	if c.ICE == nil {
		return []wosh.ICEServer{{URLs: []string{"stun:stun.l.google.com:19302"}}}
	}
	return c.ICE
}

func (c Config) term() string {
	if c.Term != "" {
		return c.Term
	}
	return "xterm-256color"
}

func (c Config) transport() string {
	switch c.Transport {
	case "webrtc", "bridge":
		return c.Transport
	}
	return "auto"
}

// WoshPath finds the wosh binary.
func (c Config) WoshPath() (string, error) {
	if c.Wosh != "" {
		return c.Wosh, nil
	}
	if p, err := exec.LookPath("wosh"); err == nil {
		return p, nil
	}
	home, _ := os.UserHomeDir()
	for _, d := range []string{".local/bin", "bin", "go/bin"} {
		p := filepath.Join(home, d, "wosh")
		if st, err := os.Stat(p); err == nil && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "wosh")
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("wosh binary not found (install it in PATH or run `wash config set wosh /path/to/wosh`)")
}

// Get renders one config value as text.
func (c Config) Get(key string) (string, error) {
	switch key {
	case "wosh":
		p, err := c.WoshPath()
		if err != nil {
			return "", nil
		}
		return p, nil
	case "command":
		return strings.Join(c.Command, " "), nil
	case "stun", "turn":
		var parts []string
		for _, s := range c.ice() {
			for _, u := range s.URLs {
				isTurn := strings.HasPrefix(u, "turn")
				if key == "stun" && !isTurn {
					parts = append(parts, u)
				} else if key == "turn" && isTurn {
					parts = append(parts, u+"|"+s.Username+"|***")
				}
			}
		}
		sep := ","
		if key == "turn" {
			sep = ";"
		}
		return strings.Join(parts, sep), nil
	case "relay":
		return strconv.FormatBool(c.Relay), nil
	case "transport":
		return c.transport(), nil
	case "max_sessions":
		return strconv.Itoa(c.maxSessions()), nil
	case "term":
		return c.term(), nil
	case "forward_agent":
		return strconv.FormatBool(c.ForwardAgent), nil
	}
	return "", fmt.Errorf("unknown key %q", key)
}

// Set changes one config value from text.
func (c *Config) Set(key, val string) error {
	val = strings.TrimSpace(val)
	switch key {
	case "wosh":
		if val != "" {
			if _, err := os.Stat(val); err != nil {
				return err
			}
		}
		c.Wosh = val
	case "command":
		c.Command = strings.Fields(val)
	case "stun":
		var keep []wosh.ICEServer
		for _, s := range c.ice() {
			if len(s.URLs) > 0 && strings.HasPrefix(s.URLs[0], "turn") {
				keep = append(keep, s)
			}
		}
		if val != "none" {
			for _, u := range strings.Split(val, ",") {
				if u = strings.TrimSpace(u); u != "" {
					if !strings.HasPrefix(u, "stun") {
						u = "stun:" + u
					}
					keep = append(keep, wosh.ICEServer{URLs: []string{u}})
				}
			}
		}
		if keep == nil {
			keep = []wosh.ICEServer{}
		}
		c.ICE = keep
	case "turn":
		var keep []wosh.ICEServer
		for _, s := range c.ice() {
			if len(s.URLs) > 0 && !strings.HasPrefix(s.URLs[0], "turn") {
				keep = append(keep, s)
			}
		}
		for _, t := range strings.Split(val, ";") {
			if t = strings.TrimSpace(t); t == "" {
				continue
			}
			p := strings.SplitN(t, "|", 3)
			u := p[0]
			if !strings.HasPrefix(u, "turn") {
				u = "turn:" + u
			}
			s := wosh.ICEServer{URLs: []string{u}}
			if len(p) > 1 {
				s.Username = p[1]
			}
			if len(p) > 2 {
				s.Credential = p[2]
			}
			keep = append(keep, s)
		}
		if keep == nil {
			keep = []wosh.ICEServer{}
		}
		c.ICE = keep
	case "relay":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		c.Relay = b
	case "transport":
		if val != "auto" && val != "webrtc" && val != "bridge" {
			return errors.New("transport must be auto, webrtc or bridge")
		}
		c.Transport = val
	case "max_sessions":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 1000 {
			return errors.New("max_sessions must be 1..1000")
		}
		c.MaxSessions = n
	case "term":
		c.Term = val
	case "forward_agent":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return err
		}
		c.ForwardAgent = b
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

// --- local key store ---------------------------------------------------------

// LocalKey is a passkey this user approved; washd verifies logins against
// these, independently of the web side's database.
type LocalKey struct {
	link.KeyRecord
	ApprovedAt time.Time `json:"approved_at"`
}

func loadKeys() ([]LocalKey, error) {
	var ks []LocalKey
	err := readJSON(paths.KeysFile(), &ks)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return ks, err
}

func saveKeys(ks []LocalKey) error {
	sort.Slice(ks, func(i, j int) bool { return ks[i].ApprovedAt.Before(ks[j].ApprovedAt) })
	if ks == nil {
		ks = []LocalKey{}
	}
	return writeJSON(paths.KeysFile(), ks)
}
