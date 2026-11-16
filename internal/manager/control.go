package manager

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"wash/internal/paths"
)

// Control protocol between `wash` and washd: one JSON Request per line on
// $XDG_RUNTIME_DIR/wash/washd.sock (0600, same uid only), one Response back.
type Request struct {
	Op   string `json:"op"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Key  string `json:"key,omitempty"`
	Val  string `json:"val,omitempty"`
	All  bool   `json:"all,omitempty"`
}

type Response struct {
	OK   bool            `json:"ok"`
	Err  string          `json:"err,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

func (m *Manager) listenControl() (net.Listener, error) {
	sock := paths.Socket()
	if c, err := net.DialTimeout("unix", sock, 300*time.Millisecond); err == nil {
		c.Close()
		return nil, errors.New("washd is already running")
	}
	_ = os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sock, 0o600)
	_ = os.WriteFile(paths.PIDFile(), []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go m.serveControl(c)
		}
	}()
	go func() {
		<-m.quit
		ln.Close()
		_ = os.Remove(sock)
		_ = os.Remove(paths.PIDFile())
	}()
	return ln, nil
}

// sameUser checks the peer's uid (Linux SO_PEERCRED; elsewhere the 0700
// runtime dir and 0600 socket are the guard).
func sameUser(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	okUID := true
	_ = raw.Control(func(fd uintptr) {
		cred, err := peerUID(int(fd))
		if err == nil && cred != os.Getuid() {
			okUID = false
		}
	})
	return okUID
}

func (m *Manager) serveControl(c net.Conn) {
	defer c.Close()
	if !sameUser(c) {
		return
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	line, err := bufio.NewReaderSize(c, 64*1024).ReadBytes('\n')
	if err != nil {
		return
	}
	var req Request
	resp := Response{}
	if err := json.Unmarshal(line, &req); err != nil {
		resp.Err = "bad request"
	} else {
		v, err := m.control(req)
		if err != nil {
			resp.Err = err.Error()
		} else {
			resp.OK = true
			if v != nil {
				resp.Data, _ = json.Marshal(v)
			}
		}
	}
	b, _ := json.Marshal(resp)
	_, _ = c.Write(append(b, '\n'))
}

func (m *Manager) control(req Request) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	switch req.Op {
	case "status":
		return m.Status(), nil
	case "stop":
		if req.All {
			for _, s := range m.List() {
				if err := m.Kill(s.ID); err != nil {
					log.Printf("stop: kill %s: %v", s.ID, err)
				}
			}
		}
		go func() {
			time.Sleep(100 * time.Millisecond)
			m.Stop()
		}()
		return nil, nil
	case "sessions.list":
		return m.List(), nil
	case "sessions.new":
		return m.New(ctx, req.Name, 0, 0)
	case "sessions.kill":
		if req.All {
			n := 0
			for _, s := range m.List() {
				if m.Kill(s.ID) == nil {
					n++
				}
			}
			return n, nil
		}
		return nil, m.Kill(req.ID)
	case "sessions.rename":
		return nil, m.Rename(req.ID, req.Name)
	case "keys.list":
		return m.Keys(ctx)
	case "keys.approve":
		return m.Approve(ctx, req.ID)
	case "keys.revoke":
		return nil, m.Revoke(ctx, req.ID)
	case "keys.open":
		d := time.Duration(0)
		if req.Val != "" {
			var err error
			if d, err = time.ParseDuration(req.Val); err != nil || d <= 0 {
				return nil, fmt.Errorf("bad duration %q (e.g. 30m, 1h)", req.Val)
			}
		}
		return m.OpenRegistration(ctx, d)
	case "agent":
		return nil, m.SetAgent(req.Val)
	case "config.reload":
		m.mu.Lock()
		m.cfg = LoadConfig()
		m.mu.Unlock()
		return nil, nil
	}
	return nil, fmt.Errorf("unknown op %q", req.Op)
}

// Call sends one request to a running washd (used by `wash`).
func Call(req Request, out any) error {
	c, err := net.DialTimeout("unix", paths.Socket(), time.Second)
	if err != nil {
		return ErrNotRunning
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReaderSize(c, 1<<20).ReadBytes('\n')
	if err != nil {
		return err
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return err
	}
	if !resp.OK {
		return errors.New(resp.Err)
	}
	if out != nil && len(resp.Data) > 0 {
		return json.Unmarshal(resp.Data, out)
	}
	return nil
}

// ErrNotRunning: no washd for this user.
var ErrNotRunning = errors.New("washd is not running (start it with `wash up`)")
