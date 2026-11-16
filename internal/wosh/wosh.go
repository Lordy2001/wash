// Package wosh holds the subset of the wosh protocol (repos/wosh,
// internal/wire, protocol version 2) that wash needs to drive wosh session
// daemons. wosh keeps its packages internal, so the few types are mirrored
// here; keep them in sync with wosh's wire.Msg / wire.ICEServer.
//
// A wosh daemon (`wosh _daemon --id ID`) owns one PTY and listens on a unix
// control socket. A client sends one JSON line {"t":"offer",...} carrying a
// WebRTC SDP offer and gets {"t":"answer","sdp":...} back; the session then
// runs over a data channel labelled "wosh" whose binary messages are frames
// (first byte = type, see the F* constants). wash's browser client speaks
// these frames directly over WebRTC, or through washd's WebSocket bridge.
package wosh

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"
)

// Version is the wosh signaling protocol version wash was written against.
const Version = 2

// Message types used on a daemon control socket.
const (
	TOffer  = "offer"
	TAnswer = "answer"
	TError  = "err"
	TType   = "type"
	TOK     = "ok"
)

// Frame types on the "wosh" data channel (mirrors wosh/internal/wire/frame.go).
const (
	FOutput  = 'o' // S->C  u64 offset + bytes
	FInput   = 'i' // C->S  u64 offset + bytes
	FAck     = 'a' // S->C  u64 input offset received
	FResize  = 'r' // C->S  u16 cols + u16 rows
	FRedraw  = 'R' // C->S
	FPing    = 'p' // C->S  u64 nonce
	FPong    = 'P' // S->C  u64 nonce
	FExit    = 'x' // S->C  i32 exit status
	FExitAck = 'X' // C->S
	FKill    = 'k' // C->S
	FControl = 'c' // both JSON
	FEchoAck = 'e' // S->C  u64
)

// ICEServer mirrors webrtc.ICEServer (and wosh's wire.ICEServer).
type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// Msg is a wosh signaling message (fields wash uses).
type Msg struct {
	T     string            `json:"t"`
	V     int               `json:"v,omitempty"`
	ID    string            `json:"id,omitempty"`
	User  string            `json:"user,omitempty"`
	Key   string            `json:"key,omitempty"`
	SDP   string            `json:"sdp,omitempty"`
	ICE   []ICEServer       `json:"ice,omitempty"`
	Relay bool              `json:"relay,omitempty"`
	Term  string            `json:"term,omitempty"`
	Cols  uint16            `json:"cols,omitempty"`
	Rows  uint16            `json:"rows,omitempty"`
	RxOut uint64            `json:"rx_out,omitempty"`
	Err   string            `json:"err,omitempty"`
	Env   map[string]string `json:"env,omitempty"`
	Text  string            `json:"text,omitempty"`
	CID   string            `json:"cid,omitempty"`  // offer: client instance (shared sessions)
	Join  bool              `json:"join,omitempty"` // offer: watch if another client has control
}

// Request sends one message to a daemon control socket and returns its reply.
func Request(ctx context.Context, sock string, m Msg) (Msg, error) {
	if m.V == 0 {
		m.V = Version
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return Msg{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	}
	b, _ := json.Marshal(m)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return Msg{}, err
	}
	line, err := bufio.NewReaderSize(c, 64*1024).ReadBytes('\n')
	if err != nil {
		return Msg{}, err
	}
	var r Msg
	if err := json.Unmarshal(line, &r); err != nil {
		return Msg{}, err
	}
	if r.T == TError {
		return r, errors.New(r.Err)
	}
	return r, nil
}

// Alive reports whether a daemon is listening on sock.
func Alive(sock string) bool {
	c, err := net.DialTimeout("unix", sock, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}
