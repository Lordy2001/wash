// Package link is the RPC between washd (one per unix user) and wash-web.
//
// washd dials wash-web (wss://host/api/link, bearer token from enrollment)
// and keeps that WebSocket open. Either side may send requests; both reuse
// Peer. For every browser terminal connection wash-web sends "attach" with a
// fresh connection id; washd validates the ticket and dials back
// /api/link/conn?sid=ID, and wash-web splices the browser's WebSocket to it.
package link

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// Msg is one link message: a request (Op set, ID>0) or a reply (Re set).
type Msg struct {
	ID   uint64          `json:"id,omitempty"`
	Re   uint64          `json:"re,omitempty"`
	Op   string          `json:"op,omitempty"`
	Err  string          `json:"err,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Ops web -> manager.
const (
	OpChallenge = "challenge" // -> Nonce
	OpVerify    = "verify"    // VerifyReq -> Ticket
	OpAttach    = "attach"    // AttachReq -> {}
)

// Ops manager -> web.
const (
	OpKeysList    = "keys.list"    // -> []KeyInfo
	OpKeysGet     = "keys.get"     // KeyRef -> KeyRecord
	OpKeysApprove = "keys.approve" // KeyRef -> {}
	OpKeysRevoke  = "keys.revoke"  // KeyRef -> {}
	OpKeysOpen    = "keys.open"    // RegWindow -> RegWindow (allow passkey creation for a while)
	OpInfo        = "info"         // -> Info
	OpPlaybackPut = "playback.put" // PlaybackChunk -> PlaybackInfo (publish a recording)
	OpPlaybackDel = "playback.del" // PlaybackRef -> {}
)

// PlaybackChunk uploads a recording (asciicast v2) for public playback at
// /playback/UUID, in order: Seq 0 starts (or replaces) it, Last publishes it.
// The UUID is chosen by washd; wash-web only accepts it from the user that
// first published it.
type PlaybackChunk struct {
	UUID  string `json:"uuid"`
	Seq   int    `json:"seq"`
	Data  []byte `json:"data"`
	Last  bool   `json:"last,omitempty"`
	Title string `json:"title,omitempty"`
}

// PlaybackChunkSize keeps a chunk (base64 in JSON) under the link's read limit.
const PlaybackChunkSize = 1 << 20

type PlaybackRef struct {
	UUID string `json:"uuid"`
}

// PlaybackInfo is the reply to the last chunk.
type PlaybackInfo struct {
	UUID string `json:"uuid"`
	URL  string `json:"url,omitempty"` // public URL (WASH_PUBLIC_URL), if wash-web knows it
	Path string `json:"path"`          // /playback/UUID
	Size int64  `json:"size"`
}

type Nonce struct {
	Nonce []byte `json:"nonce"`
}

type VerifyReq struct {
	Assertion json.RawMessage `json:"assertion"` // browser's PublicKeyCredential JSON
	Remote    string          `json:"remote,omitempty"`
}

type Ticket struct {
	Ticket string `json:"ticket"`
}

type AttachReq struct {
	SID    string `json:"sid"`
	Ticket string `json:"ticket"`
	Remote string `json:"remote,omitempty"`
}

// KeyInfo is a passkey as wash-web knows it.
type KeyInfo struct {
	ID       string    `json:"id"` // passkey.ShortID
	User     string    `json:"user"`
	Name     string    `json:"name"`
	Approved bool      `json:"approved"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitzero"` // pending keys are purged then
	LastUsed time.Time `json:"last_used,omitzero"`
	Origin   string    `json:"origin"`
	AAGUID   string    `json:"aaguid,omitempty"`
}

type KeyRef struct {
	ID string `json:"id"`
}

// KeyRecord is everything washd stores to verify a key on its own.
type KeyRecord struct {
	KeyInfo
	UserHandle []byte          `json:"user_handle"`
	RPID       string          `json:"rp_id"`
	Credential json.RawMessage `json:"credential"` // webauthn.Credential JSON
}

// RegWindow opens (For > 0) or closes (For == 0) passkey creation on the
// website for the manager's user. The reply carries the resulting window.
type RegWindow struct {
	For    time.Duration `json:"for,omitempty"`
	Until  time.Time     `json:"until,omitzero"`   // reply: when it closes (zero: closed)
	Always bool          `json:"always,omitempty"` // reply: the site runs with WASH_REGISTRATION=open
}

type Info struct {
	User    string `json:"user"`
	Version string `json:"version"`
}

// Handler serves incoming requests.
type Handler func(ctx context.Context, op string, data json.RawMessage) (any, error)

// Peer runs request/response over one WebSocket.
type Peer struct {
	c       *websocket.Conn
	handler Handler

	wmu     sync.Mutex
	mu      sync.Mutex
	next    uint64
	pending map[uint64]chan Msg
	done    chan struct{}
	err     error
}

// NewPeer wraps a connection; call Run to start reading.
func NewPeer(c *websocket.Conn, h Handler) *Peer {
	c.SetReadLimit(4 << 20)
	return &Peer{c: c, handler: h, pending: map[uint64]chan Msg{}, done: make(chan struct{})}
}

// Done is closed when the link is gone.
func (p *Peer) Done() <-chan struct{} { return p.done }

// Close closes the link.
func (p *Peer) Close(reason string) { _ = p.c.Close(websocket.StatusNormalClosure, reason) }

// Run reads until the connection fails.
func (p *Peer) Run(ctx context.Context) error {
	defer func() {
		p.mu.Lock()
		for id, ch := range p.pending {
			close(ch)
			delete(p.pending, id)
		}
		p.mu.Unlock()
		close(p.done)
	}()
	go p.keepalive(ctx)
	for {
		_, b, err := p.c.Read(ctx)
		if err != nil {
			p.err = err
			return err
		}
		var m Msg
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		if m.Re != 0 {
			p.mu.Lock()
			ch := p.pending[m.Re]
			delete(p.pending, m.Re)
			p.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.Op != "" {
			go p.serve(ctx, m)
		}
	}
}

func (p *Peer) keepalive(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.done:
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := p.c.Ping(pctx)
			cancel()
			if err != nil {
				_ = p.c.Close(websocket.StatusGoingAway, "ping timeout")
				return
			}
		}
	}
}

func (p *Peer) serve(ctx context.Context, m Msg) {
	r := Msg{Re: m.ID}
	if p.handler == nil {
		r.Err = "no handler"
	} else if v, err := p.handler(ctx, m.Op, m.Data); err != nil {
		r.Err = err.Error()
	} else if v != nil {
		r.Data, _ = json.Marshal(v)
	}
	_ = p.write(ctx, r)
}

func (p *Peer) write(ctx context.Context, m Msg) error {
	b, _ := json.Marshal(m)
	p.wmu.Lock()
	defer p.wmu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return p.c.Write(wctx, websocket.MessageText, b)
}

// ErrClosed is returned for calls on a closed link.
var ErrClosed = errors.New("link closed")

// Call sends a request and decodes the reply into out (may be nil).
func (p *Peer) Call(ctx context.Context, op string, in, out any) error {
	ch := make(chan Msg, 1)
	p.mu.Lock()
	select {
	case <-p.done:
		p.mu.Unlock()
		return ErrClosed
	default:
	}
	p.next++
	id := p.next
	p.pending[id] = ch
	p.mu.Unlock()
	m := Msg{ID: id, Op: op}
	if in != nil {
		m.Data, _ = json.Marshal(in)
	}
	if err := p.write(ctx, m); err != nil {
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return err
	}
	select {
	case r, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if r.Err != "" {
			return errors.New(r.Err)
		}
		if out != nil && len(r.Data) > 0 {
			return json.Unmarshal(r.Data, out)
		}
		return nil
	case <-ctx.Done():
		p.mu.Lock()
		delete(p.pending, id)
		p.mu.Unlock()
		return ctx.Err()
	}
}

// Splice copies messages both ways between two WebSockets until one ends.
func Splice(ctx context.Context, a, b *websocket.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a.SetReadLimit(1 << 20)
	b.SetReadLimit(1 << 20)
	cp := func(dst, src *websocket.Conn) {
		defer cancel()
		for {
			t, data, err := src.Read(ctx)
			if err != nil {
				reason := "peer closed"
				if s := websocket.CloseStatus(err); s != -1 {
					var ce websocket.CloseError
					if errors.As(err, &ce) && ce.Reason != "" {
						reason = ce.Reason
					}
				}
				_ = dst.Close(websocket.StatusNormalClosure, reason)
				return
			}
			if err := dst.Write(ctx, t, data); err != nil {
				_ = src.Close(websocket.StatusGoingAway, "write failed")
				return
			}
		}
	}
	go cp(a, b)
	cp(b, a)
}
