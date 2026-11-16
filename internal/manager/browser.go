package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"

	"wash/internal/wosh"
)

// Browser protocol (after wash-web hands the WebSocket over).
//
// washd -> browser (text JSON):
//
//	{"t":"hello","user","host","version","ice":[...],"relay","transport","resume","sessions":[...]}
//	{"t":"sessions","sessions":[...]}                 pushed on every change
//	{"t":"answer","rid","sdp"}  {"t":"created","rid","session"}  {"t":"ticket","rid","ticket"}
//	{"t":"ok","rid"}  {"t":"err","rid","err"}  {"t":"bridged","rid"}
//	{"t":"taken","id","cid","from"}   another browser (page cid, address from) now
//	                                  holds session id: a wosh session has one peer,
//	                                  so the others stop reconnecting to it
//
// browser -> washd:
//
//	{"t":"list"} {"t":"new","name","cols","rows"} {"t":"kill","id"} {"t":"rename","id","name"}
//	{"t":"offer","id","sdp","cols","rows","rx_out","cid","take"}   WebRTC straight to the wosh daemon
//	   take: the user opened the session (tab, reload, "take it back"). Without it
//	   (an automatic reconnect) the offer is refused while another page holds the
//	   session: "taken: ...".
//	{"t":"ticket"}                                     ticket for another socket (bridge)
//	{"t":"hop.add","id","hop":{id,parent,host,user,key}}  remember a chained hop
//	{"t":"hop.del","id","name":HOPID}                 forget it (and hops below it)
//	{"t":"adopt","id":PARENT,"hop":{...},"sock","route":[ssh args]}  chained hop is up:
//	                                                   make it a remote session, end PARENT
//	{"t":"build","name":"linux-amd64"}                 wosh build for a hop's middle host:
//	                                                   {"t":"chunk","data"}..., then {"t":"build","stamp","n"}
//	{"t":"bridge","id","cols","rows","rx_out","cid","take"}   this socket becomes the session:
//	                                                   binary messages are wosh frames
type bmsg struct {
	T        string           `json:"t"`
	RID      int              `json:"rid,omitempty"`
	ID       string           `json:"id,omitempty"`
	Name     string           `json:"name,omitempty"`
	SDP      string           `json:"sdp,omitempty"`
	Cols     uint16           `json:"cols,omitempty"`
	Rows     uint16           `json:"rows,omitempty"`
	RxOut    uint64           `json:"rx_out,omitempty"`
	Err      string           `json:"err,omitempty"`
	Ticket   string           `json:"ticket,omitempty"`
	Session  *SessionInfo     `json:"session,omitempty"`
	Sessions []SessionInfo    `json:"sessions,omitempty"`
	User     string           `json:"user,omitempty"`
	Host     string           `json:"host,omitempty"`
	Version  string           `json:"version,omitempty"`
	ICE      []wosh.ICEServer `json:"ice,omitempty"`
	Relay    bool             `json:"relay,omitempty"`
	Trans    string           `json:"transport,omitempty"`
	Resume   string           `json:"resume,omitempty"`
	Hop      *Hop             `json:"hop,omitempty"`
	Data     string           `json:"data,omitempty"`  // build chunk (base64)
	Stamp    string           `json:"stamp,omitempty"` // build stamp
	N        int              `json:"n,omitempty"`     // build: number of chunks sent
	Sock     string           `json:"sock,omitempty"`  // adopt: hop daemon socket (from its hello)
	Route    []string         `json:"route,omitempty"` // adopt: ssh args the parent used (hello.hop)
	CID      string           `json:"cid,omitempty"`   // offer/bridge/taken: the page that connects
	From     string           `json:"from,omitempty"`  // taken: that browser's address
	Take     bool             `json:"take,omitempty"`  // offer/bridge: a deliberate takeover
}

// holder is the browser page that last connected to a session.
type holder struct {
	cid, from string
	conn      *browserConn
}

// claim checks that page cid may connect to session sid: always when the user
// asked (take), else only if no other page holds it. A device that slept
// through a takeover therefore does not grab the session back on waking.
func (m *Manager) claim(sid, cid string, take bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.holders[sid]; ok && !take && cid != "" && h.cid != cid {
		return fmt.Errorf("taken: this session is open on another device (%s)", h.from)
	}
	return nil
}

func (m *Manager) hold(b *browserConn, sid, cid string) {
	if cid == "" {
		return
	}
	m.mu.Lock()
	m.holders[sid] = holder{cid: cid, from: b.remote, conn: b}
	m.mu.Unlock()
}

type browserConn struct {
	m      *Manager
	c      *websocket.Conn
	remote string
	key    string // passkey that authenticated this browser
	wmu    sync.Mutex
	sid    string // session this connection is showing
	bridge bool
	ctx    context.Context
	cancel context.CancelFunc
}

func (b *browserConn) close(reason string) {
	_ = b.c.Close(4000, reason)
	b.cancel()
}

func (b *browserConn) send(m bmsg) {
	data, _ := json.Marshal(m)
	b.wmu.Lock()
	defer b.wmu.Unlock()
	ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
	defer cancel()
	_ = b.c.Write(ctx, websocket.MessageText, data)
}

func (b *browserConn) sendBinary(p []byte) error {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	return b.c.Write(ctx, websocket.MessageBinary, p)
}

// taken tells every other browser page that the page cid (on connection by)
// now holds session sid. The wosh daemon keeps one peer per session and drops
// the previous one; without this, that page would reconnect and take the
// session back, and two devices would trade it forever.
func (m *Manager) taken(by *browserConn, sid, cid string) {
	m.mu.Lock()
	var cs []*browserConn
	for c := range m.conns {
		if !c.bridge && c != by {
			cs = append(cs, c)
		}
	}
	m.mu.Unlock()
	for _, c := range cs {
		go c.send(bmsg{T: "taken", ID: sid, CID: cid, From: by.remote})
	}
}

// changed pushes the session list to every browser.
func (m *Manager) changed() {
	list := m.List()
	m.mu.Lock()
	var cs []*browserConn
	for c := range m.conns {
		if !c.bridge {
			cs = append(cs, c)
		}
	}
	m.mu.Unlock()
	for _, c := range cs {
		go c.send(bmsg{T: "sessions", Sessions: list})
	}
}

func (m *Manager) setAttached(b *browserConn, sid string) {
	m.mu.Lock()
	if b.sid != "" {
		m.attached[b.sid]--
		if m.attached[b.sid] <= 0 {
			delete(m.attached, b.sid)
		}
	}
	b.sid = sid
	if sid != "" {
		m.attached[sid]++
	}
	m.mu.Unlock()
}

// serveBrowser dials wash-web back for connection sid and runs the
// browser protocol on it.
func (m *Manager) serveBrowser(sid, remote string, t *ticket) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	c, err := m.dial(ctx, "/api/link/conn?sid="+sid)
	cancel()
	if err != nil {
		log.Printf("dial back for %s: %v", remote, err)
		return
	}
	c.SetReadLimit(1 << 20)
	bctx, bcancel := context.WithCancel(context.Background())
	b := &browserConn{m: m, c: c, remote: remote, key: t.key, ctx: bctx, cancel: bcancel}
	m.mu.Lock()
	m.conns[b] = true
	m.mu.Unlock()
	defer func() {
		m.setAttached(b, "")
		m.mu.Lock()
		delete(m.conns, b)
		for sid, h := range m.holders {
			if h.conn == b { // that page went away: nobody holds the session
				delete(m.holders, sid)
			}
		}
		m.mu.Unlock()
		bcancel()
		_ = c.CloseNow()
		m.changed()
	}()
	cfg := m.config()
	host, _ := os.Hostname()
	b.send(bmsg{T: "hello", User: m.user, Host: host, Version: Version, ICE: cfg.ice(), Relay: cfg.Relay,
		Trans: cfg.transport(), Resume: m.issue("resume", t.key, resumeTTL), Sessions: m.List()})
	for {
		typ, data, err := c.Read(bctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		var req bmsg
		if json.Unmarshal(data, &req) != nil {
			continue
		}
		if req.T == "bridge" {
			m.bridge(b, req)
			return
		}
		go m.handleBrowser(b, req)
	}
}

func (m *Manager) handleBrowser(b *browserConn, req bmsg) {
	fail := func(err error) { b.send(bmsg{T: "err", RID: req.RID, Err: err.Error()}) }
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	switch req.T {
	case "list":
		b.send(bmsg{T: "sessions", RID: req.RID, Sessions: m.List()})
	case "new":
		s, err := m.New(ctx, req.Name, req.Cols, req.Rows)
		if err != nil {
			fail(err)
			return
		}
		b.send(bmsg{T: "created", RID: req.RID, Session: &s})
	case "kill":
		if err := m.Kill(req.ID); err != nil {
			fail(err)
			return
		}
		b.send(bmsg{T: "ok", RID: req.RID})
	case "rename":
		if err := m.Rename(req.ID, req.Name); err != nil {
			fail(err)
			return
		}
		b.send(bmsg{T: "ok", RID: req.RID})
	case "hop.add":
		if req.Hop == nil {
			fail(errUnknown("hop.add without hop"))
			return
		}
		if err := m.AddHop(req.ID, *req.Hop); err != nil {
			fail(err)
			return
		}
		b.send(bmsg{T: "ok", RID: req.RID})
	case "hop.del":
		if err := m.DelHop(req.ID, req.Name); err != nil {
			fail(err)
			return
		}
		b.send(bmsg{T: "ok", RID: req.RID})
	case "adopt":
		// a chained hop is up: make it a remote session, end the parent
		if req.Hop == nil {
			fail(errUnknown("adopt without hop"))
			return
		}
		si, err := m.Adopt(req.ID, *req.Hop, req.Sock, req.Route)
		if err != nil {
			fail(err)
			return
		}
		b.send(bmsg{T: "adopted", RID: req.RID, Session: &si})
	case "build":
		// a chained hop's middle host needs a wosh build for another platform
		bd, err := m.woshBuild(req.Name)
		if err != nil {
			fail(err)
			return
		}
		const part = 256 << 10 // stays under the WebSocket read limits once base64'd
		n := 0
		for off := 0; off < len(bd.gz); off += part {
			end := min(off+part, len(bd.gz))
			b.send(bmsg{T: "chunk", RID: req.RID, Data: base64.StdEncoding.EncodeToString(bd.gz[off:end])})
			n++
		}
		b.send(bmsg{T: "build", RID: req.RID, Stamp: bd.stamp, N: n})
	case "ticket":
		b.send(bmsg{T: "ticket", RID: req.RID, Ticket: m.issue("sub", b.key, subTTL)})
	case "offer":
		s, err := m.get(req.ID)
		if err != nil {
			fail(err)
			return
		}
		if err := m.claim(s.ID, req.CID, req.Take); err != nil {
			fail(err)
			return
		}
		o := m.offerFor(s, req.Cols, req.Rows, req.RxOut, m.config())
		o.SDP = req.SDP
		ans, err := m.signal(s)(ctx, o)
		if err != nil {
			if s.Remote != nil && strings.Contains(err.Error(), wosh.ErrNoSession) {
				m.Forget(s.ID) // the remote session ended while nobody watched
			}
			fail(err)
			return
		}
		m.setAttached(b, s.ID)
		m.hold(b, s.ID, req.CID)
		m.taken(b, s.ID, req.CID)
		m.changed()
		b.send(bmsg{T: "answer", RID: req.RID, SDP: ans.SDP})
	default:
		fail(errUnknown(req.T))
	}
}

type errUnknown string

func (e errUnknown) Error() string { return "unknown request " + string(e) }

// bridge turns this WebSocket into the session: washd is the wosh peer and
// forwards frames between the data channel and the socket.
func (m *Manager) bridge(b *browserConn, req bmsg) {
	s, err := m.get(req.ID)
	if err == nil {
		err = m.claim(s.ID, req.CID, req.Take)
	}
	if err != nil {
		b.send(bmsg{T: "err", RID: req.RID, Err: err.Error()})
		return
	}
	m.mu.Lock()
	b.bridge = true
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(b.ctx, 20*time.Second)
	// frames may arrive before "bridged" is sent; hold them until it is
	ready := make(chan struct{})
	defer func() {
		select {
		case <-ready:
		default:
			close(ready)
		}
	}()
	offer := m.offerFor(s, req.Cols, req.Rows, req.RxOut, m.config())
	if s.Remote == nil {
		offer.ICE, offer.Relay = nil, false // same host
	}
	pc, dc, err := dialDaemon(ctx, m.signal(s), offer,
		func(p []byte) {
			<-ready
			if b.sendBinary(p) != nil {
				b.cancel()
			}
		},
		func() { b.close("session connection closed") })
	cancel()
	if err != nil {
		b.send(bmsg{T: "err", RID: req.RID, Err: err.Error()})
		return
	}
	defer pc.Close()
	m.setAttached(b, s.ID)
	m.hold(b, s.ID, req.CID)
	m.taken(b, s.ID, req.CID)
	m.changed()
	b.send(bmsg{T: "bridged", RID: req.RID})
	close(ready)
	for {
		typ, data, err := b.c.Read(b.ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary || len(data) == 0 {
			continue
		}
		if err := sendDC(dc, data); err != nil {
			return
		}
	}
}

func sendDC(dc *webrtc.DataChannel, p []byte) error {
	for dc.BufferedAmount() > 4<<20 {
		time.Sleep(10 * time.Millisecond)
	}
	return dc.Send(p)
}
