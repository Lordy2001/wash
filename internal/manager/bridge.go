package manager

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"

	"wash/internal/wosh"
)

func newAPI() *webrtc.API {
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetICETimeouts(3*time.Second, 8*time.Second, time.Second)
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

type signalFunc func(context.Context, wosh.Msg) (wosh.Msg, error)

// dialDaemon connects washd itself to a session daemon as a wosh peer,
// signaling with signal (local socket, or ssh route for remote sessions).
// onMsg receives frames; the returned channel is the open data channel.
func dialDaemon(ctx context.Context, signal signalFunc, offer wosh.Msg, onMsg func([]byte), onClose func()) (*webrtc.PeerConnection, *webrtc.DataChannel, error) {
	cfg := webrtc.Configuration{} // same host: no ICE servers needed
	for _, x := range offer.ICE { // another host (remote session): STUN/TURN as configured
		cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{URLs: x.URLs, Username: x.Username, Credential: x.Credential})
	}
	if offer.Relay {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, err := newAPI().NewPeerConnection(cfg)
	if err != nil {
		return nil, nil, err
	}
	dc, err := pc.CreateDataChannel("wosh", nil)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	opened := make(chan struct{})
	dc.OnOpen(func() { close(opened) })
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if onMsg != nil {
			onMsg(m.Data)
		}
	})
	dc.OnClose(func() {
		if onClose != nil {
			onClose()
		}
	})
	pc.OnConnectionStateChange(func(st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateClosed {
			if onClose != nil {
				onClose()
			}
		}
	})
	sdp, err := pc.CreateOffer(nil)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	if err := pc.SetLocalDescription(sdp); err != nil {
		pc.Close()
		return nil, nil, err
	}
	select {
	case <-webrtc.GatheringCompletePromise(pc):
	case <-ctx.Done():
		pc.Close()
		return nil, nil, ctx.Err()
	}
	offer.SDP = pc.LocalDescription().SDP
	ans, err := signal(ctx, offer)
	if err != nil {
		pc.Close()
		return nil, nil, err
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: ans.SDP}); err != nil {
		pc.Close()
		return nil, nil, err
	}
	select {
	case <-opened:
		return pc, dc, nil
	case <-ctx.Done():
		pc.Close()
		return nil, nil, errors.New("timed out connecting to the session daemon")
	}
}

// warmStart makes the daemon start its shell (it does so on the first
// offer), then disconnects; the session keeps running. Until the shell's
// startup output settles, washd stands in for the terminal and answers the
// primary device attributes query (ESC [ c): fish and other programs send
// it at startup and wait for the answer (fish warns after 2 s without one).
func warmStart(ctx context.Context, s *Session, offer wosh.Msg, signal signalFunc) error {
	if s.Remote == nil {
		offer.ICE, offer.Relay = nil, false // same host
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	frames := make(chan []byte, 64)
	done := make(chan struct{})
	defer close(done)
	pc, dc, err := dialDaemon(ctx, signal, offer, func(p []byte) {
		select {
		case frames <- append([]byte(nil), p...):
		case <-done:
		}
	}, nil)
	if err != nil {
		return err
	}
	answerStartup(dc, frames, warmFirst, warmQuiet, warmMax)
	return pc.Close()
}

const (
	warmFirst = 2 * time.Second        // wait this long for the shell's first output
	warmQuiet = 300 * time.Millisecond // then until output pauses this long
	warmMax   = 4 * time.Second        // at most
	da1Reply  = "\x1b[?62;22c"         // what the browser terminal answers (VT220, ANSI colour)
)

// answerStartup answers DA1 queries in the session output until it is quiet.
func answerStartup(dc interface{ Send([]byte) error }, frames <-chan []byte, first, quiet, maxWait time.Duration) {
	var inOff uint64
	var tail []byte
	idle := time.NewTimer(first)
	defer idle.Stop()
	deadline := time.After(maxWait)
	for {
		select {
		case <-idle.C:
			return
		case <-deadline:
			return
		case b := <-frames:
			if len(b) < 9 {
				continue
			}
			off := binary.BigEndian.Uint64(b[1:9])
			switch b[0] {
			case wosh.FAck:
				inOff = max(inOff, off)
			case wosh.FOutput:
				buf := append(tail, b[9:]...)
				for n := countDA1(buf, len(tail)); n > 0; n-- {
					if dc.Send(inputFrame(inOff, da1Reply)) == nil {
						inOff += uint64(len(da1Reply))
					}
				}
				tail = append([]byte(nil), buf[max(len(buf)-3, 0):]...)
				idle.Reset(quiet)
			}
		}
	}
}

// countDA1 counts DA1 queries (ESC [ c, ESC [ 0 c) in buf that end after
// the first skip bytes (those were already seen).
func countDA1(buf []byte, skip int) int {
	n := 0
	for i := 0; i+2 < len(buf); i++ {
		if buf[i] != 0x1b || buf[i+1] != '[' {
			continue
		}
		end := -1
		switch {
		case buf[i+2] == 'c':
			end = i + 3
		case buf[i+2] == '0' && i+3 < len(buf) && buf[i+3] == 'c':
			end = i + 4
		}
		if end > skip {
			n++
		}
	}
	return n
}

func inputFrame(off uint64, data string) []byte {
	b := make([]byte, 9+len(data))
	b[0] = wosh.FInput
	binary.BigEndian.PutUint64(b[1:], off)
	copy(b[9:], data)
	return b
}

// hangUp connects as a wosh peer and sends FKill (sessions on other hosts).
func hangUp(ctx context.Context, signal signalFunc, offer wosh.Msg) error {
	pc, dc, err := dialDaemon(ctx, signal, offer, nil, nil)
	if err != nil {
		return err
	}
	defer pc.Close()
	if err := dc.Send([]byte{wosh.FKill}); err != nil {
		return err
	}
	time.Sleep(300 * time.Millisecond)
	return nil
}
