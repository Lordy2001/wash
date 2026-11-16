package manager

import (
	"context"
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
// offer), then disconnects; the session keeps running.
func warmStart(ctx context.Context, s *Session, offer wosh.Msg, signal signalFunc) error {
	offer.ICE, offer.Relay = nil, false // same host
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	pc, _, err := dialDaemon(ctx, signal, offer, nil, nil)
	if err != nil {
		return err
	}
	time.Sleep(100 * time.Millisecond)
	return pc.Close()
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
