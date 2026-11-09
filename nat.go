package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ICE discovers and checks transport candidates. Only the mesh event loop can
// authorize a WireGuard trial or change a route. LAN discovery is independent.
type natState struct {
	transport wireGuardUDP
	engine    *iceTraversal
	links     []linkAddr
	starts    map[[16]byte]natStart
	selected  map[wgtypes.Key]netip.AddrPort
	remote    map[wgtypes.Key]string
	restartAt map[wgtypes.Key]time.Time
	retryAt   time.Time
}

type natStart struct {
	peer     wgtypes.Key
	endpoint netip.AddrPort // Invalid for signaling through the stable tunnel.
	at       time.Time
}

func (m *mesh) enableNAT(t wireGuardUDP) {
	m.nat = &natState{transport: t, starts: make(map[[16]byte]natStart), selected: make(map[wgtypes.Key]netip.AddrPort), remote: make(map[wgtypes.Key]string), restartAt: make(map[wgtypes.Key]time.Time)}
}

func (m *mesh) closeNAT() error {
	if m.nat == nil || m.nat.engine == nil {
		return nil
	}
	err := m.nat.engine.Close()
	m.nat.engine = nil
	return err
}

func (m *mesh) natTick(now time.Time) {
	if m.nat == nil {
		return
	}
	n := m.nat
	for id, s := range n.starts {
		if now.Sub(s.at) >= 10*time.Second {
			delete(n.starts, id)
		}
	}
	var links []linkAddr
	for _, link := range m.links {
		if link.Prefix.Addr().Is4() {
			links = append(links, link)
		}
	}
	if filter, ok := n.transport.(interface{ SetLinks([]linkAddr) }); ok {
		filter.SetLinks(links)
	}
	if n.engine != nil && !slices.Equal(links, n.links) {
		_ = m.closeNAT()
		n.remote = make(map[wgtypes.Key]string)
		n.selected = make(map[wgtypes.Key]netip.AddrPort)
	}
	if n.engine == nil {
		if len(links) == 0 || now.Before(n.retryAt) {
			return
		}
		n.retryAt = now.Add(5 * time.Second)
		engine, err := newICETraversal(n.transport, m.wgPort, m.c.NAT.Servers, links)
		if err != nil {
			// Do not print credentials or block normal LAN pairing on ICE errors.
			slog.Warn("experimental ICE unavailable; LAN pairing remains enabled")
			return
		}
		n.engine, n.links = engine, slices.Clone(links)
		for _, p := range m.peers {
			n.restartAt[p.spec.key] = now.Add(30 * time.Second)
			p.signalNext = time.Time{}
		}
	}
	// Selected is authoritative even if a callback queue filled or an old
	// callback arrived after an agent replacement. Events contain no secrets.
	for i := 0; i < 256; i++ {
		select {
		case <-n.engine.Events():
		default:
			i = 256
		}
	}
	for _, p := range m.peers {
		if err := n.engine.EnsurePeer(p.spec.key, bytes.Compare(m.public[:], p.spec.key[:]) < 0); err != nil {
			continue
		}
		u := n.engine.Selected(p.spec.key)
		if validNATEndpoint(u.Endpoint) && (u.State == ice.ConnectionStateConnected || u.State == ice.ConnectionStateCompleted) {
			if n.selected[p.spec.key] != u.Endpoint {
				slog.Info("ICE direct candidate selected", "peer", p.spec.IP, "endpoint", u.Endpoint)
				n.selected[p.spec.key] = u.Endpoint
			}
			p.natOffer, p.natOfferAt = u.Endpoint, now
			if !m.freshNATPath(p, u.Endpoint, now) {
				m.startNATSession(p, u.Endpoint, now)
			}
		}
		healthy := false
		for _, c := range p.paths {
			if c.nat && m.fresh(c, now) {
				healthy = true
				break
			}
		}
		if healthy {
			// Neither STUN loss nor an ICE restart may tear down a healthy
			// authenticated path or its actual WireGuard session.
			n.restartAt[p.spec.key] = now.Add(30 * time.Second)
		} else if !now.Before(n.restartAt[p.spec.key]) {
			_ = n.engine.Restart(p.spec.key)
			n.restartAt[p.spec.key] = now.Add(30 * time.Second)
			p.signalNext = time.Time{}
		}
	}
}

func (m *mesh) receiveWireGuard(pkt packet, now time.Time) error {
	if stun.IsMessage(pkt.Data) {
		if m.nat.engine != nil {
			m.nat.engine.Input(pkt)
		}
		return nil // A full ICE queue must never redirect STUN into Noise.
	}
	return m.receivePacket(pkt, now, true)
}

func validNATEndpoint(endpoint netip.AddrPort) bool {
	a := endpoint.Addr()
	return endpoint.IsValid() && endpoint.Port() != 0 && a.Is4() && a.IsGlobalUnicast() && !a.IsLoopback() && !a.IsLinkLocalUnicast()
}

func (m *mesh) freshNATPath(p *meshPeer, endpoint netip.AddrPort, now time.Time) bool {
	for _, c := range p.paths {
		if c.nat && c.addr == endpoint && m.fresh(c, now) && m.crypto.sessions[c.session] != nil {
			return true
		}
	}
	return false
}

func (m *mesh) signalTick(p *meshPeer, now time.Time) {
	if m.nat == nil || now.Before(p.signalNext) {
		return
	}
	p.signalNext = now.Add(time.Duration(m.c.NAT.Refresh))
	s := m.crypto.sessions[p.signal]
	if s == nil || !s.ready || !now.Before(s.expires) || !p.signalLast.IsZero() && now.Sub(p.signalLast) >= max(5*time.Second, 3*time.Duration(m.c.NAT.Refresh)) {
		p.signal, p.signalToken = [16]byte{}, ""
		if bytes.Compare(m.public[:], p.spec.key[:]) >= 0 {
			return
		}
		id, data, err := m.crypto.Start(p.spec.key, now)
		if err == nil && m.net.Send(data, netip.AddrPortFrom(p.spec.IP, m.c.Port), m.tunnel) == nil {
			m.nat.starts[id] = natStart{peer: p.spec.key, at: now}
		}
		return
	}
	if p.signalToken == "" {
		p.signalToken = rand.Text()
	}
	var signals []iceSignal
	if m.nat.engine != nil {
		signals = m.nat.engine.Signals(p.spec.key)
	}
	if len(signals) == 0 {
		m.send(p.signal, message{Op: "signal", Token: p.signalToken, Port: m.wgPort}, netip.AddrPortFrom(p.spec.IP, m.c.Port), m.tunnel, now)
	}
	for _, signal := range signals {
		m.send(p.signal, message{Op: "signal", Token: p.signalToken, Port: m.wgPort, ICE: &signal}, netip.AddrPortFrom(p.spec.IP, m.c.Port), m.tunnel, now)
	}
}

func (m *mesh) receiveEndpoint(p *meshPeer, _ [16]byte, msg message, _ time.Time) {
	if m.nat == nil || m.nat.engine == nil || msg.ICE == nil {
		return
	}
	if m.nat.engine.Remote(p.spec.key, *msg.ICE) == nil && m.nat.remote[p.spec.key] != msg.ICE.Generation {
		m.nat.remote[p.spec.key] = msg.ICE.Generation
		p.signalNext = time.Time{}
	}
}

func (m *mesh) startNATSession(p *meshPeer, endpoint netip.AddrPort, now time.Time) {
	for _, s := range m.nat.starts {
		if s.peer == p.spec.key && s.endpoint == endpoint && now.Sub(s.at) < 5*time.Second {
			return
		}
	}
	session, data, err := m.crypto.Start(p.spec.key, now)
	if err == nil && m.nat.transport.Send(data, endpoint) == nil {
		m.nat.starts[session] = natStart{peer: p.spec.key, endpoint: endpoint, at: now}
	}
}

func (m *mesh) renewNATSession(p *meshPeer, c *path, now time.Time) {
	if m.nat == nil || !c.nat || !m.fresh(c, now) {
		return
	}
	s := m.crypto.sessions[c.session]
	if s == nil || s.expires.Sub(now) < max(10*time.Second, 2*time.Duration(m.c.NAT.Refresh)) {
		m.startNATSession(p, c.addr, now)
	}
}

func (m *mesh) rawLink(pkt packet) (linkAddr, bool) {
	for _, link := range m.links {
		if link.Index == pkt.IfIndex && link.Prefix.Addr() == pkt.Destination && link.Prefix.Addr().Is4() {
			return link, true
		}
	}
	return linkAddr{}, false
}

func (m *mesh) rawAuthorized(p *meshPeer, source netip.AddrPort, now time.Time) bool {
	for _, c := range p.paths {
		if c.nat && c.addr == source && m.fresh(c, now) {
			return true
		}
	}
	return validNATEndpoint(source) && source.Addr() == p.natOffer.Addr() && now.Sub(p.natOfferAt) < 2*time.Minute
}

func (m *mesh) sendPath(id [16]byte, msg message, c *path, now time.Time) bool {
	if !c.nat {
		return m.send(id, msg, c.addr, c.link, now)
	}
	if m.nat == nil {
		return false
	}
	body, _ := json.Marshal(msg)
	data, err := m.crypto.Seal(id, body, now)
	return err == nil && m.nat.transport.Send(data, c.addr) == nil
}

func (m *mesh) stage(p *meshPeer, c *path) (bool, error) {
	if s, ok := m.control.(interface {
		Stage(wgtypes.Key, netip.Addr, wgtypes.Key, netip.AddrPort) (bool, error)
	}); ok {
		return s.Stage(p.spec.key, p.spec.IP, p.spec.psk, netip.AddrPortFrom(c.addr.Addr(), c.port))
	}
	return true, nil
}
