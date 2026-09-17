package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// One event loop owns all protocol state and serializes configuration changes.
type routeControl interface {
	Apply(wgtypes.Key, netip.Addr, wgtypes.Key, netip.AddrPort) error
	Restore(wgtypes.Key) error
	Check() error
}

type message struct {
	Op    string `json:"op"`
	Token string `json:"token"`
	Port  uint16 `json:"port"`
}

type sample struct {
	at  time.Time
	rtt time.Duration
}
type measurements struct {
	since   time.Time
	samples []sample
}

func (w *measurements) add(now time.Time, rtt time.Duration, window time.Duration) {
	w.samples = slices.DeleteFunc(w.samples, func(s sample) bool { return now.Sub(s.at) > window })
	if len(w.samples) < 1024 {
		w.samples = append(w.samples, sample{now, rtt})
	}
}

func (w measurements) median(now time.Time, c config) (time.Duration, bool) {
	if w.since.IsZero() || now.Sub(w.since) < time.Duration(c.Window) {
		return 0, false
	}
	var values []time.Duration
	for _, s := range w.samples {
		if now.Sub(s.at) <= time.Duration(c.Window) {
			values = append(values, s.rtt)
		}
	}
	// At least 80% of the scheduled probes must succeed. Loss is not a low RTT.
	needed := (int(c.Window/c.Probe)*8 + 9) / 10
	if len(values) < needed {
		return 0, false
	}
	slices.Sort(values)
	return values[len(values)/2], true
}

func improves(candidate, baseline time.Duration, c config) bool {
	return candidate < baseline && baseline-candidate >= time.Duration(c.MinGain) && float64(candidate) <= float64(baseline)*(1-c.Gain)
}

type path struct {
	link     linkAddr
	addr     netip.AddrPort
	session  [16]byte
	incoming [16]byte
	port     uint16
	lastPong time.Time
	stats    measurements
}

type discovery struct {
	since, proof, next time.Time
	broadcast          bool
}
type start struct {
	key       wgtypes.Key
	link      linkAddr
	at        time.Time
	multicast bool
}
type probe struct {
	path      *path
	at        time.Time
	session   [16]byte
	multicast bool
	measure   bool
}
type meshPeer struct {
	spec                             peerSpec
	paths                            map[string]*path
	discovery                        map[linkAddr]*discovery
	pending                          map[string]probe
	tunnel                           measurements
	lastTunnel                       time.Time
	remoteAt                         time.Time
	selected                         *path
	phase, trial                     string
	since, cooldown                  time.Time
	baseline                         time.Duration
	localGood, remoteGood, committed bool
}

type mesh struct {
	c       config
	net     network
	control routeControl
	crypto  *secure
	public  wgtypes.Key
	wgPort  uint16
	tunnel  linkAddr
	peers   map[wgtypes.Key]*meshPeer
	starts  map[[16]byte]start
	links   []linkAddr
	dry     bool
	notify  func()
	verify  func() error
}

func newMesh(c config, n network, control routeControl, private wgtypes.Key, port uint16, tunnel linkAddr, dry bool) *mesh {
	m := &mesh{c: c, net: n, control: control, public: private.PublicKey(), wgPort: port, tunnel: tunnel, dry: dry,
		peers: make(map[wgtypes.Key]*meshPeer), starts: make(map[[16]byte]start)}
	var keys []wgtypes.Key
	for _, spec := range c.Peers {
		keys = append(keys, spec.key)
		m.peers[spec.key] = &meshPeer{spec: spec, paths: make(map[string]*path), discovery: make(map[linkAddr]*discovery), pending: make(map[string]probe)}
	}
	m.crypto = newSecure(private, keys)
	return m
}

func (m *mesh) run(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(m.c.Probe))
	defer ticker.Stop()
	if err := m.refresh(time.Now()); err != nil {
		return err
	}
	if err := m.tick(time.Now()); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case p, ok := <-m.net.Incoming():
			if !ok {
				return errors.New("discovery sockets closed")
			}
			if err := m.receive(p, time.Now()); err != nil {
				return err
			}
		case _, ok := <-m.net.Changed():
			if !ok {
				return errors.New("interface monitor closed")
			}
			if err := m.refresh(time.Now()); err != nil {
				return err
			}
		case now := <-ticker.C:
			if err := m.refresh(now); err != nil {
				return err
			}
			if err := m.tick(now); err != nil {
				return err
			}
			if m.notify != nil {
				m.notify()
			}
		}
	}
}

func (m *mesh) refresh(now time.Time) error {
	links, err := m.net.Links()
	if err != nil {
		slog.Warn("interface discovery", "error", err)
	}
	m.links = links
	for _, p := range m.peers {
		for link := range p.discovery {
			if !slices.Contains(links, link) {
				delete(p.discovery, link)
			}
		}
		for id, candidate := range p.paths {
			if !slices.Contains(links, candidate.link) {
				if p.selected == candidate {
					if err := m.restore(p, now, "interface removed"); err != nil {
						return err
					}
				}
				delete(p.paths, id)
			}
		}
	}
	return nil
}

func pathName(link linkAddr, addr netip.AddrPort) string {
	return fmt.Sprintf("%d/%s/%s", link.Index, link.Prefix, addr)
}

func (m *mesh) lan(packet packet) (linkAddr, bool) {
	source := packet.Source.Addr().WithZone("")
	for _, l := range m.links {
		if l.Index != packet.IfIndex || !l.Prefix.Contains(source) || source == l.Prefix.Addr() || source == l.Broadcast || source.IsMulticast() || source.IsUnspecified() {
			continue
		}
		if packet.Destination == l.Prefix.Addr() || packet.Destination == l.Broadcast || slices.Contains(m.c.groups(), packet.Destination) {
			return l, true
		}
	}
	return linkAddr{}, false
}

func (m *mesh) receive(packet packet, now time.Time) error {
	if packet.Source.Port() != m.c.Port {
		return nil
	}
	link, lan := m.lan(packet)
	tunnel := packet.IfIndex == m.tunnel.Index && packet.Destination == m.c.Address
	if !lan && !tunnel {
		return nil
	}
	event, err := m.crypto.Receive(packet.Data, now)
	if err != nil {
		return nil
	} // Invalid traffic must not become a log flood.
	p := m.peers[event.Peer]
	if p == nil || tunnel && packet.Source.Addr() != p.spec.IP {
		return nil
	}
	if len(event.Reply) != 0 {
		if lan {
			_ = m.net.Send(event.Reply, packet.Source, link)
		}
		return nil
	}
	if !event.Ready {
		return nil
	}
	if event.Body == nil {
		s, ok := m.starts[event.ID]
		delete(m.starts, event.ID)
		if !ok || !lan || s.key != event.Peer || s.link != link {
			return nil
		}
		candidate := m.candidate(p, link, packet.Source, now)
		if candidate != nil {
			m.ping(p, candidate, event.ID, s.multicast, now)
		}
		return nil
	}
	var msg message
	if json.Unmarshal(event.Body, &msg) != nil || len(msg.Token) > 64 || msg.Token == "" || msg.Port == 0 {
		return nil
	}
	var candidate *path
	if lan {
		candidate = p.paths[pathName(link, packet.Source)]
		if msg.Op == "ping" {
			candidate = m.candidate(p, link, packet.Source, now)
		}
		if candidate == nil {
			return nil
		}
	}
	switch msg.Op {
	case "ping":
		if tunnel {
			link = m.tunnel
		}
		m.send(event.ID, message{"pong", msg.Token, m.wgPort}, packet.Source, link, now)
		if lan {
			candidate.incoming = event.ID
		}
	case "pong":
		q, ok := p.pending[msg.Token]
		if !ok || q.session != event.ID || now.Sub(q.at) > time.Duration(m.c.Failure) || (q.path == nil) != tunnel || q.path != candidate {
			return nil
		}
		delete(p.pending, msg.Token)
		if tunnel {
			p.tunnel.add(now, now.Sub(q.at), time.Duration(m.c.Window))
			p.lastTunnel = now
		} else {
			candidate.session, candidate.port = event.ID, msg.Port
			if q.measure {
				candidate.stats.add(now, now.Sub(q.at), time.Duration(m.c.Window))
			}
			candidate.lastPong = now
			if q.multicast {
				if d := p.discovery[link]; d != nil {
					d.proof = now
				}
			}
		}
	default:
		if lan && candidate != nil && m.fresh(candidate, now) {
			return m.coordinate(p, candidate, msg, now)
		}
	}
	return nil
}

func (m *mesh) candidate(p *meshPeer, link linkAddr, addr netip.AddrPort, now time.Time) *path {
	name := pathName(link, addr)
	c := p.paths[name]
	if c == nil {
		if len(p.paths) >= 16 {
			return nil
		}
		c = &path{link: link, addr: addr, stats: measurements{since: now}}
		p.paths[name] = c
	}
	return c
}

func (m *mesh) send(id [16]byte, msg message, addr netip.AddrPort, link linkAddr, now time.Time) bool {
	body, _ := json.Marshal(msg)
	data, err := m.crypto.Seal(id, body, now)
	return err == nil && m.net.Send(data, addr, link) == nil
}

func (m *mesh) ping(p *meshPeer, candidate *path, id [16]byte, multicast bool, now time.Time) {
	if len(p.pending) >= 2048 {
		return
	}
	addr, link := netip.AddrPortFrom(p.spec.IP, m.c.Port), m.tunnel
	if candidate != nil {
		addr, link = candidate.addr, candidate.link
	}
	token := rand.Text()
	if m.send(id, message{"ping", token, m.wgPort}, addr, link, now) {
		p.pending[token] = probe{candidate, now, id, multicast, candidate == nil || id == candidate.session}
	}
}

func (m *mesh) announce(p *meshPeer, link linkAddr, group netip.Addr, multicast bool, now time.Time) {
	id, data, err := m.crypto.Start(p.spec.key, now)
	if err != nil {
		return
	}
	if m.net.Send(data, netip.AddrPortFrom(group, m.c.Port), link) == nil {
		m.starts[id] = start{p.spec.key, link, now, multicast}
	}
}

func (m *mesh) fresh(c *path, now time.Time) bool {
	return c.port != 0 && !c.lastPong.IsZero() && now.Sub(c.lastPong) < time.Duration(m.c.Failure)
}

func (m *mesh) qualified(p *meshPeer, c *path, now time.Time) (time.Duration, bool) {
	// The pinned wgctrl Linux encoder omits sockaddr_in6 scope IDs. Discovery
	// still works, but do not install an ambiguous link-local WireGuard endpoint.
	if c.addr.Addr().Is6() && c.addr.Addr().IsLinkLocalUnicast() {
		return 0, false
	}
	base, ok := p.tunnel.median(now, m.c)
	lan, ready := c.stats.median(now, m.c)
	return base, ok && ready && m.fresh(c, now) && improves(lan, base, m.c)
}

func (m *mesh) tick(now time.Time) error {
	if err := m.control.Check(); err != nil {
		return err
	}
	if m.verify != nil {
		if err := m.verify(); err != nil {
			return err
		}
	}
	for id, s := range m.starts {
		if now.Sub(s.at) >= 10*time.Second {
			delete(m.starts, id)
		}
	}
	used := make(map[[16]byte]bool)
	for id := range m.starts {
		used[id] = true
	}
	for _, p := range m.peers {
		for _, c := range p.paths {
			used[c.session], used[c.incoming] = true, true
		}
		for _, q := range p.pending {
			used[q.session] = true
		}
	}
	m.crypto.Prune(used, now)
	for _, p := range m.peers {
		for token, q := range p.pending {
			if now.Sub(q.at) > time.Duration(m.c.Failure) {
				delete(p.pending, token)
			}
		}
		for _, link := range m.links {
			d := p.discovery[link]
			if d == nil {
				d = &discovery{since: now}
				p.discovery[link] = d
			}
			proof := d.proof
			if proof.IsZero() {
				proof = d.since
			}
			if !d.broadcast && now.Sub(proof) >= time.Duration(m.c.BroadcastAfter) {
				d.broadcast, d.next = true, now
			}
			if now.Before(d.next) {
				continue
			}
			d.next = now.Add(time.Duration(m.c.Discovery))
			group := m.c.Multicast6
			if link.Prefix.Addr().Is4() {
				group = m.c.Multicast4
			}
			if link.Multicast {
				m.announce(p, link, group, true, now)
			}
			if d.broadcast && link.Broadcast.IsValid() {
				m.announce(p, link, link.Broadcast, false, now)
			}
		}
		var session [16]byte
		for name, c := range p.paths {
			if now.Sub(c.stats.since) > time.Duration(m.c.Failure) && !m.fresh(c, now) && c != p.selected {
				delete(p.paths, name)
				continue
			}
			id := c.session
			if m.crypto.sessions[id] == nil {
				// Validate a received session on the timer, not in response to every
				// incoming ping. Two simultaneous sessions must not cause ping loops.
				id = c.incoming
			}
			m.ping(p, c, id, false, now)
			if m.fresh(c, now) {
				session = c.session
			}
		}
		if p.selected != nil {
			session = p.selected.session
		}
		if session != ([16]byte{}) {
			if p.tunnel.since.IsZero() {
				p.tunnel.since = now
			}
			m.ping(p, nil, session, false, now)
		}
		if p.phase != "" {
			if err := m.advance(p, now); err != nil {
				return err
			}
			if p.phase != "active" {
				continue
			}
		}
		if now.Before(p.cooldown) || bytes.Compare(m.public[:], p.spec.key[:]) >= 0 {
			continue
		}
		var best *path
		var bestRTT, base time.Duration
		for _, c := range p.paths {
			if c == p.selected {
				continue
			}
			if b, ok := m.qualified(p, c, now); ok {
				rtt, _ := c.stats.median(now, m.c)
				if best == nil || rtt < bestRTT {
					best, bestRTT, base = c, rtt, b
				}
			}
		}
		if best != nil {
			if m.dry {
				slog.Info("direct path available; no change", "peer", p.spec.IP, "endpoint", best.addr, "baseline", base, "lan", bestRTT)
				p.cooldown = now.Add(time.Duration(m.c.Cooldown))
			} else {
				p.selected, p.phase, p.trial, p.since, p.baseline = best, "prepare", rand.Text(), now, base
				p.localGood, p.remoteGood, p.committed = false, false, false
				m.command(p, "prepare", now)
			}
		}
	}
	return nil
}

func (m *mesh) command(p *meshPeer, op string, now time.Time) {
	c := p.selected
	if c != nil {
		m.send(c.session, message{op, p.trial, m.wgPort}, c.addr, c.link, now)
	}
}

func (m *mesh) coordinate(p *meshPeer, c *path, msg message, now time.Time) error {
	if m.dry {
		return nil
	}
	if msg.Op == "prepare" && (p.phase == "" || p.phase == "active" && p.selected != c) && !now.Before(p.cooldown) && bytes.Compare(p.spec.key[:], m.public[:]) < 0 {
		if base, ok := m.qualified(p, c, now); ok {
			p.selected, p.phase, p.trial, p.since, p.baseline = c, "prepared", msg.Token, now, base
			p.localGood, p.remoteGood, p.committed = false, false, false
			m.command(p, "ready", now)
		}
		return nil
	}
	if p.selected != c || p.trial != msg.Token {
		return nil
	}
	switch msg.Op {
	case "prepare":
		if p.phase == "prepared" {
			m.command(p, "ready", now)
		}
	case "ready":
		if p.phase == "prepare" {
			m.command(p, "commit", now)
			return m.apply(p, now)
		}
	case "commit":
		if p.phase == "prepared" {
			if err := m.apply(p, now); err != nil {
				return err
			}
		}
		if p.phase == "trial" || p.phase == "active" {
			p.committed = true
			m.command(p, "committed", now)
		}
	case "committed":
		p.committed = true
	case "keep":
		if p.phase == "trial" || p.phase == "active" {
			p.remoteGood = true
			p.remoteAt = now
		}
	case "hold":
		p.remoteGood = false
	case "abort":
		return m.restore(p, now, "remote rollback")
	}
	return nil
}

func (m *mesh) apply(p *meshPeer, now time.Time) error {
	c := p.selected
	if m.verify != nil {
		if err := m.verify(); err != nil {
			return err
		}
	}
	if err := m.control.Apply(p.spec.key, p.spec.IP, p.spec.psk, netip.AddrPortFrom(c.addr.Addr(), c.port)); err != nil {
		m.command(p, "abort", now)
		return fmt.Errorf("apply direct path for %s: %w", p.spec.IP, err)
	}
	p.phase, p.since = "trial", now
	p.tunnel, p.lastTunnel = measurements{since: now}, time.Time{}
	p.pending = make(map[string]probe) // Do not count probes from the old route.
	slog.Info("direct path trial", "peer", p.spec.IP, "endpoint", c.addr)
	return nil
}

func (m *mesh) advance(p *meshPeer, now time.Time) error {
	if !m.fresh(p.selected, now) {
		return m.restore(p, now, "LAN health timeout")
	}
	switch p.phase {
	case "prepare", "prepared":
		if now.Sub(p.since) >= time.Duration(m.c.Failure) {
			return m.restore(p, now, "coordination timeout")
		}
		if p.phase == "prepare" {
			m.command(p, "prepare", now)
		} else {
			m.command(p, "ready", now)
		}
	case "trial", "active":
		last := p.lastTunnel
		if last.IsZero() {
			last = p.since
		}
		if now.Sub(last) >= time.Duration(m.c.Failure) {
			return m.restore(p, now, "WireGuard health timeout")
		}
		if !p.committed && bytes.Compare(m.public[:], p.spec.key[:]) < 0 {
			m.command(p, "commit", now)
		}
		if p.phase == "trial" {
			p.localGood = false
			if rtt, ok := p.tunnel.median(now, m.c); ok {
				if !improves(rtt, p.baseline, m.c) {
					return m.restore(p, now, "trial did not improve RTT")
				}
				p.localGood = true
			} else if now.Sub(p.since) >= time.Duration(m.c.Window) {
				return m.restore(p, now, "trial packet loss")
			}
			// Accommodate the maximum supported remote window (one minute).
			if now.Sub(p.since) > 2*time.Minute {
				return m.restore(p, now, "trial confirmation timeout")
			}
			if p.localGood && p.remoteGood && now.Sub(p.remoteAt) < time.Duration(m.c.Failure) && p.committed {
				p.phase = "active"
				p.cooldown = now.Add(time.Duration(m.c.Cooldown))
				slog.Info("direct path active", "peer", p.spec.IP, "endpoint", p.selected.addr)
			}
		}
		if p.localGood {
			m.command(p, "keep", now)
		} else {
			m.command(p, "hold", now)
		}
	}
	return nil
}

func (m *mesh) restore(p *meshPeer, now time.Time, reason string) error {
	m.command(p, "abort", now)
	if err := m.control.Restore(p.spec.key); err != nil {
		return err
	}
	slog.Info("stable path restored", "peer", p.spec.IP, "reason", reason)
	p.selected, p.phase, p.trial = nil, "", ""
	p.localGood, p.remoteGood, p.committed = false, false, false
	p.cooldown = now.Add(time.Duration(m.c.Cooldown))
	p.tunnel, p.lastTunnel = measurements{since: now}, time.Time{}
	p.pending = make(map[string]probe)
	return nil
}
