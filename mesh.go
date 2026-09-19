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
	"strings"
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
	Proof string `json:"proof,omitempty"`
	Rekey bool   `json:"experimental_rekey,omitempty"`
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

// An uncommitted replacement must not change the active route or its health state.
type routeProposal struct {
	path         *path
	phase, token string
	since        time.Time
	baseline     time.Duration
	remoteRekey  bool
}

type routeState struct {
	selected                         *path
	phase, trial                     string
	since, resumed                   time.Time
	baseline                         time.Duration
	localGood, remoteGood, committed bool
	remoteRekey                      bool
	tunnel                           measurements
	lastTunnel, remoteAt             time.Time
}

type meshPeer struct {
	routeState
	spec           peerSpec
	pskValid       bool
	pskLogAfter    time.Time
	pskStatus      rosenpassResponse
	rosenpassPath  *path
	rosenpassToken string
	rekey          *pskTransition
	completedRekey *pskTransition
	paths          map[string]*path
	discovery      map[linkAddr]*discovery
	pending        map[string]probe
	replacement    *routeProposal
	previous       *routeState
	cooldown       time.Time
	retired        map[string]time.Time
	retiredUntil   time.Time
}

type mesh struct {
	c         config
	net       network
	control   routeControl
	crypto    *secure
	public    wgtypes.Key
	wgPort    uint16
	tunnel    linkAddr
	peers     map[wgtypes.Key]*meshPeer
	starts    map[[16]byte]start
	links     []linkAddr
	dry       bool
	notify    func()
	verify    func() error
	rosenpass func(string, rosenpassRequest) (rosenpassResponse, error)
}

func newMesh(c config, n network, control routeControl, private wgtypes.Key, port uint16, tunnel linkAddr, dry bool) *mesh {
	m := &mesh{c: c, net: n, control: control, public: private.PublicKey(), wgPort: port, tunnel: tunnel, dry: dry,
		peers: make(map[wgtypes.Key]*meshPeer), starts: make(map[[16]byte]start), rosenpass: queryRosenpass}
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
		case <-ticker.C:
			if err := m.refresh(time.Now()); err != nil {
				return err
			}
			if err := m.tick(time.Now()); err != nil {
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
					if err := m.rollback(p, now, "interface removed"); err != nil {
						return err
					}
				} else if p.replacement != nil && p.replacement.path == candidate {
					m.cancelReplacement(p, now)
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
	started := time.Now()
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
	if json.Unmarshal(event.Body, &msg) != nil || len(msg.Token) > 64 || len(msg.Proof) > 64 || msg.Token == "" || msg.Port == 0 {
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
		m.send(event.ID, message{Op: "pong", Token: msg.Token, Port: m.wgPort}, packet.Source, link, now)
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
			return m.coordinate(p, candidate, msg, now.Add(time.Since(started)))
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
	if m.send(id, message{Op: "ping", Token: token, Port: m.wgPort}, addr, link, now) {
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
	compare := base
	if p.phase == "active" {
		// Compare LAN with LAN. Tunnel overhead must not favor another alias.
		var measured bool
		compare, measured = p.selected.stats.median(now, m.c)
		ok = ok && measured
	}
	return base, ok && ready && m.fresh(c, now) && improves(lan, compare, m.c)
}

func (m *mesh) tick(now time.Time) error {
	started := time.Now()
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
		pskOK, err := m.pollPSK(p, now.Add(time.Since(started)))
		if err != nil {
			return err
		}
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
		checkedAt := now.Add(time.Since(started))
		if p.phase != "" {
			if err := m.advance(p, checkedAt); err != nil {
				return err
			}
			if p.phase != "active" {
				continue
			}
		}
		if !pskOK || p.rekey != nil || p.replacement != nil || checkedAt.Before(p.cooldown) || bytes.Compare(m.public[:], p.spec.key[:]) >= 0 {
			continue
		}
		var best *path
		var bestRTT, base time.Duration
		for _, c := range p.paths {
			if c == p.selected {
				continue
			}
			if b, ok := m.qualified(p, c, checkedAt); ok {
				rtt, _ := c.stats.median(checkedAt, m.c)
				if best == nil || rtt < bestRTT {
					best, bestRTT, base = c, rtt, b
				}
			}
		}
		if best != nil {
			if m.dry {
				slog.Info("direct path available; no change", "peer", p.spec.IP, "endpoint", best.addr, "baseline", base, "lan", bestRTT)
				p.cooldown = checkedAt.Add(time.Duration(m.c.Cooldown))
			} else if p.phase == "active" {
				p.replacement = &routeProposal{path: best, phase: "prepare", token: rand.Text(), since: checkedAt, baseline: base}
				m.pathCommand(p, best, p.replacement.token, "prepare", checkedAt)
			} else {
				p.selected, p.phase, p.trial, p.since, p.baseline = best, "prepare", rand.Text(), checkedAt, base
				p.localGood, p.remoteGood, p.committed = false, false, false
				m.command(p, "prepare", checkedAt)
			}
		}
	}
	return nil
}

func (m *mesh) command(p *meshPeer, op string, now time.Time) {
	m.pathCommand(p, p.selected, p.trial, op, now)
}

func (m *mesh) pathCommand(p *meshPeer, c *path, token, op string, now time.Time) {
	if c != nil {
		msg := message{Op: op, Token: token, Port: m.wgPort, Rekey: p.spec.ExperimentalRekey}
		msg.Proof = pskProof(p.spec.psk, op, token, m.public, p.spec.key)
		m.send(c.session, msg, c.addr, c.link, now)
	}
}

func (m *mesh) cancelReplacement(p *meshPeer, now time.Time) {
	if r := p.replacement; r != nil {
		m.pathCommand(p, r.path, r.token, "abort", now)
		m.retire(p, r.token, now)
		p.replacement = nil
		p.cooldown = now.Add(time.Duration(m.c.Cooldown))
		slog.Info("direct path replacement cancelled", "peer", p.spec.IP, "endpoint", r.path.addr)
	}
}

// Remote retries can use a later session during one minute of coordination and
// two minutes of trial. Retain the token until that last session also expires.
const retiredTokenLifetime = secureSessionLifetime + 3*time.Minute

func (m *mesh) retire(p *meshPeer, token string, now time.Time) {
	if token == "" {
		return
	}
	if p.retired == nil {
		p.retired = make(map[string]time.Time)
	}
	for token, until := range p.retired {
		if !now.Before(until) {
			delete(p.retired, token)
		}
	}
	// Never evict a live token. Saturation blocks new proposals for the full
	// retention period instead of allowing delayed packets to reuse a token.
	if len(p.retired) >= 1024 {
		p.retiredUntil = now.Add(retiredTokenLifetime)
		return
	}
	p.retired[token] = now.Add(retiredTokenLifetime)
}

func (m *mesh) coordinate(p *meshPeer, c *path, msg message, now time.Time) error {
	started, receivedAt := time.Now(), now
	if m.dry {
		return nil
	}
	if msg.Op == "rosenpass-select" {
		if p.spec.RosenpassSocket != "" && bytes.Compare(p.spec.key[:], m.public[:]) < 0 {
			p.rosenpassPath, p.rosenpassToken = c, msg.Token
		}
		return nil
	}
	if strings.HasPrefix(msg.Op, "rekey-") {
		return m.coordinateRekey(p, c, msg, now)
	}
	if msg.Op == "prepare" {
		if now.Before(p.retiredUntil) {
			p.retiredUntil = now.Add(retiredTokenLifetime)
			return nil
		}
		if now.Before(p.retired[msg.Token]) {
			return nil
		}
	}
	if msg.Op == "prepare" || msg.Op == "ready" || msg.Op == "commit" {
		if ok, err := m.pollPSK(p, now); err != nil || !ok {
			return err
		}
		now = receivedAt.Add(time.Since(started))
		if !checkPSKProof(p.spec.psk, msg, p.spec.key, m.public) {
			return nil
		}
	}
	if msg.Op == "prepare" && p.rekey == nil && p.replacement == nil && (p.phase == "" || p.phase == "active" && p.selected != c) && !now.Before(p.cooldown) && bytes.Compare(p.spec.key[:], m.public[:]) < 0 {
		if base, ok := m.qualified(p, c, now); ok {
			if p.phase == "active" {
				p.replacement = &routeProposal{path: c, phase: "prepared", token: msg.Token, since: now, baseline: base, remoteRekey: msg.Rekey}
			} else {
				p.selected, p.phase, p.trial, p.since, p.baseline = c, "prepared", msg.Token, now, base
				p.localGood, p.remoteGood, p.committed = false, false, false
				p.remoteRekey = msg.Rekey
			}
			m.pathCommand(p, c, msg.Token, "ready", now)
		} else {
			m.retire(p, msg.Token, now)
		}
		return nil
	}
	if r := p.replacement; r != nil && r.path == c && r.token == msg.Token {
		if !m.fresh(c, now) || now.Sub(r.since) >= time.Duration(m.c.Failure) {
			m.cancelReplacement(p, now)
			return nil
		}
		switch msg.Op {
		case "prepare":
			if r.phase == "prepared" {
				m.pathCommand(p, c, r.token, "ready", now)
			}
		case "ready":
			if r.phase == "prepare" {
				r.remoteRekey = msg.Rekey
				return m.apply(p, now)
			}
		case "commit":
			if r.phase == "prepared" {
				if err := m.apply(p, now); err != nil {
					return err
				}
				if p.selected == c && p.trial == msg.Token {
					p.committed = true
					m.command(p, "committed", receivedAt.Add(time.Since(started)))
				}
			}
		case "abort":
			m.cancelReplacement(p, now)
		}
		return nil
	}
	if old := p.previous; old != nil && old.selected == c && old.trial == msg.Token {
		switch msg.Op {
		case "abort":
			m.retire(p, old.trial, now)
			p.previous = nil // The remote no longer has the fallback route.
		case "keep":
			old.remoteGood, old.remoteAt = true, now
		case "hold":
			old.remoteGood = false
		}
		return nil
	}
	if p.selected != c || p.trial != msg.Token {
		if msg.Op == "prepare" {
			m.retire(p, msg.Token, now)
		}
		return nil
	}
	switch msg.Op {
	case "prepare":
		if p.phase == "prepared" {
			m.command(p, "ready", now)
		}
	case "ready":
		if p.phase == "prepare" {
			p.remoteRekey = msg.Rekey
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
			m.command(p, "committed", receivedAt.Add(time.Since(started)))
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
		return m.rollback(p, now, "remote rollback")
	}
	return nil
}

func (m *mesh) apply(p *meshPeer, now time.Time) error {
	started := time.Now()
	r := p.replacement
	leader := p.phase == "prepare" || r != nil && r.phase == "prepare"
	if m.verify != nil {
		if err := m.verify(); err != nil {
			return err
		}
	}
	// Include preflight time in the expiry check; never apply a cached file key.
	if ok, err := m.pollPSK(p, now.Add(time.Since(started))); err != nil || !ok {
		return err
	}
	checkedAt := now.Add(time.Since(started))
	c := p.selected
	token := p.trial
	if r != nil {
		if p.replacement != r {
			return nil // A key change cancelled this replacement during preflight.
		}
		if !m.fresh(r.path, checkedAt) || checkedAt.Sub(r.since) >= time.Duration(m.c.Failure) {
			m.cancelReplacement(p, checkedAt)
			return nil
		}
		if !m.fresh(p.selected, checkedAt) {
			return m.restore(p, checkedAt, "LAN health timeout")
		}
		if checkedAt.Sub(p.lastTunnel) >= time.Duration(m.c.Failure) {
			return m.restore(p, checkedAt, "WireGuard health timeout")
		}
		c, token = r.path, r.token
	}
	if c == nil {
		return nil // A key change cancelled this coordination round.
	}
	if r == nil && (!m.fresh(c, checkedAt) || checkedAt.Sub(p.since) >= time.Duration(m.c.Failure)) {
		return m.restore(p, checkedAt, "coordination timeout")
	}
	if err := m.control.Apply(p.spec.key, p.spec.IP, p.spec.psk, netip.AddrPortFrom(c.addr.Addr(), c.port)); err != nil {
		m.pathCommand(p, c, token, "abort", now.Add(time.Since(started)))
		return fmt.Errorf("apply direct path for %s: %w", p.spec.IP, err)
	}
	if r != nil {
		old := p.routeState
		p.previous = &old
		p.selected, p.trial, p.baseline, p.remoteRekey = c, r.token, r.baseline, r.remoteRekey
		p.localGood, p.remoteGood, p.committed = false, false, false
		p.replacement = nil
	}
	now = now.Add(time.Since(started))
	p.phase, p.since = "trial", now
	p.resumed = time.Time{}
	p.tunnel, p.lastTunnel = measurements{since: now}, time.Time{}
	p.pending = make(map[string]probe) // Do not count probes from the old route.
	if leader {
		m.command(p, "commit", now)
	}
	slog.Info("direct path trial", "peer", p.spec.IP, "endpoint", c.addr)
	return nil
}

func (m *mesh) advance(p *meshPeer, now time.Time) error {
	if !m.fresh(p.selected, now) {
		return m.rollback(p, now, "LAN health timeout")
	}
	if p.rekey != nil {
		return m.advanceRekey(p, now)
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
		if last.Before(p.resumed) {
			last = p.resumed
		}
		if now.Sub(last) >= time.Duration(m.c.Failure) {
			return m.rollback(p, now, "WireGuard health timeout")
		}
		if !p.committed && bytes.Compare(m.public[:], p.spec.key[:]) < 0 {
			m.command(p, "commit", now)
		}
		if p.phase == "trial" {
			p.localGood = false
			if rtt, ok := p.tunnel.median(now, m.c); ok {
				if !improves(rtt, p.baseline, m.c) {
					return m.rollback(p, now, "trial did not improve RTT")
				}
				p.localGood = true
			} else if now.Sub(p.since) >= time.Duration(m.c.Window) {
				return m.rollback(p, now, "trial packet loss")
			}
			// Accommodate the maximum supported remote window (one minute).
			if now.Sub(p.since) > 2*time.Minute {
				return m.rollback(p, now, "trial confirmation timeout")
			}
			if p.localGood && p.remoteGood && now.Sub(p.remoteAt) < time.Duration(m.c.Failure) && p.committed {
				if p.previous != nil {
					m.retire(p, p.previous.trial, now)
					p.previous = nil
				}
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
	if r := p.replacement; r != nil {
		if !m.fresh(r.path, now) || now.Sub(r.since) >= time.Duration(m.c.Failure) {
			m.cancelReplacement(p, now)
		} else if r.phase == "prepare" {
			m.pathCommand(p, r.path, r.token, "prepare", now)
		} else {
			m.pathCommand(p, r.path, r.token, "ready", now)
		}
	}
	return nil
}

func (m *mesh) rollback(p *meshPeer, now time.Time, reason string) error {
	old := p.previous
	if old == nil {
		return m.restore(p, now, reason)
	}
	started, receivedAt := time.Now(), now
	if m.verify != nil {
		if err := m.verify(); err != nil {
			return err
		}
	}
	if ok, err := m.pollPSK(p, now.Add(time.Since(started))); err != nil || !ok || p.previous != old {
		return err
	}
	now = now.Add(time.Since(started))
	c := old.selected
	if !slices.Contains(m.links, c.link) || !m.fresh(c, now) {
		return m.restore(p, now, reason)
	}
	// Apply on an owned peer changes only its endpoint, not its key or routes.
	if err := m.control.Apply(p.spec.key, p.spec.IP, p.spec.psk, netip.AddrPortFrom(c.addr.Addr(), c.port)); err != nil {
		return err
	}
	now = receivedAt.Add(time.Since(started))
	m.command(p, "abort", now)
	m.retire(p, p.trial, now)
	p.routeState, p.previous = *old, nil
	// The old endpoint could not be tested through WireGuard during the trial.
	// Require a new tunnel reply within the normal failure timeout after rollback.
	p.resumed = now
	p.cooldown = now.Add(time.Duration(m.c.Cooldown))
	p.pending = make(map[string]probe)
	slog.Info("previous direct path restored", "peer", p.spec.IP, "reason", reason)
	return nil
}

func (m *mesh) restore(p *meshPeer, now time.Time, reason string) error {
	m.cancelReplacement(p, now)
	m.command(p, "abort", now)
	if err := m.control.Restore(p.spec.key); err != nil {
		return err
	}
	slog.Info("stable path restored", "peer", p.spec.IP, "reason", reason)
	m.retire(p, p.trial, now)
	if p.previous != nil {
		m.retire(p, p.previous.trial, now)
		p.previous = nil
	}
	p.selected, p.phase, p.trial = nil, "", ""
	p.localGood, p.remoteGood, p.committed = false, false, false
	p.rekey, p.completedRekey, p.remoteRekey = nil, nil, false
	p.cooldown = now.Add(time.Duration(m.c.Cooldown))
	p.tunnel, p.lastTunnel = measurements{since: now}, time.Time{}
	p.pending = make(map[string]probe)
	return nil
}
