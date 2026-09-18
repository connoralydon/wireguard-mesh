package main

import (
	"errors"
	"math/rand"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type meshDelivery struct {
	at time.Time
	to *meshNode
	p  packet
}

type meshSimulation struct {
	t                        *testing.T
	now, next                time.Time
	nodes                    [2]*meshNode
	queue                    []meshDelivery
	dropMulticast, blockedWG bool
}

// B and C share a LAN. The hub is a 50 ms one-way tunnel transport.
type meshNode struct {
	s                      *meshSimulation
	m                      *mesh
	p                      *meshPeer
	other                  *meshNode
	lan                    linkAddr
	segment                int
	up, dropLAN, applied   bool
	appliedPSK             wgtypes.Key
	applies, restores      int
	multicasts, broadcasts int
}

func newMeshSimulation(t *testing.T) *meshSimulation {
	s := &meshSimulation{t: t, now: time.Unix(1000, 0)}
	s.next = s.now
	keys := [2]wgtypes.Key{controlTestKey(11), controlTestKey(22)}
	ips := [2]netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")}
	lans := [2]string{"192.0.2.2/24", "192.0.2.3/24"}
	for i := range s.nodes {
		n := &meshNode{s: s, up: true, lan: linkAddr{Index: 10 + i, Name: "lan0", Prefix: netip.MustParsePrefix(lans[i]), Broadcast: netip.MustParseAddr("192.0.2.255"), Multicast: true}}
		c := defaults()
		c.Address = ips[i]
		c.Peers = []peerSpec{{IP: ips[1-i], key: keys[1-i].PublicKey(), psk: controlTestKey(33)}}
		tunnel := linkAddr{Index: 20 + i, Name: "wg0", Prefix: netip.PrefixFrom(ips[i], 32)}
		n.m = newMesh(c, n, n, keys[i], uint16(51830+i), tunnel, false)
		// Test-only entropy; protocol tokens are opaque to the simulation.
		n.m.crypto.random = rand.New(rand.NewSource(int64(i + 1)))
		n.p = n.m.peers[c.Peers[0].key]
		s.nodes[i] = n
	}
	s.nodes[0].other, s.nodes[1].other = s.nodes[1], s.nodes[0]
	return s
}

func (n *meshNode) Incoming() <-chan packet  { return nil }
func (n *meshNode) Changed() <-chan struct{} { return nil }
func (n *meshNode) Close() error             { return nil }
func (n *meshNode) Check() error             { return nil }
func (n *meshNode) Links() ([]linkAddr, error) {
	if n.up {
		return []linkAddr{n.lan}, nil
	}
	return nil, nil
}

func (n *meshNode) Apply(key wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort) error {
	n.s.t.Helper()
	if key != n.other.m.public || ip != n.other.m.c.Address || psk != n.p.spec.psk || endpoint != netip.AddrPortFrom(n.other.lan.Prefix.Addr(), n.other.m.wgPort) {
		n.s.t.Fatal("incorrect direct route arguments")
	}
	if n.p.spec.PresharedKeyFile != "" && psk == (wgtypes.Key{}) {
		n.s.t.Fatal("file-backed peer was installed without a PSK")
	}
	n.applies++
	n.applied = true
	n.appliedPSK = psk
	return nil
}

func (n *meshNode) Restore(key wgtypes.Key) error {
	if key != n.other.m.public {
		n.s.t.Fatal("incorrect restore key")
	}
	n.restores++
	n.applied = false
	return nil
}

func (n *meshNode) Send(data []byte, dst netip.AddrPort, link linkAddr) error {
	s, other := n.s, n.other
	if dst.Port() != other.m.c.Port || (link != n.lan && link != n.m.tunnel) {
		s.t.Fatal("incorrect discovery port or source link")
	}
	lanOK := n.up && other.up && n.segment == other.segment && !n.dropLAN
	delay, index := time.Millisecond, other.lan.Index
	if link == n.m.tunnel {
		if dst.Addr() != other.m.c.Address {
			s.t.Fatal("incorrect tunnel destination")
		}
		index, delay = other.m.tunnel.Index, 50*time.Millisecond
		if n.applied || other.applied {
			// Asymmetric route changes drop packets, rather than inventing a fast path.
			if !n.applied || !other.applied || n.appliedPSK != other.appliedPSK || s.blockedWG || !lanOK {
				return nil
			}
			delay = time.Millisecond
		}
	} else {
		multicast, broadcast := dst.Addr().IsMulticast(), dst.Addr() == n.lan.Broadcast
		if multicast {
			n.multicasts++
		}
		if broadcast {
			n.broadcasts++
		}
		if !multicast && !broadcast && dst.Addr() != other.lan.Prefix.Addr() {
			s.t.Fatal("incorrect LAN destination")
		}
		if !lanOK || multicast && s.dropMulticast {
			return nil
		}
	}
	e := meshDelivery{s.now.Add(delay), other, packet{Data: slices.Clone(data), Source: netip.AddrPortFrom(link.Prefix.Addr(), n.m.c.Port), Destination: dst.Addr(), IfIndex: index}}
	// Keep delivery order stable for equal timestamps, including generated replies.
	i := len(s.queue)
	for i > 0 && s.queue[i-1].at.After(e.at) {
		i--
	}
	s.queue = slices.Insert(s.queue, i, e)
	return nil
}

func (s *meshSimulation) run(d time.Duration) {
	s.t.Helper()
	end := s.now.Add(d)
	for {
		if len(s.queue) > 0 && !s.queue[0].at.After(s.next) && !s.queue[0].at.After(end) {
			e := s.queue[0]
			s.queue, s.now = s.queue[1:], e.at
			if err := e.to.m.receive(e.p, s.now); err != nil {
				s.t.Fatal(err)
			}
			continue
		}
		if s.next.After(end) {
			break
		}
		s.now, s.next = s.next, s.next.Add(time.Duration(s.nodes[0].m.c.Probe))
		for _, n := range s.nodes {
			if err := n.m.refresh(s.now); err != nil {
				s.t.Fatal(err)
			}
			if err := n.m.tick(s.now); err != nil {
				s.t.Fatal(err)
			}
		}
	}
	s.now = end
}

func (s *meshSimulation) active() {
	s.t.Helper()
	for i, n := range s.nodes {
		rtt, ok := n.p.tunnel.median(s.now, n.m.c)
		if n.p.phase != "active" || !n.applied || !ok || rtt != 2*time.Millisecond || n.p.baseline != 100*time.Millisecond {
			s.t.Fatalf("node %d: phase=%q applied=%v RTT=%v ready=%v baseline=%v", i, n.p.phase, n.applied, rtt, ok, n.p.baseline)
		}
	}
}

func TestMeshDirectTrial(t *testing.T) {
	s := newMeshSimulation(t)
	s.run(15 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 0 {
			t.Fatal("route changed before baseline qualification")
		}
	}
	s.run(3 * time.Second)
	for _, n := range s.nodes {
		if n.p.phase != "trial" || n.applies != 1 || !n.applied {
			t.Fatal("both peers must apply the trial route")
		}
	}
	s.run(13 * time.Second)
	for _, n := range s.nodes {
		if n.p.phase != "trial" {
			t.Fatal("trial ended before its 15-second measurement window")
		}
	}
	s.run(4 * time.Second)
	s.active()
}

func TestMeshBroadcastFallback(t *testing.T) {
	s := newMeshSimulation(t)
	s.dropMulticast = true
	for _, n := range s.nodes {
		n.m.c.Discovery, n.m.c.BroadcastAfter = duration(3*time.Second), duration(5*time.Second)
	}
	s.run(4 * time.Second)
	for _, n := range s.nodes {
		if n.multicasts == 0 || n.broadcasts != 0 || len(n.p.paths) != 0 || n.applies != 0 {
			t.Fatal("multicast loss did not defer discovery until fallback")
		}
	}
	s.run(36 * time.Second)
	s.active()
	for _, n := range s.nodes {
		if n.broadcasts == 0 || !n.p.discovery[n.lan].broadcast || !n.p.discovery[n.lan].proof.IsZero() {
			t.Fatal("broadcast fallback incorrectly required multicast proof")
		}
	}
}

func TestMeshLossRollbackAndCooldown(t *testing.T) {
	for _, mode := range []string{"LAN loss", "one-way loss", "interface removed"} {
		t.Run(mode, func(t *testing.T) {
			s := newMeshSimulation(t)
			for _, n := range s.nodes {
				n.m.c.Discovery = duration(3 * time.Second)
			}
			s.run(35 * time.Second)
			s.active()
			s.nodes[0].dropLAN = true
			if mode == "LAN loss" {
				s.nodes[1].dropLAN = true
			}
			if mode == "interface removed" {
				s.nodes[0].up = false
			}
			s.run(7 * time.Second)
			deadline := s.nodes[0].p.cooldown
			for _, n := range s.nodes {
				if n.applied || n.p.phase != "" || n.p.selected != nil || n.restores != 1 || !n.p.cooldown.After(s.now) {
					t.Fatal("loss did not restore the hub route and start cooldown")
				}
				if n.p.cooldown.Before(deadline) {
					deadline = n.p.cooldown
				}
				n.up, n.dropLAN = true, false
			}
			s.run(deadline.Sub(s.now) - time.Second)
			for _, n := range s.nodes {
				if n.applies != 1 || n.applied {
					t.Fatal("direct route retried during cooldown")
				}
				c := n.p.paths[pathName(n.lan, netip.AddrPortFrom(n.other.lan.Prefix.Addr(), n.m.c.Port))]
				if c == nil {
					t.Fatal("recovered LAN was not rediscovered during cooldown")
				}
				if _, ok := n.m.qualified(n.p, c, s.now); !ok {
					t.Fatal("cooldown test requires a qualified alternative to the hub")
				}
			}
			// Link-event and probe-timeout recovery can start different cooldowns.
			// Allow a rejected early proposal, one cooldown retry, and a full trial.
			s.run(80 * time.Second)
			s.active()
		})
	}
}

func TestMeshWireGuardBlocked(t *testing.T) {
	s := newMeshSimulation(t)
	s.blockedWG = true
	s.run(18 * time.Second)
	for _, n := range s.nodes {
		if n.p.phase != "trial" || n.applies != 1 || !n.m.fresh(n.p.selected, s.now) || !n.p.lastTunnel.IsZero() {
			t.Fatal("expected healthy discovery but a blocked WireGuard trial")
		}
	}
	s.run(7 * time.Second)
	for _, n := range s.nodes {
		if n.applied || n.p.phase != "" || n.restores != 1 || len(n.p.paths) != 1 {
			t.Fatal("blocked WireGuard did not roll back despite working discovery")
		}
	}
}

func TestMeshNoChanges(t *testing.T) {
	for _, mode := range []string{"dry run", "separate LANs"} {
		t.Run(mode, func(t *testing.T) {
			s := newMeshSimulation(t)
			if mode == "separate LANs" {
				s.nodes[1].segment = 1 // Multicast and broadcast cannot cross this boundary.
			}
			for _, n := range s.nodes {
				n.m.dry = mode == "dry run"
				n.m.c.Discovery, n.m.c.BroadcastAfter = duration(3*time.Second), duration(5*time.Second)
			}
			s.run(40 * time.Second)
			for _, n := range s.nodes {
				if n.applies != 0 || n.restores != 0 || n.p.phase != "" || n.p.selected != nil {
					t.Fatal("unsafe or dry-run route change")
				}
				if mode == "dry run" {
					if len(n.p.paths) != 1 {
						t.Fatal("dry run did not discover the eligible path")
					}
					for _, c := range n.p.paths {
						if _, ok := n.m.qualified(n.p, c, s.now); !ok {
							t.Fatal("dry-run path did not qualify")
						}
					}
				} else if len(n.p.paths) != 0 || n.multicasts == 0 || n.broadcasts == 0 {
					t.Fatal("separate LANs must remain undiscovered after both discovery methods")
				}
			}
		})
	}
}

func TestMeasurementsAndImprovement(t *testing.T) {
	c, now := defaults(), time.Unix(1000, 0)
	w := measurements{since: now.Add(-time.Duration(c.Window))}
	for i := 0; i < 11; i++ {
		w.add(now.Add(time.Duration(i-10)*time.Second), time.Duration(i+1)*time.Millisecond, time.Duration(c.Window))
	}
	if _, ok := w.median(now, c); ok {
		t.Fatal("fewer than 12 of 15 samples qualified")
	}
	w.add(now, 12*time.Millisecond, time.Duration(c.Window))
	if rtt, ok := w.median(now, c); !ok || rtt != 7*time.Millisecond {
		t.Fatal("minimum sample count or median is incorrect")
	}
	if _, ok := w.median(now.Add(-time.Nanosecond), c); ok {
		t.Fatal("incomplete window qualified")
	}
	if _, ok := w.median(now.Add(time.Duration(c.Window)), c); ok {
		t.Fatal("expired samples still qualified")
	}
	w.add(now.Add(time.Duration(c.Window)+time.Nanosecond), time.Millisecond, time.Duration(c.Window))
	if len(w.samples) != 1 {
		t.Fatal("add retained expired samples")
	}
	for _, tc := range []struct {
		candidate, baseline time.Duration
		want                bool
	}{{80, 100, true}, {81, 100, false}, {1, 2, false}, {8, 10, true}, {100, 100, false}, {101, 100, false}} {
		if improves(tc.candidate*time.Millisecond, tc.baseline*time.Millisecond, c) != tc.want {
			t.Errorf("incorrect improvement decision: %+v", tc)
		}
	}
}

func TestMeshUnsolicitedPongPreservesCandidate(t *testing.T) {
	s := newMeshSimulation(t)
	s.run(2200 * time.Millisecond) // Drain the scheduled LAN and hub replies.
	n := s.nodes[0]
	c := n.p.paths[pathName(n.lan, netip.AddrPortFrom(n.other.lan.Prefix.Addr(), n.m.c.Port))]
	if c == nil || !n.m.fresh(c, s.now) {
		t.Fatal("missing confirmed candidate")
	}
	before := *c
	id, _, _ := secureTestOpen(t, n.other.m.crypto, n.m.crypto, s.now)
	if id == before.session || !n.other.m.send(id, message{Op: "pong", Token: "unsolicited", Port: 65000}, netip.AddrPortFrom(n.lan.Prefix.Addr(), n.m.c.Port), n.other.lan, s.now) {
		t.Fatal("could not send a pong on a different authenticated session")
	}
	s.run(time.Millisecond)
	if !n.m.crypto.sessions[id].ready {
		t.Fatal("pong was not authenticated by the receiver")
	}
	if c.session != before.session || c.port != before.port || c.incoming != before.incoming || c.lastPong != before.lastPong || len(c.stats.samples) != len(before.stats.samples) {
		t.Fatal("unsolicited pong changed the confirmed candidate")
	}
}

func TestMeshLinkLocalNeverQualifies(t *testing.T) {
	s := newMeshSimulation(t)
	for _, n := range s.nodes {
		n.m.dry = true
	}
	s.run(18 * time.Second)
	n := s.nodes[0]
	c := n.p.paths[pathName(n.lan, netip.AddrPortFrom(n.other.lan.Prefix.Addr(), n.m.c.Port))]
	if c == nil {
		t.Fatal("missing measured candidate")
	}
	candidate := *c
	for _, tc := range []struct {
		endpoint string
		want     bool
	}{{"192.0.2.3:51823", true}, {"[fd00::3]:51823", true}, {"[fe80::3]:51823", false}, {"[fe80::3%lan0]:51823", false}} {
		candidate.addr = netip.MustParseAddrPort(tc.endpoint)
		if _, ok := n.m.qualified(n.p, &candidate, s.now); ok != tc.want {
			t.Errorf("qualification for %s = %v, want %v", tc.endpoint, ok, tc.want)
		}
	}
}

func TestMeshTrialNeedsCurrentApprovals(t *testing.T) {
	setup := func() (*meshSimulation, *meshNode) {
		s := newMeshSimulation(t)
		s.run(18 * time.Second)
		n, window := s.nodes[0], time.Duration(s.nodes[0].m.c.Window)
		p := n.p
		p.since = s.now.Add(-window)
		p.tunnel = measurements{since: p.since}
		// Exactly 12 samples qualify; the oldest expires one nanosecond later.
		for i := 0; i < 11; i++ {
			p.tunnel.add(p.since.Add(time.Duration(i)*time.Second), 2*time.Millisecond, window)
		}
		p.tunnel.add(s.now, 2*time.Millisecond, window)
		p.lastTunnel, p.remoteGood, p.committed = s.now, false, true
		return s, n
	}
	s, n := setup()
	p := n.p
	if err := n.m.advance(p, s.now); err != nil || !p.localGood || p.phase != "trial" {
		t.Fatal("local approval was not established while awaiting remote approval:", err)
	}
	s.now = s.now.Add(time.Nanosecond)
	p.remoteGood, p.remoteAt = true, s.now
	if err := n.m.advance(p, s.now); err != nil || p.localGood || p.phase != "" || n.applied || n.restores != 1 {
		t.Fatal("an insufficient complete window did not restore the stable route:", err)
	}
	s, n = setup()
	p = n.p
	p.remoteGood = true
	p.remoteAt = s.now.Add(-time.Duration(n.m.c.Failure))
	if err := n.m.advance(p, s.now); err != nil || !p.localGood || p.phase != "trial" {
		t.Fatal("expired remote approval activated the trial:", err)
	}
	p.remoteAt = s.now
	if err := n.m.advance(p, s.now); err != nil || p.phase != "active" || n.restores != 0 {
		t.Fatal("fresh local and remote approval did not activate the trial:", err)
	}
}

func TestMeshOneScheduledSamplePerInterval(t *testing.T) {
	s := newMeshSimulation(t)
	for _, n := range s.nodes {
		n.m.dry = true
	}
	s.run(20 * time.Second)
	for _, n := range s.nodes {
		for _, c := range n.p.paths {
			if count := len(c.stats.samples); count < 12 || count > 16 {
				t.Fatalf("confirmation traffic changed the scheduled measurement count: %d", count)
			}
		}
	}
}

func TestMeshTrialAllowsRemoteMinuteWindow(t *testing.T) {
	s := newMeshSimulation(t)
	s.nodes[1].m.c.Window = duration(time.Minute)
	// Isolate trial timing from retries while the longer baseline window fills.
	for _, n := range s.nodes {
		n.p.cooldown = s.now.Add(62 * time.Second)
	}
	s.run(100 * time.Second)
	for i, n := range s.nodes {
		if n.p.phase != "trial" || n.applies != 1 || n.restores != 0 || n.p.localGood != (i == 0) {
			t.Fatalf("node %d did not wait for the longer remote window", i)
		}
	}
	s.run(30 * time.Second)
	s.active()
}

func TestMeshVerifyFailurePreventsConfiguration(t *testing.T) {
	s := newMeshSimulation(t)
	s.run(2200 * time.Millisecond)
	n := s.nodes[0]
	n.p.selected = n.m.candidate(n.p, n.lan, netip.AddrPortFrom(n.other.lan.Prefix.Addr(), n.m.c.Port), s.now)
	n.p.phase, n.p.trial = "prepared", "verify-failure"
	injected, calls := errors.New("injected preflight failure"), 0
	n.m.verify = func() error {
		calls++
		return injected
	}
	if err := n.m.tick(s.now); !errors.Is(err, injected) {
		t.Fatal("tick did not return the preflight error:", err)
	}
	msg := message{Op: "commit", Token: n.p.trial, Port: n.other.m.wgPort}
	msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.other.m.public, n.m.public)
	if err := n.m.coordinate(n.p, n.p.selected, msg, s.now); !errors.Is(err, injected) {
		t.Fatal("commit did not return the preflight error:", err)
	}
	if calls != 2 || n.p.phase != "prepared" || n.applies != 0 || n.restores != 0 || n.other.applies != 0 || n.other.restores != 0 {
		t.Fatal("preflight failure changed route configuration or trial state")
	}
}
