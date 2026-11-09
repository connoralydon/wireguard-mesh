package main

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLANFirstGate(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{LANFirst: duration(30 * time.Second)}
	n.m.enableNAT(nil)
	n.m.natTick(s.now)
	deadline := n.m.nat.lanUntil[n.p.spec.key]
	if deadline != s.now.Add(30*time.Second) || n.m.nat.engine != nil {
		t.Fatal("NAT started before the LAN deadline")
	}
	n.m.natTick(s.now.Add(time.Second))
	if n.m.nat.lanUntil[n.p.spec.key] != deadline {
		t.Fatal("periodic tick reset the LAN deadline")
	}
	// No host socket is needed to check the gate after the deadline.
	later := deadline.Add(time.Second)
	n.old.lastPong = later
	if n.m.natAllowed(n.p, later) {
		t.Fatal("healthy LAN allowed NAT")
	}
	n.m.natTick(later)
	if n.m.nat.engine != nil {
		t.Fatal("healthy LAN started the ICE engine")
	}
	n.old.lastPong = s.now
	n.next.lastPong = s.now
	if !n.m.natAllowed(n.p, later) {
		t.Fatal("failed LAN did not allow NAT fallback")
	}
}

func TestLANFirstRequiresQualifiedCandidate(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{LANFirst: duration(30 * time.Second)}
	n.m.enableNAT(nil)
	n.p.phase, n.p.selected = "", nil
	n.p.tunnel = replacementSamples(s.now, 30*time.Millisecond)
	n.next.stats = replacementSamples(s.now, 10*time.Millisecond)
	n.old.lastPong = time.Time{}
	if n.m.natAllowed(n.p, s.now) {
		t.Fatal("qualified LAN allowed NAT")
	}
	n.next.stats = replacementSamples(s.now, 40*time.Millisecond)
	if !n.m.natAllowed(n.p, s.now) {
		t.Fatal("poor LAN blocked NAT")
	}
	n.next.stats = measurements{since: s.now}
	if !n.m.natAllowed(n.p, s.now) {
		t.Fatal("unready LAN blocked NAT")
	}
}

func TestFailedLANTrialAllowsNATAndRetriesLater(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{LANFirst: duration(30 * time.Second)}
	n.m.enableNAT(nil)
	n.m.nat.lanUntil[n.p.spec.key] = s.now.Add(-time.Second)
	n.p.paths = map[string]*path{"lan": n.next}
	n.p.selected, n.p.phase, n.p.since = n.next, "trial", s.now.Add(-time.Duration(n.m.c.Failure))
	n.p.lastTunnel = time.Time{} // LAN control works, but WireGuard does not.
	n.next.lastPong = s.now
	if err := n.m.advance(n.p, s.now); err != nil {
		t.Fatal(err)
	}
	if n.p.phase != "" || !n.m.natAllowed(n.p, s.now) {
		t.Fatal("failed LAN trial did not open NAT fallback")
	}
	n.p.tunnel = replacementSamples(s.now, 30*time.Millisecond)
	n.next.stats = replacementSamples(s.now, time.Millisecond)
	if _, ok := n.m.qualified(n.p, n.next, s.now); ok {
		t.Fatal("fresh control probes immediately retried the failed LAN route")
	}
	later := n.next.retryAt
	n.next.lastPong = later
	n.next.stats = replacementSamples(later, time.Millisecond)
	n.p.tunnel = replacementSamples(later, 30*time.Millisecond)
	if _, ok := n.m.qualified(n.p, n.next, later); !ok {
		t.Fatal("LAN route remained suppressed after retry time")
	}
}

func TestFailedLANExclusionExpiresAndPreservesWAN(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.enableNAT(nil)
	lan := netip.MustParseAddr("172.21.4.3")
	n.m.links = []linkAddr{{Prefix: netip.MustParsePrefix("172.21.4.2/24")}}
	n.next.addr = netip.AddrPortFrom(lan, 51821)
	n.m.failLAN(n.p, n.next, s.now)
	if got := n.m.excludedLAN(n.p.spec.key, s.now); len(got) != 1 || got[0] != lan {
		t.Fatalf("failed LAN exclusion: %v", got)
	}
	engine := &iceTraversal{excluded: make(map[wgtypes.Key]map[netip.Addr]bool)}
	if _, err := engine.SetExcludedIPs(n.p.spec.key, n.m.excludedLAN(n.p.spec.key, s.now)); err != nil || engine.allowedRemoteIP(n.p.spec.key, lan) {
		t.Fatalf("failed LAN was not excluded from ICE: %v", err)
	}
	wan := &path{nat: true, addr: netip.MustParseAddrPort("192.0.2.13:40001")}
	n.m.failLAN(n.p, wan, s.now)
	if got := n.m.excludedLAN(n.p.spec.key, s.now); len(got) != 1 || got[0] != lan {
		t.Fatalf("WAN failure changed exclusions: %v", got)
	}
	if got := n.m.excludedLAN(n.p.spec.key, n.next.retryAt); len(got) != 0 {
		t.Fatalf("expired exclusion remains: %v", got)
	}
	wan.addr = netip.AddrPortFrom(lan, 51821)
	n.m.failLAN(n.p, wan, s.now)
	if got := n.m.excludedLAN(n.p.spec.key, s.now); len(got) != 1 || got[0] != lan {
		t.Fatalf("on-link ICE trial was not excluded: %v", got)
	}
}

func TestFailedLANBlocksCachedRawPath(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{}
	n.m.enableNAT(nil)
	n.p.phase, n.p.selected = "", nil
	n.p.paths = map[string]*path{}
	lan := netip.MustParseAddrPort("172.21.4.3:51821")
	link := linkAddr{Prefix: netip.MustParsePrefix("172.21.4.2/24")}
	raw := &path{nat: true, addr: lan, link: link, port: lan.Port(), lastPong: s.now, stats: replacementSamples(s.now, time.Millisecond)}
	n.p.tunnel = replacementSamples(s.now, 30*time.Millisecond)
	if _, ok := n.m.qualified(n.p, raw, s.now); !ok {
		t.Fatal("raw path did not qualify before failure")
	}
	// The path's own link remains authoritative even if the current link
	// snapshot has changed while a trial was in flight.
	n.m.links = nil
	n.m.failLAN(n.p, raw, s.now)
	cached := *raw
	cached.retryAt = time.Time{} // Another cached endpoint for the same IP.
	if _, ok := n.m.qualified(n.p, &cached, s.now); ok {
		t.Fatal("fresh cached raw path bypassed the failed IP backoff")
	}
	newLAN := cached
	newLAN.nat = false
	if _, ok := n.m.qualified(n.p, &newLAN, s.now); !ok {
		t.Fatal("new normal LAN path was blocked by raw IP exclusion")
	}
	wan := cached
	wan.addr = netip.MustParseAddrPort("192.0.2.13:40011")
	if _, ok := n.m.qualified(n.p, &wan, s.now); !ok {
		t.Fatal("off-link NAT rebind was blocked")
	}
	later := raw.retryAt
	cached.lastPong = later
	cached.stats = replacementSamples(later, time.Millisecond)
	n.p.tunnel = replacementSamples(later, 30*time.Millisecond)
	if _, ok := n.m.qualified(n.p, &cached, later); !ok {
		t.Fatal("cached raw path remained blocked after backoff")
	}
}

func TestFailedLANBackoffSurvivesCandidateExpiry(t *testing.T) {
	s := newMeshSimulation(t)
	n := s.nodes[0]
	n.m.c.NAT = &natConfig{}
	n.m.enableNAT(nil)
	n.m.nat.lanUntil[n.p.spec.key] = s.now.Add(time.Minute)
	c := n.m.candidate(n.p, n.lan, netip.AddrPortFrom(n.other.lan.Prefix.Addr(), n.m.c.Port), s.now)
	c.port, c.lastPong = n.m.wgPort, s.now
	n.m.failLAN(n.p, c, s.now)
	later := s.now.Add(time.Duration(n.m.c.Failure) + time.Second)
	if err := n.m.tick(later); err != nil {
		t.Fatal(err)
	}
	if got := n.m.candidate(n.p, c.link, c.addr, later); got != c || !later.Before(got.retryAt) {
		t.Fatal("ordinary candidate expiry cleared the failed LAN backoff")
	}
	// Only a meaningful link change, not lost or delayed control replies,
	// removes this path's retry state and permits a new LAN candidate.
	n.up = false
	if err := n.m.refresh(later); err != nil {
		t.Fatal(err)
	}
	n.up = true
	if err := n.m.refresh(later); err != nil {
		t.Fatal(err)
	}
	if got := n.m.candidate(n.p, c.link, c.addr, later); got == c || !got.retryAt.IsZero() {
		t.Fatal("link cycle did not permit a new LAN candidate")
	}
}

func TestFailedLANOverflowPausesNAT(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{}
	n.m.enableNAT(nil)
	n.p.phase, n.p.selected = "", nil
	n.p.paths = map[string]*path{}
	link := linkAddr{Prefix: netip.MustParsePrefix("172.21.4.2/24")}
	n.m.links = []linkAddr{link}
	for i := 1; i <= 17; i++ {
		ip := netip.AddrFrom4([4]byte{172, 21, 4, byte(i)})
		c := &path{addr: netip.AddrPortFrom(ip, 51821), link: link}
		n.m.failLAN(n.p, c, s.now.Add(time.Duration(i)*time.Second))
	}
	key := n.p.spec.key
	if len(n.m.nat.failedLAN[key]) != 16 {
		t.Fatalf("failure state is not bounded: %d", len(n.m.nat.failedLAN[key]))
	}
	now := s.now.Add(17 * time.Second)
	deadline := n.m.nat.failedLANUntil[key]
	if !deadline.Equal(now.Add(max(2*time.Minute, 2*time.Duration(n.m.c.Window)+30*time.Second))) {
		t.Fatalf("unexpected pause deadline: %v", deadline)
	}
	raw := &path{nat: true, addr: netip.MustParseAddrPort("172.21.4.17:40000"), port: 40000, lastPong: now, stats: replacementSamples(now, time.Millisecond)}
	n.p.tunnel = replacementSamples(now, 30*time.Millisecond)
	if n.m.natAllowed(n.p, now) {
		t.Fatal("overflow allowed NAT discovery")
	}
	if _, ok := n.m.qualified(n.p, raw, now); ok {
		t.Fatal("untracked failed IP qualified through a cached raw path")
	}
	// A later failure during the pause must extend it, even after a slot opens.
	laterFailure := deadline.Add(-time.Second)
	n.m.failLAN(n.p, &path{addr: netip.MustParseAddrPort("172.21.4.18:51821"), link: link}, laterFailure)
	deadline = laterFailure.Add(max(2*time.Minute, 2*time.Duration(n.m.c.Window)+30*time.Second))
	if n.m.nat.failedLANUntil[key] != deadline || n.m.natAllowed(n.p, laterFailure) {
		t.Fatal("later failure did not extend the NAT pause")
	}
	healthy := *raw
	healthy.addr = netip.MustParseAddrPort("192.0.2.13:40001")
	healthy.lastPong = laterFailure
	n.p.selected, n.p.phase = &healthy, "active"
	n.m.natTick(laterFailure)
	if n.p.selected != &healthy || n.p.phase != "active" {
		t.Fatal("overflow tore down a healthy NAT route")
	}
	n.p.selected, n.p.phase = nil, ""
	newLAN := *raw
	newLAN.nat = false
	if _, ok := n.m.qualified(n.p, &newLAN, now); !ok {
		t.Fatal("overflow blocked a new normal LAN path")
	}
	n.p.selected, n.p.phase = &newLAN, "active"
	newLAN.lastPong = deadline
	if n.m.natAllowed(n.p, deadline) {
		t.Fatal("healthy active LAN did not remain preferred")
	}
	n.p.selected, n.p.phase = nil, ""
	raw.lastPong = deadline
	raw.stats = replacementSamples(deadline, time.Millisecond)
	n.p.tunnel = replacementSamples(deadline, 30*time.Millisecond)
	if _, ok := n.m.qualified(n.p, raw, deadline); !ok {
		t.Fatal("NAT did not recover after all failure windows expired")
	}
}

func TestFailedLANReplacementRestoresNAT(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{LANFirst: duration(30 * time.Second)}
	n.m.enableNAT(nil)
	n.old.nat = true
	old := n.p.routeState
	n.p.previous = &old
	n.p.selected, n.p.phase, n.p.since = n.next, "trial", s.now.Add(-time.Duration(n.m.c.Failure))
	n.p.lastTunnel = time.Time{}
	n.old.lastPong, n.next.lastPong = s.now, s.now
	if err := n.m.advance(n.p, s.now); err != nil {
		t.Fatal(err)
	}
	if n.p.selected != n.old || n.p.phase != "active" || n.p.previous != nil {
		t.Fatal("failed LAN replacement did not restore the NAT route")
	}
	if !s.now.Before(n.next.retryAt) {
		t.Fatal("failed LAN replacement was not delayed")
	}
}

func TestHubProbeReplyInterfaceBinding(t *testing.T) {
	s, nodes := replacementPair(t)
	n, other := nodes[0], nodes[1]
	n.m.directTunnel = linkAddr{Index: 999}
	id := n.old.session
	n.p.hub = measurements{since: s.now.Add(-time.Minute)}
	n.p.pending["hub"] = probe{at: s.now, session: id, ifIndex: n.m.tunnel.Index, hub: true}
	body, err := json.Marshal(message{Op: "pong", Token: "hub", Port: other.m.wgPort})
	if err != nil {
		t.Fatal(err)
	}
	reply := func(index int) {
		data, err := other.m.crypto.Seal(id, body, s.now)
		if err != nil {
			t.Fatal(err)
		}
		err = n.m.receive(packet{Data: data, Source: netip.AddrPortFrom(other.m.c.Address, n.m.c.Port), Destination: n.m.c.Address, IfIndex: index}, s.now.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
	}
	reply(n.m.directTunnel.Index)
	if len(n.p.hub.samples) != 0 || len(n.p.pending) == 0 {
		t.Fatal("direct reply accepted as a hub measurement")
	}
	reply(n.m.tunnel.Index)
	if len(n.p.hub.samples) != 1 {
		t.Fatal("stable-interface reply did not record a hub measurement")
	}
}

func TestNATToLANUsesFreshHubBaseline(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.NAT = &natConfig{LANFirst: duration(30 * time.Second)}
	n.m.enableNAT(nil)
	n.old.nat = true
	n.old.stats = replacementSamples(s.now, 2*time.Millisecond)
	n.next.stats = replacementSamples(s.now, 10*time.Millisecond)
	n.p.tunnel = replacementSamples(s.now, 3*time.Millisecond)
	n.p.hub = replacementSamples(s.now, 30*time.Millisecond)
	base, ok := n.m.qualified(n.p, n.next, s.now)
	if !ok || base != 30*time.Millisecond {
		t.Fatalf("LAN did not qualify against hub: baseline %v, qualified %v", base, ok)
	}
	n.p.selected, n.p.phase, n.p.baseline = n.next, "trial", base
	n.p.since, n.p.lastTunnel = s.now.Add(-time.Minute), s.now
	n.p.tunnel = replacementSamples(s.now, 10*time.Millisecond)
	if err := n.m.advance(n.p, s.now); err != nil || !n.p.localGood {
		t.Fatalf("LAN trial did not use hub baseline: localGood %v, error %v", n.p.localGood, err)
	}
	n.p.selected, n.p.phase = n.old, "active"
	n.p.hub = replacementSamples(s.now.Add(-time.Minute), 30*time.Millisecond)
	if _, ok := n.m.qualified(n.p, n.next, s.now); ok {
		t.Fatal("stale hub samples qualified LAN")
	}
}
