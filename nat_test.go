package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestNATConfiguration(t *testing.T) {
	base := fmt.Sprintf(`"address":"10.0.0.2","peers":[{"public_key":%q,"ip":"10.0.0.3"}]`, controlTestKey(7).PublicKey().String())
	for _, fields := range []string{
		`"version":2,"nat_traversal":{"experimental":true,"stun_servers":["203.0.113.1:3478"]}`,
		`"direct_interface":"wg-direct","nat_traversal":{"experimental":true,"stun_servers":["203.0.113.1:3478"]}`,
	} {
		if _, err := readConfig(strings.NewReader("{" + base + "," + fields + "}")); err != nil {
			t.Fatal("valid experimental NAT configuration rejected:", err)
		}
	}
	for _, fields := range []string{
		`"version":2,"nat_traversal":{"stun_servers":["203.0.113.1:3478"]}`,
		`"nat_traversal":{"experimental":true,"stun_servers":["203.0.113.1:3478"]}`,
		`"version":2,"nat_traversal":{"experimental":true,"stun_servers":[]}`,
		`"version":2,"nat_traversal":{"experimental":true,"stun_servers":["127.0.0.1:3478"]}`,
		`"version":2,"nat_traversal":{"experimental":true,"stun_servers":["[2001:db8::1]:3478"]}`,
		`"version":2,"nat_traversal":{"experimental":true,"stun_servers":["203.0.113.1:3478","203.0.113.1:3478"]}`,
		`"version":2,"nat_traversal":{"experimental":true,"stun_servers":["203.0.113.1:3478"],"refresh_interval":"100ms"}`,
	} {
		if _, err := readConfig(strings.NewReader("{" + base + "," + fields + "}")); err == nil {
			t.Fatal("invalid experimental NAT configuration accepted")
		}
	}
}

func TestRouteModeMustMatch(t *testing.T) {
	s := newMeshSimulation(t)
	s.nodes[0].m.c.DirectInterface = "auto"
	s.run(time.Minute)
	for _, n := range s.nodes {
		if n.applied || n.applies != 0 {
			t.Fatal("mixed route modes changed WireGuard before agreement")
		}
	}
}

func TestICESignalsFitEncryptedEnvelope(t *testing.T) {
	nodes, _, keys := iceTestPair(t)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(nodes[0].Signals(keys[1])) == 1 {
		time.Sleep(time.Millisecond)
	}
	for _, signal := range nodes[0].Signals(keys[1]) {
		body, err := json.Marshal(message{Op: "signal", Token: strings.Repeat("x", 26), Port: 51821, ICE: &signal})
		if err != nil || len(body) > secureInnerMaxSize-secureHeaderN-16 {
			t.Fatal("ICE signal exceeds the authenticated envelope budget")
		}
	}
}

func TestNATCandidateAuthorization(t *testing.T) {
	s := newMeshSimulation(t)
	n := s.nodes[0]
	now := s.now
	addr := netip.MustParseAddrPort("203.0.113.10:40001")
	if n.m.rawAuthorized(n.p, addr, now) {
		t.Fatal("unselected ICE endpoint authorized")
	}
	n.p.natOffer, n.p.natOfferAt = addr, now
	if !n.m.rawAuthorized(n.p, addr, now) || n.m.rawAuthorized(n.p, netip.MustParseAddrPort("203.0.113.11:40001"), now) || n.m.rawAuthorized(n.p, addr, now.Add(3*time.Minute)) {
		t.Fatal("ICE candidate source or lifetime binding failed")
	}
}

func TestNATCannotDisplaceHealthyLAN(t *testing.T) {
	s, nodes := replacementPair(t)
	for _, n := range nodes {
		n.next.nat = true
		if _, ok := n.m.qualified(n.p, n.next, s.now); ok {
			t.Fatal("faster experimental ICE candidate displaced healthy LAN")
		}
	}
	leader, follower := nodes[0], nodes[1]
	check := follower.unchanged(t)
	msg := message{Op: "prepare", Token: "ice-prepare", Port: leader.next.port}
	msg.Proof = pskProof(leader.p.spec.psk, msg.Op, msg.Token, leader.m.public, follower.m.public)
	if err := follower.m.coordinate(follower.p, follower.next, msg, s.now); err != nil {
		t.Fatal(err)
	}
	if follower.p.replacement != nil {
		t.Fatal("received ICE proposal displaced healthy LAN")
	}
	check()
}
