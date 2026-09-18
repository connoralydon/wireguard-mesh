package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type rekeyFake struct {
	*meshNode
	handshake time.Time
	rekeys    int
	err       error
}

func (f *rekeyFake) Rekey(key, old, next wgtypes.Key) error {
	if key != f.p.spec.key || old != f.appliedPSK || next == old || next == (wgtypes.Key{}) || !f.applied {
		f.s.t.Fatal("invalid rekey operation")
	}
	if f.err != nil {
		return f.err
	}
	f.appliedPSK = next
	f.rekeys++
	return nil
}

func (f *rekeyFake) Handshake(wgtypes.Key) (time.Time, error) { return f.handshake, nil }

func rekeySimulation(t *testing.T) (*meshSimulation, [2]*rekeyFake) {
	t.Helper()
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, true)
	var controls [2]*rekeyFake
	for i, n := range s.nodes {
		n.p.spec.ExperimentalRekey = true
		controls[i] = &rekeyFake{meshNode: n, handshake: s.now}
		n.m.control = controls[i]
	}
	s.run(35 * time.Second)
	s.active()
	for _, n := range s.nodes {
		if !n.p.remoteRekey {
			t.Fatal("rekey capability not negotiated")
		}
	}
	return s, controls
}

func TestPSKProofBinding(t *testing.T) {
	key, a, b := controlTestKey(1), controlTestKey(2), controlTestKey(3)
	msg := message{Op: "rekey-ready", Token: "fresh-challenge"}
	msg.Proof = pskProof(key, msg.Op, msg.Token, a, b)
	if !checkPSKProof(key, msg, a, b) {
		t.Fatal("valid proof rejected")
	}
	if checkPSKProof(key, msg, b, a) || checkPSKProof(controlTestKey(4), msg, a, b) {
		t.Fatal("proof not bound to key and direction")
	}
	for _, changed := range []message{{Op: "rekey-commit", Token: msg.Token, Proof: msg.Proof}, {Op: msg.Op, Token: "old-challenge", Proof: msg.Proof}, {Op: msg.Op, Token: msg.Token}} {
		if checkPSKProof(key, changed, a, b) {
			t.Fatal("operation, challenge, or proof not checked")
		}
	}
}

func TestMeshExperimentalRekey(t *testing.T) {
	s, controls := rekeySimulation(t)
	var paths [2]*path
	for i, n := range s.nodes {
		paths[i] = n.p.selected
		writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
	}
	s.run(3 * time.Second)
	for _, f := range controls {
		if f.rekeys != 1 || f.p.rekey == nil || f.p.rekey.phase != "observing" || f.restores != 0 {
			t.Fatal("key was not updated in place after mutual confirmation")
		}
	}
	// Working traffic under matching keys is not a handshake observation.
	s.run(5 * time.Second)
	for _, f := range controls {
		if f.p.rekey == nil {
			t.Fatal("traffic completed rekey without a new timestamp")
		}
		f.handshake = s.now
	}
	s.run(4 * time.Second)
	for i, f := range controls {
		if f.p.rekey != nil || f.p.selected != paths[i] || f.rekeys != 1 || f.applies != 1 || f.restores != 0 || f.appliedPSK != controlTestKey(44) {
			t.Fatal("successful experimental update changed the direct path")
		}
	}
}

func TestMeshExperimentalRekeyFallback(t *testing.T) {
	for _, failure := range []string{"mismatch", "one file", "no handshake", "one handshake", "apply error"} {
		t.Run(failure, func(t *testing.T) {
			s, controls := rekeySimulation(t)
			for i, n := range s.nodes {
				if failure == "one file" && i == 1 {
					continue
				}
				key := controlTestKey(44)
				if failure == "mismatch" && i == 1 {
					key = controlTestKey(45)
				}
				writeTestPSK(t, n.p.spec.PresharedKeyFile, key.String(), s.now)
				if failure == "apply error" {
					controls[i].err = errors.New("injected update failure")
				}
			}
			s.run(3 * time.Second)
			if failure == "one handshake" {
				controls[0].handshake = s.now
			}
			if failure == "no handshake" || failure == "one handshake" {
				s.run(90 * time.Second)
			} else {
				s.run(6 * time.Second)
			}
			for _, f := range controls {
				if f.applied || f.p.rekey != nil {
					t.Fatal("failed coordination did not restore hub")
				}
				if (failure == "mismatch" || failure == "one file") && f.rekeys != 0 {
					t.Fatal("key installed without mutual possession")
				}
			}
		})
	}
}

func TestMeshExperimentalRekeyLostCompletion(t *testing.T) {
	s, controls := rekeySimulation(t)
	for _, n := range s.nodes {
		writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
	}
	s.run(3 * time.Second)
	for _, f := range controls {
		f.handshake = s.now
	}
	a := s.nodes[0]
	a.p.rekey.remoteObserved = s.now
	s.queue = nil
	if err := a.m.advance(a.p, s.now); err != nil || a.p.rekey != nil {
		t.Fatal("first peer did not complete its observation", err)
	}
	s.queue = nil // Lose its final observation, not the retry from the other peer.
	s.run(4 * time.Second)
	for _, f := range controls {
		if f.p.rekey != nil || f.rekeys != 1 || f.restores != 0 {
			t.Fatal("completion retry did not recover the lost observation")
		}
	}
}

func TestMeshRekeyDefersNewPath(t *testing.T) {
	s, _ := rekeySimulation(t)
	for _, n := range s.nodes {
		writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
	}
	s.run(3 * time.Second)
	n := s.nodes[0]
	if bytes.Compare(n.m.public[:], n.other.m.public[:]) < 0 {
		n = n.other // Only the follower accepts path proposals.
	}
	old, transition := n.p.selected, n.p.rekey
	n.p.cooldown = s.now
	n.m.c.MinGain = 0
	alternative := *old
	alternative.stats = measurements{since: s.now.Add(-time.Duration(n.m.c.Window))}
	for range 15 {
		alternative.stats.add(s.now, time.Microsecond, time.Duration(n.m.c.Window))
	}
	if _, ok := n.m.qualified(n.p, &alternative, s.now); !ok {
		t.Fatal("test needs a qualified faster alternative")
	}
	msg := message{Op: "rekey-observed", Token: transition.token, Port: n.other.m.wgPort}
	msg.Proof = pskProof(transition.key, msg.Op, msg.Token, n.other.m.public, n.m.public)
	if err := n.m.coordinate(n.p, old, msg, s.now); err != nil {
		t.Fatal(err)
	}
	msg.Op, msg.Token = "prepare", "new-path-before-next-tick"
	msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.other.m.public, n.m.public)
	if err := n.m.coordinate(n.p, &alternative, msg, s.now); err != nil {
		t.Fatal(err)
	}
	if n.p.rekey != transition || n.p.selected != old || n.p.phase != "active" {
		t.Fatal("new path proposal overwrote the unfinished rekey")
	}
}

type discardMeshNetwork struct{ network }

func (discardMeshNetwork) Send([]byte, netip.AddrPort, linkAddr) error { return nil }

func TestMeshRosenpassAgreedLAN(t *testing.T) {
	s := newMeshSimulation(t)
	s.run(5 * time.Second)
	leader, follower := s.nodes[0], s.nodes[1]
	if bytes.Compare(leader.m.public[:], follower.m.public[:]) > 0 {
		leader, follower = follower, leader
	}
	var selected [2]*path
	var reported [2]rosenpassRequest
	for i, n := range []*meshNode{leader, follower} {
		n.p.spec.RosenpassSocket = "/run/adapter.sock"
		n.m.net = discardMeshNetwork{n.m.net}
		n.m.rosenpass = func(_ string, r rosenpassRequest) (rosenpassResponse, error) {
			reported[i] = r
			return rosenpassResponse{}, nil
		}
		for _, c := range n.p.paths {
			copy := *c
			// The leader prefers this link; the follower's local ordering does not.
			copy.link.Index = 1 + i*98
			copy.link.Name = "lan1"
			copy.link.Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 2)}), 24)
			copy.addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(3 - i)}), n.m.c.Port)
			n.m.links = append(n.m.links, copy.link)
			selected[i] = &copy
			break
		}
		n.p.paths[pathName(selected[i].link, selected[i].addr)] = selected[i]
		_, _, _ = n.m.readPeerPSK(n.p, s.now)
	}
	if reported[0].Link != selected[0].link || reported[1].Address.IsValid() {
		t.Fatal("follower independently selected a different Rosenpass LAN")
	}
	msg := message{Op: "rosenpass-select", Token: leader.p.rosenpassToken, Port: leader.m.wgPort}
	if err := follower.m.coordinate(follower.p, selected[1], msg, s.now); err != nil {
		t.Fatal(err)
	}
	_, _, _ = follower.m.readPeerPSK(follower.p, s.now)
	if reported[1].Link != selected[1].link || reported[1].Address != selected[0].link.Prefix.Addr() {
		t.Fatal("follower did not use the authenticated receiving address pair")
	}
	// A WireGuard trial on another path must not disrupt a healthy RP exchange.
	for _, n := range []*meshNode{leader, follower} {
		for _, c := range n.p.paths {
			if c != n.p.rosenpassPath {
				n.p.selected = c
				break
			}
		}
		old := n.p.rosenpassPath
		_, _, _ = n.m.readPeerPSK(n.p, s.now)
		if n.p.rosenpassPath != old {
			t.Fatal("WireGuard proposal restarted a healthy Rosenpass endpoint")
		}
	}
}

func TestMeshRosenpassLANBeforeKey(t *testing.T) {
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, false)
	status := rosenpassResponse{}
	requests := [2]int{}
	for i, n := range s.nodes {
		n.p.spec.RosenpassSocket = "/run/mesh-rp/adapter.sock"
		n.m.rosenpass = func(socket string, r rosenpassRequest) (rosenpassResponse, error) {
			if r.Peer != n.p.spec.key.String() || socket != n.p.spec.RosenpassSocket {
				t.Fatal("unapproved adapter mapping")
			}
			if r.Address.IsValid() {
				if r.Address != n.other.lan.Prefix.Addr() || r.Link != n.lan {
					t.Fatal("incorrect LAN endpoint report")
				}
				requests[i]++
			} else if requests[i] == 0 {
				t.Fatal("startup withdrew an existing exchange before discovery")
			}
			return status, nil
		}
	}
	s.run(5 * time.Second)
	for i, n := range s.nodes {
		if requests[i] == 0 || n.applies != 0 {
			t.Fatal("LAN not reported before first PSK")
		}
		writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(33).String(), s.now)
	}
	key := controlTestKey(33)
	status = rosenpassResponse{Instance: "instance", Generation: 1, KeyGeneration: 1, Hash: sha256.Sum256(key[:]), Expires: s.now.Add(3 * time.Minute), Valid: true}
	s.run(35 * time.Second)
	s.active()
	s.run(5 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 1 || n.restores != 0 {
			t.Fatal("existing valid PSK not reused")
		}
	}
	// A new process must invalidate the active path even if its file key repeats.
	status.Generation++
	s.run(3 * time.Second)
	for _, n := range s.nodes {
		if n.applied {
			t.Fatal("process restart retained old active path")
		}
	}
}

func TestMeshRosenpassReusesLiveProducer(t *testing.T) {
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, true)
	key := controlTestKey(33)
	status := rosenpassResponse{Instance: "already-running", Generation: 9, KeyGeneration: 12,
		Hash: sha256.Sum256(key[:]), Expires: s.now.Add(time.Minute), Valid: true}
	withdrawals := [2]int{}
	for i, n := range s.nodes {
		n.p.spec.RosenpassSocket = "/run/adapter.sock"
		n.m.rosenpass = func(_ string, r rosenpassRequest) (rosenpassResponse, error) {
			if !r.Address.IsValid() {
				withdrawals[i]++
				return rosenpassResponse{}, nil
			}
			return status, nil
		}
	}
	s.run(35 * time.Second)
	s.active()
	for i, n := range s.nodes {
		if withdrawals[i] != 0 || n.p.pskStatus != status || n.applies != 1 || n.restores != 0 {
			t.Fatal("startup did not reuse the live producer's valid PSK")
		}
		n.up = false
	}
	s.run(2 * time.Second)
	for i, n := range s.nodes {
		if withdrawals[i] != 1 || n.applied {
			t.Fatal("loss of a known interface did not withdraw the endpoint")
		}
	}
}

func TestMeshRosenpassStatusFileRace(t *testing.T) {
	for _, failure := range []string{"stale", "hash", "generation", "key generation", "instance", "unavailable"} {
		t.Run(failure, func(t *testing.T) {
			s := newMeshSimulation(t)
			meshPSKFiles(t, s, true)
			s.run(35 * time.Second)
			n := s.nodes[0]
			n.p.spec.RosenpassSocket = "/run/adapter.sock"
			key := n.p.spec.psk
			calls := 0
			n.m.rosenpass = func(_ string, r rosenpassRequest) (rosenpassResponse, error) {
				if r.Address != netip.MustParseAddr("192.0.2.3") {
					t.Fatal("missing LAN address")
				}
				calls++
				status := rosenpassResponse{Instance: "instance", Generation: 1, KeyGeneration: 1, Hash: sha256.Sum256(key[:]), Expires: s.now.Add(time.Minute), Valid: true}
				if failure == "unavailable" {
					return status, errors.New("adapter stopped")
				}
				if failure == "hash" {
					status.Hash = [32]byte{}
				}
				if calls == 2 {
					switch failure {
					case "stale":
						status.Valid = false
					case "generation":
						status.Generation++
					case "key generation":
						status.KeyGeneration++
					case "instance":
						status.Instance = "restarted"
					}
				}
				return status, nil
			}
			if ok, err := n.m.pollPSK(n.p, s.now); err != nil || ok || n.applied {
				t.Fatal("invalid or changing exchange status retained direct peer", err)
			}
		})
	}
}
