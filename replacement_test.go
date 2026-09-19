package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"testing/synctest"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Use the existing simulation to establish the route, then control delivery and
// RTT samples directly. No packet reaches a host socket or a kernel device.
type replacementNetwork struct {
	*meshNode
	links []linkAddr
	sent  []message
}

func (n *replacementNetwork) Links() ([]linkAddr, error) { return n.links, nil }
func (n *replacementNetwork) Send(data []byte, _ netip.AddrPort, _ linkAddr) error {
	e, err := n.other.m.crypto.Receive(data, n.s.now)
	if err != nil {
		return err
	}
	if e.Body != nil {
		var msg message
		if err := json.Unmarshal(e.Body, &msg); err != nil {
			return err
		}
		n.sent = append(n.sent, msg)
	}
	return nil
}

func (n *replacementNetwork) take(t *testing.T, op string) message {
	t.Helper()
	for i := len(n.sent) - 1; i >= 0; i-- {
		if n.sent[i].Op == op {
			return n.sent[i]
		}
	}
	t.Fatalf("missing %s message", op)
	return message{}
}

type replacementNode struct {
	*replacementNetwork
	old, next *path
	fake      *controlFake
	journal   string
}

func replacementSamples(now time.Time, rtt time.Duration) measurements {
	w := measurements{since: now.Add(-time.Minute)}
	for i := range 15 {
		w.samples = append(w.samples, sample{now.Add(-time.Duration(i) * time.Second), rtt})
	}
	return w
}

func replacementPair(t *testing.T) (*meshSimulation, [2]*replacementNode) {
	t.Helper()
	s := newMeshSimulation(t)
	s.run(35 * time.Second)
	s.active()
	if bytes.Compare(s.nodes[0].m.public[:], s.nodes[1].m.public[:]) > 0 {
		s.nodes[0], s.nodes[1] = s.nodes[1], s.nodes[0]
	}
	var nodes [2]*replacementNode
	for i, n := range s.nodes {
		old := n.p.selected
		old.link.Prefix = netip.MustParsePrefix([]string{"fd00::2/64", "fd00::3/64"}[i])
		old.link.Broadcast, old.link.Multicast = netip.Addr{}, false
		old.addr = netip.AddrPortFrom(netip.MustParseAddr([]string{"fd00::3", "fd00::2"}[i]), n.m.c.Port)
		next := *old
		// Both local and remote addresses change, but the interface stays the same.
		next.link.Prefix = netip.MustParsePrefix([]string{"fd00::12/64", "fd00::13/64"}[i])
		next.addr = netip.AddrPortFrom(netip.MustParseAddr([]string{"fd00::13", "fd00::12"}[i]), n.m.c.Port)
		old.stats = replacementSamples(s.now, 10*time.Millisecond)
		next.stats = replacementSamples(s.now, time.Millisecond)
		n.p.tunnel = replacementSamples(s.now, 15*time.Millisecond)
		n.p.lastTunnel, old.lastPong, next.lastPong = s.now, s.now, s.now
		n.p.cooldown = s.now
		n.p.paths = map[string]*path{pathName(old.link, old.addr): old, pathName(next.link, next.addr): &next}
		net := &replacementNetwork{meshNode: n, links: []linkAddr{old.link, next.link}}
		n.m.net, n.m.links = net, net.links
		control, fake, journal := controlFixture(t, "10.0.0.0/8")
		if err := control.Apply(n.p.spec.key, n.p.spec.IP, n.p.spec.psk, netip.AddrPortFrom(old.addr.Addr(), old.port)); err != nil {
			t.Fatal(err)
		}
		peer := controlFindPeer(&fake.d, n.p.spec.key)
		peer.ReceiveBytes, peer.TransmitBytes, peer.LastHandshakeTime = 1234, 5678, s.now
		n.m.control = control
		nodes[i] = &replacementNode{net, old, &next, fake, journal}
	}
	return s, nodes
}

func (n *replacementNode) unchanged(t *testing.T) func() {
	t.Helper()
	device, journal, calls := controlClone(n.fake.d), controlReadJournal(t, n.journal), n.fake.calls
	p := *n.p
	return func() {
		t.Helper()
		if n.fake.calls != calls {
			t.Errorf("pending proposal wrote WireGuard: calls %d -> %d", calls, n.fake.calls)
		}
		controlAssertDevice(t, n.fake.d, device)
		if !reflect.DeepEqual(controlReadJournal(t, n.journal), journal) {
			t.Error("pending proposal changed the journal")
		}
		if n.p.selected != p.selected || n.p.phase != p.phase || n.p.trial != p.trial || n.p.since != p.since ||
			n.p.baseline != p.baseline || n.p.localGood != p.localGood || n.p.remoteGood != p.remoteGood ||
			n.p.committed != p.committed || n.p.remoteRekey != p.remoteRekey || n.p.remoteAt != p.remoteAt ||
			!reflect.DeepEqual(n.p.tunnel, p.tunnel) || n.p.spec.psk != p.spec.psk {
			t.Error("pending proposal changed active protocol state")
		}
	}
}

func TestMeshReplacementRefused(t *testing.T) {
	for _, reason := range []string{"cooldown", "path disagreement", "same selected", "lost prepare", "lost ready"} {
		t.Run(reason, func(t *testing.T) {
			s, nodes := replacementPair(t)
			leader, follower := nodes[0], nodes[1]
			if reason == "cooldown" {
				follower.p.cooldown = s.now.Add(time.Minute)
			}
			if reason == "path disagreement" {
				follower.next.stats = replacementSamples(s.now, 12*time.Millisecond)
			}
			check := leader.unchanged(t)
			checkFollower := follower.unchanged(t)
			if err := leader.m.tick(s.now); err != nil {
				t.Fatal(err)
			}
			prepare := leader.take(t, "prepare")
			if reason != "lost prepare" {
				c := follower.next
				if reason == "same selected" {
					c = follower.old
				}
				if err := follower.m.coordinate(follower.p, c, prepare, s.now); err != nil {
					t.Fatal(err)
				}
				if reason == "lost ready" {
					follower.take(t, "ready")
				} else {
					for _, msg := range follower.sent {
						if msg.Op == "ready" {
							t.Error("follower accepted a refused path")
						}
					}
				}
			}
			check()
			checkFollower()
			s.now = leader.p.replacement.since.Add(time.Duration(leader.m.c.Failure))
			leader.old.lastPong, leader.next.lastPong, leader.p.lastTunnel = s.now, s.now, s.now
			if err := leader.m.advance(leader.p, s.now); err != nil {
				t.Fatal(err)
			}
			check()
		})
	}
}

func TestMeshReplacementLostCommit(t *testing.T) {
	s, nodes := replacementPair(t)
	leader, follower := nodes[0], nodes[1]
	check := follower.unchanged(t)
	if err := leader.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	if err := follower.m.coordinate(follower.p, follower.next, leader.take(t, "prepare"), s.now); err != nil {
		t.Fatal(err)
	}
	leader.accept(t, follower, "ready")
	leader.take(t, "commit") // Drop the commit after the leader has applied it.
	check()
	// The follower never sees a commit. Its old LAN and tunnel still respond.
	s.now = follower.p.replacement.since.Add(time.Duration(follower.m.c.Failure))
	follower.old.lastPong, follower.next.lastPong, follower.p.lastTunnel = s.now, s.now, s.now
	if err := follower.m.advance(follower.p, s.now); err != nil {
		t.Fatal(err)
	}
	check()
}

func TestMeshReplacementEquivalentAlias(t *testing.T) {
	s, nodes := replacementPair(t)
	for _, n := range nodes {
		n.next.stats = replacementSamples(s.now, 10*time.Millisecond)
		if _, ok := n.m.qualified(n.p, n.next, s.now); ok {
			t.Error("equal LAN RTT qualified against WireGuard overhead")
		}
	}
	leader := nodes[0]
	check := leader.unchanged(t)
	if err := leader.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	for _, msg := range leader.sent {
		if msg.Op == "prepare" {
			t.Error("equivalent IPv6 alias started a replacement")
		}
	}
	check()
}

func (n *replacementNode) accept(t *testing.T, from *replacementNode, op string) {
	t.Helper()
	if err := n.m.coordinate(n.p, n.next, from.take(t, op), n.s.now); err != nil {
		t.Fatal(err)
	}
}

func TestMeshReplacementAgreed(t *testing.T) {
	s, nodes := replacementPair(t)
	leader, follower := nodes[0], nodes[1]
	if err := leader.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	follower.accept(t, leader, "prepare")
	leader.accept(t, follower, "ready")
	follower.accept(t, leader, "commit")
	leader.accept(t, follower, "committed")
	// Repeated commit packets must not reinstall the peer or reset the window.
	follower.accept(t, leader, "commit")
	for _, n := range nodes {
		peer := controlFindPeer(&n.fake.d, n.p.spec.key)
		if n.p.selected != n.next || n.p.phase != "trial" || n.p.replacement != nil || !n.p.committed ||
			n.fake.calls != 2 || peer.Endpoint.AddrPort() != netip.AddrPortFrom(n.next.addr.Addr(), n.next.port) ||
			peer.ReceiveBytes != 1234 || peer.TransmitBytes != 5678 || peer.LastHandshakeTime != s.now {
			t.Fatal("agreed replacement did not update only the route and trial state")
		}
		for _, cfg := range n.fake.configs {
			for _, p := range cfg.Peers {
				if p.Remove {
					t.Fatal("agreed replacement removed the peer")
				}
			}
		}
	}
	s.now = s.now.Add(time.Duration(leader.m.c.Window))
	for _, n := range nodes {
		n.p.tunnel = replacementSamples(s.now, 3*time.Millisecond)
		n.p.lastTunnel, n.next.lastPong = s.now, s.now
		if err := n.m.advance(n.p, s.now); err != nil || n.p.phase != "trial" {
			t.Fatal("replacement did not wait for remote approval", err)
		}
	}
	leader.accept(t, follower, "keep")
	follower.accept(t, leader, "keep")
	for _, n := range nodes {
		if err := n.m.advance(n.p, s.now); err != nil || n.p.phase != "active" || n.p.selected != n.next || n.p.previous != nil || n.fake.calls != 2 {
			t.Fatal("successful replacement did not become active", err)
		}
	}
}

func TestMeshReplacementCancellation(t *testing.T) {
	for _, role := range []int{0, 1} {
		for _, cause := range []string{"timeout", "candidate loss", "alias removed", "remote abort"} {
			t.Run([]string{"leader/", "follower/"}[role]+cause, func(t *testing.T) {
				s, nodes := replacementPair(t)
				n := nodes[role]
				check := n.unchanged(t)
				if err := nodes[0].m.tick(s.now); err != nil {
					t.Fatal(err)
				}
				nodes[1].accept(t, nodes[0], "prepare")
				token := nodes[0].take(t, "prepare").Token
				s.now = s.now.Add(time.Second)
				switch cause {
				case "timeout":
					s.now = n.p.replacement.since.Add(time.Duration(n.m.c.Failure))
					n.next.lastPong = s.now
				case "candidate loss":
					n.next.lastPong = s.now.Add(-time.Duration(n.m.c.Failure))
				case "alias removed":
					n.links = []linkAddr{n.old.link}
					if err := n.m.refresh(s.now); err != nil {
						t.Fatal(err)
					}
				case "remote abort":
					if err := n.m.coordinate(n.p, n.next, message{Op: "abort", Token: token}, s.now); err != nil {
						t.Fatal(err)
					}
				}
				n.old.lastPong, n.p.lastTunnel = s.now, s.now
				if err := n.m.tick(s.now); err != nil {
					t.Fatal(err)
				}
				check()
				if n.p.replacement != nil || !n.p.cooldown.After(s.now) {
					t.Fatal("failed replacement did not cancel and enter cooldown")
				}
				// A delayed reply cannot revive a cancelled proposal.
				n.accept(t, nodes[1-role], []string{"ready", "prepare"}[role])
				msg := message{Op: "commit", Token: token}
				msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.p.spec.key, n.m.public)
				if err := n.m.coordinate(n.p, n.next, msg, s.now); err != nil {
					t.Fatal(err)
				}
				check()
			})
		}
	}
}

func TestMeshReplacementHealthLoss(t *testing.T) {
	for _, role := range []int{0, 1} {
		for _, cause := range []string{"LAN", "WireGuard", "interface"} {
			for _, event := range []string{"tick", "commit"} {
				t.Run([]string{"leader/", "follower/"}[role]+cause+"/"+event, func(t *testing.T) {
					s, nodes := replacementPair(t)
					n := nodes[role]
					if err := nodes[0].m.tick(s.now); err != nil {
						t.Fatal(err)
					}
					nodes[1].accept(t, nodes[0], "prepare")
					switch cause {
					case "LAN":
						n.old.lastPong = s.now.Add(-time.Duration(n.m.c.Failure))
					case "WireGuard":
						n.p.lastTunnel = s.now.Add(-time.Duration(n.m.c.Failure))
					case "interface":
						n.links = []linkAddr{n.next.link}
						if err := n.m.refresh(s.now); err != nil {
							t.Fatal(err)
						}
					}
					if event == "tick" {
						if err := n.m.tick(s.now); err != nil {
							t.Fatal(err)
						}
					} else {
						msg := message{Op: []string{"ready", "commit"}[role], Token: nodes[0].take(t, "prepare").Token}
						msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.p.spec.key, n.m.public)
						if err := n.m.coordinate(n.p, n.next, msg, s.now); err != nil {
							t.Fatal(err)
						}
					}
					if n.p.selected != nil || n.p.phase != "" || n.p.replacement != nil || n.fake.calls != 2 ||
						controlFindPeer(&n.fake.d, n.p.spec.key) != nil || len(controlReadJournal(t, n.journal).Peers) != 0 {
						t.Fatal("active path loss did not restore the hub")
					}
				})
			}
		}
	}
}

func TestMeshReplacementRekey(t *testing.T) {
	for _, role := range []int{0, 1} {
		for _, event := range []string{"poll", "preflight"} {
			t.Run([]string{"leader/", "follower/"}[role]+event, func(t *testing.T) {
				s, nodes := replacementPair(t)
				n := nodes[role]
				n.p.spec.ExperimentalRekey, n.p.remoteRekey, n.p.pskValid = true, true, true
				n.p.spec.PresharedKeyFile = filepath.Join(t.TempDir(), "key")
				writeTestPSK(t, n.p.spec.PresharedKeyFile, n.p.spec.psk.String(), s.now)
				check := n.unchanged(t)
				if err := nodes[0].m.tick(s.now); err != nil {
					t.Fatal(err)
				}
				nodes[1].accept(t, nodes[0], "prepare")
				msg := message{Op: []string{"ready", "commit"}[role], Token: nodes[0].take(t, "prepare").Token}
				msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.p.spec.key, n.m.public)
				changeKey := func() error {
					writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
					return nil
				}
				if event == "preflight" {
					n.m.verify = changeKey
				} else {
					_ = changeKey()
				}
				if err := n.m.coordinate(n.p, n.next, msg, s.now); err != nil {
					t.Fatal(err)
				}
				check()
				if n.p.replacement != nil || n.p.rekey == nil || n.p.rekey.key != controlTestKey(44) {
					t.Fatal("key transition did not cancel the pending route")
				}
				transition := n.p.rekey
				s.now = s.now.Add(time.Second)
				n.m.verify = nil
				if err := n.m.tick(s.now); err != nil || n.p.rekey != transition {
					t.Fatal("cancelled route changed the key transition", err)
				}
				check()
				s.now = transition.since.Add(time.Duration(n.m.c.Failure))
				n.old.lastPong, n.next.lastPong, n.p.lastTunnel = s.now, s.now, s.now
				if err := n.m.tick(s.now); err != nil {
					t.Fatal(err)
				}
				if n.p.phase != "" || n.p.rekey != nil || n.fake.calls != 2 || controlFindPeer(&n.fake.d, n.p.spec.key) != nil {
					t.Fatal("unconfirmed rekey did not retain its hub recovery rule")
				}
			})
		}
	}
}

func TestMeshReplacementUnconfirmed(t *testing.T) {
	for _, role := range []int{0, 1} {
		for _, cause := range []string{"proof", "token", "path", "committed", "keep", "hold", "expired"} {
			t.Run([]string{"leader/", "follower/"}[role]+cause, func(t *testing.T) {
				s, nodes := replacementPair(t)
				n := nodes[role]
				check := n.unchanged(t)
				if err := nodes[0].m.tick(s.now); err != nil {
					t.Fatal(err)
				}
				nodes[1].accept(t, nodes[0], "prepare")
				msg := message{Op: []string{"ready", "commit"}[role], Token: nodes[0].take(t, "prepare").Token}
				c := n.next
				switch cause {
				case "token":
					msg.Token = n.p.trial
				case "path":
					c = n.old
				case "committed", "keep", "hold":
					msg.Op = cause
				case "expired":
					s.now = n.p.replacement.since.Add(time.Duration(n.m.c.Failure))
					n.old.lastPong, n.next.lastPong, n.p.lastTunnel = s.now, s.now, s.now
				}
				msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.p.spec.key, n.m.public)
				if cause == "proof" {
					msg.Proof = pskProof(controlTestKey(44), msg.Op, msg.Token, n.p.spec.key, n.m.public)
				}
				if err := n.m.coordinate(n.p, c, msg, s.now); err != nil {
					t.Fatal(err)
				}
				check()
				if (n.p.replacement == nil) != (cause == "expired") {
					t.Fatal("unconfirmed message changed the replacement state")
				}
			})
		}
	}
}

func TestMeshReplacementActiveMessages(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[0]
	if err := n.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	r := n.p.replacement
	s.now = s.now.Add(time.Second)
	for _, op := range []string{"hold", "keep"} {
		if err := n.m.coordinate(n.p, n.old, message{Op: op, Token: n.p.trial}, s.now); err != nil {
			t.Fatal(err)
		}
		if n.p.remoteGood != (op == "keep") || n.p.replacement != r || n.fake.calls != 1 {
			t.Fatal("pending replacement interfered with active approvals")
		}
	}
	if err := n.m.advance(n.p, s.now); err != nil {
		t.Fatal(err)
	}
	if n.take(t, "keep").Token != n.p.trial || n.take(t, "prepare").Token == n.p.trial || n.p.remoteAt != s.now {
		t.Fatal("active and pending control messages did not use separate tokens")
	}
	if err := n.m.coordinate(n.p, n.old, message{Op: "abort", Token: n.p.trial}, s.now); err != nil {
		t.Fatal(err)
	}
	if n.p.phase != "" || n.p.replacement != nil || controlFindPeer(&n.fake.d, n.p.spec.key) != nil {
		t.Fatal("pending replacement suppressed an active route abort")
	}
}

func TestMeshReplacementPreflightBeforeCommit(t *testing.T) {
	s, nodes := replacementPair(t)
	leader, follower := nodes[0], nodes[1]
	if err := leader.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	follower.accept(t, leader, "prepare")
	failure := errors.New("preflight failed")
	leader.m.verify = func() error { return failure }
	if err := leader.m.coordinate(leader.p, leader.next, follower.take(t, "ready"), s.now); !errors.Is(err, failure) {
		t.Fatal("missing preflight error", err)
	}
	for _, msg := range leader.sent {
		if msg.Op == "commit" {
			t.Error("commit sent before local preflight completed")
			follower.accept(t, leader, "commit")
		}
	}
	if follower.fake.calls != 1 || follower.p.selected != follower.old {
		t.Fatal("failed local preflight changed the remote route")
	}
}

func TestMeshReplacementAbortAfterApply(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost commit", true: "both applied"}[both], func(t *testing.T) {
			s, nodes := replacementPair(t)
			leader, follower := nodes[0], nodes[1]
			devices := []wgtypes.Device{controlClone(leader.fake.d), controlClone(follower.fake.d)}
			states := []meshPeer{*leader.p, *follower.p}
			journals := []controlJournal{controlReadJournal(t, leader.journal), controlReadJournal(t, follower.journal)}
			if err := leader.m.tick(s.now); err != nil {
				t.Fatal(err)
			}
			follower.accept(t, leader, "prepare")
			leader.accept(t, follower, "ready")
			if both {
				follower.accept(t, leader, "commit")
				leader.accept(t, follower, "committed")
			}
			if both {
				s.now = follower.p.since.Add(time.Duration(follower.m.c.Failure))
			} else {
				s.now = follower.p.replacement.since.Add(time.Duration(follower.m.c.Failure))
			}
			for _, n := range nodes {
				n.old.lastPong, n.next.lastPong = s.now, s.now
			}
			if !both {
				follower.p.lastTunnel = s.now
			}
			if err := follower.m.advance(follower.p, s.now); err != nil {
				t.Fatal(err)
			}
			leader.accept(t, follower, "abort")
			follower.accept(t, leader, "abort")
			for i, n := range nodes {
				controlAssertDevice(t, n.fake.d, devices[i])
				if n.p.phase != "active" || n.p.selected != n.old || n.p.trial != states[i].trial || n.p.baseline != states[i].baseline ||
					n.p.localGood != states[i].localGood || n.p.remoteGood != states[i].remoteGood || n.p.committed != states[i].committed ||
					!reflect.DeepEqual(controlReadJournal(t, n.journal), journals[i]) {
					t.Fatal("rollback did not retain the previous active route and journal")
				}
				for _, cfg := range n.fake.configs[1:] {
					for _, pc := range cfg.Peers {
						if pc.Remove || pc.PresharedKey != nil || len(pc.AllowedIPs) != 0 || !pc.UpdateOnly {
							t.Fatal("rollback was not an endpoint-only update")
						}
					}
				}
			}
			counts := []int{len(leader.sent), len(follower.sent)}
			leader.accept(t, follower, "abort")
			follower.accept(t, leader, "abort")
			if len(leader.sent) != counts[0] || len(follower.sent) != counts[1] {
				t.Fatal("retired abort messages caused a reply loop")
			}
		})
	}
}

func TestMeshReplacementRetiredPrepare(t *testing.T) {
	s, nodes := replacementPair(t)
	leader, follower := nodes[0], nodes[1]
	if err := leader.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	follower.accept(t, leader, "prepare")
	var delayed []packet
	for _, op := range []string{"prepare", "commit"} {
		msg := leader.take(t, "prepare")
		msg.Op = op
		msg.Proof = pskProof(leader.p.spec.psk, op, msg.Token, leader.m.public, follower.m.public)
		body, _ := json.Marshal(msg)
		data, err := leader.m.crypto.Seal(leader.next.session, body, s.now)
		if err != nil {
			t.Fatal(err)
		}
		delayed = append(delayed, packet{Data: data, Source: netip.AddrPortFrom(leader.next.link.Prefix.Addr(), leader.m.c.Port),
			Destination: follower.next.link.Prefix.Addr(), IfIndex: follower.next.link.Index})
	}
	s.now = follower.p.replacement.since.Add(time.Duration(follower.m.c.Failure))
	follower.old.lastPong, follower.next.lastPong, follower.p.lastTunnel = s.now, s.now, s.now
	if err := follower.m.advance(follower.p, s.now); err != nil {
		t.Fatal(err)
	}
	s.now = follower.p.cooldown.Add(time.Second)
	follower.old.lastPong, follower.next.lastPong, follower.p.lastTunnel = s.now, s.now, s.now
	follower.old.stats = replacementSamples(s.now, 10*time.Millisecond)
	follower.next.stats = replacementSamples(s.now, time.Millisecond)
	follower.p.tunnel = replacementSamples(s.now, 15*time.Millisecond)
	check := follower.unchanged(t)
	for _, packet := range delayed {
		if err := follower.m.receive(packet, s.now); err != nil {
			t.Fatal(err)
		}
	}
	check()
	if follower.p.replacement != nil {
		t.Fatal("delayed prepare revived a retired transaction after cooldown")
	}
}

func TestMeshReplacementRetiredLaterSession(t *testing.T) {
	s, nodes := replacementPair(t)
	leader, follower := nodes[0], nodes[1]
	if err := leader.m.tick(s.now); err != nil {
		t.Fatal(err)
	}
	follower.accept(t, leader, "prepare")
	s.now = s.now.Add(time.Second)
	retiredAt := s.now
	follower.m.cancelReplacement(follower.p, retiredAt)
	// Lose the abort. The leader can retry in a later session before its timeout.
	s.now = s.now.Add(2 * time.Second)
	if s.now.Sub(leader.p.replacement.since) >= time.Duration(leader.m.c.Failure) {
		t.Fatal("retry is outside the remote coordination period")
	}
	id, _, _ := secureTestOpen(t, leader.m.crypto, follower.m.crypto, s.now)
	secureTestSend(t, leader.m.crypto, follower.m.crypto, id, []byte("confirm"), s.now)
	leader.next.session, follower.next.session = id, id
	var delayed []packet
	for _, op := range []string{"prepare", "commit"} {
		msg := leader.take(t, "prepare")
		msg.Op = op
		msg.Proof = pskProof(leader.p.spec.psk, op, msg.Token, leader.m.public, follower.m.public)
		body, _ := json.Marshal(msg)
		data, err := leader.m.crypto.Seal(id, body, s.now)
		if err != nil {
			t.Fatal(err)
		}
		delayed = append(delayed, packet{Data: data, Source: netip.AddrPortFrom(leader.next.link.Prefix.Addr(), leader.m.c.Port),
			Destination: follower.next.link.Prefix.Addr(), IfIndex: follower.next.link.Index})
	}
	s.now = retiredAt.Add(secureSessionLifetime + time.Second)
	if !s.now.Before(follower.m.crypto.sessions[id].expires) {
		t.Fatal("later session expired before the delayed delivery")
	}
	follower.old.lastPong, follower.next.lastPong, follower.p.lastTunnel = s.now, s.now, s.now
	follower.old.stats = replacementSamples(s.now, 10*time.Millisecond)
	follower.next.stats = replacementSamples(s.now, time.Millisecond)
	follower.p.tunnel = replacementSamples(s.now, 15*time.Millisecond)
	check := follower.unchanged(t)
	for _, packet := range delayed {
		if err := follower.m.receive(packet, s.now); err != nil {
			t.Fatal(err)
		}
	}
	if follower.m.crypto.sessions[id].highest != 2 {
		t.Fatal("delayed packets did not pass secure session authentication")
	}
	check()
	if follower.p.replacement != nil {
		t.Fatal("later session revived a retired transaction after ten minutes")
	}
}

func TestMeshReplacementBlockingTime(t *testing.T) {
	for _, stage := range []string{"polls", "second poll", "preflight", "apply", "tick"} {
		t.Run(stage, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, nodes := replacementPair(t)
				leader, follower := nodes[0], nodes[1]
				if err := leader.m.tick(s.now); err != nil {
					t.Fatal(err)
				}
				follower.accept(t, leader, "prepare")
				before := s.now
				switch stage {
				case "polls", "second poll":
					leader.p.spec.PresharedKeyFile = filepath.Join(t.TempDir(), "key")
					leader.p.spec.RosenpassSocket = "test-adapter"
					leader.p.pskValid = true
					writeTestPSK(t, leader.p.spec.PresharedKeyFile, leader.p.spec.psk.String(), s.now)
					status := rosenpassResponse{Valid: true, Hash: sha256.Sum256(leader.p.spec.psk[:]), Expires: s.now.Add(time.Minute)}
					calls := 0
					leader.m.rosenpass = func(string, rosenpassRequest) (rosenpassResponse, error) {
						calls++
						if stage == "second poll" {
							if calls > 2 {
								time.Sleep(3 * time.Second)
							}
						} else if calls <= 2 {
							time.Sleep(2 * time.Second)
						} else {
							time.Sleep(time.Second)
						}
						return status, nil
					}
				case "preflight", "tick":
					leader.m.verify = func() error { time.Sleep(6 * time.Second); return nil }
				case "apply":
					leader.fake.hook = func(call int, stage string) error {
						if call == 2 && stage == "before" {
							time.Sleep(3 * time.Second)
						}
						return nil
					}
				}
				if stage == "tick" {
					if err := leader.m.tick(s.now); err != nil {
						t.Fatal(err)
					}
				} else {
					leader.accept(t, follower, "ready")
				}
				if stage == "tick" {
					if leader.p.phase != "" || leader.p.replacement != nil || leader.fake.calls != 2 {
						t.Fatal("blocking timer preflight suppressed active health checks")
					}
				} else if stage == "apply" {
					if leader.p.phase != "trial" || leader.p.since != before.Add(3*time.Second) || leader.p.tunnel.since != leader.p.since {
						t.Fatal("trial clock started before successful application")
					}
				} else {
					if leader.fake.calls != 1 || leader.p.selected != leader.old {
						t.Error("blocking calls applied an expired proposal")
					}
					for _, msg := range leader.sent {
						if msg.Op == "commit" {
							t.Error("blocking calls sent commit for an expired proposal")
						}
					}
				}
			})
		})
	}
}

func TestMeshReplacementRollbackHealth(t *testing.T) {
	for _, loss := range []string{"LAN", "interface", "WireGuard", "none", "remote abort", "key"} {
		t.Run(loss, func(t *testing.T) {
			s, nodes := replacementPair(t)
			leader, follower := nodes[0], nodes[1]
			if err := leader.m.tick(s.now); err != nil {
				t.Fatal(err)
			}
			follower.accept(t, leader, "prepare")
			leader.accept(t, follower, "ready")
			s.now = follower.p.replacement.since.Add(time.Duration(follower.m.c.Failure))
			for _, n := range nodes {
				n.old.lastPong, n.next.lastPong = s.now, s.now
			}
			follower.p.lastTunnel = s.now
			if err := follower.m.advance(follower.p, s.now); err != nil {
				t.Fatal(err)
			}
			switch loss {
			case "LAN":
				leader.old.lastPong = s.now.Add(-time.Duration(leader.m.c.Failure))
			case "interface":
				leader.m.links = []linkAddr{leader.next.link}
			case "remote abort":
				if err := leader.m.coordinate(leader.p, leader.old, message{Op: "abort", Token: leader.p.previous.trial}, s.now); err != nil {
					t.Fatal(err)
				}
			case "key":
				leader.p.pskValid = true
				leader.p.spec.PresharedKeyFile = filepath.Join(t.TempDir(), "key")
				writeTestPSK(t, leader.p.spec.PresharedKeyFile, controlTestKey(44).String(), s.now)
			}
			leader.accept(t, follower, "abort")
			if loss == "WireGuard" || loss == "none" {
				if leader.p.phase != "active" || leader.p.selected != leader.old || leader.p.previous != nil {
					t.Fatal("missing endpoint rollback")
				}
				if loss == "none" {
					leader.p.lastTunnel = leader.p.resumed.Add(time.Second)
				}
				s.now = leader.p.resumed.Add(time.Duration(leader.m.c.Failure))
				leader.old.lastPong = s.now
				if err := leader.m.advance(leader.p, s.now); err != nil {
					t.Fatal(err)
				}
			}
			if loss == "none" {
				if leader.p.phase != "active" || leader.fake.calls != 3 {
					t.Fatal("healthy rollback did not retain the peer")
				}
			} else if leader.p.phase != "" || leader.p.previous != nil || controlFindPeer(&leader.fake.d, leader.p.spec.key) != nil {
				t.Fatal("unsafe fallback did not restore the hub")
			}
		})
	}
}

func TestMeshReplacementRetirementBound(t *testing.T) {
	s, nodes := replacementPair(t)
	n := nodes[1]
	for i := range 1025 {
		n.m.retire(n.p, strconv.Itoa(i), s.now)
	}
	if len(n.p.retired) != 1024 || n.p.retiredUntil != s.now.Add(retiredTokenLifetime) || n.p.retired["0"] != s.now.Add(retiredTokenLifetime) {
		t.Fatal("retired tokens did not use the fixed bound and retention period")
	}
	msg := message{Op: "prepare", Token: "blocked-token"}
	msg.Proof = pskProof(n.p.spec.psk, msg.Op, msg.Token, n.p.spec.key, n.m.public)
	check := n.unchanged(t)
	if err := n.m.coordinate(n.p, n.next, msg, s.now); err != nil {
		t.Fatal(err)
	}
	check()
	if n.p.replacement != nil || n.p.retiredUntil != s.now.Add(retiredTokenLifetime) {
		t.Fatal("full retirement state did not block proposals for the full retention period")
	}
	s.now = n.p.retiredUntil.Add(time.Second)
	n.m.retire(n.p, "fresh-token", s.now)
	if len(n.p.retired) != 1 {
		t.Fatal("expired retired tokens were not removed")
	}
	n.old.lastPong, n.next.lastPong, n.p.lastTunnel = s.now, s.now, s.now
	n.old.stats = replacementSamples(s.now, 10*time.Millisecond)
	n.next.stats = replacementSamples(s.now, time.Millisecond)
	n.p.tunnel = replacementSamples(s.now, 15*time.Millisecond)
	if err := n.m.coordinate(n.p, n.next, msg, s.now); err != nil || n.p.replacement == nil {
		t.Fatal("retirement saturation did not expire", err)
	}
}
