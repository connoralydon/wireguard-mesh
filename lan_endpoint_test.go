package main

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeLANEndpointControl struct {
	routeControl
	changed  bool
	err      error
	applyErr error
	calls    int
	last     netip.AddrPort
}

func (c *fakeLANEndpointControl) Apply(key wgtypes.Key, ip netip.Addr, psk wgtypes.Key, endpoint netip.AddrPort) error {
	if c.applyErr != nil {
		return c.applyErr
	}
	return c.routeControl.Apply(key, ip, psk, endpoint)
}

func (c *fakeLANEndpointControl) EnsureEndpoint(_ wgtypes.Key, _ netip.Addr, _ wgtypes.Key, endpoint netip.AddrPort) (bool, error) {
	c.calls++
	c.last = endpoint
	return c.changed, c.err
}

func lanEndpointFixture(t *testing.T) (*meshSimulation, *replacementNode, *fakeLANEndpointControl) {
	t.Helper()
	s, nodes := replacementPair(t)
	n := nodes[0]
	n.m.c.DirectInterface = "auto"
	n.m.c.NAT = &natConfig{}
	n.m.enableNAT(nil)
	c := &fakeLANEndpointControl{routeControl: n.m.control}
	n.m.control = c
	return s, n, c
}

func TestLANEndpointCorrectionRequiresNewTrialEvidence(t *testing.T) {
	for _, phase := range []string{"trial", "active"} {
		t.Run(phase, func(t *testing.T) {
			s, n, c := lanEndpointFixture(t)
			n.p.phase = phase
			n.p.since = s.now.Add(-30 * time.Second)
			n.p.localGood, n.p.remoteGood, n.p.committed = true, true, true
			n.p.remoteAt = s.now
			n.p.pending["old"] = probe{at: s.now}
			c.changed = true
			if err := n.m.advance(n.p, s.now); err != nil {
				t.Fatal(err)
			}
			if c.calls != 1 || c.last != netip.AddrPortFrom(n.old.addr.Addr(), n.old.port) || n.p.phase != "trial" || n.p.localGood || n.p.remoteGood || len(n.p.pending) != 0 || len(n.p.tunnel.samples) != 0 || !n.p.lastTunnel.IsZero() {
				t.Fatal("endpoint correction retained evidence from the old transport")
			}
			if phase == "trial" && n.p.since != s.now.Add(-30*time.Second) {
				t.Fatal("endpoint correction extended the overall trial deadline")
			}
			c.changed = false
			later := s.now.Add(time.Duration(n.m.c.Probe))
			n.old.lastPong = later
			if err := n.m.advance(n.p, later); err != nil || n.p.phase != "trial" {
				t.Fatal("corrected trial did not get a fresh measurement window:", err)
			}
			later = later.Add(time.Duration(n.m.c.Window))
			n.old.lastPong, n.p.lastTunnel, n.p.remoteAt = later, later, later
			n.p.tunnel = replacementSamples(later, time.Millisecond)
			n.p.remoteGood = true
			if err := n.m.advance(n.p, later); err != nil || n.p.phase != "active" {
				t.Fatal("new LAN measurements did not complete the corrected trial:", err)
			}
		})
	}
}

func TestLANEndpointRepeatedRoamingRestoresHub(t *testing.T) {
	s, n, c := lanEndpointFixture(t)
	c.changed = true
	if err := n.m.advance(n.p, s.now); err != nil {
		t.Fatal(err)
	}
	later := s.now.Add(time.Duration(n.m.c.Failure) + time.Second)
	n.old.lastPong = later
	if err := n.m.advance(n.p, later); err != nil {
		t.Fatal(err)
	}
	if n.p.selected != nil || n.p.phase != "" || !later.Before(n.old.retryAt) {
		t.Fatal("repeated endpoint roaming kept an unproved LAN route")
	}
}

func TestLANEndpointRacingUpdateNeedsRetry(t *testing.T) {
	s, n, c := lanEndpointFixture(t)
	c.err = errEndpointRoamed
	if ready, err := n.m.keepLANEndpoint(n.p, s.now); err != nil || ready || n.p.phase != "trial" || n.p.localGood || len(n.p.tunnel.samples) != 0 {
		t.Fatal("racing endpoint update was fatal or retained old evidence:", err)
	}
	later := s.now.Add(time.Duration(n.m.c.Failure) + time.Second)
	n.old.lastPong = later
	if ready, err := n.m.keepLANEndpoint(n.p, later); err != nil || ready || n.p.phase != "" {
		t.Fatal("racing endpoint updates did not reach bounded fallback:", err)
	}
}

func TestLANEndpointRacingApplyKeepsCoordinationDeadline(t *testing.T) {
	s, n, c := lanEndpointFixture(t)
	n.p.phase, n.p.since = "prepare", s.now
	c.applyErr = errEndpointRoamed
	if err := n.m.apply(n.p, s.now); err != nil || n.p.phase != "prepare" || n.p.since != s.now {
		t.Fatal("racing apply was fatal or advanced the route:", err)
	}
	later := s.now.Add(time.Duration(n.m.c.Failure) + time.Second)
	n.old.lastPong = later
	if err := n.m.advance(n.p, later); err != nil || n.p.phase != "" {
		t.Fatal("racing apply extended the coordination deadline:", err)
	}
}

func TestLANEndpointPreflightAndNATRoaming(t *testing.T) {
	for _, scenario := range []string{"NAT", "no route mode", "prepare", "verification", "missing key", "changed key", "write error"} {
		t.Run(scenario, func(t *testing.T) {
			s, n, c := lanEndpointFixture(t)
			wantErr := errors.New("test failure")
			switch scenario {
			case "NAT":
				n.old.nat = true
			case "no route mode":
				n.m.c.DirectInterface = ""
			case "prepare":
				n.p.phase = "prepare"
			case "verification":
				n.m.verify = func() error { return wantErr }
			case "missing key", "changed key":
				n.p.pskValid = true
				n.p.spec.PresharedKeyFile = filepath.Join(t.TempDir(), "psk")
				if scenario == "changed key" {
					writeTestPSK(t, n.p.spec.PresharedKeyFile, controlTestKey(66).String(), s.now)
				}
			case "write error":
				c.err = wantErr
			}
			ready, err := n.m.keepLANEndpoint(n.p, s.now)
			if scenario == "verification" || scenario == "write error" {
				if !errors.Is(err, wantErr) || ready {
					t.Fatal("endpoint preflight or write failure was ignored:", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			wantCalls := 0
			if scenario == "write error" {
				wantCalls = 1
			}
			if c.calls != wantCalls {
				t.Fatal("endpoint maintenance bypassed preflight or pinned a NAT path")
			}
			if scenario == "missing key" || scenario == "changed key" {
				if ready || n.p.selected != nil || n.p.phase != "" {
					t.Fatal("endpoint correction crossed a key transition")
				}
			}
		})
	}
}
