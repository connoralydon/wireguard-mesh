package main

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestRosenpassRouteBootstrapAndRotation(t *testing.T) {
	s := newMeshSimulation(t)
	meshPSKFiles(t, s, true)
	var status [2]rosenpassResponse
	var calls [2]int
	for i, n := range s.nodes {
		n.m.c.DirectInterface = "auto"
		n.p.spec.RosenpassSocket = "fake-vpn-adapter"
		n.m.rosenpass = func(_ string, request rosenpassRequest) (rosenpassResponse, error) {
			calls[i]++
			if request.Peer != n.p.spec.key.String() || request.Address != n.p.spec.IP || request.Link != n.m.tunnel {
				t.Fatal("route mode did not bind Rosenpass to the VPN peer and interface")
			}
			return status[i], nil
		}
		// A fresh-looking file alone must not authorize a direct path. The
		// adapter is queried before any LAN candidate or ICE endpoint exists.
		if _, _, err := n.m.readPeerPSK(n.p, s.now); !errors.Is(err, errPSKFile) || calls[i] != 1 {
			t.Fatal("Rosenpass bootstrap depended on a direct candidate or trusted an orphan file")
		}
	}
	s.run(35 * time.Second)
	for _, n := range s.nodes {
		if n.applies != 0 || n.applied {
			t.Fatal("missing Rosenpass exchange permitted direct traffic")
		}
	}
	key := controlTestKey(33)
	for i := range status {
		status[i] = rosenpassResponse{Instance: "vpn-adapter", Generation: 1, KeyGeneration: 1, Valid: true,
			Hash: sha256.Sum256(key[:]), Expires: s.now.Add(3 * time.Minute)}
	}
	s.run(40 * time.Second)
	s.active()
	for _, n := range s.nodes {
		if n.appliedPSK != key || n.applies != 1 {
			t.Fatal("Rosenpass key was not installed by the initial direct trial")
		}
	}
	key = controlTestKey(44)
	for i, n := range s.nodes {
		writeTestPSK(t, n.p.spec.PresharedKeyFile, key.String(), s.now)
		status[i].Hash, status[i].KeyGeneration = sha256.Sum256(key[:]), 2
		status[i].Expires = s.now.Add(3 * time.Minute)
		if ok, err := n.m.pollPSK(n.p, s.now); err != nil || !ok || n.applied || n.p.phase != "" || n.applies != 1 {
			t.Fatal("rotation did not restore before accepting the new key:", err)
		}
	}
	// Allow a fresh discovery interval and measurement window, as in the
	// existing file-backed rotation test. Restoration was checked above.
	s.run(80 * time.Second)
	s.active()
	for _, n := range s.nodes {
		if n.appliedPSK != key || n.applies != 2 {
			t.Fatal("rotated Rosenpass key did not require a new direct trial")
		}
	}
	for i := range status {
		status[i].Valid = false
	}
	s.run(30 * time.Second)
	for _, n := range s.nodes {
		if n.applied || n.applies != 2 || n.p.pskValid {
			t.Fatal("fresh orphan key survived loss of the Rosenpass adapter status")
		}
	}
}
