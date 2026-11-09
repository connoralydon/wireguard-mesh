//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestRouteChronology(t *testing.T) {
	p := snapshot{present: true, handshake: true}
	var s observerState
	if !s.step("route", p, true, true, wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}, false) || s.route.HandshakeBeforeRoute {
		t.Fatal("first direct route accepted handshake")
	}
	s = observerState{}
	s.step("route", p, true, false, wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}, false)
	s.step("route", p, true, true, wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}, false)
	if !s.route.HandshakeBeforeRoute {
		t.Fatal("prior handshake not accepted")
	}
	s = observerState{}
	s.step("route", p, true, false, wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}, false)
	s.step("route", snapshot{}, true, false, wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}, false)
	s.step("route", p, true, true, wgtypes.Key{}, wgtypes.Key{}, wgtypes.Key{}, false)
	if s.route.HandshakeBeforeRoute {
		t.Fatal("removed peer retained proof")
	}
}

func TestRekeyChronology(t *testing.T) {
	old, key, wrong := wgtypes.Key{1}, wgtypes.Key{2}, wgtypes.Key{3}
	step := func(s *observerState, p snapshot, direct bool, b, a wgtypes.Key) bool {
		return s.step("rekey", p, true, direct, b, a, old, true)
	}
	p := snapshot{present: true, handshake: true, key: key}
	var s observerState
	step(&s, snapshot{}, false, key, key)
	step(&s, p, false, key, key)
	if !step(&s, p, true, key, key) || !s.rekey.NewKeyInstalled || !s.rekey.NewHandshakeBeforeRoute {
		t.Fatal("valid rekey rejected")
	}
	for _, tc := range []struct {
		name          string
		absent        bool
		pre           snapshot
		before, after wgtypes.Key
	}{
		{"no removal", false, p, key, key}, {"old key", true, snapshot{true, true, old}, key, key}, {"wrong key", true, snapshot{true, true, wrong}, key, key}, {"changed file", true, p, key, wrong},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s observerState
			if tc.absent {
				step(&s, snapshot{}, false, key, key)
			}
			step(&s, tc.pre, false, tc.before, tc.after)
			step(&s, p, true, key, key)
			if s.rekey.NewHandshakeBeforeRoute {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	var noRelay observerState
	noRelay.step("rekey", snapshot{}, false, false, key, key, old, true)
	noRelay.step("rekey", p, false, false, key, key, old, true)
	step(&noRelay, p, true, key, key)
	if noRelay.rekey.NewHandshakeBeforeRoute {
		t.Fatal("missing relay accepted")
	}
	var earlyRelay observerState
	step(&earlyRelay, snapshot{true, true, old}, false, key, key)
	earlyRelay.step("rekey", snapshot{}, false, false, key, key, old, true)
	step(&earlyRelay, p, true, key, key)
	if earlyRelay.rekey.RelaySeen || earlyRelay.rekey.NewHandshakeBeforeRoute {
		t.Fatal("hub observation before peer removal was accepted")
	}
}

func TestReadKeyErrorsAreGeneric(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	for _, value := range []string{"sensitive-invalid-value", strings.Repeat("secret", 30), (wgtypes.Key{}).String()} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readKey(path)
		if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), path) {
			t.Fatal("unsafe key error")
		}
	}
	_, err := readKey(dir)
	if err == nil || err.Error() != errObservation.Error() {
		t.Fatal("directory accepted")
	}
	key := wgtypes.Key{7}
	if err := os.WriteFile(path, []byte(key.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readKey(path)
	if err != nil || got != key {
		t.Fatal("valid key rejected")
	}
}

func TestOnlyStableInterfaceProvesHubRoute(t *testing.T) {
	k := kernel{index: 8, stable: 5}
	for _, tc := range []struct {
		index         int
		known, direct bool
	}{{8, true, true}, {5, true, false}, {9, false, false}, {0, false, false}} {
		known, direct := k.routeKind(tc.index)
		if known != tc.known || direct != tc.direct {
			t.Fatal("incorrect route classification")
		}
	}
}
