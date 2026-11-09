package main

import (
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type routeFakeWG struct {
	stable, direct wgtypes.Device
	writes         int
	partialAdd     bool
	failRemove     bool
	failUpdate     bool
	ignoreUpdate   bool
}

func (f *routeFakeWG) Device(n string) (*wgtypes.Device, error) {
	if n == f.stable.Name {
		d := controlClone(f.stable)
		return &d, nil
	}
	if n == f.direct.Name {
		d := controlClone(f.direct)
		return &d, nil
	}
	return nil, errors.New("unknown device")
}
func (f *routeFakeWG) ConfigureDevice(n string, c wgtypes.Config) error {
	if n != f.direct.Name {
		return errors.New("stable write")
	}
	f.writes++
	for _, p := range c.Peers {
		if p.Remove {
			if f.failRemove {
				f.failRemove = false
				return errors.New("remove failed")
			}
			f.direct.Peers = nil
			continue
		}
		if p.UpdateOnly {
			if f.failUpdate {
				return errors.New("update failed")
			}
			peer := controlFindPeer(&f.direct, p.PublicKey)
			if peer == nil || p.PresharedKey != nil || p.PersistentKeepaliveInterval != nil || len(p.AllowedIPs) != 0 {
				return errors.New("invalid endpoint update")
			}
			if !f.ignoreUpdate {
				peer.Endpoint = p.Endpoint
			}
			continue
		}
		if f.partialAdd {
			f.direct.Peers = append(f.direct.Peers, wgtypes.Peer{PublicKey: p.PublicKey, ProtocolVersion: 1})
			f.partialAdd = false
			return errors.New("partial add")
		}
		f.direct.Peers = append(f.direct.Peers, wgtypes.Peer{PublicKey: p.PublicKey, PresharedKey: *p.PresharedKey, AllowedIPs: p.AllowedIPs, PersistentKeepaliveInterval: *p.PersistentKeepaliveInterval, Endpoint: p.Endpoint, ProtocolVersion: 1})
	}
	return nil
}

type routeFakeOps struct {
	entries            []netlink.Route
	adds, deletes      int
	addError, delError bool
	onAdd              func()
}

func (*routeFakeOps) index(string) (int, error) { return 12, nil }
func (f *routeFakeOps) list(ip netip.Addr) ([]netlink.Route, error) {
	var out []netlink.Route
	for _, r := range f.entries {
		if r.Dst != nil && r.Dst.String() == netip.PrefixFrom(ip, ip.BitLen()).String() {
			out = append(out, r)
		}
	}
	return out, nil
}
func (f *routeFakeOps) add(r netlink.Route) error {
	if f.onAdd != nil {
		f.onAdd()
	}
	f.adds++
	f.entries = append(f.entries, r)
	if f.addError {
		f.addError = false
		return errors.New("add applied with error")
	}
	return nil
}

func TestRouteControlStagedRoamBeforeApply(t *testing.T) {
	c, w, routes, _ := routeFixture(t)
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	lan := netip.MustParseAddrPort("192.0.2.2:51820")
	if _, err := c.Stage(k, ip, psk, lan); err != nil {
		t.Fatal(err)
	}
	w.direct.Peers[0].LastHandshakeTime = time.Now()
	w.direct.Peers[0].Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.2:40002"))
	w.ignoreUpdate = true
	if err := c.Apply(k, ip, psk, lan); !errors.Is(err, errEndpointRoamed) || routes.adds != 0 || c.journal.Peers[k.String()].Phase != "staged" {
		t.Fatal("racing endpoint update promoted a staged route:", err)
	}
	w.ignoreUpdate = false
	routes.onAdd = func() {
		if got := w.direct.Peers[0].Endpoint.AddrPort(); got != lan {
			t.Errorf("endpoint at route add = %v, want %v", got, lan)
		}
	}
	if err := c.Apply(k, ip, psk, lan); err != nil {
		t.Fatal(err)
	}
	if routes.adds != 1 {
		t.Fatal("route not added")
	}
}

func TestRouteControlEnsureEndpoint(t *testing.T) {
	c, w, routes, _ := routeFixture(t)
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	lan := netip.MustParseAddrPort("192.0.2.2:51820")
	if _, err := c.Stage(k, ip, psk, lan); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnsureEndpoint(k, ip, psk, lan); err == nil {
		t.Fatal("accepted staged peer")
	}
	handshake := time.Now().Add(-time.Hour)
	w.direct.Peers[0].LastHandshakeTime = handshake
	if err := c.Apply(k, ip, psk, lan); err != nil {
		t.Fatal(err)
	}
	writes := w.writes
	if changed, err := c.EnsureEndpoint(k, ip, psk, lan); err != nil || changed || w.writes != writes {
		t.Fatalf("unchanged endpoint: changed=%v err=%v writes=%d", changed, err, w.writes)
	}
	peer := &w.direct.Peers[0]
	peer.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.2:40002"))
	peer.ReceiveBytes, peer.TransmitBytes = 123, 456
	if changed, err := c.EnsureEndpoint(k, ip, psk, lan); err != nil || !changed {
		t.Fatalf("roamed endpoint: changed=%v err=%v", changed, err)
	}
	if peer.Endpoint.AddrPort() != lan || peer.PresharedKey != psk || peer.ReceiveBytes != 123 || peer.TransmitBytes != 456 || !peer.LastHandshakeTime.Equal(handshake) || len(routes.entries) != 1 || routes.adds != 1 || routes.deletes != 0 {
		t.Fatal("endpoint update changed peer or route state")
	}
	for _, scenario := range []string{"psk", "ip", "handshake", "route", "owner", "write", "drift"} {
		t.Run(scenario, func(t *testing.T) {
			c, w, routes, _ := routeFixture(t)
			if _, err := c.Stage(k, ip, psk, lan); err != nil {
				t.Fatal(err)
			}
			w.direct.Peers[0].LastHandshakeTime = handshake
			if err := c.Apply(k, ip, psk, lan); err != nil {
				t.Fatal(err)
			}
			w.direct.Peers[0].Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("198.51.100.2:40002"))
			wantIP, wantPSK := ip, psk
			switch scenario {
			case "psk":
				wantPSK = controlTestKey(6)
			case "ip":
				wantIP = netip.MustParseAddr("10.0.0.3")
			case "handshake":
				w.direct.Peers[0].LastHandshakeTime = time.Time{}
			case "route":
				routes.entries = append(routes.entries, routes.entries[0])
			case "owner":
				w.stable.Peers[0].AllowedIPs = nil
			case "write":
				w.failUpdate = true
			case "drift":
				w.ignoreUpdate = true
			}
			changed, err := c.EnsureEndpoint(k, wantIP, wantPSK, lan)
			if scenario == "drift" {
				if !changed || !errors.Is(err, errEndpointRoamed) {
					t.Fatalf("endpoint drift was not reported for bounded retry: changed=%v err=%v", changed, err)
				}
			} else if err == nil || changed {
				t.Fatalf("accepted %s: changed=%v err=%v", scenario, changed, err)
			}
		})
	}
}
func (f *routeFakeOps) del(r netlink.Route) error {
	f.deletes++
	for i, v := range f.entries {
		if v.Equal(r) {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			if f.delError {
				f.delError = false
				return errors.New("delete applied with error")
			}
			return nil
		}
	}
	return errors.New("missing route")
}
func routeFixture(t *testing.T) (*routeController, *routeFakeWG, *routeFakeOps, string) {
	t.Helper()
	priv := controlTestKey(99)
	w := &routeFakeWG{stable: wgtypes.Device{Name: "stable", Type: wgtypes.LinuxKernel, PrivateKey: priv, PublicKey: priv.PublicKey(), ListenPort: 1000, Peers: []wgtypes.Peer{{PublicKey: controlTestKey(7), AllowedIPs: []net.IPNet{controlTestNet("10.0.0.0/24")}}}}, direct: wgtypes.Device{Name: "direct", Type: wgtypes.LinuxKernel, PrivateKey: priv, PublicKey: priv.PublicKey(), ListenPort: 1001}}
	r := &routeFakeOps{}
	p := filepath.Join(t.TempDir(), "private", "state")
	c, e := openRouteController(w, "stable", "direct", p, netip.MustParseAddr("10.0.0.1"), 10, r, false)
	if e != nil {
		t.Fatal(e)
	}
	return c, w, r, p
}
func TestRouteControlLifecycle(t *testing.T) {
	c, w, r, _ := routeFixture(t)
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	endpoint := netip.MustParseAddrPort("192.0.2.2:51820")
	ready, e := c.Stage(k, ip, psk, endpoint)
	if e != nil || ready || len(r.entries) != 0 {
		t.Fatalf("stage: %v %v %+v", ready, e, r.entries)
	}
	if e = c.Apply(k, ip, psk, endpoint); e == nil {
		t.Fatal("apply without handshake")
	}
	w.direct.Peers[0].LastHandshakeTime = time.Now()
	ready, e = c.Stage(k, ip, psk, endpoint)
	if e != nil || !ready {
		t.Fatalf("handshake: %v %v", ready, e)
	}
	if e = c.Apply(k, ip, psk, endpoint); e != nil {
		t.Fatal(e)
	}
	if e = c.Check(); e != nil {
		t.Fatal(e)
	}
	if len(r.entries) != 1 || r.entries[0].Src.String() != "10.0.0.1" {
		t.Fatal("bad route")
	}
	writes := w.writes
	_, e = c.Stage(k, ip, psk, netip.MustParseAddrPort("192.0.2.3:51820"))
	if e != nil || writes != w.writes {
		t.Fatal("active stage mutated peer", e)
	}
	other := netip.MustParseAddrPort("192.0.2.3:51820")
	w.direct.Peers[0].ReceiveBytes = 123
	if e = c.Apply(k, ip, psk, other); e != nil || w.direct.Peers[0].Endpoint.AddrPort() != other {
		t.Fatal("endpoint update failed", e)
	}
	if w.direct.Peers[0].PresharedKey != psk || w.direct.Peers[0].ReceiveBytes != 123 || len(w.direct.Peers[0].AllowedIPs) != 1 || w.direct.Peers[0].PersistentKeepaliveInterval != time.Second {
		t.Fatal("endpoint update changed peer state")
	}
	if e = c.Apply(k, ip, psk, netip.AddrPort{}); e == nil {
		t.Fatal("invalid endpoint accepted")
	}
	if e = c.Apply(k, ip, psk, endpoint); e != nil || w.direct.Peers[0].Endpoint.AddrPort() != endpoint {
		t.Fatal("endpoint rollback failed", e)
	}
	if e = c.Restore(k); e != nil {
		t.Fatal(e)
	}
	if len(r.entries) != 0 || len(w.direct.Peers) != 0 || r.deletes != 1 {
		t.Fatal("restore incomplete")
	}
}
func TestRouteControlCollisionAndRecovery(t *testing.T) {
	c, w, r, path := routeFixture(t)
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	endpoint := netip.MustParseAddrPort("192.0.2.2:51820")
	n := controlHostNet(ip)
	r.entries = []netlink.Route{{Dst: &n, Priority: 9, Gw: net.ParseIP("10.0.0.254")}}
	if _, e := c.Stage(k, ip, psk, endpoint); e == nil || w.writes != 0 {
		t.Fatal("collision accepted")
	}
	r.entries = nil
	if _, e := c.Stage(k, ip, psk, endpoint); e != nil {
		t.Fatal(e)
	}
	w.direct.Peers[0].LastHandshakeTime = time.Now()
	if e := c.Apply(k, ip, psk, endpoint); e != nil {
		t.Fatal(e)
	}
	if _, e := openRouteController(w, "stable", "", path, netip.Addr{}, 0, r, true); e != nil {
		t.Fatal(e)
	}
	if len(r.entries) != 0 || len(w.direct.Peers) != 0 {
		t.Fatal("recovery incomplete")
	}
}
func TestRouteControlExternalPeerConflict(t *testing.T) {
	c, w, _, _ := routeFixture(t)
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	endpoint := netip.MustParseAddrPort("192.0.2.2:51820")
	if _, e := c.Stage(k, ip, psk, endpoint); e != nil {
		t.Fatal(e)
	}
	w.direct.Peers[0].PersistentKeepaliveInterval = 25 * time.Second
	if e := c.Restore(k); e == nil {
		t.Fatal("changed peer removed")
	}
	if len(w.direct.Peers) != 1 {
		t.Fatal("peer removed")
	}
}

func TestRouteControlRecoveryFailures(t *testing.T) {
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	endpoint := netip.MustParseAddrPort("192.0.2.2:51820")
	for _, scenario := range []string{"planning", "partial-peer", "partial-psk", "partial-keepalive", "partial-host", "aborting", "partial-conflict", "staged", "route-add", "route-delete"} {
		t.Run(scenario, func(t *testing.T) {
			c, w, r, path := routeFixture(t)
			partial := scenario == "partial-peer" || scenario == "partial-psk" || scenario == "partial-keepalive" || scenario == "partial-host" || scenario == "partial-conflict" || scenario == "aborting"
			if partial {
				w.partialAdd = true
			}
			_, err := c.Stage(k, ip, psk, endpoint)
			if partial {
				if err == nil {
					t.Fatal("expected add failure")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "partial-psk":
				w.direct.Peers[0].PresharedKey = psk
			case "partial-keepalive":
				w.direct.Peers[0].PersistentKeepaliveInterval = time.Second
			case "partial-host":
				w.direct.Peers[0].AllowedIPs = []net.IPNet{controlHostNet(ip)}
			}
			if scenario == "planning" {
				w.direct.Peers = nil
				c.journal.Peers[k.String()].Phase = "planning"
				if err = c.save(); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "aborting" {
				w.failRemove = true
				if err = c.Restore(k); err == nil {
					t.Fatal("expected remove error")
				}
			}
			if scenario == "partial-conflict" {
				w.direct.Peers[0].PersistentKeepaliveInterval = 25 * time.Second
				if _, err = openRouteController(w, "stable", "", path, netip.Addr{}, 0, r, true); err == nil {
					t.Fatal("accepted unrelated partial peer")
				}
				if len(w.direct.Peers) != 1 {
					t.Fatal("removed changed peer")
				}
				return
			}
			if scenario == "route-add" || scenario == "route-delete" {
				w.direct.Peers[0].LastHandshakeTime = time.Now()
				if scenario == "route-add" {
					r.addError = true
				}
				err = c.Apply(k, ip, psk, endpoint)
				if scenario == "route-add" && err == nil {
					t.Fatal("expected add error")
				}
				if scenario == "route-delete" && err != nil {
					t.Fatal(err)
				}
				if scenario == "route-delete" {
					r.delError = true
					if err = c.Restore(k); err == nil {
						t.Fatal("expected delete error")
					}
				}
			}
			if _, err = openRouteController(w, "stable", "", path, netip.Addr{}, 0, r, true); err != nil {
				t.Fatal(err)
			}
			if len(w.direct.Peers) != 0 || len(r.entries) != 0 {
				t.Fatal("recovery left managed state")
			}
		})
	}
}

func TestRouteControlStableOwnerAndRouteConflicts(t *testing.T) {
	k, psk := controlTestKey(3), controlTestKey(5)
	ip := netip.MustParseAddr("10.0.0.2")
	endpoint := netip.MustParseAddrPort("192.0.2.2:51820")
	for _, operation := range []string{"stage", "apply", "check", "restore"} {
		t.Run(operation, func(t *testing.T) {
			c, w, _, _ := routeFixture(t)
			if _, e := c.Stage(k, ip, psk, endpoint); e != nil {
				t.Fatal(e)
			}
			w.stable.Peers[0].AllowedIPs = []net.IPNet{controlTestNet("10.1.0.0/16")}
			w.direct.Peers[0].LastHandshakeTime = time.Now()
			var err error
			switch operation {
			case "stage":
				_, err = c.Stage(k, ip, psk, endpoint)
			case "apply":
				err = c.Apply(k, ip, psk, endpoint)
			case "check":
				err = c.Check()
			case "restore":
				err = c.Restore(k)
			}
			if err == nil || len(w.direct.Peers) != 1 {
				t.Fatal("stable owner change accepted")
			}
		})
	}
	t.Run("changed route metric", func(t *testing.T) {
		c, w, r, _ := routeFixture(t)
		if _, e := c.Stage(k, ip, psk, endpoint); e != nil {
			t.Fatal(e)
		}
		w.direct.Peers[0].LastHandshakeTime = time.Now()
		if e := c.Apply(k, ip, psk, endpoint); e != nil {
			t.Fatal(e)
		}
		r.entries[0].Priority++
		if e := c.Restore(k); e == nil || len(r.entries) != 1 || len(w.direct.Peers) != 1 {
			t.Fatal("changed route accepted")
		}
	})
	t.Run("changed route mtu", func(t *testing.T) {
		c, w, r, _ := routeFixture(t)
		if _, e := c.Stage(k, ip, psk, endpoint); e != nil {
			t.Fatal(e)
		}
		w.direct.Peers[0].LastHandshakeTime = time.Now()
		if e := c.Apply(k, ip, psk, endpoint); e != nil {
			t.Fatal(e)
		}
		r.entries[0].MTU = 1400
		if e := c.Restore(k); e == nil || len(r.entries) != 1 {
			t.Fatal("changed route accepted")
		}
	})
}

func TestRouteControlDeviceValidation(t *testing.T) {
	c, w, r, path := routeFixture(t)
	w.direct.Type = wgtypes.Userspace
	if _, e := openRouteController(w, "stable", "direct", path, c.journal.Source, 10, r, false); e == nil {
		t.Fatal("userspace device accepted")
	}
	for _, name := range []string{"", ".", "..", "bad/name", "bad:name", "bad name", "1234567890123456"} {
		if routeValidName(name) {
			t.Fatalf("invalid name accepted: %q", name)
		}
	}
}

func TestRouteControlResolvedJournal(t *testing.T) {
	c, w, r, path := routeFixture(t)
	k, ip := controlTestKey(3), netip.MustParseAddr("10.0.0.2")
	if _, err := c.Stage(k, ip, controlTestKey(5), netip.MustParseAddrPort("192.0.2.2:51820")); err != nil {
		t.Fatal(err)
	}
	if err := c.RestoreAll(); err != nil {
		t.Fatal(err)
	}
	changed, err := openRouteController(w, "stable", "direct", path, c.journal.Source, 20, r, false)
	if err != nil || changed.journal.Metric != 20 {
		t.Fatal("resolved journal prevented a new route metric:", err)
	}
	w.direct.Name = "removed"
	if _, err := openRouteController(w, "stable", "", path, netip.Addr{}, 0, r, true); err != nil {
		t.Fatal("resolved route journal required an unused direct device:", err)
	}
}
