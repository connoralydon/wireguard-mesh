package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type controlFake struct {
	t     *testing.T
	d     wgtypes.Device
	calls int
	hook  func(int, string) error
	drop  bool
}

func controlTestKey(b byte) (k wgtypes.Key) {
	for i := range k {
		k[i] = b
	}
	return k
}

func controlTestNet(s string) net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *n
}

func controlClone(d wgtypes.Device) wgtypes.Device {
	d.Peers = slices.Clone(d.Peers)
	for i := range d.Peers {
		p := &d.Peers[i]
		p.AllowedIPs = slices.Clone(p.AllowedIPs)
		if p.Endpoint != nil {
			e := *p.Endpoint
			p.Endpoint = &e
		}
	}
	return d
}

func (f *controlFake) Device(name string) (*wgtypes.Device, error) {
	if name != f.d.Name {
		return nil, errors.New("wrong device name")
	}
	d := controlClone(f.d)
	return &d, nil
}

func (f *controlFake) ConfigureDevice(name string, cfg wgtypes.Config) error {
	f.t.Helper()
	if name != f.d.Name || cfg.ReplacePeers || cfg.PrivateKey != nil || cfg.ListenPort != nil || cfg.FirewallMark != nil {
		f.t.Fatal("controller tried to change device settings")
	}
	f.calls++
	step := func(stage string) error {
		if f.hook != nil {
			return f.hook(f.calls, stage)
		}
		return nil
	}
	if err := step("before"); err != nil || f.drop {
		return err
	}
	for _, pc := range cfg.Peers {
		if pc.ReplaceAllowedIPs || pc.PersistentKeepaliveInterval != nil {
			f.t.Fatal("controller tried to replace prefixes or keepalive settings")
		}
		p := controlFindPeer(&f.d, pc.PublicKey)
		if pc.Remove {
			f.d.Peers = slices.DeleteFunc(f.d.Peers, func(p wgtypes.Peer) bool { return p.PublicKey == pc.PublicKey })
			if err := step("removed"); err != nil {
				return err
			}
			continue
		}
		if p == nil {
			if pc.UpdateOnly {
				continue
			}
			f.d.Peers = append(f.d.Peers, wgtypes.Peer{PublicKey: pc.PublicKey, ProtocolVersion: 1})
			p = &f.d.Peers[len(f.d.Peers)-1]
			if err := step("created"); err != nil {
				return err
			}
		}
		if pc.PresharedKey != nil {
			p.PresharedKey = *pc.PresharedKey
			if err := step("psk"); err != nil {
				return err
			}
		}
		if pc.Endpoint != nil {
			e := *pc.Endpoint
			p.Endpoint = &e
			if err := step("endpoint"); err != nil {
				return err
			}
		}
		for _, n := range pc.AllowedIPs {
			// WireGuard transfers an equal prefix, but retains broader prefixes.
			for i := range f.d.Peers {
				q := &f.d.Peers[i]
				q.AllowedIPs = slices.DeleteFunc(q.AllowedIPs, func(old net.IPNet) bool { return old.String() == n.String() })
			}
			p.AllowedIPs = append(p.AllowedIPs, n)
			if err := step("allowed"); err != nil {
				return err
			}
		}
	}
	return step("after")
}

func controlFixture(t *testing.T, prefix string) (*controller, *controlFake, string) {
	t.Helper()
	private := controlTestKey(99)
	f := &controlFake{t: t, d: wgtypes.Device{
		Name: "wg-test", PrivateKey: private, PublicKey: private.PublicKey(), ListenPort: 51820, FirewallMark: 7,
		Peers: []wgtypes.Peer{
			{PublicKey: controlTestKey(2), PresharedKey: controlTestKey(4), Endpoint: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:51820")),
				PersistentKeepaliveInterval: 25 * time.Second, ProtocolVersion: 1,
				AllowedIPs: []net.IPNet{controlTestNet(prefix), controlTestNet("192.0.2.0/24")}},
			{PublicKey: controlTestKey(6), AllowedIPs: []net.IPNet{controlTestNet("198.51.100.0/24")}},
		},
	}}
	path := filepath.Join(t.TempDir(), "state", "recovery.json")
	c, err := newController(f, f.d.Name, path)
	if err != nil {
		t.Fatal(err)
	}
	return c, f, path
}

func controlApply(c *controller, ip string) error {
	return c.Apply(controlTestKey(3), netip.MustParseAddr(ip), controlTestKey(5), netip.MustParseAddrPort("192.0.2.3:51820"))
}

func controlAssertDevice(t *testing.T, got, want wgtypes.Device) {
	t.Helper()
	normalize := func(d wgtypes.Device) wgtypes.Device {
		d = controlClone(d)
		slices.SortFunc(d.Peers, func(a, b wgtypes.Peer) int { return bytes.Compare(a.PublicKey[:], b.PublicKey[:]) })
		for i := range d.Peers {
			slices.SortFunc(d.Peers[i].AllowedIPs, func(a, b net.IPNet) int { return strings.Compare(a.String(), b.String()) })
		}
		return d
	}
	if !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Fatal("WireGuard state differs from expected state")
	}
}

func controlReadJournal(t *testing.T, path string) controlJournal {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var j controlJournal
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	return j
}

func TestControlHostRoutes(t *testing.T) {
	for _, tc := range []struct{ prefix, ip string }{
		{"10.0.0.0/8", "10.2.3.4"}, {"10.2.3.4/32", "10.2.3.4"},
		{"0.0.0.0/0", "10.2.3.4"}, {"fd00::/64", "fd00::3"}, {"fd00::3/128", "fd00::3"}, {"::/0", "fd00::3"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			c, f, path := controlFixture(t, tc.prefix)
			baseline := controlClone(f.d)
			if key, port := c.Identity(); key != f.d.PrivateKey || port != 51820 {
				t.Fatal("wrong startup identity")
			}
			f.hook = func(call int, stage string) error {
				if call == 1 && stage == "before" {
					r := controlReadJournal(t, path).Peers[controlTestKey(3).String()]
					if r == nil || r.Phase != "adding" || r.Owner != controlTestKey(2) || r.Prefix.String() != tc.prefix {
						t.Fatal("ownership journal was not written before apply")
					}
				}
				return nil
			}
			if err := controlApply(c, tc.ip); err != nil {
				t.Fatal(err)
			}
			owner, host, err := controlOwner(&f.d, netip.MustParseAddr(tc.ip), wgtypes.Key{})
			if err != nil || owner != controlTestKey(3) || host.Bits() != host.Addr().BitLen() {
				t.Fatal("direct host route was not applied")
			}
			if err := c.Check(); err != nil {
				t.Fatal(err)
			}
			if err := c.Restore(controlTestKey(3)); err != nil {
				t.Fatal(err)
			}
			if err := c.Restore(controlTestKey(3)); err != nil {
				t.Fatal("restore is not idempotent:", err)
			}
			controlAssertDevice(t, f.d, baseline)
			if len(controlReadJournal(t, path).Peers) != 0 {
				t.Fatal("completed recovery remains in journal")
			}
		})
	}
}

func TestControlPartialApplyErrors(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
		for _, stage := range []string{"before", "created", "psk", "endpoint", "allowed", "after"} {
			t.Run(prefix+"/"+stage, func(t *testing.T) {
				c, f, path := controlFixture(t, prefix)
				baseline := controlClone(f.d)
				injected := errors.New("injected configuration error")
				f.hook = func(call int, at string) error {
					if call == 1 && at == stage {
						return injected
					}
					return nil
				}
				if err := controlApply(c, "10.2.3.4"); !errors.Is(err, injected) {
					t.Fatal("apply error was not returned:", err)
				}
				controlAssertDevice(t, f.d, baseline)
				if len(controlReadJournal(t, path).Peers) != 0 {
					t.Fatal("partial apply was not rolled back")
				}
			})
		}
	}
}

func controlCrash(t *testing.T, run func()) {
	t.Helper()
	defer func() {
		if recover() != "simulated crash" {
			t.Fatal("expected a simulated crash")
		}
	}()
	run()
}

func TestControlRestartDuringApply(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
		for _, stage := range []string{"before", "created", "psk", "endpoint", "allowed", "after", "active"} {
			t.Run(prefix+"/"+stage, func(t *testing.T) {
				c, f, path := controlFixture(t, prefix)
				baseline := controlClone(f.d)
				f.hook = func(call int, at string) error {
					if call == 1 && at == stage {
						panic("simulated crash")
					}
					return nil
				}
				if stage == "active" {
					if err := controlApply(c, "10.2.3.4"); err != nil {
						t.Fatal(err)
					}
				} else {
					controlCrash(t, func() { _ = controlApply(c, "10.2.3.4") })
				}
				f.hook = nil
				restarted, err := newController(f, f.d.Name, path)
				if err != nil {
					t.Fatal(err)
				}
				controlAssertDevice(t, f.d, baseline)
				if err := controlApply(restarted, "10.2.3.4"); err != nil {
					t.Fatal("recovery prevented a new trial:", err)
				}
				if err := restarted.RestoreAll(); err != nil {
					t.Fatal(err)
				}
				controlAssertDevice(t, f.d, baseline)
			})
		}
	}
}

func TestControlRestartDuringRestore(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		call   int
		stage  string
	}{
		{"10.0.0.0/8", 2, "before"}, {"10.0.0.0/8", 2, "removed"}, {"10.0.0.0/8", 2, "after"},
		{"10.2.3.4/32", 2, "before"}, {"10.2.3.4/32", 2, "allowed"}, {"10.2.3.4/32", 2, "after"},
		{"10.2.3.4/32", 3, "before"}, {"10.2.3.4/32", 3, "removed"}, {"10.2.3.4/32", 3, "after"},
	} {
		t.Run(tc.prefix+"/"+tc.stage, func(t *testing.T) {
			c, f, path := controlFixture(t, tc.prefix)
			baseline := controlClone(f.d)
			if err := controlApply(c, "10.2.3.4"); err != nil {
				t.Fatal(err)
			}
			f.hook = func(call int, stage string) error {
				if call == tc.call && stage == tc.stage {
					if controlReadJournal(t, path).Peers[controlTestKey(3).String()].Phase != "restoring" {
						t.Fatal("restore intent was not durable")
					}
					panic("simulated crash")
				}
				return nil
			}
			controlCrash(t, func() { _ = c.Restore(controlTestKey(3)) })
			f.hook = nil
			if _, err := newController(f, f.d.Name, path); err != nil {
				t.Fatal(err)
			}
			controlAssertDevice(t, f.d, baseline)
		})
	}
}

func TestControlPreservesUnrelatedEditsAndRoaming(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
		t.Run(prefix, func(t *testing.T) {
			c, f, _ := controlFixture(t, prefix)
			if err := controlApply(c, "10.2.3.4"); err != nil {
				t.Fatal(err)
			}
			hub := controlFindPeer(&f.d, controlTestKey(2))
			hub.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.9:9000"))
			hub.PresharedKey = controlTestKey(20)
			hub.PersistentKeepaliveInterval = 17 * time.Second
			hub.AllowedIPs = append(hub.AllowedIPs, controlTestNet("172.16.0.0/12"))
			direct := controlFindPeer(&f.d, controlTestKey(3))
			direct.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.3:1234"))
			direct.LastHandshakeTime, direct.ReceiveBytes, direct.TransmitBytes = time.Now(), 900, 800
			f.d.Peers = append(f.d.Peers, wgtypes.Peer{PublicKey: controlTestKey(30), AllowedIPs: []net.IPNet{controlTestNet("203.0.113.0/24")}})
			want := controlClone(f.d)
			want.Peers = slices.DeleteFunc(want.Peers, func(p wgtypes.Peer) bool { return p.PublicKey == controlTestKey(3) })
			if strings.HasSuffix(prefix, "/32") {
				hub = controlFindPeer(&want, controlTestKey(2))
				hub.AllowedIPs = append(hub.AllowedIPs, controlTestNet(prefix))
			}
			if err := c.Check(); err != nil {
				t.Fatal("unrelated edits were treated as conflicts:", err)
			}
			if err := c.RestoreAll(); err != nil {
				t.Fatal(err)
			}
			controlAssertDevice(t, f.d, want)
		})
	}
}

func TestControlOwnedDriftRefusesWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*wgtypes.Device)
	}{
		{"extra prefix", func(d *wgtypes.Device) {
			p := controlFindPeer(d, controlTestKey(3))
			p.AllowedIPs = append(p.AllowedIPs, controlTestNet("172.16.0.0/12"))
		}},
		{"missing prefix", func(d *wgtypes.Device) { controlFindPeer(d, controlTestKey(3)).AllowedIPs = nil }},
		{"PSK", func(d *wgtypes.Device) { controlFindPeer(d, controlTestKey(3)).PresharedKey = controlTestKey(42) }},
		{"zero PSK", func(d *wgtypes.Device) { controlFindPeer(d, controlTestKey(3)).PresharedKey = wgtypes.Key{} }},
		{"keepalive", func(d *wgtypes.Device) {
			controlFindPeer(d, controlTestKey(3)).PersistentKeepaliveInterval = time.Second
		}},
		{"protocol", func(d *wgtypes.Device) { controlFindPeer(d, controlTestKey(3)).ProtocolVersion = 2 }},
		{"missing direct", func(d *wgtypes.Device) {
			d.Peers = slices.DeleteFunc(d.Peers, func(p wgtypes.Peer) bool { return p.PublicKey == controlTestKey(3) })
		}},
		{"missing hub", func(d *wgtypes.Device) {
			d.Peers = slices.DeleteFunc(d.Peers, func(p wgtypes.Peer) bool { return p.PublicKey == controlTestKey(2) })
		}},
		{"identity", func(d *wgtypes.Device) { d.PublicKey = controlTestKey(44) }},
	} {
		for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
			t.Run(tc.name+"/"+prefix, func(t *testing.T) {
				c, f, path := controlFixture(t, prefix)
				if err := controlApply(c, "10.2.3.4"); err != nil {
					t.Fatal(err)
				}
				tc.edit(&f.d)
				want, calls := controlClone(f.d), f.calls
				if c.Check() == nil || c.Restore(controlTestKey(3)) == nil || controlApply(c, "10.2.3.4") == nil {
					t.Fatal("owned drift was accepted")
				}
				if _, err := newController(f, f.d.Name, path); err == nil {
					t.Fatal("startup erased external changes")
				}
				if f.calls != calls {
					t.Fatal("conflict caused a WireGuard write")
				}
				controlAssertDevice(t, f.d, want)
			})
		}
	}
}

func TestControlStableOwnerAndExistingPeer(t *testing.T) {
	for _, mode := range []string{"missing owner", "existing empty", "existing routes", "self", "zero key", "ambiguous owner"} {
		t.Run(mode, func(t *testing.T) {
			c, f, _ := controlFixture(t, "10.0.0.0/8")
			key := controlTestKey(3)
			switch mode {
			case "missing owner":
				f.d.Peers[0].AllowedIPs = nil
			case "existing empty":
				f.d.Peers = append(f.d.Peers, wgtypes.Peer{PublicKey: key})
			case "existing routes":
				f.d.Peers = append(f.d.Peers, wgtypes.Peer{PublicKey: key, AllowedIPs: []net.IPNet{controlTestNet("172.16.0.0/12")}})
			case "self":
				key = f.d.PublicKey
			case "zero key":
				key = wgtypes.Key{}
			case "ambiguous owner":
				f.d.Peers[1].AllowedIPs = append(f.d.Peers[1].AllowedIPs, controlTestNet("10.0.0.0/8"))
			}
			want := controlClone(f.d)
			if err := c.Apply(key, netip.MustParseAddr("10.2.3.4"), controlTestKey(5), netip.MustParseAddrPort("192.0.2.3:51820")); err == nil {
				t.Fatal("unsupported peer arrangement accepted")
			}
			if f.calls != 0 {
				t.Fatal("invalid apply wrote WireGuard configuration")
			}
			controlAssertDevice(t, f.d, want)
		})
	}
	t.Run("longest prefix", func(t *testing.T) {
		c, f, path := controlFixture(t, "10.0.0.0/8")
		f.d.Peers[1].AllowedIPs = append(f.d.Peers[1].AllowedIPs, controlTestNet("10.2.0.0/16"))
		if err := controlApply(c, "10.2.3.4"); err != nil {
			t.Fatal(err)
		}
		r := controlReadJournal(t, path).Peers[controlTestKey(3).String()]
		if r.Owner != controlTestKey(6) || r.Prefix.String() != "10.2.0.0/16" {
			t.Fatal("longest-prefix owner not recorded")
		}
		f.d.Peers[0].AllowedIPs = append(f.d.Peers[0].AllowedIPs, controlTestNet("10.2.3.0/24"))
		if c.Check() == nil || c.RestoreAll() == nil {
			t.Fatal("new stable owner was not treated as a conflict")
		}
	})
}

func TestControlCorruptJournal(t *testing.T) {
	for _, mode := range []string{"syntax", "trailing", "unknown field", "version", "interface", "identity", "nil records", "nil record", "bad key", "bad phase", "self owner", "missing prefix", "duplicate IP"} {
		t.Run(mode, func(t *testing.T) {
			c, f, path := controlFixture(t, "10.2.3.4/32")
			if err := controlApply(c, "10.2.3.4"); err != nil {
				t.Fatal(err)
			}
			j := controlReadJournal(t, path)
			key := controlTestKey(3).String()
			switch mode {
			case "version":
				j.Version++
			case "interface":
				j.Name = "another-interface"
			case "identity":
				j.Public = controlTestKey(88)
			case "nil records":
				j.Peers = nil
			case "nil record":
				j.Peers[key] = nil
			case "bad key":
				j.Peers["not-a-key"] = j.Peers[key]
			case "bad phase":
				j.Peers[key].Phase = "unknown"
			case "self owner":
				j.Peers[key].Owner = controlTestKey(3)
			case "missing prefix":
				j.Peers[key].Prefix = netip.Prefix{}
			case "duplicate IP":
				j.Peers[controlTestKey(33).String()] = j.Peers[key]
			}
			data, err := json.Marshal(j)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "syntax":
				data = []byte(`{"Version":`)
			case "trailing":
				data = append(data, []byte(`{}`)...)
			case "unknown field":
				data = append([]byte(`{"Unexpected":true,`), data[1:]...)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			want, calls := controlClone(f.d), f.calls
			if _, err := newController(f, f.d.Name, path); err == nil {
				t.Fatal("corrupt journal accepted")
			}
			if f.calls != calls {
				t.Fatal("corrupt journal caused a WireGuard write")
			}
			controlAssertDevice(t, f.d, want)
		})
	}
}

func TestControlJournalProtection(t *testing.T) {
	t.Run("permissions and no secrets", func(t *testing.T) {
		c, _, path := controlFixture(t, "10.0.0.0/8")
		if err := controlApply(c, "10.2.3.4"); err != nil {
			t.Fatal(err)
		}
		for path, perm := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != perm {
				t.Fatalf("wrong journal permissions for %s", path)
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []wgtypes.Key{controlTestKey(99), controlTestKey(4), controlTestKey(5)} {
			encoded, _ := json.Marshal(secret)
			if bytes.Contains(data, encoded) || bytes.Contains(data, []byte(secret.String())) {
				t.Fatal("journal contains a private key or PSK")
			}
		}
	})
	for _, mode := range []string{"file symlink", "directory symlink", "file permissions", "directory permissions", "blocked write"} {
		t.Run(mode, func(t *testing.T) {
			c, f, path := controlFixture(t, "10.0.0.0/8")
			victim := filepath.Join(t.TempDir(), "untouched")
			if err := os.WriteFile(victim, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "file symlink":
				err = os.Symlink(victim, path)
			case "directory symlink":
				link := filepath.Join(t.TempDir(), "link")
				err = os.Symlink(filepath.Dir(path), link)
				path = filepath.Join(link, "recovery.json")
			case "file permissions":
				err = os.WriteFile(path, []byte("{}"), 0644)
			case "directory permissions":
				err = os.Chmod(filepath.Dir(path), 0755)
			case "blocked write":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := newController(f, f.d.Name, path); err == nil {
				t.Fatal("unsafe journal path was accepted")
			}
			if mode != "directory symlink" {
				if err := controlApply(c, "10.2.3.4"); err == nil {
					t.Fatal("apply ignored an unsafe journal write")
				}
			}
			if f.calls != 0 {
				t.Fatal("unsafe journal caused WireGuard changes")
			}
			data, err := os.ReadFile(victim)
			if err != nil || string(data) != "untouched" {
				t.Fatal("symlink target was modified")
			}
		})
	}
}

func TestControlVerifiesWrites(t *testing.T) {
	c, f, _ := controlFixture(t, "10.0.0.0/8")
	f.drop = true
	if controlApply(c, "10.2.3.4") == nil {
		t.Fatal("silently dropped apply was accepted")
	}
	f.drop = false
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	f.drop = true
	if c.RestoreAll() == nil {
		t.Fatal("silently dropped removal was accepted")
	}
	f.drop = false
	if err := c.RestoreAll(); err != nil {
		t.Fatal("restore retry failed:", err)
	}
}

func TestControlMultiplePeersAndRepeatedApply(t *testing.T) {
	c, f, path := controlFixture(t, "10.0.0.0/8")
	baseline := controlClone(f.d)
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(controlTestKey(3), netip.MustParseAddr("10.2.3.4"), controlTestKey(5), netip.MustParseAddrPort("192.0.2.4:9999")); err != nil {
		t.Fatal(err)
	}
	if controlFindPeer(&f.d, controlTestKey(3)).Endpoint.Port != 9999 {
		t.Fatal("repeated apply did not update the endpoint")
	}
	if err := controlApply(c, "10.2.3.5"); err == nil {
		t.Fatal("second address for one peer accepted")
	}
	if err := c.Apply(controlTestKey(7), netip.MustParseAddr("10.2.3.4"), wgtypes.Key{}, netip.MustParseAddrPort("192.0.2.7:51820")); err == nil {
		t.Fatal("duplicate managed address accepted")
	}
	if err := c.Apply(controlTestKey(7), netip.MustParseAddr("10.2.3.7"), wgtypes.Key{}, netip.MustParseAddrPort("[fe80::7%en0]:51820")); err != nil {
		t.Fatal(err)
	}
	if len(controlReadJournal(t, path).Peers) != 2 {
		t.Fatal("missing independent ownership records")
	}
	if err := c.RestoreAll(); err != nil {
		t.Fatal(err)
	}
	controlAssertDevice(t, f.d, baseline)
}

func TestControlFailedRecoveryRemainsRetryable(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
		for _, stage := range []string{"before", "after"} {
			t.Run(prefix+"/"+stage, func(t *testing.T) {
				c, f, path := controlFixture(t, prefix)
				baseline := controlClone(f.d)
				injected := errors.New("injected error")
				f.hook = func(call int, at string) error {
					if call == 1 && at == "after" || call == 2 && at == stage {
						return injected
					}
					return nil
				}
				if err := controlApply(c, "10.2.3.4"); !errors.Is(err, injected) {
					t.Fatal("missing apply and rollback error:", err)
				}
				if len(controlReadJournal(t, path).Peers) != 1 || c.Check() == nil {
					t.Fatal("unfinished rollback was not retained")
				}
				f.hook = nil
				if _, err := newController(f, f.d.Name, path); err != nil {
					t.Fatal(err)
				}
				controlAssertDevice(t, f.d, baseline)
			})
		}
	}
}

func TestControlJournalFailureAfterApply(t *testing.T) {
	c, f, path := controlFixture(t, "10.2.3.4/32")
	baseline := controlClone(f.d)
	f.hook = func(call int, stage string) error {
		if call == 1 && stage == "after" {
			return os.Chmod(filepath.Dir(path), 0500)
		}
		return nil
	}
	if err := controlApply(c, "10.2.3.4"); err == nil {
		t.Fatal("journal failure was not returned")
	}
	if f.calls != 1 || controlReadJournal(t, path).Peers[controlTestKey(3).String()].Phase != "adding" {
		t.Fatal("failed journal write lost the write-ahead recovery record")
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	f.hook = nil
	if _, err := newController(f, f.d.Name, path); err != nil {
		t.Fatal(err)
	}
	controlAssertDevice(t, f.d, baseline)
}

func TestControlRecoveryConflictPreservesPeer(t *testing.T) {
	c, f, path := controlFixture(t, "10.2.3.4/32")
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	f.hook = func(call int, stage string) error {
		if call == 2 && stage == "allowed" {
			panic("simulated crash")
		}
		return nil
	}
	controlCrash(t, func() { _ = c.RestoreAll() })
	f.hook = nil
	p := controlFindPeer(&f.d, controlTestKey(3))
	p.AllowedIPs = append(p.AllowedIPs, controlTestNet("172.16.0.0/12"))
	want, calls := controlClone(f.d), f.calls
	if _, err := newController(f, f.d.Name, path); err == nil || f.calls != calls {
		t.Fatal("recovery erased a changed peer")
	}
	controlAssertDevice(t, f.d, want)
}

func TestControlRestoreAllContinuesAfterConflict(t *testing.T) {
	c, f, path := controlFixture(t, "10.0.0.0/8")
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(controlTestKey(7), netip.MustParseAddr("10.2.3.7"), wgtypes.Key{}, netip.MustParseAddrPort("192.0.2.7:51820")); err != nil {
		t.Fatal(err)
	}
	controlFindPeer(&f.d, controlTestKey(3)).PersistentKeepaliveInterval = time.Second
	if c.RestoreAll() == nil {
		t.Fatal("missing conflict error")
	}
	if controlFindPeer(&f.d, controlTestKey(7)) != nil || controlFindPeer(&f.d, controlTestKey(3)) == nil || len(controlReadJournal(t, path).Peers) != 1 {
		t.Fatal("independent recovery did not preserve only the conflicting peer")
	}
}

func TestControlInvalidAddresses(t *testing.T) {
	for _, tc := range []struct{ ip, endpoint string }{
		{"0.0.0.0", "192.0.2.3:51820"}, {"224.0.0.1", "192.0.2.3:51820"}, {"::ffff:10.2.3.4", "192.0.2.3:51820"},
		{"fe80::3%en0", "192.0.2.3:51820"}, {"10.2.3.4", "192.0.2.3:0"}, {"10.2.3.4", "[fe80::3]:51820"},
		{"10.2.3.4", "0.0.0.0:51820"}, {"10.2.3.4", "239.0.0.1:51820"},
	} {
		t.Run(tc.ip+"/"+tc.endpoint, func(t *testing.T) {
			c, f, _ := controlFixture(t, "10.0.0.0/8")
			if err := c.Apply(controlTestKey(3), netip.MustParseAddr(tc.ip), wgtypes.Key{}, netip.MustParseAddrPort(tc.endpoint)); err == nil || f.calls != 0 {
				t.Fatal("invalid host or endpoint accepted")
			}
		})
	}
}
