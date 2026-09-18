package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type controlFake struct {
	t        *testing.T
	d        wgtypes.Device
	calls    int
	hook     func(int, string) error
	drop     bool
	readHook func() error
	configs  []wgtypes.Config
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
	if f.readHook != nil {
		if err := f.readHook(); err != nil {
			return nil, err
		}
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
	f.configs = append(f.configs, cfg)
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
			reads := 0
			f.readHook = func() error {
				reads++
				if reads == 2 && controlReadJournal(t, path).Peers[controlTestKey(3).String()].Phase != "planning" {
					t.Fatal("absence and ownership were not rechecked from durable planning")
				}
				return nil
			}
			f.hook = func(call int, stage string) error {
				if call == 1 && stage == "before" {
					r := controlReadJournal(t, path).Peers[controlTestKey(3).String()]
					if reads != 2 || r == nil || r.Phase != "adding" || r.Owner != controlTestKey(2) || r.Prefix.String() != tc.prefix {
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
				if c.Check() == nil || controlApply(c, "10.2.3.4") == nil || c.Rekey(controlTestKey(3), controlTestKey(5), controlTestKey(8)) == nil {
					t.Fatal("owned drift was accepted")
				}
				if at, err := c.Handshake(controlTestKey(3)); err == nil || !at.IsZero() {
					t.Fatal("handshake accepted owned drift")
				}
				baseline := tc.name == "missing direct" && prefix == "10.0.0.0/8"
				if err := c.Restore(controlTestKey(3)); (err == nil) != baseline {
					t.Fatal("restore did not distinguish a verified baseline from a conflict:", err)
				}
				if _, err := newController(f, f.d.Name, path); (err == nil) != baseline {
					t.Fatal("startup did not distinguish a verified baseline from a conflict:", err)
				}
				if len(controlReadJournal(t, path).Peers) == 0 && !baseline {
					t.Fatal("conflict lost its journal record")
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
	for _, mode := range []string{"syntax", "trailing", "unknown field", "version", "interface", "identity", "nil records", "nil record", "bad key", "bad phase", "self owner", "missing prefix", "duplicate IP", "missing next hash", "zero next hash", "unexpected next hash"} {
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
			case "missing next hash":
				j.Peers[key].Phase = "rekeying"
			case "zero next hash":
				j.Peers[key].Phase = "rekeying"
				j.Peers[key].NextPSKHash = new([32]byte)
			case "unexpected next hash":
				hash := j.Peers[key].PSKHash
				j.Peers[key].NextPSKHash = &hash
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

func TestControlRekey(t *testing.T) {
	for _, tc := range []struct{ prefix, ip string }{
		{"10.0.0.0/8", "10.2.3.4"}, {"10.2.3.4/32", "10.2.3.4"},
		{"fd00::/64", "fd00::3"}, {"fd00::3/128", "fd00::3"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			c, f, path := controlFixture(t, tc.prefix)
			baseline := controlClone(f.d)
			if err := controlApply(c, tc.ip); err != nil {
				t.Fatal(err)
			}
			key, oldPSK, newPSK := controlTestKey(3), controlTestKey(5), controlTestKey(8)
			p := controlFindPeer(&f.d, key)
			p.Endpoint = net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.3:9999"))
			p.LastHandshakeTime, p.ReceiveBytes, p.TransmitBytes = time.Now(), 123, 456
			want := controlClone(f.d)
			controlFindPeer(&want, key).PresharedKey = newPSK
			f.hook = func(call int, stage string) error {
				if call == 2 && stage == "before" {
					r := controlReadJournal(t, path).Peers[key.String()]
					if r.Phase != "rekeying" || r.PSKHash != sha256.Sum256(oldPSK[:]) || r.NextPSKHash == nil || *r.NextPSKHash != sha256.Sum256(newPSK[:]) {
						t.Fatal("rekey transition was not durable before the update")
					}
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					for _, secret := range []wgtypes.Key{f.d.PrivateKey, controlTestKey(4), oldPSK, newPSK} {
						encoded, _ := json.Marshal(secret)
						if bytes.Contains(data, encoded) || bytes.Contains(data, []byte(secret.String())) {
							t.Fatal("rekey journal contains a secret")
						}
					}
				}
				return nil
			}
			if err := c.Rekey(key, oldPSK, newPSK); err != nil {
				t.Fatal(err)
			}
			cfg := wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, UpdateOnly: true, PresharedKey: &newPSK}}}
			if f.calls != 2 || !reflect.DeepEqual(f.configs[1], cfg) {
				t.Fatal("rekey was not a PSK-only UpdateOnly operation")
			}
			controlAssertDevice(t, f.d, want)
			r := controlReadJournal(t, path).Peers[key.String()]
			data, err := json.Marshal(r)
			if err != nil || r.Phase != "active" || r.PSKHash != sha256.Sum256(newPSK[:]) || bytes.Contains(data, []byte("NextPSKHash")) {
				t.Fatal("completed rekey did not retain only the installed hash")
			}
			if err := c.Check(); err != nil {
				t.Fatal(err)
			}
			if at, err := c.Handshake(key); err != nil || !at.Equal(p.LastHandshakeTime) {
				t.Fatal("rekey changed the handshake:", at, err)
			}
			if err := c.Rekey(key, oldPSK, controlTestKey(9)); err == nil || f.calls != 2 {
				t.Fatal("completed rekey still accepted the old hash")
			}
			if _, err := newController(f, f.d.Name, path); err != nil {
				t.Fatal(err)
			}
			controlAssertDevice(t, f.d, baseline)
		})
	}
}

func TestControlRekeyPreconditions(t *testing.T) {
	for _, mode := range []string{"unmanaged", "stable owner", "zero new", "wrong old", "planning", "adding", "aborting", "restoring", "rekeying", "other drift", "other unfinished"} {
		t.Run(mode, func(t *testing.T) {
			c, f, path := controlFixture(t, "10.0.0.0/8")
			if err := controlApply(c, "10.2.3.4"); err != nil {
				t.Fatal(err)
			}
			key, oldPSK, newPSK := controlTestKey(3), controlTestKey(5), controlTestKey(8)
			switch mode {
			case "unmanaged":
				key = controlTestKey(9)
			case "stable owner":
				key = controlTestKey(2)
			case "zero new":
				newPSK = wgtypes.Key{}
			case "wrong old":
				oldPSK = controlTestKey(9)
			case "other drift", "other unfinished":
				other := controlTestKey(7)
				if err := c.Apply(other, netip.MustParseAddr("10.2.3.7"), oldPSK, netip.MustParseAddrPort("192.0.2.7:51820")); err != nil {
					t.Fatal(err)
				}
				if mode == "other drift" {
					controlFindPeer(&f.d, other).PresharedKey = newPSK
				} else {
					c.journal.Peers[other.String()].Phase = "restoring"
				}
			default:
				c.journal.Peers[key.String()].Phase = mode
			}
			want, calls := controlClone(f.d), f.calls
			journal := controlReadJournal(t, path)
			if c.Rekey(key, oldPSK, newPSK) == nil || f.calls != calls {
				t.Fatal("invalid rekey was accepted or wrote WireGuard state")
			}
			controlAssertDevice(t, f.d, want)
			if !reflect.DeepEqual(controlReadJournal(t, path), journal) {
				t.Fatal("invalid rekey changed the journal")
			}
		})
	}
	t.Run("zero old", func(t *testing.T) {
		c, _, _ := controlFixture(t, "10.0.0.0/8")
		key := controlTestKey(3)
		if err := c.Apply(key, netip.MustParseAddr("10.2.3.4"), wgtypes.Key{}, netip.MustParseAddrPort("192.0.2.3:51820")); err != nil {
			t.Fatal(err)
		}
		if err := c.Rekey(key, wgtypes.Key{}, controlTestKey(8)); err != nil {
			t.Fatal("rekey from an unkeyed peer failed:", err)
		}
	})
}

func TestControlRekeyFailures(t *testing.T) {
	for _, tc := range []struct{ prefix, ip string }{
		{"10.0.0.0/8", "10.2.3.4"}, {"10.2.3.4/32", "10.2.3.4"},
		{"fd00::/64", "fd00::3"}, {"fd00::3/128", "fd00::3"},
	} {
		for _, stage := range []string{"before", "psk", "after", "readback"} {
			for _, mode := range []string{"error", "crash"} {
				t.Run(tc.prefix+"/"+stage+"/"+mode, func(t *testing.T) {
					c, f, path := controlFixture(t, tc.prefix)
					baseline := controlClone(f.d)
					if err := controlApply(c, tc.ip); err != nil {
						t.Fatal(err)
					}
					injected := errors.New("injected rekey failure")
					fail := func() error {
						if mode == "crash" {
							panic("simulated crash")
						}
						return injected
					}
					f.hook = func(call int, at string) error {
						if call == 2 && at == stage {
							return fail()
						}
						return nil
					}
					reads := 0
					f.readHook = func() error {
						reads++
						if reads == 3 && stage == "readback" {
							return fail()
						}
						return nil
					}
					key, oldPSK, newPSK := controlTestKey(3), controlTestKey(5), controlTestKey(8)
					if mode == "crash" {
						controlCrash(t, func() { _ = c.Rekey(key, oldPSK, newPSK) })
					} else if err := c.Rekey(key, oldPSK, newPSK); !errors.Is(err, injected) {
						t.Fatal("rekey error was not returned:", err)
					}
					f.hook, f.readHook = nil, nil
					r := controlReadJournal(t, path).Peers[key.String()]
					if r.Phase != "rekeying" || r.PSKHash != sha256.Sum256(oldPSK[:]) || r.NextPSKHash == nil || *r.NextPSKHash != sha256.Sum256(newPSK[:]) {
						t.Fatal("failed rekey lost its two recovery hashes")
					}
					if f.calls != 2 || c.Check() == nil || controlApply(c, tc.ip) == nil || c.Rekey(key, oldPSK, newPSK) == nil {
						t.Fatal("unfinished rekey was accepted as active")
					}
					if at, err := c.Handshake(key); err == nil || !at.IsZero() {
						t.Fatal("unfinished rekey returned a handshake")
					}
					if mode == "crash" {
						if _, err := newController(f, f.d.Name, path); err != nil {
							t.Fatal(err)
						}
					} else if err := c.RestoreAll(); err != nil {
						t.Fatal(err)
					}
					controlAssertDevice(t, f.d, baseline)
					if len(controlReadJournal(t, path).Peers) != 0 {
						t.Fatal("completed rekey recovery remains in the journal")
					}
				})
			}
		}
	}
}

func TestControlRekeyReadChecks(t *testing.T) {
	for _, at := range []int{1, 2, 3} {
		for _, mode := range []string{"read error", "PSK conflict", "prefix conflict", "owner conflict", "identity conflict", "other peer conflict"} {
			t.Run(mode+"/"+strconv.Itoa(at), func(t *testing.T) {
				c, f, path := controlFixture(t, "10.0.0.0/8")
				if err := controlApply(c, "10.2.3.4"); err != nil {
					t.Fatal(err)
				}
				if err := c.Apply(controlTestKey(7), netip.MustParseAddr("10.2.3.7"), controlTestKey(5), netip.MustParseAddrPort("192.0.2.7:51820")); err != nil {
					t.Fatal(err)
				}
				reads := 0
				injected := errors.New("injected device read error")
				f.readHook = func() error {
					reads++
					if reads != at {
						return nil
					}
					switch mode {
					case "read error":
						return injected
					case "PSK conflict":
						controlFindPeer(&f.d, controlTestKey(3)).PresharedKey = controlTestKey(42)
					case "prefix conflict":
						p := controlFindPeer(&f.d, controlTestKey(3))
						p.AllowedIPs = append(p.AllowedIPs, controlTestNet("172.16.0.0/12"))
					case "owner conflict":
						controlFindPeer(&f.d, controlTestKey(2)).AllowedIPs = nil
					case "identity conflict":
						f.d.PublicKey = controlTestKey(42)
					case "other peer conflict":
						controlFindPeer(&f.d, controlTestKey(7)).PresharedKey = controlTestKey(42)
					}
					return nil
				}
				err := c.Rekey(controlTestKey(3), controlTestKey(5), controlTestKey(8))
				if err == nil || (mode == "read error" && !errors.Is(err, injected)) {
					t.Fatal("rekey did not check the device:", err)
				}
				f.readHook = nil
				calls := 2
				phase := "active"
				if at > 1 {
					phase = "rekeying"
				}
				if at == 3 {
					calls++
				}
				journal := controlReadJournal(t, path)
				if f.calls != calls || journal.Peers[controlTestKey(3).String()].Phase != phase {
					t.Fatal("failed read or ownership check lost the pending record or caused an extra write")
				}
				if mode != "read error" && mode != "other peer conflict" {
					want := controlClone(f.d)
					if c.Restore(controlTestKey(3)) == nil || f.calls != calls {
						t.Fatal("restore overwrote a conflict")
					}
					controlAssertDevice(t, f.d, want)
					if _, err := newController(f, f.d.Name, path); err == nil {
						t.Fatal("startup accepted a conflict")
					}
					if !reflect.DeepEqual(controlReadJournal(t, path).Peers[controlTestKey(3).String()], journal.Peers[controlTestKey(3).String()]) ||
						!reflect.DeepEqual(controlFindPeer(&f.d, controlTestKey(3)), controlFindPeer(&want, controlTestKey(3))) {
						t.Fatal("startup changed the conflicting peer or its journal record")
					}
					if mode != "PSK conflict" && mode != "prefix conflict" {
						controlAssertDevice(t, f.d, want)
					}
				}
			})
		}
	}
}

func TestControlRekeyDroppedUpdate(t *testing.T) {
	c, f, path := controlFixture(t, "10.2.3.4/32")
	baseline := controlClone(f.d)
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	f.drop = true
	if c.Rekey(controlTestKey(3), controlTestKey(5), controlTestKey(8)) == nil {
		t.Fatal("silently dropped rekey was accepted")
	}
	if controlReadJournal(t, path).Peers[controlTestKey(3).String()].Phase != "rekeying" {
		t.Fatal("dropped update lost its recovery record")
	}
	f.drop = false
	if err := c.RestoreAll(); err != nil {
		t.Fatal(err)
	}
	controlAssertDevice(t, f.d, baseline)
}

func TestControlRekeyJournalFailure(t *testing.T) {
	for _, stage := range []string{"before", "after"} {
		for _, recovery := range []string{"retry", "restart"} {
			t.Run(stage+"/"+recovery, func(t *testing.T) {
				c, f, path := controlFixture(t, "10.2.3.4/32")
				baseline := controlClone(f.d)
				if err := controlApply(c, "10.2.3.4"); err != nil {
					t.Fatal(err)
				}
				if stage == "before" {
					if err := os.Chmod(filepath.Dir(path), 0500); err != nil {
						t.Fatal(err)
					}
				} else {
					f.hook = func(call int, at string) error {
						if call == 2 && at == "after" {
							return os.Chmod(filepath.Dir(path), 0500)
						}
						return nil
					}
				}
				if c.Rekey(controlTestKey(3), controlTestKey(5), controlTestKey(8)) == nil || c.Check() == nil {
					t.Fatal("rekey ignored a journal failure")
				}
				calls, phase := 1, "active"
				if stage == "after" {
					calls, phase = 2, "rekeying"
				}
				if c.RestoreAll() == nil || f.calls != calls || controlReadJournal(t, path).Peers[controlTestKey(3).String()].Phase != phase {
					t.Fatal("failed journal write lost recovery state or allowed a WireGuard write")
				}
				if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				f.hook = nil
				if recovery == "restart" {
					if _, err := newController(f, f.d.Name, path); err != nil {
						t.Fatal(err)
					}
				} else if err := c.RestoreAll(); err != nil {
					t.Fatal(err)
				}
				controlAssertDevice(t, f.d, baseline)
			})
		}
	}
}

func TestControlRekeyRestoreCrash(t *testing.T) {
	c, f, path := controlFixture(t, "10.2.3.4/32")
	baseline := controlClone(f.d)
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	f.hook = func(call int, stage string) error {
		if call == 2 && stage == "after" {
			return errors.New("injected rekey error")
		}
		if call == 3 && stage == "allowed" {
			panic("simulated crash")
		}
		return nil
	}
	if c.Rekey(controlTestKey(3), controlTestKey(5), controlTestKey(8)) == nil {
		t.Fatal("missing rekey error")
	}
	controlCrash(t, func() { _ = c.RestoreAll() })
	f.hook = nil
	r := controlReadJournal(t, path).Peers[controlTestKey(3).String()]
	if r.Phase != "restoring" || r.NextPSKHash == nil {
		t.Fatal("partial restore lost the rekey transition")
	}
	if _, err := newController(f, f.d.Name, path); err != nil {
		t.Fatal(err)
	}
	controlAssertDevice(t, f.d, baseline)
}

func TestControlHandshake(t *testing.T) {
	c, f, path := controlFixture(t, "10.0.0.0/8")
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	key := controlTestKey(3)
	for _, want := range []time.Time{{}, time.Now()} {
		controlFindPeer(&f.d, key).LastHandshakeTime = want
		if got, err := c.Handshake(key); err != nil || got != want {
			t.Fatal("wrong handshake time:", got, err)
		}
	}
	for _, key := range []wgtypes.Key{{}, controlTestKey(2), controlTestKey(9), f.d.PublicKey} {
		if got, err := c.Handshake(key); err == nil || !got.IsZero() {
			t.Fatal("handshake accepted an unmanaged peer")
		}
	}
	for _, phase := range []string{"planning", "adding", "aborting", "restoring", "rekeying"} {
		c.journal.Peers[key.String()].Phase = phase
		if got, err := c.Handshake(key); err == nil || !got.IsZero() {
			t.Fatal("handshake accepted an inactive peer")
		}
	}
	c.journal.Peers[key.String()].Phase = "active"
	injected := errors.New("injected device read error")
	f.readHook = func() error { return injected }
	if got, err := c.Handshake(key); !errors.Is(err, injected) || !got.IsZero() {
		t.Fatal("handshake ignored a device error")
	}
	if f.calls != 1 || controlReadJournal(t, path).Peers[key.String()].Phase != "active" {
		t.Fatal("handshake changed WireGuard state or the journal")
	}
}

func TestControlRestoredBaseline(t *testing.T) {
	for _, tc := range []struct{ prefix, ip string }{
		{"10.0.0.0/8", "10.2.3.4"}, {"10.2.3.4/32", "10.2.3.4"}, {"0.0.0.0/0", "10.2.3.4"},
		{"fd00::/64", "fd00::3"}, {"fd00::3/128", "fd00::3"}, {"::/0", "fd00::3"},
	} {
		for _, mode := range []string{"restart", "restore"} {
			t.Run(tc.prefix+"/"+mode, func(t *testing.T) {
				c, f, path := controlFixture(t, tc.prefix)
				baseline := controlClone(f.d)
				if err := controlApply(c, tc.ip); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(path)
				if err != nil || bytes.Contains(data, []byte("NextPSKHash")) || controlReadJournal(t, path).Version != 1 {
					t.Fatal("active journal no longer uses the original v1 format")
				}
				f.d = controlClone(baseline)
				if c.Check() == nil || controlApply(c, tc.ip) == nil || c.Rekey(controlTestKey(3), controlTestKey(5), controlTestKey(8)) == nil {
					t.Fatal("runtime accepted an absent active peer")
				}
				if at, err := c.Handshake(controlTestKey(3)); err == nil || !at.IsZero() {
					t.Fatal("handshake accepted an absent active peer")
				}
				if mode == "restart" {
					if _, err := newController(f, f.d.Name, path); err != nil {
						t.Fatal("startup rejected a verified baseline:", err)
					}
				} else if err := c.RestoreAll(); err != nil {
					t.Fatal("restore rejected a verified baseline:", err)
				}
				if f.calls != 1 || len(controlReadJournal(t, path).Peers) != 0 {
					t.Fatal("baseline recovery wrote WireGuard state or retained a resolved record")
				}
				controlAssertDevice(t, f.d, baseline)
			})
		}
	}
}

func TestControlBaselineConflicts(t *testing.T) {
	for _, tc := range []struct{ prefix, ip, alternate string }{
		{"10.0.0.0/8", "10.2.3.4", "10.2.3.4/32"}, {"10.2.3.4/32", "10.2.3.4", "10.0.0.0/8"},
		{"fd00::/64", "fd00::3", "fd00::3/128"}, {"fd00::3/128", "fd00::3", "fd00::/64"},
	} {
		for _, mode := range []string{"interface", "identity", "missing owner", "missing prefix", "changed prefix", "changed owner", "ambiguous owner", "recreated direct"} {
			t.Run(tc.prefix+"/"+mode, func(t *testing.T) {
				c, f, path := controlFixture(t, tc.prefix)
				baseline := controlClone(f.d)
				if err := controlApply(c, tc.ip); err != nil {
					t.Fatal(err)
				}
				f.d = baseline
				switch mode {
				case "interface":
					f.d.Name = "wg-other"
				case "identity":
					f.d.PublicKey = controlTestKey(42)
				case "missing owner":
					f.d.Peers = f.d.Peers[1:]
				case "missing prefix":
					f.d.Peers[0].AllowedIPs = nil
				case "changed prefix":
					f.d.Peers[0].AllowedIPs = []net.IPNet{controlTestNet(tc.alternate)}
				case "changed owner":
					f.d.Peers[0].AllowedIPs = nil
					f.d.Peers[1].AllowedIPs = []net.IPNet{controlTestNet(tc.prefix)}
				case "ambiguous owner":
					f.d.Peers[1].AllowedIPs = []net.IPNet{controlTestNet(tc.prefix)}
				case "recreated direct":
					f.d.Peers = append(f.d.Peers, wgtypes.Peer{PublicKey: controlTestKey(3)})
				}
				want := controlClone(f.d)
				journal := controlReadJournal(t, path)
				if c.RestoreAll() == nil {
					t.Fatal("restore accepted a conflicting baseline")
				}
				if _, err := newController(f, f.d.Name, path); err == nil {
					t.Fatal("startup accepted a conflicting baseline")
				}
				if f.calls != 1 || !reflect.DeepEqual(controlReadJournal(t, path), journal) {
					t.Fatal("baseline conflict changed WireGuard state or its journal record")
				}
				controlAssertDevice(t, f.d, want)
			})
		}
	}
}

func TestControlBaselineRecoveryFailure(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
		for _, mode := range []string{"owner conflict", "journal failure"} {
			t.Run(prefix+"/"+mode, func(t *testing.T) {
				c, f, path := controlFixture(t, prefix)
				baseline := controlClone(f.d)
				if err := controlApply(c, "10.2.3.4"); err != nil {
					t.Fatal(err)
				}
				f.d = controlClone(baseline)
				reads := 0
				f.readHook = func() error {
					reads++
					if reads == 2 {
						if mode == "owner conflict" {
							f.d.Peers[0].AllowedIPs = nil
						} else if err := os.Chmod(filepath.Dir(path), 0500); err != nil {
							t.Fatal(err)
						}
					}
					return nil
				}
				if c.RestoreAll() == nil || f.calls != 1 || len(c.journal.Peers) != 1 || len(controlReadJournal(t, path).Peers) != 1 {
					t.Fatal("failed baseline recovery lost its journal record or wrote WireGuard state")
				}
				f.readHook = nil
				f.d = controlClone(baseline)
				if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if _, err := newController(f, f.d.Name, path); err != nil {
					t.Fatal("baseline recovery retry failed:", err)
				}
				if f.calls != 1 || len(controlReadJournal(t, path).Peers) != 0 {
					t.Fatal("baseline recovery retry wrote WireGuard state or retained a resolved record")
				}
				controlAssertDevice(t, f.d, baseline)
			})
		}
	}
}

func TestControlApplyAppearedPeer(t *testing.T) {
	for _, prefix := range []string{"10.0.0.0/8", "10.2.3.4/32"} {
		for _, mode := range []string{"empty", "matching", "conflicting"} {
			t.Run(prefix+"/"+mode, func(t *testing.T) {
				c, f, path := controlFixture(t, prefix)
				key := controlTestKey(3)
				external := wgtypes.Peer{
					PublicKey: key, ProtocolVersion: 1,
					Endpoint: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.3:9999")),
				}
				if mode != "empty" {
					external.PresharedKey = controlTestKey(5)
					external.AllowedIPs = []net.IPNet{controlTestNet("10.2.3.4/32")}
					if mode == "conflicting" {
						external.PresharedKey = controlTestKey(42)
					}
				}
				reads := 0
				f.readHook = func() error {
					reads++
					if reads == 2 {
						if controlReadJournal(t, path).Peers[key.String()].Phase != "planning" {
							t.Fatal("missing non-owning planning record")
						}
						if mode != "empty" {
							for i := range f.d.Peers {
								p := &f.d.Peers[i]
								p.AllowedIPs = slices.DeleteFunc(p.AllowedIPs, func(n net.IPNet) bool { return n.String() == "10.2.3.4/32" })
							}
						}
						f.d.Peers = append(f.d.Peers, external)
					}
					return nil
				}
				if err := controlApply(c, "10.2.3.4"); err == nil || !strings.Contains(err.Error(), "direct peer appeared before apply") {
					t.Fatal("apply did not reject the external peer:", err)
				}
				f.readHook = nil
				want := controlClone(f.d)
				journal := controlReadJournal(t, path)
				if f.calls != 0 || journal.Peers[key.String()].Phase != "planning" || !reflect.DeepEqual(c.journal, journal) {
					t.Fatal("apply wrote WireGuard state or lost the planning record")
				}
				if c.RestoreAll() == nil {
					t.Fatal("restore accepted an external peer during planning")
				}
				if _, err := newController(f, f.d.Name, path); err == nil || !strings.Contains(err.Error(), "startup recovery") {
					t.Fatal("startup did not reject the planning conflict:", err)
				}
				if f.calls != 0 || !reflect.DeepEqual(controlReadJournal(t, path), journal) {
					t.Fatal("recovery wrote an externally created peer or changed the planning record")
				}
				controlAssertDevice(t, f.d, want)
			})
		}
	}
}

func TestControlPlanningSaveFailure(t *testing.T) {
	for _, tc := range []struct{ prefix, ip string }{
		{"10.0.0.0/8", "10.2.3.4"}, {"10.2.3.4/32", "10.2.3.4"},
		{"fd00::/64", "fd00::3"}, {"fd00::3/128", "fd00::3"},
	} {
		for _, stage := range []string{"promotion", "conflict", "retirement"} {
			for _, peer := range []string{"empty", "matching"} {
				t.Run(tc.prefix+"/"+stage+"/"+peer, func(t *testing.T) {
					c, f, path := controlFixture(t, tc.prefix)
					t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0700) })
					key := controlTestKey(3)
					appear := func() {
						p := wgtypes.Peer{PublicKey: key, ProtocolVersion: 1, Endpoint: net.UDPAddrFromAddrPort(netip.MustParseAddrPort("203.0.113.3:9999"))}
						if peer == "matching" {
							p.PresharedKey = controlTestKey(5)
							p.AllowedIPs = []net.IPNet{controlHostNet(netip.MustParseAddr(tc.ip))}
							for i := range f.d.Peers {
								q := &f.d.Peers[i]
								q.AllowedIPs = slices.DeleteFunc(q.AllowedIPs, func(n net.IPNet) bool { return n.String() == p.AllowedIPs[0].String() })
							}
						}
						f.d.Peers = append(f.d.Peers, p)
					}
					injected := errors.New("injected planning read failure")
					reads := 0
					f.readHook = func() error {
						reads++
						if reads == 2 {
							if stage == "retirement" {
								return injected
							}
							if stage == "conflict" {
								appear()
							}
							if err := os.Chmod(filepath.Dir(path), 0500); err != nil {
								t.Fatal(err)
							}
						}
						return nil
					}
					err := controlApply(c, tc.ip)
					if err == nil || (stage == "conflict" && err.Error() != "direct peer appeared before apply") || (stage == "retirement" && !errors.Is(err, injected)) {
						t.Fatal("apply did not stop safely during planning:", err)
					}
					f.readHook = nil
					if stage == "retirement" {
						reads = 0
						f.readHook = func() error {
							reads++
							if reads == 2 {
								if err := os.Chmod(filepath.Dir(path), 0500); err != nil {
									t.Fatal(err)
								}
							}
							return nil
						}
						if c.RestoreAll() == nil {
							t.Fatal("planning retirement ignored a journal failure")
						}
						f.readHook = nil
					}
					journal := controlReadJournal(t, path)
					if f.calls != 0 || journal.Peers[key.String()].Phase != "planning" || !reflect.DeepEqual(c.journal, journal) {
						t.Fatal("failed save lost the planning record or claimed ownership")
					}
					if stage != "conflict" {
						appear()
					}
					want := controlClone(f.d)
					if c.RestoreAll() == nil {
						t.Fatal("restore adopted an external peer after a journal failure")
					}
					if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
						t.Fatal(err)
					}
					if _, err := newController(f, f.d.Name, path); err == nil || !strings.Contains(err.Error(), "startup recovery") {
						t.Fatal("startup did not reject the retained planning conflict:", err)
					}
					if f.calls != 0 || !reflect.DeepEqual(controlReadJournal(t, path), journal) {
						t.Fatal("recovery changed the external peer or its planning record")
					}
					controlAssertDevice(t, f.d, want)
				})
			}
		}
	}
}

func TestControlPlanningRecovery(t *testing.T) {
	for _, tc := range []struct{ prefix, ip string }{
		{"10.0.0.0/8", "10.2.3.4"}, {"10.2.3.4/32", "10.2.3.4"},
		{"fd00::/64", "fd00::3"}, {"fd00::3/128", "fd00::3"},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			c, f, path := controlFixture(t, tc.prefix)
			baseline := controlClone(f.d)
			reads := 0
			f.readHook = func() error {
				reads++
				if reads == 2 {
					panic("simulated crash")
				}
				return nil
			}
			controlCrash(t, func() { _ = controlApply(c, tc.ip) })
			f.readHook = nil
			if controlReadJournal(t, path).Peers[controlTestKey(3).String()].Phase != "planning" || c.Check() == nil || controlApply(c, tc.ip) == nil {
				t.Fatal("unfinished planning was not retained or was accepted as active")
			}
			if _, err := newController(f, f.d.Name, path); err != nil {
				t.Fatal("startup rejected the planning baseline:", err)
			}
			if f.calls != 0 || len(controlReadJournal(t, path).Peers) != 0 {
				t.Fatal("planning recovery wrote WireGuard state or retained a resolved record")
			}
			controlAssertDevice(t, f.d, baseline)
		})
	}
}

func TestControlApplyActiveRecheckRetainsJournal(t *testing.T) {
	c, f, path := controlFixture(t, "10.0.0.0/8")
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	journal := controlReadJournal(t, path)
	reads := 0
	f.readHook = func() error {
		reads++
		if reads == 2 {
			controlFindPeer(&f.d, controlTestKey(3)).PresharedKey = controlTestKey(42)
		}
		return nil
	}
	if controlApply(c, "10.2.3.4") == nil {
		t.Fatal("apply accepted an active peer conflict")
	}
	f.readHook = nil
	want := controlClone(f.d)
	if c.RestoreAll() == nil {
		t.Fatal("restore accepted an active peer conflict")
	}
	if _, err := newController(f, f.d.Name, path); err == nil {
		t.Fatal("startup accepted an active peer conflict")
	}
	if f.calls != 1 || !reflect.DeepEqual(controlReadJournal(t, path), journal) {
		t.Fatal("active peer conflict caused a write or lost its journal record")
	}
	controlAssertDevice(t, f.d, want)
}

func TestControlApplyRecheckRetainsJournal(t *testing.T) {
	c, f, path := controlFixture(t, "10.0.0.0/8")
	reads := 0
	f.readHook = func() error {
		reads++
		if reads == 2 {
			f.d.Peers[0].AllowedIPs = nil
		}
		return nil
	}
	if controlApply(c, "10.2.3.4") == nil || f.calls != 0 || len(controlReadJournal(t, path).Peers) != 1 {
		t.Fatal("apply recheck lost an unresolved journal record or changed WireGuard state")
	}
	f.readHook = nil
	journal := controlReadJournal(t, path)
	if c.RestoreAll() == nil {
		t.Fatal("planning recovery accepted a missing baseline owner prefix")
	}
	if _, err := newController(f, f.d.Name, path); err == nil {
		t.Fatal("startup accepted a conflicting planning baseline")
	}
	if f.calls != 0 || !reflect.DeepEqual(controlReadJournal(t, path), journal) {
		t.Fatal("planning baseline conflict caused a write or lost its journal record")
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
