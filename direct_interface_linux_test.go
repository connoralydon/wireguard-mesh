//go:build linux

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type directFake struct {
	links                                       map[string]netlink.Link
	devices                                     map[string]*wgtypes.Device
	addrs                                       []netlink.Addr
	routeList                                   []netlink.Route
	addError, configError, upError, deleteError error
	applyDelete                                 bool
	autoPorts                                   []int
	autoCalls                                   int
	unmarked                                    bool
}

func (f *directFake) add(n, a string) error {
	if f.links[n] != nil {
		return syscall.EEXIST
	}
	f.links[n] = &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: n, Alias: a, Index: 7}, LinkType: "wireguard"}
	if f.unmarked {
		f.links[n].Attrs().Alias = ""
	}
	f.devices[n] = &wgtypes.Device{Name: n, Type: wgtypes.LinuxKernel}
	return f.addError
}
func (f *directFake) lookup(n string) (netlink.Link, error) {
	if l := f.links[n]; l != nil {
		return l, nil
	}
	return nil, os.ErrNotExist
}
func (f *directFake) up(l netlink.Link) error { l.Attrs().Flags |= net.FlagUp; return f.upError }
func (f *directFake) del(l netlink.Link) error {
	if f.deleteError == nil || f.applyDelete {
		delete(f.links, l.Attrs().Name)
		delete(f.devices, l.Attrs().Name)
	}
	return f.deleteError
}
func (f *directFake) addresses(netlink.Link) ([]netlink.Addr, error) { return f.addrs, nil }
func (f *directFake) routes() ([]netlink.Route, error)               { return f.routeList, nil }
func (f *directFake) Device(n string) (*wgtypes.Device, error) {
	if d := f.devices[n]; d != nil {
		v := *d
		return &v, nil
	}
	return nil, os.ErrNotExist
}
func (f *directFake) ConfigureDevice(n string, c wgtypes.Config) error {
	d := f.devices[n]
	if c.PrivateKey != nil {
		d.PrivateKey = *c.PrivateKey
		d.PublicKey = c.PrivateKey.PublicKey()
	}
	if c.ListenPort != nil {
		d.ListenPort = *c.ListenPort
		if d.ListenPort == 0 {
			d.ListenPort = 44444
			if f.autoCalls < len(f.autoPorts) {
				d.ListenPort = f.autoPorts[f.autoCalls]
			}
			f.autoCalls++
		}
	}
	return f.configError
}
func directFixture(t *testing.T) (*directFake, string, wgtypes.Key) {
	t.Helper()
	k, e := wgtypes.GeneratePrivateKey()
	if e != nil {
		t.Fatal(e)
	}
	f := &directFake{links: map[string]netlink.Link{}, devices: map[string]*wgtypes.Device{"wg0": {Name: "wg0", Type: wgtypes.LinuxKernel, PrivateKey: k, PublicKey: k.PublicKey(), ListenPort: 1234}}}
	dir := filepath.Join(t.TempDir(), "private")
	return f, filepath.Join(dir, "journal"), k
}
func TestDirectLifecycle(t *testing.T) {
	f, p, k := directFixture(t)
	o, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
	if e != nil {
		t.Fatal(e)
	}
	d := f.devices[o.Name]
	if !strings.HasPrefix(f.links[o.Name].Attrs().Alias, "wireguard-mesh:") || len(f.links[o.Name].Attrs().Alias) != len("wireguard-mesh:")+64 {
		t.Fatal("invalid ownership alias")
	}
	if d.PublicKey != k.PublicKey() || d.ListenPort != 44444 {
		t.Fatal("identity or port")
	}
	data, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte(k.String())) || bytes.Contains(data, k[:]) {
		t.Fatal("private key in journal")
	}
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
	delete(f.devices, "wg0")
	if e = recoverDirectInterfaceWithOps(f, "changed", p, f); e != nil {
		t.Fatal(e)
	}
}
func TestDirectRecoveryPartial(t *testing.T) {
	for _, phase := range []string{"add", "configure", "up"} {
		t.Run(phase, func(t *testing.T) {
			f, p, _ := directFixture(t)
			switch phase {
			case "add":
				f.addError = errors.New("ambiguous add")
			case "configure":
				f.configError = errors.New("ambiguous configure")
			case "up":
				f.upError = errors.New("ambiguous up")
			}
			if _, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f); e == nil {
				t.Fatal("expected error")
			}
			if len(f.links) != 0 {
				t.Fatal("best-effort cleanup left link")
			}
			if e := recoverDirectInterfaceWithOps(f, "wg0", p, f); e != nil {
				t.Fatal(e)
			}
			if len(f.links) != 0 {
				t.Fatal("link remains")
			}
		})
	}
}
func TestDirectCollisionAndConflicts(t *testing.T) {
	f, p, _ := directFixture(t)
	o, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
	if e != nil {
		t.Fatal(e)
	}
	l := f.links[o.Name]
	for _, test := range []struct {
		name  string
		set   func()
		reset func()
	}{
		{"alias", func() { l.Attrs().Alias = "other" }, func() { l.Attrs().Alias = o.journal.Marker }},
		{"index", func() { l.Attrs().Index++ }, func() { l.Attrs().Index-- }},
		{"address", func() { f.addrs = []netlink.Addr{{}} }, func() { f.addrs = nil }},
		{"route", func() { f.routeList = []netlink.Route{{LinkIndex: 7, Table: 123}} }, func() { f.routeList = nil }},
		{"input route", func() { f.routeList = []netlink.Route{{ILinkIndex: 7}} }, func() { f.routeList = nil }},
		{"peer", func() { f.devices[o.Name].Peers = []wgtypes.Peer{{}} }, func() { f.devices[o.Name].Peers = nil }},
		{"key", func() { f.devices[o.Name].PublicKey = wgtypes.Key{} }, func() { f.devices[o.Name].PublicKey = o.journal.Public }},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.set()
			defer test.reset()
			if e := o.Close(); e == nil {
				t.Fatal("expected conflict")
			}
		})
	}
	f.deleteError = errors.New("applied")
	f.applyDelete = true
	if e = o.Close(); e == nil {
		t.Fatal("expected delete error")
	}
	if e = recoverDirectInterfaceWithOps(f, "wg0", p, f); e != nil {
		t.Fatal(e)
	}
}
func TestDirectNameCollision(t *testing.T) {
	f, p, _ := directFixture(t)
	first, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
	if e != nil {
		t.Fatal(e)
	}
	name := first.Name
	if e = first.Close(); e != nil {
		t.Fatal(e)
	}
	other := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 99, Alias: "foreign"}, LinkType: "wireguard"}
	f.links[name] = other
	second, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
	if e != nil {
		t.Fatal(e)
	}
	if second.Name != name+"-1" || f.links[name] != other {
		t.Fatal("collision not preserved")
	}
	if e = second.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestDirectRequestedPortAndType(t *testing.T) {
	f, p, _ := directFixture(t)
	if _, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 1234, f); e == nil {
		t.Fatal("stable port accepted")
	}
	if _, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 5555, f); e == nil {
		t.Fatal("discovery port accepted")
	}
	o, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 7777, f)
	if e != nil {
		t.Fatal(e)
	}
	if f.devices[o.Name].ListenPort != 7777 {
		t.Fatal("requested port not applied")
	}
	original := f.links[o.Name]
	f.links[o.Name] = &netlink.GenericLink{LinkAttrs: *original.Attrs(), LinkType: "dummy"}
	if e = o.Close(); e == nil {
		t.Fatal("wrong link type accepted")
	}
	f.links[o.Name] = original
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestDirectUnmarkedCreationRefusesRecovery(t *testing.T) {
	f, path, _ := directFixture(t)
	f.unmarked, f.addError = true, errors.New("ownership marking did not complete")
	if _, err := ensureDirectInterfaceWithOps(f, "wg0", path, 5555, 0, f); err == nil || len(f.links) != 1 {
		t.Fatal("ambiguous unmarked link was adopted or deleted")
	}
	if err := recoverDirectInterfaceWithOps(f, "wg0", path, f); err == nil || len(f.links) != 1 {
		t.Fatal("recovery trusted an unmarked interface")
	}
}

func TestDirectAutoPortRetry(t *testing.T) {
	f, p, _ := directFixture(t)
	f.autoPorts = []int{5555, 1234, 3333}
	o, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
	if e != nil {
		t.Fatal(e)
	}
	if f.autoCalls != 3 || f.devices[o.Name].ListenPort != 3333 {
		t.Fatal("auto port did not retry")
	}
	if e = o.Close(); e != nil {
		t.Fatal(e)
	}
	f, p, _ = directFixture(t)
	f.autoPorts = make([]int, 16)
	for i := range f.autoPorts {
		f.autoPorts[i] = 5555
	}
	if _, e = ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f); e == nil || f.autoCalls != 16 || len(f.links) != 0 {
		t.Fatalf("retry limit or cleanup: calls=%d links=%d err=%v", f.autoCalls, len(f.links), e)
	}
}
func TestDirectCleanupFailureAndMissingStable(t *testing.T) {
	f, p, _ := directFixture(t)
	createErr := errors.New("config failed")
	delErr := errors.New("delete failed")
	f.configError = createErr
	f.deleteError = delErr
	_, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
	if !errors.Is(e, createErr) || !errors.Is(e, delErr) || len(f.links) != 1 {
		t.Fatalf("cleanup error not retained: %v", e)
	}
	delete(f.devices, "wg0")
	f.deleteError = nil
	if e = recoverDirectInterfaceWithOps(f, "wg0", p, f); e != nil || len(f.links) != 0 {
		t.Fatalf("recovery with missing stable: %v", e)
	}
}
func TestDirectUnsafeJournal(t *testing.T) {
	for _, kind := range []string{"symlink", "mode", "directory", "unknown", "stable"} {
		t.Run(kind, func(t *testing.T) {
			f, p, _ := directFixture(t)
			if e := os.Mkdir(filepath.Dir(p), 0700); e != nil {
				t.Fatal(e)
			}
			if kind == "symlink" {
				target := filepath.Join(filepath.Dir(p), "target")
				if e := os.WriteFile(target, []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(target, p); e != nil {
					t.Fatal(e)
				}
			} else if kind == "directory" {
				if e := os.Chmod(filepath.Dir(p), 0755); e != nil {
					t.Fatal(e)
				}
			} else if kind == "mode" {
				if e := os.WriteFile(p, []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Chmod(p, 0644); e != nil {
					t.Fatal(e)
				}
			} else {
				o, e := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
				if e != nil {
					t.Fatal(e)
				}
				if kind == "unknown" {
					b, e := os.ReadFile(p)
					if e != nil {
						t.Fatal(e)
					}
					b = append(b[:len(b)-1], []byte(",\"Unknown\":1}")...)
					if e = os.WriteFile(p, b, 0600); e != nil {
						t.Fatal(e)
					}
				} else {
					o.journal.Stable = "other"
					if e = o.save(); e != nil {
						t.Fatal(e)
					}
				}
			}
			before := len(f.links)
			if e := recoverDirectInterfaceWithOps(f, "wg0", p, f); e == nil {
				t.Fatal("unsafe journal accepted")
			}
			if len(f.links) != before {
				t.Fatal("unsafe journal changed link")
			}
		})
	}
}

func TestDirectKernelMulticastCleanup(t *testing.T) {
	for _, change := range []string{"none", "metric", "table", "protocol", "type", "mtu", "source", "input", "destination"} {
		t.Run(change, func(t *testing.T) {
			f, p, _ := directFixture(t)
			o, err := ensureDirectInterfaceWithOps(f, "wg0", p, 5555, 0, f)
			if err != nil {
				t.Fatal(err)
			}
			r := directKernelMulticastRoute(f.links[o.Name].Attrs().Index)
			switch change {
			case "metric":
				r.Priority++
			case "table":
				r.Table = 254
			case "protocol":
				r.Protocol++
			case "type":
				r.Type++
			case "mtu":
				r.MTU = 1200
			case "source":
				r.Src = net.ParseIP("2001:db8::1")
			case "input":
				r.ILinkIndex = r.LinkIndex
			case "destination":
				r.Dst.Mask = net.CIDRMask(16, 128)
			}
			f.routeList = []netlink.Route{r}
			err = o.Close()
			if change == "none" {
				if err != nil || len(f.links) != 0 {
					t.Fatalf("kernel multicast route blocked cleanup: %v", err)
				}
			} else if err == nil || len(f.links) != 1 {
				t.Fatal("modified multicast route was ignored")
			}
		})
	}
}
