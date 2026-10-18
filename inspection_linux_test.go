package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type interfaceReaderFake struct {
	links                      []netlink.Link
	addresses                  []netlink.Addr
	linkErr, addrErr           error
	linkRequests, addrRequests int
}

func (f *interfaceReaderFake) LinkList() ([]netlink.Link, error) {
	f.linkRequests++
	return f.links, f.linkErr
}

func (f *interfaceReaderFake) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	if link != nil || family != netlink.FAMILY_ALL {
		return nil, errors.New("addresses were not requested in one full dump")
	}
	f.addrRequests++
	return f.addresses, f.addrErr
}

func interfaceFixture(count int) *interfaceReaderFake {
	f := &interfaceReaderFake{}
	for i := 1; i <= count; i++ {
		f.links = append(f.links, &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
			Index: i, Name: fmt.Sprintf("test%d", i), Flags: net.FlagUp | net.FlagMulticast, OperState: netlink.OperUp,
		}})
		f.addresses = append(f.addresses, netlink.Addr{LinkIndex: i, IPNet: &net.IPNet{
			IP: net.IPv4(192, 0, 2, byte(i)), Mask: net.CIDRMask(24, 32),
		}})
	}
	return f
}

func TestInterfaceInspectionUsesTwoDumps(t *testing.T) {
	for _, count := range []int{1, 8, 128} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := interfaceFixture(count)
			states, err := readInterfaceStates(f)
			if err != nil || len(states) != count {
				t.Fatalf("interface snapshot: count=%d, error=%v", len(states), err)
			}
			if f.linkRequests != 1 || f.addrRequests != 1 {
				t.Fatalf("query count grows with interfaces: links=%d addresses=%d", f.linkRequests, f.addrRequests)
			}
			for i, state := range states {
				want := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), 24)
				if state.iface.Index != i+1 || state.iface.Name != fmt.Sprintf("test%d", i+1) || !slices.Equal(state.prefixes, []netip.Prefix{want}) {
					t.Fatal("addresses were assigned to the wrong interface")
				}
			}
		})
	}
}

func TestInterfaceInspectionRejectsPartialDumps(t *testing.T) {
	for _, field := range []string{"links", "addresses"} {
		t.Run(field, func(t *testing.T) {
			f := interfaceFixture(3)
			if field == "links" {
				f.linkErr = netlink.ErrDumpInterrupted
			} else {
				f.addrErr = netlink.ErrDumpInterrupted
			}
			states, err := readInterfaceStates(f)
			if !errors.Is(err, netlink.ErrDumpInterrupted) || states != nil {
				t.Fatal("partial snapshot was accepted")
			}
		})
	}
}

func TestInterfaceInspectionFiltersUnusableAddresses(t *testing.T) {
	f := interfaceFixture(1)
	for _, flags := range []int{unix.IFA_F_TENTATIVE, unix.IFA_F_DADFAILED} {
		address := f.addresses[0]
		address.Flags = flags
		f.addresses = append(f.addresses, address)
	}
	f.addresses = append(f.addresses, netlink.Addr{LinkIndex: 1})
	states, err := readInterfaceStates(f)
	if err != nil || len(states[0].prefixes) != 1 {
		t.Fatal("unusable address was accepted")
	}
	for _, state := range []netlink.LinkOperState{netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperNotPresent} {
		f.links[0].Attrs().OperState = state
		states, err = readInterfaceStates(f)
		if err != nil || len(states[0].prefixes) != 0 {
			t.Fatal("unavailable interface retained addresses")
		}
	}
	f.links[0].Attrs().OperState = netlink.OperUp
	f.links[0].Attrs().Flags &^= net.FlagUp
	states, err = readInterfaceStates(f)
	if err != nil || len(states[0].prefixes) != 0 {
		t.Fatal("administratively down interface retained addresses")
	}
}

func TestRuntimeInspectionUsesFreshDevice(t *testing.T) {
	_, links := transportLoopback(t)
	link := links[0]
	c, f, _ := controlFixture(t, "10.0.0.0/8")
	f.d.ListenPort = 51820
	reads := 0
	f.readHook = func() error { reads++; return nil }
	config := config{Address: link.Prefix.Addr()}
	check := func() error { return checkRuntime(link.Name, config, link, 51820, c.checkDevice) }
	if err := check(); err != nil || reads != 1 {
		t.Fatalf("one inspection must read one device: reads=%d error=%v", reads, err)
	}
	f.d.ListenPort++
	if err := check(); err == nil || reads != 2 {
		t.Fatal("inspection reused the previous listen port")
	}
	f.d.ListenPort--
	f.d.PublicKey = controlTestKey(88)
	if err := check(); err == nil || reads != 3 {
		t.Fatal("inspection ignored identity change")
	}
	link.Index++
	if err := check(); err == nil || reads != 3 {
		t.Fatal("replaced interface was accepted")
	}
}

func TestControllerInspectionDoesNotCacheMutationPreflight(t *testing.T) {
	c, f, _ := controlFixture(t, "10.0.0.0/8")
	if err := controlApply(c, "10.2.3.4"); err != nil {
		t.Fatal(err)
	}
	reads := 0
	f.readHook = func() error { reads++; return nil }
	if _, err := c.checkDevice(); err != nil || reads != 1 {
		t.Fatalf("controller inspection: reads=%d error=%v", reads, err)
	}
	for i := range f.d.Peers {
		if f.d.Peers[i].PublicKey == controlTestKey(3) {
			f.d.Peers[i].AllowedIPs = nil
		}
	}
	before := f.calls
	if err := controlApply(c, "10.2.3.4"); err == nil || reads != 2 || f.calls != before {
		t.Fatal("mutation used an old controller snapshot")
	}
}

func BenchmarkInterfaceInspection(b *testing.B) {
	for _, count := range []int{1, 8, 128} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			f := interfaceFixture(count)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := readInterfaceStates(f); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
