package main

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
)

func TestNetworkIPv6ZoneValidation(t *testing.T) {
	receiver, links := transportLoopback(t)
	link, target := transportFamily(t, receiver, links, false)
	sender, err := openNetwork(0, []string{link.Name}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	for _, zone := range []string{"", link.Name, strconv.Itoa(link.Index)} {
		destination := netip.AddrPortFrom(target.Addr().WithZone(zone), target.Port())
		if err := sender.Send([]byte("zone"), destination, link); err != nil {
			t.Fatalf("matching IPv6 zone %q: %v", zone, err)
		}
		if got := transportPacket(t, receiver); string(got.Data) != "zone" || got.Destination != target.Addr() {
			t.Fatal("IPv6 zone changed the received destination")
		}
	}
	for _, zone := range []string{"wrong-interface", strconv.Itoa(link.Index + 10000)} {
		destination := netip.AddrPortFrom(target.Addr().WithZone(zone), target.Port())
		if err := sender.Send([]byte("reject"), destination, link); err == nil {
			t.Fatal("IPv6 zone for another interface was accepted")
		}
	}
}

// Run only on the isolated QEMU LAN. Normal host tests must not send LAN
// multicast. This checks real Linux packet-info scoping, not a socket mock.
func TestNetworkScopedIPv6LAN(t *testing.T) {
	name := os.Getenv("WGMESH_IPV6_TEST_INTERFACE")
	if name == "" {
		t.Skip("set WGMESH_IPV6_TEST_INTERFACE only in an isolated test network")
	}
	group := netip.MustParseAddr("ff12::5747:4d54")
	receiver, err := openNetwork(0, []string{name}, nil, []netip.Addr{group}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	links, err := receiver.Links()
	if err != nil {
		t.Fatal(err)
	}
	var link linkAddr
	for _, candidate := range links {
		if candidate.Prefix.Addr().Is6() && candidate.Prefix.Addr().IsLinkLocalUnicast() {
			link = candidate
			break
		}
	}
	if link.Index == 0 || !link.Multicast || receiver.(*udpNetwork).v6 == nil {
		t.Fatal("test LAN needs an active IPv6 link-local address and multicast")
	}
	sender, err := openNetwork(0, []string{name}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	port := uint16(receiver.(*udpNetwork).v6.LocalAddr().(*net.UDPAddr).Port)
	for _, address := range []netip.Addr{link.Prefix.Addr(), group} {
		for _, zone := range []string{"", link.Name, strconv.Itoa(link.Index)} {
			t.Run(address.String()+"/"+zone, func(t *testing.T) {
				data := []byte("isolated IPv6 packet-info scope test")
				if err := sender.Send(data, netip.AddrPortFrom(address.WithZone(zone), port), link); err != nil {
					t.Fatal(err)
				}
				got := transportPacket(t, receiver)
				if !bytes.Equal(got.Data, data) || got.Destination != address || got.Source.Addr().WithZone("") != link.Prefix.Addr() {
					t.Fatal("IPv6 packet did not retain its source and destination")
				}
				if address.IsMulticast() && got.IfIndex != link.Index {
					t.Fatal("multicast packet used the wrong source interface")
				}
			})
		}
	}
}
