package main

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestBroadcastAddress(t *testing.T) {
	for _, tt := range []struct{ prefix, want string }{
		{"192.0.2.19/24", "192.0.2.255"},
		{"192.0.2.5/30", "192.0.2.7"},
		{"10.1.2.3/8", "10.255.255.255"},
		{"1.2.3.4/0", "255.255.255.255"},
		{"10.0.0.1/1", "127.255.255.255"},
		{"192.0.2.0/31", ""},
		{"192.0.2.1/32", ""},
		{"2001:db8::1/64", ""},
		{"::ffff:192.0.2.1/120", ""},
		{"", ""},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			prefix, _ := netip.ParsePrefix(tt.prefix)
			want, _ := netip.ParseAddr(tt.want)
			if got := broadcastAddress(prefix); got != want {
				t.Fatalf("broadcast = %s, want %s", got, want)
			}
		})
	}
	prefix := netip.MustParsePrefix("192.0.2.19/24")
	iface := net.Interface{Index: 9, Name: "test0", Flags: net.FlagUp | net.FlagMulticast}
	if l := addressedLink(iface, prefix); l.Broadcast.IsValid() || !l.Multicast || l.Prefix != prefix || l.Index != 9 {
		t.Fatalf("link without broadcast flag: %+v", l)
	}
	iface.Flags |= net.FlagBroadcast
	if got := addressedLink(iface, prefix).Broadcast; got != netip.MustParseAddr("192.0.2.255") {
		t.Fatalf("broadcast with interface flag = %s", got)
	}
}

func TestSelectInterface(t *testing.T) {
	for _, tt := range []struct {
		name             string
		flags            net.Flags
		include, exclude []string
		wgName           string
		want             bool
	}{
		{"down", 0, []string{"mesh-test-veth"}, nil, "", false},
		{"explicit virtual", net.FlagUp, []string{"mesh-test-veth"}, nil, "", true},
		{"explicit loopback", net.FlagUp | net.FlagLoopback, []string{"mesh-test-veth"}, nil, "", true},
		{"excluded", net.FlagUp, []string{"mesh-test-veth"}, []string{"mesh-test-veth"}, "", false},
		{"tunnel excluded", net.FlagUp, []string{"mesh-test-veth"}, nil, "mesh-test-veth", false},
		{"not included", net.FlagUp, []string{"other"}, nil, "", false},
		{"default loopback", net.FlagUp | net.FlagLoopback, nil, nil, "", false},
		{"default tunnel", net.FlagUp | net.FlagPointToPoint, nil, nil, "", false},
		{"no device", net.FlagUp, nil, nil, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			iface := net.Interface{Name: "mesh-test-veth", Flags: tt.flags}
			if got := selectInterface(iface, tt.include, tt.exclude, tt.wgName); got != tt.want {
				t.Fatalf("selected = %v, want %v", got, tt.want)
			}
		})
	}
	for _, text := range []string{"192.0.2.1", "169.254.1.2", "127.0.0.1", "::1", "fe80::1", "2001:db8::1"} {
		if !usableLinkAddress(netip.MustParseAddr(text)) {
			t.Errorf("rejected usable address %s", text)
		}
	}
	for _, text := range []string{"0.0.0.0", "::", "ff02::1", "239.1.2.3", "255.255.255.255", "::ffff:192.0.2.1"} {
		if usableLinkAddress(netip.MustParseAddr(text)) {
			t.Errorf("accepted unusable address %s", text)
		}
	}
}

func transportLoopback(t *testing.T) (*udpNetwork, []linkAddr) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&(net.FlagUp|net.FlagLoopback) != net.FlagUp|net.FlagLoopback {
			continue
		}
		netw, err := openNetwork(0, []string{iface.Name}, nil, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := netw.Close(); err != nil {
				t.Error(err)
			}
		})
		links, err := netw.Links()
		if err != nil || len(links) == 0 {
			t.Fatalf("loopback links: %v, %v", links, err)
		}
		return netw.(*udpNetwork), links
	}
	t.Fatal("no active loopback interface")
	return nil, nil
}

func transportFamily(t *testing.T, n *udpNetwork, links []linkAddr, v4 bool) (linkAddr, netip.AddrPort) {
	t.Helper()
	var addr net.Addr
	if v4 && n.v4 != nil {
		addr = n.v4.LocalAddr()
	} else if !v4 && n.v6 != nil {
		addr = n.v6.LocalAddr()
	}
	for _, link := range links {
		if addr != nil && link.Prefix.Addr().Is4() == v4 && link.Prefix.Addr().IsLoopback() {
			return link, netip.AddrPortFrom(link.Prefix.Addr(), uint16(addr.(*net.UDPAddr).Port))
		}
	}
	if v4 {
		t.Fatal("IPv4 loopback unavailable")
	}
	t.Skip("IPv6 loopback unavailable")
	return linkAddr{}, netip.AddrPort{}
}

func transportPacket(t *testing.T, n network) packet {
	t.Helper()
	select {
	case p, ok := <-n.Incoming():
		if !ok {
			t.Fatal("incoming channel closed")
		}
		return p
	case <-time.After(3 * time.Second):
		t.Fatal("UDP receive timeout")
		return packet{}
	}
}

func TestNetworkLoopback(t *testing.T) {
	a, aLinks := transportLoopback(t)
	b, bLinks := transportLoopback(t)
	for _, v4 := range []bool{true, false} {
		name := "udp6"
		if v4 {
			name = "udp4"
		}
		t.Run(name, func(t *testing.T) {
			aLink, aAddr := transportFamily(t, a, aLinks, v4)
			bLink, bAddr := transportFamily(t, b, bLinks, v4)
			data := []byte("plain UDP transport test")
			if err := a.Send(data, bAddr, aLink); err != nil {
				t.Fatal(err)
			}
			p := transportPacket(t, b)
			if !bytes.Equal(p.Data, data) || p.Source != aAddr || p.Destination != bAddr.Addr() || p.IfIndex != bLink.Index {
				t.Fatalf("unexpected packet: %+v", p)
			}
			if err := b.Send([]byte("reply"), p.Source, bLink); err != nil {
				t.Fatal(err)
			}
			reply := transportPacket(t, a)
			if string(reply.Data) != "reply" || reply.Source != bAddr || reply.Destination != aAddr.Addr() || reply.IfIndex != aLink.Index {
				t.Fatalf("unexpected reply: %+v", reply)
			}
			if err := a.Send([]byte("second"), bAddr, aLink); err != nil {
				t.Fatal(err)
			}
			transportPacket(t, b)
			if !bytes.Equal(p.Data, data) {
				t.Fatal("a later receive changed the earlier packet")
			}
		})
	}
}

func TestNetworkSocketOptions(t *testing.T) {
	n, _ := transportLoopback(t)
	if n.v4 == nil {
		t.Fatal("IPv4 socket unavailable")
	}
	if ttl, err := n.v4.MulticastTTL(); err != nil || ttl != 1 {
		t.Fatalf("multicast TTL = %d, %v", ttl, err)
	}
	u := n.v4.PacketConn.(*net.UDPConn)
	if !u.LocalAddr().(*net.UDPAddr).IP.IsUnspecified() {
		t.Fatal("IPv4 listener is not wildcard")
	}
	raw, err := u.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var broadcast int
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		broadcast, optionErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST)
	}); err != nil || optionErr != nil || broadcast == 0 {
		t.Fatalf("SO_BROADCAST = %d, %v, %v", broadcast, err, optionErr)
	}
	if n.v6 != nil {
		if hops, err := n.v6.MulticastHopLimit(); err != nil || hops != 1 {
			t.Fatalf("multicast hop limit = %d, %v", hops, err)
		}
		a4, a6 := n.v4.LocalAddr().(*net.UDPAddr), n.v6.LocalAddr().(*net.UDPAddr)
		if a4.Port != a6.Port || !a6.IP.IsUnspecified() {
			t.Fatalf("wildcard socket addresses differ: %v, %v", a4, a6)
		}
	}
}

func TestNetworkDatagramLimit(t *testing.T) {
	n, links := transportLoopback(t)
	link, target := transportFamily(t, n, links, true)
	raw, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, size := range []int{networkDatagramLimit + 1, 9000, networkDatagramLimit} {
		if _, err := raw.Write(bytes.Repeat([]byte{byte(size)}, size)); err != nil {
			t.Fatal(err)
		}
	}
	p := transportPacket(t, n)
	if len(p.Data) != networkDatagramLimit || !bytes.Equal(p.Data, bytes.Repeat([]byte{byte(networkDatagramLimit % 256)}, networkDatagramLimit)) {
		t.Fatalf("received truncated or oversized datagram: %d bytes", len(p.Data))
	}
	if err := n.Send(make([]byte, networkDatagramLimit+1), target, link); err == nil {
		t.Fatal("oversized send accepted")
	}
	if err := n.Send(nil, target, link); err == nil {
		t.Fatal("empty send accepted")
	}
	if _, err := raw.Write(nil); err != nil {
		t.Fatal(err)
	}
	if p := transportPacket(t, n); len(p.Data) != 0 {
		t.Fatal("empty datagram was not received")
	}
}

func TestNetworkOverflowAndClose(t *testing.T) {
	n, links := transportLoopback(t)
	link, target := transportFamily(t, n, links, true)
	for range cap(n.incoming) * 3 {
		if err := n.Send([]byte("fill"), target, link); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(n.incoming) < cap(n.incoming) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(n.incoming) != cap(n.incoming) {
		t.Fatal("receive queue did not fill")
	}
	closed := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() { n.Close() })
		}
		wg.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked with a full receive queue")
	}
	count := 0
	for range n.Incoming() {
		count++
	}
	if count != cap(n.incoming) {
		t.Fatalf("queue size = %d, want %d", count, cap(n.incoming))
	}
	for range n.Changed() {
	}
	if _, err := n.Links(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Links after Close: %v", err)
	}
	if err := n.Send(nil, target, link); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close: %v", err)
	}
}

func TestNetworkChangedCoalesces(t *testing.T) {
	n := &udpNetwork{changed: make(chan struct{}, 1)}
	for range 100 {
		n.signalChanged()
	}
	if len(n.Changed()) != 1 {
		t.Fatal("change notifications did not coalesce")
	}
	<-n.Changed()
	n.signalChanged()
	if len(n.Changed()) != 1 {
		t.Fatal("change notification did not resume")
	}
}

func TestNetworkReadFailureCloses(t *testing.T) {
	netw, err := openNetwork(0, []string{"mesh-test-missing"}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer netw.Close()
	n := netw.(*udpNetwork)
	if n.v4 == nil {
		t.Skip("IPv4 socket unavailable")
	}
	// A closed socket is a permanent read error outside normal shutdown.
	if err := n.v4.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-n.Incoming():
		if ok {
			t.Fatal("received a packet instead of transport shutdown")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("permanent read failure did not close the transport")
	}
	if _, err := n.Links(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Links after read failure: %v", err)
	}
}

func TestTunnelLink(t *testing.T) {
	n, links := transportLoopback(t)
	link, _ := transportFamily(t, n, links, true)
	got, err := tunnelLink(link.Name, link.Prefix.Addr())
	if err != nil || got != link {
		t.Fatalf("assigned address: %+v, %v", got, err)
	}
	if _, err := tunnelLink(link.Name, netip.MustParseAddr("192.0.2.19")); err == nil {
		t.Fatal("unassigned tunnel address accepted")
	}
	if _, err := tunnelLink("mesh-no-interface", link.Prefix.Addr()); err == nil {
		t.Fatal("missing tunnel interface accepted")
	}
	if _, err := tunnelLink(link.Name, netip.Addr{}); err == nil {
		t.Fatal("invalid tunnel address accepted")
	}
}

func TestNetworkValidation(t *testing.T) {
	for _, group := range []netip.Addr{netip.Addr{}, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("ff02::1%invalid")} {
		if n, err := openNetwork(0, nil, nil, []netip.Addr{group}, ""); err == nil {
			n.Close()
			t.Fatalf("invalid multicast group accepted: %s", group)
		}
	}
	if n, err := openNetwork(-1, nil, nil, nil, ""); err == nil {
		n.Close()
		t.Fatal("invalid port accepted")
	}
	n, links := transportLoopback(t)
	link, target := transportFamily(t, n, links, true)
	for _, bad := range []netip.AddrPort{
		{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("0.0.0.0:1234"),
		netip.MustParseAddrPort("[::1]:1234"), netip.MustParseAddrPort("[::ffff:127.0.0.1]:1234"),
	} {
		if err := n.Send([]byte("test"), bad, link); err == nil {
			t.Errorf("invalid destination accepted: %s", bad)
		}
	}
	if err := n.Send([]byte("test"), target, linkAddr{}); err == nil {
		t.Fatal("missing source link accepted")
	}
	if other, err := openNetwork(int(target.Port()), []string{link.Name}, nil, nil, ""); err == nil {
		other.Close()
		t.Fatal("bound port accepted by a second transport")
	}
	include := []string{link.Name}
	other, err := openNetwork(0, include, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	include[0] = "not-the-loopback"
	otherLinks, err := other.Links()
	if err != nil || !slices.Equal(links, otherLinks) {
		t.Fatalf("constructor did not copy include list: %+v, %v", otherLinks, err)
	}
}

func TestNetworkPartialFamily(t *testing.T) {
	n, links := transportLoopback(t)
	link, target := transportFamily(t, n, links, false)
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	port := blocker.LocalAddr().(*net.UDPAddr).Port
	other, err := openNetwork(port, []string{links[0].Name}, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if got := other.(*udpNetwork); got.v4 != nil || got.v6 == nil {
		t.Fatal("did not retain only the available address family")
	}
	if err := other.Send([]byte("IPv6 fallback"), target, link); err != nil {
		t.Fatal(err)
	}
	if p := transportPacket(t, n); string(p.Data) != "IPv6 fallback" || p.Source.Port() != uint16(port) {
		t.Fatalf("remaining socket did not send: %+v", p)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	rebound, err := net.ListenUDP("udp6", &net.UDPAddr{Port: port})
	if err != nil {
		t.Fatalf("Close left the IPv6 port bound: %v", err)
	}
	rebound.Close()
}
