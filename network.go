package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type linkAddr struct {
	Index     int
	Name      string
	Prefix    netip.Prefix // Retains the local address, not the masked network address.
	Broadcast netip.Addr
	Multicast bool
}

type packet struct {
	Data        []byte
	Source      netip.AddrPort
	Destination netip.Addr
	IfIndex     int
}

type network interface {
	Send([]byte, netip.AddrPort, linkAddr) error
	Links() ([]linkAddr, error)
	Incoming() <-chan packet
	Changed() <-chan struct{}
	Close() error
}

const networkDatagramLimit = 1200

type membership struct {
	index int
	name  string
	group netip.Addr
}

type udpNetwork struct {
	v4               *ipv4.PacketConn
	v6               *ipv6.PacketConn
	include, exclude []string
	groups           []netip.Addr
	wgName           string
	incoming         chan packet
	changed, done    chan struct{}
	wg               sync.WaitGroup
	once             sync.Once
	mu               sync.Mutex // Serializes membership refresh and socket closure.
	joined           map[membership][]netip.Prefix
	closeErr         error
}

func openNetwork(port int, include, exclude []string, groups []netip.Addr, wgName string) (network, error) {
	for _, group := range groups {
		if !group.IsMulticast() || group.Is4In6() || group.Zone() != "" {
			return nil, fmt.Errorf("invalid multicast group %s", group)
		}
	}
	n := &udpNetwork{
		include: slices.Clone(include), exclude: slices.Clone(exclude), groups: slices.Clone(groups), wgName: wgName,
		incoming: make(chan packet, 64), changed: make(chan struct{}, 1), done: make(chan struct{}),
		joined: make(map[membership][]netip.Prefix),
	}
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) {
			if network == "udp4" {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
			}
		}); e != nil {
			return e
		}
		return err
	}}
	var setupErr error
	for _, family := range []string{"udp4", "udp6"} {
		conn, err := lc.ListenPacket(context.Background(), family, net.JoinHostPort("", strconv.Itoa(port)))
		if err == nil {
			if family == "udp4" {
				p := ipv4.NewPacketConn(conn)
				err = errors.Join(p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true), p.SetMulticastTTL(1))
				if err == nil {
					n.v4 = p
				}
			} else {
				p := ipv6.NewPacketConn(conn)
				err = errors.Join(p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true), p.SetMulticastHopLimit(1))
				if err == nil {
					n.v6 = p
				}
			}
			if err != nil {
				conn.Close()
			} else {
				port = conn.LocalAddr().(*net.UDPAddr).Port
			}
		}
		if err != nil {
			log.Printf("%s socket unavailable: %v", family, err)
			setupErr = errors.Join(setupErr, fmt.Errorf("%s: %w", family, err))
		}
	}
	if n.v4 == nil && n.v6 == nil {
		n.Close()
		return nil, setupErr
	}
	if err := n.watch(); err != nil {
		n.Close()
		return nil, err
	}
	if _, err := n.Links(); err != nil {
		n.Close()
		return nil, err
	}
	// Finish setup before a failed receiver can initiate shutdown.
	n.wg.Add(2)
	go n.receive(true)
	go n.receive(false)
	return n, nil
}

func (n *udpNetwork) Incoming() <-chan packet  { return n.incoming }
func (n *udpNetwork) Changed() <-chan struct{} { return n.changed }

func (n *udpNetwork) Send(data []byte, destination netip.AddrPort, link linkAddr) error {
	select {
	case <-n.done:
		return net.ErrClosed
	default:
	}
	source, target := link.Prefix.Addr(), destination.Addr()
	if len(data) == 0 || len(data) > networkDatagramLimit || !destination.IsValid() || destination.Port() == 0 ||
		!link.Prefix.IsValid() || !usableLinkAddress(source) || link.Index <= 0 ||
		target.IsUnspecified() || target.Is4In6() || source.Is4() != target.Is4() {
		return errors.New("invalid UDP packet, destination, or source link")
	}
	zone := strconv.Itoa(link.Index)
	if target.Zone() != "" && target.Zone() != link.Name && target.Zone() != zone {
		return errors.New("destination zone differs from source interface")
	}
	if target.Is6() && (target.IsLinkLocalUnicast() || target.IsLinkLocalMulticast()) {
		destination = netip.AddrPortFrom(target.WithZone(zone), destination.Port())
	}
	addr := net.UDPAddrFromAddrPort(destination)
	if target.Is4() && n.v4 != nil {
		_, err := n.v4.WriteTo(data, &ipv4.ControlMessage{Src: net.IP(source.AsSlice()), IfIndex: link.Index}, addr)
		return err
	}
	if target.Is6() && n.v6 != nil {
		_, err := n.v6.WriteTo(data, &ipv6.ControlMessage{Src: net.IP(source.AsSlice()), IfIndex: link.Index}, addr)
		return err
	}
	return errors.New("UDP address family is unavailable")
}

func (n *udpNetwork) receive(v4 bool) {
	defer n.wg.Done()
	if (v4 && n.v4 == nil) || (!v4 && n.v6 == nil) {
		return
	}
	// The extra byte distinguishes a full-size packet from any truncated packet.
	var buffer [networkDatagramLimit + 1]byte
	for {
		var size, index int
		var dst net.IP
		var src net.Addr
		var err error
		if v4 {
			var cm *ipv4.ControlMessage
			size, cm, src, err = n.v4.ReadFrom(buffer[:])
			if cm != nil {
				dst, index = cm.Dst, cm.IfIndex
			}
		} else {
			var cm *ipv6.ControlMessage
			size, cm, src, err = n.v6.ReadFrom(buffer[:])
			if cm != nil {
				dst, index = cm.Dst, cm.IfIndex
			}
		}
		if err != nil {
			select {
			case <-n.done:
				return
			default:
			}
			var temporary net.Error
			if errors.As(err, &temporary) && temporary.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			log.Printf("UDP receive failed (IPv4=%t); closing transport: %v", v4, err)
			go n.Close() // Close waits for this receiver to return.
			return
		}
		destination, ok := netip.AddrFromSlice(dst)
		if size > networkDatagramLimit || !ok || index <= 0 {
			continue
		}
		source := src.(*net.UDPAddr).AddrPort()
		a := source.Addr().Unmap()
		if a.IsLinkLocalUnicast() && a.Is6() {
			a = a.WithZone(strconv.Itoa(index))
		}
		p := packet{Data: slices.Clone(buffer[:size]), Source: netip.AddrPortFrom(a, source.Port()), Destination: destination.Unmap(), IfIndex: index}
		select {
		case n.incoming <- p:
		default:
		}
	}
}

// Only failure to enumerate interfaces is fatal; individual failures are logged.
func (n *udpNetwork) Links() ([]linkAddr, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	select {
	case <-n.done:
		return nil, net.ErrClosed
	default:
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var links []linkAddr
	wanted := make(map[membership][]netip.Prefix)
	for _, iface := range interfaces {
		if !selectInterface(iface, n.include, n.exclude, n.wgName) {
			continue
		}
		prefixes, err := interfacePrefixes(iface)
		if err != nil {
			log.Printf("skip addresses on %s: %v", iface.Name, err)
			continue
		}
		slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		for _, prefix := range prefixes {
			if !usableLinkAddress(prefix.Addr()) {
				continue
			}
			link := addressedLink(iface, prefix)
			links = append(links, link)
			for _, group := range n.groups {
				if link.Multicast && group.Is4() == prefix.Addr().Is4() &&
					((group.Is4() && n.v4 != nil) || (group.Is6() && n.v6 != nil)) {
					key := membership{iface.Index, iface.Name, group}
					wanted[key] = append(wanted[key], prefix)
				}
			}
		}
	}
	// Memberships belong to interfaces, not individual source addresses.
	// Rejoin only those whose address sets changed; retain all other joins.
	for key, prefixes := range n.joined {
		if !slices.Equal(prefixes, wanted[key]) {
			n.groupMembership(key, false) // A removed interface may already have lost the membership.
			delete(n.joined, key)
		}
	}
	for key, prefixes := range wanted {
		if _, ok := n.joined[key]; !ok {
			if e := n.groupMembership(key, true); e != nil {
				log.Printf("join %s on %s failed; will retry: %v", key.group, key.name, e)
			} else {
				n.joined[key] = prefixes
			}
		}
	}
	return links, nil
}

func (n *udpNetwork) groupMembership(key membership, join bool) error {
	iface := &net.Interface{Index: key.index, Name: key.name}
	addr := &net.UDPAddr{IP: net.IP(key.group.AsSlice())}
	if key.group.Is4() {
		if join {
			return n.v4.JoinGroup(iface, addr)
		}
		return n.v4.LeaveGroup(iface, addr)
	}
	if join {
		return n.v6.JoinGroup(iface, addr)
	}
	return n.v6.LeaveGroup(iface, addr)
}

func selectInterface(iface net.Interface, include, exclude []string, wgName string) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Name == wgName || slices.Contains(exclude, iface.Name) {
		return false
	}
	if len(include) != 0 {
		return slices.Contains(include, iface.Name)
	}
	return iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) == 0 && physicalInterface(iface.Name)
}

func usableLinkAddress(a netip.Addr) bool {
	return !a.Is4In6() && (a.IsGlobalUnicast() || a.IsLinkLocalUnicast() || a.IsLoopback())
}

func addressedLink(iface net.Interface, prefix netip.Prefix) linkAddr {
	l := linkAddr{Index: iface.Index, Name: iface.Name, Prefix: prefix, Multicast: iface.Flags&net.FlagMulticast != 0}
	if iface.Flags&net.FlagBroadcast != 0 {
		l.Broadcast = broadcastAddress(prefix)
	}
	return l
}

func broadcastAddress(prefix netip.Prefix) netip.Addr {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Bits() > 30 {
		return netip.Addr{}
	}
	ip := prefix.Addr().As4()
	binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])|(^uint32(0)>>prefix.Bits()))
	return netip.AddrFrom4(ip)
}

func tunnelLink(name string, address netip.Addr) (linkAddr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return linkAddr{}, err
	}
	if iface.Flags&net.FlagUp == 0 {
		return linkAddr{}, fmt.Errorf("interface %s is down", name)
	}
	prefixes, err := interfacePrefixes(*iface)
	if err != nil {
		return linkAddr{}, err
	}
	for _, prefix := range prefixes {
		if prefix.Addr() == address.WithZone("") && usableLinkAddress(address) &&
			(address.Zone() == "" || address.Zone() == name || address.Zone() == strconv.Itoa(iface.Index)) {
			return addressedLink(*iface, prefix), nil
		}
	}
	return linkAddr{}, fmt.Errorf("local tunnel address %s is not assigned to %s", address, name)
}

func (n *udpNetwork) signalChanged() {
	select {
	case n.changed <- struct{}{}:
	default:
	}
}

func (n *udpNetwork) Close() error {
	n.once.Do(func() {
		n.mu.Lock()
		close(n.done)
		if n.v4 != nil {
			n.closeErr = errors.Join(n.closeErr, n.v4.Close())
		}
		if n.v6 != nil {
			n.closeErr = errors.Join(n.closeErr, n.v6.Close())
		}
		n.mu.Unlock()
		n.wg.Wait()
		close(n.incoming)
		close(n.changed)
	})
	return n.closeErr
}
