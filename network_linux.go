package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func physicalInterface(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/class/net", name, "device"))
	return err == nil
}

// One pair of dumps replaces a separate link/address request for every
// interface. A scoped handle shares its socket, but no state survives the call.
func readInterfaces() ([]interfaceState, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	return readInterfaceStates(h)
}

type interfaceReader interface {
	LinkList() ([]netlink.Link, error)
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
}

func readInterfaceStates(reader interfaceReader) ([]interfaceState, error) {
	links, err := reader.LinkList()
	if err != nil {
		return nil, err // Never use a partial or interrupted dump.
	}
	addresses, err := reader.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	byIndex := make(map[int][]netlink.Addr)
	for _, address := range addresses {
		byIndex[address.LinkIndex] = append(byIndex[address.LinkIndex], address)
	}
	states := make([]interfaceState, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		states = append(states, interfaceState{linkInterface(attrs), linkPrefixes(attrs, byIndex[attrs.Index])})
	}
	return states, nil
}

func readInterface(name string) (interfaceState, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return interfaceState{}, err
	}
	defer h.Close()
	link, err := h.LinkByName(name)
	if err != nil {
		return interfaceState{}, err
	}
	addresses, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return interfaceState{}, err
	}
	return interfaceState{linkInterface(link.Attrs()), linkPrefixes(link.Attrs(), addresses)}, nil
}

func linkInterface(attrs *netlink.LinkAttrs) net.Interface {
	return net.Interface{Index: attrs.Index, Name: attrs.Name, MTU: attrs.MTU, Flags: attrs.Flags, HardwareAddr: attrs.HardwareAddr}
}

func interfacePrefixes(iface net.Interface) ([]netip.Prefix, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	link, err := h.LinkByIndex(iface.Index)
	if err != nil {
		var missing netlink.LinkNotFoundError
		if errors.As(err, &missing) {
			return nil, nil
		}
		return nil, err
	}
	attrs := link.Attrs()
	if attrs.Name != iface.Name {
		return nil, nil
	}
	addresses, err := h.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}
	return linkPrefixes(attrs, addresses), nil
}

func linkPrefixes(attrs *netlink.LinkAttrs, addresses []netlink.Addr) []netip.Prefix {
	if attrs.Flags&net.FlagUp == 0 {
		return nil
	}
	switch attrs.OperState {
	case netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperNotPresent:
		return nil
	}
	var prefixes []netip.Prefix
	for _, address := range addresses {
		if address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		p, err := netip.ParsePrefix(address.IPNet.String())
		if err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

func (n *udpNetwork) watch() error {
	links := make(chan netlink.LinkUpdate, 16)
	if err := netlink.LinkSubscribe(links, n.done); err != nil {
		return err
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.signalChanged()
		// Drain until netlink closes the channel, including during shutdown.
		for range links {
			n.signalChanged()
		}
	}()
	addresses := make(chan netlink.AddrUpdate, 16)
	if err := netlink.AddrSubscribe(addresses, n.done); err != nil {
		return err
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer n.signalChanged()
		for range addresses {
			n.signalChanged()
		}
	}()
	return nil
}
