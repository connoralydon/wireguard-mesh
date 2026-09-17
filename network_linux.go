package main

import (
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

func interfacePrefixes(iface net.Interface) ([]netip.Prefix, error) {
	addresses, err := netlink.AddrList(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: iface.Index}}, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
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
	return prefixes, nil
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
