//go:build !linux

package main

import (
	"net"
	"net/netip"
)

func physicalInterface(name string) bool { return false }

func interfacePrefixes(iface net.Interface) ([]netip.Prefix, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, address := range addresses {
		p, err := netip.ParsePrefix(address.String())
		if err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes, nil
}

func (n *udpNetwork) watch() error { return nil }
