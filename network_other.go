//go:build !linux

package main

import (
	"net"
	"net/netip"
)

func physicalInterface(name string) bool { return false }

func readInterfaces() ([]interfaceState, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var states []interfaceState
	for _, iface := range interfaces {
		prefixes, err := interfacePrefixes(iface)
		if err != nil {
			return nil, err
		}
		states = append(states, interfaceState{iface, prefixes})
	}
	return states, nil
}

func readInterface(name string) (interfaceState, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return interfaceState{}, err
	}
	prefixes, err := interfacePrefixes(*iface)
	return interfaceState{*iface, prefixes}, err
}

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
