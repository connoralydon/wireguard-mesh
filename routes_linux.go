package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
)

// Keep the first version small: the stable OS route must already use WireGuard.
// Only WireGuard host ownership changes; no routing rules or OS routes are added.
func checkRoutes(name string, source netip.Addr, peers []peerSpec) error {
	link, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	return checkLinkRoutes(link.Index, source, peers)
}

func checkLinkRoutes(index int, source netip.Addr, peers []peerSpec) error {
	for _, peer := range peers {
		routes, err := netlink.RouteGetWithOptions(net.IP(peer.IP.AsSlice()), &netlink.RouteGetOptions{SrcAddr: net.IP(source.AsSlice())})
		if err != nil {
			return err
		}
		if len(routes) != 1 || routes[0].LinkIndex != index || len(routes[0].MultiPath) != 0 {
			return fmt.Errorf("stable route to %s must select interface %d; policy/multipath route changes are unsupported", peer.IP, index)
		}
	}
	return nil
}
