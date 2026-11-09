package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func checkRouteModeRuntime(name string, cfg config, tunnel linkAddr, port int, device func() (*wgtypes.Device, error), c *routeController) error {
	current, err := tunnelLink(name, cfg.Address)
	if err != nil {
		return err
	}
	if current.Index != tunnel.Index {
		return errors.New("stable WireGuard interface was replaced")
	}
	d, err := device()
	if err != nil {
		return err
	}
	if d.ListenPort != port {
		return errors.New("stable WireGuard listen port changed")
	}
	if err := c.Check(); err != nil {
		return err
	}
	if cfg.Address.Is4() {
		all, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter")
		if err != nil {
			return err
		}
		for _, iface := range []string{name, cfg.DirectInterface} {
			value, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + iface + "/rp_filter")
			if err != nil {
				return err
			}
			// Linux uses max(all, interface). Loose mode permits overlap
			// while the two nodes change routes at different times.
			a, v := strings.TrimSpace(string(all)), strings.TrimSpace(string(value))
			if a == "1" && v != "2" || v == "1" && a != "2" {
				return fmt.Errorf("route mode requires loose or disabled IPv4 rp_filter on %s; the daemon does not change sysctls", iface)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, peer := range cfg.Peers {
		index := tunnel.Index
		if r := c.journal.Peers[peer.key.String()]; r != nil && r.Phase == "active" {
			index = c.journal.Index
		}
		routes, err := netlink.RouteGetWithOptions(net.IP(peer.IP.AsSlice()), &netlink.RouteGetOptions{SrcAddr: net.IP(cfg.Address.AsSlice())})
		if err != nil {
			return err
		}
		if len(routes) != 1 || routes[0].LinkIndex != index || routes[0].Table != unix.RT_TABLE_MAIN || len(routes[0].MultiPath) != 0 {
			return fmt.Errorf("unexpected OS route for %s; policy and multipath routing are unsupported", peer.IP)
		}
	}
	return nil
}
