//go:build !linux

package main

import (
	"errors"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type routeController struct{}

func newRouteController(wgClient, string, string, string, netip.Addr, int) (*routeController, error) {
	return nil, errors.New("route-based peering requires Linux")
}

func recoverRouteController(wgClient, string, string) error {
	return errors.New("route-based peering requires Linux")
}

func (*routeController) Identity() (wgtypes.Key, int) { return wgtypes.Key{}, 0 }
func (*routeController) Apply(wgtypes.Key, netip.Addr, wgtypes.Key, netip.AddrPort) error {
	return errors.New("route-based peering requires Linux")
}
func (*routeController) Restore(wgtypes.Key) error {
	return errors.New("route-based peering requires Linux")
}
func (*routeController) RestoreAll() error { return errors.New("route-based peering requires Linux") }
func (*routeController) Check() error      { return errors.New("route-based peering requires Linux") }

func checkRouteModeRuntime(string, config, linkAddr, int, func() (*wgtypes.Device, error), *routeController) error {
	return errors.New("route-based peering requires Linux")
}
