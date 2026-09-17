//go:build !linux

package main

import (
	"errors"
	"net/netip"
)

func checkRoutes(string, netip.Addr, []peerSpec) error { return errors.New("Linux is required") }
