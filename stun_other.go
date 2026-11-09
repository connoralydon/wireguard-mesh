//go:build !linux

package main

import "errors"

func openWireGuardUDP(port uint16) (wireGuardUDP, error) {
	return nil, errors.New("shared WireGuard UDP transport requires Linux")
}
