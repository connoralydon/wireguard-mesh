package main

import "net/netip"

const stunCookie uint32 = 0x2112a442 // RFC STUN cookie used only by the socket filter.
const maxUnderlayPacket = 1200

// Kernel WireGuard owns the UDP port. The raw transport copies only STUN and
// encrypted mesh envelopes; WireGuard data stays in the kernel.
type wireGuardUDP interface {
	Send([]byte, netip.AddrPort) error
	Incoming() <-chan packet
	Close() error
}
