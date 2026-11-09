package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

type iceTestTransport struct {
	sent   []byte
	target netip.AddrPort
}

func (t *iceTestTransport) Send(b []byte, target netip.AddrPort) error {
	t.sent = append([]byte(nil), b...)
	t.target = target
	return nil
}
func (*iceTestTransport) Incoming() <-chan packet { return nil }
func (*iceTestTransport) Close() error            { return nil }

func TestICEPacketConn(t *testing.T) {
	raw := &iceTestTransport{}
	c := newICEPacketConn(raw, 51820)
	if c.LocalAddr().(*net.UDPAddr).Port != 51820 {
		t.Fatal("wrong shared port")
	}
	source := netip.MustParseAddrPort("192.0.2.10:1234")
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !c.deliver(packet{Data: msg.Raw, Source: source}) {
		t.Fatal("STUN rejected")
	}
	msg.Raw[0] ^= 1
	buf := make([]byte, 128)
	n, from, err := c.ReadFrom(buf)
	if err != nil || !stun.IsMessage(buf[:n]) || from.(*net.UDPAddr).AddrPort() != source {
		t.Fatal("bad read", err)
	}
	if _, err := c.WriteTo(buf[:n], net.UDPAddrFromAddrPort(source)); err != nil || raw.target != source {
		t.Fatal("bad write", err)
	}
	if c.deliver(packet{Data: []byte("not STUN"), Source: source}) {
		t.Fatal("non-STUN accepted")
	}
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("missing deadline", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.WriteTo(buf[:n], net.UDPAddrFromAddrPort(source)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("write after close", err)
	}
}

func TestICEPacketConnWakeAndBounds(t *testing.T) {
	c := newICEPacketConn(&iceTestTransport{}, 1234)
	defer c.Close()
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []netip.AddrPort{{}, netip.MustParseAddrPort("0.0.0.0:1"), netip.MustParseAddrPort("224.0.0.1:1"), netip.MustParseAddrPort("192.0.2.1:0"), netip.MustParseAddrPort("[::1]:1")} {
		if c.deliver(packet{Data: msg.Raw, Source: source}) {
			t.Fatal("accepted invalid source")
		}
	}
	if _, err := c.WriteTo(make([]byte, maxUnderlayPacket+1), net.UDPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:1"))); err == nil {
		t.Fatal("accepted oversized write")
	}
	read := func() <-chan error {
		ch := make(chan error, 1)
		go func() { _, _, e := c.ReadFrom(make([]byte, 128)); ch <- e }()
		return ch
	}
	a, b := read(), read()
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []<-chan error{a, b} {
		select {
		case err := <-ch:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("deadline did not wake reader")
			}
		case <-time.After(time.Second):
			t.Fatal("deadline wake timed out")
		}
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	ch := read()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ch:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("close did not wake reader")
		}
	case <-time.After(time.Second):
		t.Fatal("close wake timed out")
	}
	_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := c.ReadFrom(make([]byte, 128)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed read returned wrong error")
	}
}
