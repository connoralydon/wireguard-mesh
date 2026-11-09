package main

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/pion/stun/v4"
)

// icePacketConn adapts the existing WireGuard-port transport for Pion. The
// mesh event loop must call deliver for inbound STUN packets; it remains the
// sole consumer of the raw transport's Incoming channel.
type icePacketConn struct {
	transport     wireGuardUDP
	local         *net.UDPAddr
	incoming      chan packet
	done          chan struct{}
	once          sync.Once
	mu            sync.Mutex
	deadline      time.Time
	writeDeadline time.Time
	changed       chan struct{}
}

func newICEPacketConn(t wireGuardUDP, port uint16) *icePacketConn {
	return &icePacketConn{transport: t, local: &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}, incoming: make(chan packet, 128), done: make(chan struct{}), changed: make(chan struct{})}
}

// deliver never blocks the mesh event loop and copies the caller's buffer.
func (c *icePacketConn) deliver(p packet) bool {
	a := p.Source.Addr()
	if !p.Source.IsValid() || p.Source.Port() == 0 || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a == netip.MustParseAddr("255.255.255.255") || len(p.Data) > maxUnderlayPacket || !stun.IsMessage(p.Data) {
		return false
	}
	p.Data = append([]byte(nil), p.Data...)
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.incoming <- p:
		return true
	default:
		return false
	}
}

func (c *icePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case <-c.done:
			return 0, nil, net.ErrClosed
		default:
		}
		c.mu.Lock()
		deadline := c.deadline
		changed := c.changed
		c.mu.Unlock()
		var timer *time.Timer
		var expired <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(d)
			expired = timer.C
		}
		select {
		case <-c.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-expired:
			select {
			case <-c.done:
				return 0, nil, net.ErrClosed
			default:
			}
			return 0, nil, os.ErrDeadlineExceeded
		case p := <-c.incoming:
			if timer != nil {
				timer.Stop()
			}
			select {
			case <-c.done:
				return 0, nil, net.ErrClosed
			default:
			}
			return copy(b, p.Data), net.UDPAddrFromAddrPort(p.Source), nil
		}
	}
}

func (c *icePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	if len(b) > maxUnderlayPacket {
		return 0, errors.New("underlay packet too large")
	}
	c.mu.Lock()
	deadline := c.writeDeadline
	c.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	a, ok := addr.(*net.UDPAddr)
	if !ok || a == nil {
		return 0, &net.AddrError{Err: "invalid UDP address", Addr: ""}
	}
	ap := a.AddrPort()
	if !ap.IsValid() || !ap.Addr().Unmap().Is4() || ap.Port() == 0 {
		return 0, &net.AddrError{Err: "invalid IPv4 UDP address", Addr: a.String()}
	}
	if err := c.transport.Send(b, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *icePacketConn) Close() error        { c.once.Do(func() { close(c.done) }); return nil }
func (c *icePacketConn) LocalAddr() net.Addr { return c.local }
func (c *icePacketConn) SetDeadline(t time.Time) error {
	_ = c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}
func (c *icePacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	close(c.changed)
	c.changed = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *icePacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
