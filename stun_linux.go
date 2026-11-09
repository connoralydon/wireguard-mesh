//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type rawWireGuardUDP struct {
	fd        int
	port      uint16
	incoming  chan packet
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	mu        sync.Mutex
	closeErr  error
	allowed   map[int]bool
}

// The socket sees IPv4 packets including their IP header. LoadMemShift accounts
// for IPv4 options. Reject fragments before examining the UDP payload.
func wireGuardFilter(port uint16) ([]bpf.RawInstruction, error) {
	return bpf.Assemble([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 6, Size: 2}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x3fff}, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0, SkipTrue: 12},
		bpf.LoadMemShift{Off: 0}, bpf.LoadIndirect{Off: 2, Size: 2}, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(port), SkipTrue: 9},
		bpf.LoadIndirect{Off: 12, Size: 4}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: stunCookie, SkipTrue: 8},
		bpf.LoadIndirect{Off: 4, Size: 2}, bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 520, SkipTrue: 5},
		bpf.LoadIndirect{Off: 8, Size: 4}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x01000000, SkipTrue: 3}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x02000000, SkipTrue: 2}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x03000000, SkipTrue: 1}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x04000000, SkipTrue: 0, SkipFalse: 1},
		bpf.RetConstant{Val: 0}, bpf.RetConstant{Val: 65535},
	})
}

func openWireGuardUDP(port uint16) (wireGuardUDP, error) {
	if port == 0 {
		return nil, errors.New("WireGuard port must be nonzero")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("open raw UDP socket: %w", err)
	}
	fail := func(err error) (wireGuardUDP, error) { unix.Close(fd); return nil, err }
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return fail(err)
	}
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1); err != nil {
		return fail(err)
	}
	code, err := wireGuardFilter(port)
	if err != nil {
		return fail(err)
	}
	filters := make([]unix.SockFilter, len(code))
	for i, ins := range code {
		filters[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	if err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}); err != nil {
		return fail(err)
	}
	r := &rawWireGuardUDP{fd: fd, port: port, incoming: make(chan packet, 128), done: make(chan struct{})}
	go r.receive()
	return r, nil
}

func (r *rawWireGuardUDP) Incoming() <-chan packet { return r.incoming }
func (r *rawWireGuardUDP) SetLinks(links []linkAddr) {
	allowed := make(map[int]bool, len(links))
	for _, link := range links {
		allowed[link.Index] = true
	}
	r.mu.Lock()
	r.allowed = allowed
	r.mu.Unlock()
}
func (r *rawWireGuardUDP) Close() error {
	r.closeOnce.Do(func() { r.closed.Store(true); <-r.done; r.mu.Lock(); r.closeErr = unix.Close(r.fd); r.mu.Unlock() })
	return r.closeErr
}

func (r *rawWireGuardUDP) receive() {
	defer close(r.done)
	defer close(r.incoming)
	buf := make([]byte, 65536)
	oob := make([]byte, 256)
	for !r.closed.Load() {
		p := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(p, 200)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			log.Printf("raw UDP poll: %v", err)
			return
		}
		if p[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			log.Printf("raw UDP socket poll error: %#x", p[0].Revents)
			return
		}
		if p[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, oobn, flags, _, err := unix.Recvmsg(r.fd, buf, oob, 0)
		if err == unix.EAGAIN || err == unix.EINTR {
			continue
		}
		if err != nil {
			log.Printf("raw UDP receive: %v", err)
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			continue
		}
		pkt, ok := parseRawUDP(buf[:n], oob[:oobn], r.port)
		if !ok {
			continue
		}
		select {
		case r.incoming <- pkt:
		default:
		}
	}
}

func parseRawUDP(b, oob []byte, port uint16) (packet, bool) {
	if len(b) < 28 || b[0]>>4 != 4 || b[9] != 17 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
		return packet{}, false
	}
	h := int(b[0]&15) * 4
	if h < 20 || len(b) < h+8 {
		return packet{}, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	length := int(binary.BigEndian.Uint16(b[h+4 : h+6]))
	if total != len(b) || length < 8 || length != total-h || length-8 > maxUnderlayPacket || binary.BigEndian.Uint16(b[h+2:h+4]) != port {
		return packet{}, false
	}
	var src [4]byte
	copy(src[:], b[12:16])
	source := netip.AddrPortFrom(netip.AddrFrom4(src), binary.BigEndian.Uint16(b[h:h+2]))
	if !validUnderlay(source) {
		return packet{}, false
	}
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return packet{}, false
	}
	var dst netip.Addr
	var index int
	for _, m := range msgs {
		if m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_PKTINFO {
			if len(m.Data) < 12 {
				return packet{}, false
			}
			index = int(binary.NativeEndian.Uint32(m.Data[:4]))
			var addr [4]byte
			copy(addr[:], m.Data[8:12])
			dst = netip.AddrFrom4(addr)
		}
	}
	if !dst.IsValid() || index <= 0 {
		return packet{}, false
	}
	data := append([]byte(nil), b[h+8:]...)
	return packet{Data: data, Source: source, Destination: dst, IfIndex: index}, true
}

func validUnderlay(target netip.AddrPort) bool {
	a := target.Addr()
	return a.Is4() && target.Port() != 0 && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && a != netip.MustParseAddr("255.255.255.255")
}

func (r *rawWireGuardUDP) Send(data []byte, target netip.AddrPort) error {
	if !validUnderlay(target) {
		return errors.New("invalid IPv4 underlay target")
	}
	if len(data) > maxUnderlayPacket {
		return errors.New("underlay packet too large")
	}
	routes, err := netlink.RouteGet(net.IP(target.Addr().AsSlice()))
	if err != nil {
		return fmt.Errorf("underlay route lookup: %w", err)
	}
	if len(routes) == 0 || routes[0].LinkIndex <= 0 {
		return errors.New("no underlay route")
	}
	route := routes[0]
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return fmt.Errorf("underlay link: %w", err)
	}
	if link.Type() == "wireguard" || link.Attrs().Flags&net.FlagLoopback != 0 {
		return errors.New("underlay route uses WireGuard or loopback")
	}
	src, ok := netip.AddrFromSlice(route.Src)
	if !ok || !src.Unmap().Is4() || src.IsUnspecified() {
		return errors.New("underlay route has no IPv4 source")
	}
	src = src.Unmap()
	b := make([]byte, 28+len(data))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = 17
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], target.Addr().AsSlice())
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b[:20]))
	binary.BigEndian.PutUint16(b[20:22], r.port)
	binary.BigEndian.PutUint16(b[22:24], target.Port())
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(data)))
	copy(b[28:], data)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed.Load() {
		return net.ErrClosed
	}
	if !r.allowed[route.LinkIndex] {
		return errors.New("underlay route uses an excluded interface")
	}
	dst := target.Addr().As4()
	if err := unix.Sendto(r.fd, b, 0, &unix.SockaddrInet4{Addr: dst}); err != nil {
		return fmt.Errorf("raw UDP send: %w", err)
	}
	return nil
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
