//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func TestWireGuardFilter(t *testing.T) {
	ins, err := wireGuardFilter(51820)
	if err != nil {
		t.Fatal(err)
	}
	decoded, ok := bpf.Disassemble(ins)
	if !ok {
		t.Fatal("filter disassembly")
	}
	vm, err := bpf.NewVM(decoded)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 20+8+512)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[22:24], 51820)
	binary.BigEndian.PutUint16(packet[24:26], 520)
	check := func(want bool) {
		t.Helper()
		n, err := vm.Run(packet)
		if err != nil || (n > 0) != want {
			t.Fatalf("filter got %d, %v; want %v", n, err, want)
		}
	}
	check(true)
	packet[28] = 1
	check(false)
	packet[28] = 0
	binary.BigEndian.PutUint16(packet[24:26], 40)
	check(false)
	binary.BigEndian.PutUint32(packet[32:36], stunCookie)
	check(true)
	binary.BigEndian.PutUint16(packet[22:24], 123)
	check(false)
}
func TestUnderlayValidation(t *testing.T) {
	for _, tc := range []struct {
		s     string
		valid bool
	}{{"192.0.2.1:53", true}, {"127.0.0.1:53", false}, {"[2001:db8::1]:53", false}, {"224.0.0.1:53", false}, {"192.0.2.1:0", false}} {
		if got := validUnderlay(netip.MustParseAddrPort(tc.s)); got != tc.valid {
			t.Errorf("%s: %v", tc.s, got)
		}
	}
}
func TestIPv4Checksum(t *testing.T) {
	b := []byte{0x45, 0, 0, 0x54, 0, 0, 0x40, 0, 0x40, 1, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0, 0xc7}
	binary.BigEndian.PutUint16(b[10:12], ipv4Checksum(b))
	if ipv4Checksum(b) != 0 {
		t.Fatal("bad checksum")
	}
}

func TestRawUDPMetadata(t *testing.T) {
	b := make([]byte, 28+512)
	b[0], b[9] = 0x45, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], []byte{192, 0, 2, 12})
	copy(b[16:20], []byte{172, 20, 2, 2})
	binary.BigEndian.PutUint16(b[20:22], 40001)
	binary.BigEndian.PutUint16(b[22:24], 51821)
	binary.BigEndian.PutUint16(b[24:26], 520)
	var header unix.Cmsghdr
	header.Level, header.Type = unix.IPPROTO_IP, unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(12))
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.NativeEndian, header); err != nil {
		t.Fatal(err)
	}
	oob := make([]byte, unix.CmsgSpace(12))
	copy(oob, encoded.Bytes())
	info := oob[unix.CmsgLen(0):]
	binary.NativeEndian.PutUint32(info[:4], 7)
	copy(info[8:12], []byte{172, 20, 2, 2})
	p, ok := parseRawUDP(b, oob, 51821)
	if !ok || p.Source != netip.MustParseAddrPort("192.0.2.12:40001") || p.Destination != netip.MustParseAddr("172.20.2.2") || p.IfIndex != 7 || len(p.Data) != 512 {
		t.Fatal("invalid raw UDP addresses or receive interface")
	}
	if _, ok := parseRawUDP(b, nil, 51821); ok {
		t.Fatal("missing receive-interface metadata accepted")
	}
	if _, ok := parseRawUDP(b[:len(b)-1], oob, 51821); ok {
		t.Fatal("truncated raw packet accepted")
	}
	binary.BigEndian.PutUint16(b[6:8], 0x2000)
	if _, ok := parseRawUDP(b, oob, 51821); ok {
		t.Fatal("fragment accepted")
	}
}

func FuzzRawUDP(f *testing.F) {
	b := make([]byte, 28+32)
	b[0], b[9] = 0x45, 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], []byte{192, 0, 2, 12})
	copy(b[16:20], []byte{172, 20, 2, 2})
	binary.BigEndian.PutUint16(b[20:22], 40001)
	binary.BigEndian.PutUint16(b[22:24], 51821)
	binary.BigEndian.PutUint16(b[24:26], 40)
	var header unix.Cmsghdr
	header.Level, header.Type = unix.IPPROTO_IP, unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(12))
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.NativeEndian, header); err != nil {
		f.Fatal(err)
	}
	oob := make([]byte, unix.CmsgSpace(12))
	copy(oob, encoded.Bytes())
	info := oob[unix.CmsgLen(0):]
	binary.NativeEndian.PutUint32(info[:4], 7)
	copy(info[8:12], []byte{172, 20, 2, 2})
	f.Add(b, oob)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, data, control []byte) {
		p, ok := parseRawUDP(data, control, 51821)
		if ok && (p.IfIndex <= 0 || !validUnderlay(p.Source) || !p.Destination.Is4() || len(p.Data) > maxUnderlayPacket) {
			t.Fatal("accepted raw packet without bounded IPv4 metadata")
		}
	})
}
