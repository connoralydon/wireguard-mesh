package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRosenpassVPNConfig(t *testing.T) {
	a, _, _ := rosenpassFixture(t)
	c := a.config
	c.TunnelInterface = "wg0"
	c.TunnelPeerIP = netip.MustParseAddr("10.0.0.2")
	check := func(c rosenpassConfig, want bool) {
		t.Helper()
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		_, err = readRosenpassConfig(strings.NewReader(string(b)))
		if (err == nil) != want {
			t.Fatalf("config accepted=%v, want %v: %v", err == nil, want, err)
		}
	}
	check(c, true)
	bad := c
	bad.TunnelInterface = ""
	check(bad, false)
	bad = c
	bad.TunnelPeerIP = netip.Addr{}
	check(bad, false)
	for _, ip := range []string{"127.0.0.1", "fe80::1", "::ffff:192.0.2.1", "ff02::1", "fe80::1%wg0"} {
		bad = c
		bad.TunnelPeerIP = netip.MustParseAddr(ip)
		check(bad, false)
	}
	for _, name := range []string{".", "..", "wg:0", "bad/name", "bad name"} {
		bad = c
		bad.TunnelInterface = name
		check(bad, false)
	}
}

func TestRosenpassVPNValidation(t *testing.T) {
	c := rosenpassConfig{TunnelInterface: "wg0", TunnelPeerIP: netip.MustParseAddr("10.0.0.2")}
	r := rosenpassRequest{Address: c.TunnelPeerIP, Link: linkAddr{Index: 7, Name: "wg0", Prefix: netip.MustParsePrefix("10.0.0.1/32")}}
	iface := net.Interface{Index: 7, Name: "wg0", Flags: net.FlagUp | net.FlagPointToPoint}
	prefixes := []netip.Prefix{r.Link.Prefix}
	if _, err := rosenpassVPNOnLink(r, c, iface, "wireguard", prefixes); err != nil {
		t.Fatal(err)
	}
	v6, c6 := r, c
	c6.TunnelPeerIP = netip.MustParseAddr("2001:db8::2")
	v6.Address = c6.TunnelPeerIP
	v6.Link.Prefix = netip.MustParsePrefix("2001:db8::1/128")
	if _, err := rosenpassVPNOnLink(v6, c6, iface, "wireguard", []netip.Prefix{v6.Link.Prefix}); err != nil {
		t.Fatal("IPv6 tunnel rejected:", err)
	}
	for name, change := range map[string]func(*rosenpassRequest){
		"peer":       func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("198.51.100.1") },
		"index":      func(r *rosenpassRequest) { r.Link.Index++ },
		"name":       func(r *rosenpassRequest) { r.Link.Name = "wg1" },
		"unassigned": func(r *rosenpassRequest) { r.Link.Prefix = netip.MustParsePrefix("10.0.0.3/32") },
		"family":     func(r *rosenpassRequest) { r.Link.Prefix = netip.MustParsePrefix("2001:db8::1/128") },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			p := append([]netip.Prefix{}, prefixes...)
			if name == "family" {
				p = append(p, bad.Link.Prefix)
			}
			if _, err := rosenpassVPNOnLink(bad, c, iface, "wireguard", p); err == nil {
				t.Fatal("accepted invalid request")
			}
		})
	}
	if _, err := rosenpassVPNOnLink(r, c, iface, "tun", prefixes); err == nil {
		t.Fatal("accepted non-WireGuard link")
	}
	down := iface
	down.Flags = 0
	if _, err := rosenpassVPNOnLink(r, c, down, "wireguard", prefixes); err == nil {
		t.Fatal("accepted down link")
	}
	if _, err := rosenpassOnLink(r, iface, prefixes); err == nil {
		t.Fatal("LAN mode accepted tunnel")
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	r.Link.Index, r.Link.Name, c.TunnelInterface = lo.Index, lo.Name, lo.Name
	if _, err := validateRosenpassVPNRequest(r, c); err == nil {
		t.Fatal("kernel loopback accepted as WireGuard")
	}
}

func TestRosenpassVPNProcessArgs(t *testing.T) {
	for _, initiate := range []bool{true, false} {
		t.Run(map[bool]string{true: "initiator", false: "listener"}[initiate], func(t *testing.T) {
			rosenpassVPNProcessArgs(t, initiate)
		})
	}
}

func rosenpassVPNProcessArgs(t *testing.T, initiate bool) {
	t.Helper()
	a, r, _ := rosenpassFixture(t)
	local, remote := []byte{1}, []byte{2}
	if !initiate {
		local, remote = remote, local
	}
	for path, body := range map[string][]byte{a.config.PublicKeyFile: local, a.config.PeerPublicKeyFile: remote} {
		if err := os.WriteFile(path, body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	a.config.TunnelInterface = "wg0"
	a.config.TunnelPeerIP = netip.MustParseAddr("10.0.0.2")
	r.Link = linkAddr{Index: 7, Name: "wg0", Prefix: netip.MustParsePrefix("10.0.0.1/32")}
	r.Address = a.config.TunnelPeerIP
	a.validate = func(r rosenpassRequest) (rosenpassRequest, error) {
		return rosenpassVPNOnLink(r, a.config, net.Interface{Index: 7, Name: "wg0", Flags: net.FlagUp}, "wireguard", []netip.Prefix{r.Link.Prefix})
	}
	argsFile := filepath.Join(filepath.Dir(a.config.PSKFile), "args")
	a.config.Executable = filepath.Join(filepath.Dir(a.config.PSKFile), "fake-rp")
	if err := os.WriteFile(a.config.Executable, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+argsFile+"\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	a.start = a.startProcess
	if _, err := a.request(r, time.Now()); err != nil {
		t.Fatal(err)
	}
	rosenpassWait(t, func() bool { _, err := os.Stat(argsFile); return err == nil })
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(b)), "\n")
	want := 12
	if initiate {
		want = 14
	}
	if len(args) != want || args[6] != "10.0.0.1:9998" || initiate && (args[10] != "endpoint" || args[11] != "10.0.0.2:9999") || !initiate && args[10] != "outfile" {
		t.Fatalf("wrong VPN process arguments: %q", args)
	}
}

func TestRosenpassVPNInitialInitiator(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	write := func(path string, body []byte) {
		t.Helper()
		if err := os.WriteFile(path, body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(a, []byte{0, 1})
	write(b, []byte{0, 2})
	first, err := rosenpassInitialInitiator(a, b)
	if err != nil || !first {
		t.Fatal("lower public identity did not initiate:", err)
	}
	other, err := rosenpassInitialInitiator(b, a)
	if err != nil || other {
		t.Fatal("higher public identity also initiated:", err)
	}
	write(b, []byte{0, 1})
	if _, err := rosenpassInitialInitiator(a, b); err == nil {
		t.Fatal("equal public identities accepted")
	}
	write(b, nil)
	if _, err := rosenpassInitialInitiator(a, b); err == nil {
		t.Fatal("empty public identity accepted")
	}
	if err := os.Truncate(b, 1<<20+1); err != nil {
		t.Fatal(err)
	}
	if _, err := rosenpassInitialInitiator(a, b); err == nil {
		t.Fatal("oversized public identity accepted")
	}
	for _, invalid := range []string{dir, filepath.Join(dir, "missing")} {
		if _, err := rosenpassInitialInitiator(a, invalid); err == nil {
			t.Fatal("unavailable public identity accepted")
		}
	}
}
