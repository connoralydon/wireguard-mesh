package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Opt in with ROSENPASS_TEST_EXECUTABLE pointing to a real 0.2.3 binary.
// ROSENPASS_TEST_STALE=1 also waits for its natural three-minute stale event.
func TestRosenpassExecutable(t *testing.T) {
	executable := os.Getenv("ROSENPASS_TEST_EXECUTABLE")
	if executable == "" {
		t.Skip("set ROSENPASS_TEST_EXECUTABLE to test Rosenpass 0.2.3")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	version, err := exec.CommandContext(ctx, executable, "--version").Output()
	cancel()
	if err != nil || strings.TrimSpace(string(version)) != "rosenpass 0.2.3" {
		t.Fatal("test requires Rosenpass 0.2.3")
	}
	a, r, _ := rosenpassFixture(t)
	b, _, _ := rosenpassFixture(t)
	adapters := []*rosenpassAdapter{a, b}
	var reservations []net.PacketConn
	for _, adapter := range adapters {
		adapter.config.Executable = executable
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := exec.CommandContext(ctx, executable, "gen-keys", "--public-key", adapter.config.PublicKeyFile,
			"--secret-key", adapter.config.SecretKeyFile).Run()
		cancel()
		if err != nil {
			t.Fatal("Rosenpass test key generation failed:", err)
		}
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		reservations = append(reservations, conn)
		adapter.config.ListenPort = conn.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		// Reserve distinct ports until both have been selected.
		adapter.start = adapter.startProcess
		// Only the network validation is bypassed: no LAN changes or privileges.
		adapter.validate = func(r rosenpassRequest) (rosenpassRequest, error) { return r, nil }
	}
	a.config.PeerPublicKeyFile, b.config.PeerPublicKeyFile = b.config.PublicKeyFile, a.config.PublicKeyFile
	a.config.RemotePort, b.config.RemotePort = b.config.ListenPort, a.config.ListenPort
	r.Address, r.Link.Prefix = netip.MustParseAddr("127.0.0.1"), netip.MustParsePrefix("127.0.0.1/8")
	reservations[0].Close()
	if _, err := a.request(r, time.Now()); err != nil {
		t.Fatal("Rosenpass start failed:", err)
	}
	// Drop A's first initiation before starting B. Simultaneous initiations
	// can cross; remote key confirmation is still required in production.
	reservations[1].SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := reservations[1].ReadFrom(make([]byte, 1)); err != nil {
		t.Fatal("Rosenpass did not send its initial datagram:", err)
	}
	reservations[1].Close()
	if _, err := b.request(r, time.Now()); err != nil {
		t.Fatal("Rosenpass start failed:", err)
	}
	wait := func(timeout time.Duration, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		for i, adapter := range adapters {
			adapter.mu.Lock()
			rawValid := false
			if adapter.child != nil {
				_, err := readPSKFile(peerSpec{PresharedKeyFile: adapter.child.raw}, time.Now())
				rawValid = err == nil
			}
			t.Logf("adapter %d: active=%t valid=%t key-generation=%d raw-valid=%t", i,
				adapter.child != nil, adapter.status.Valid, adapter.status.KeyGeneration, rawValid)
			adapter.mu.Unlock()
		}
		t.Fatal("Rosenpass executable did not produce the required event")
	}
	wait(30*time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		b.mu.Lock()
		defer b.mu.Unlock()
		return a.status.Valid && b.status.Valid && a.status.Hash == b.status.Hash
	})
	keyA, errA := readPSKFile(peerSpec{PresharedKeyFile: a.config.PSKFile}, time.Now())
	keyB, errB := readPSKFile(peerSpec{PresharedKeyFile: b.config.PSKFile}, time.Now())
	if errA != nil || errB != nil || keyA != keyB {
		t.Fatal("real Rosenpass exchanges did not publish matching safe PSK files")
	}
	first, err := a.request(r, time.Now())
	if err != nil || !first.Valid || first.Generation != 1 || first.KeyGeneration == 0 {
		t.Fatal("real exchange did not produce valid generation state:", err)
	}
	info, err := os.Stat(a.config.PSKFile)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		next, err := a.request(r, time.Now())
		current, statErr := os.Stat(a.config.PSKFile)
		if err != nil || next != first || statErr != nil || !os.SameFile(info, current) {
			t.Fatal("unchanged real endpoint did not reuse valid output")
		}
	}
	if os.Getenv("ROSENPASS_TEST_STALE") != "1" {
		return
	}
	a.mu.Lock()
	child := a.child
	a.mu.Unlock()
	if _, err := b.request(rosenpassRequest{Peer: r.Peer}, time.Now()); err != nil {
		t.Fatal(err)
	}
	wait(rosenpassLifetime+20*time.Second, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		// No polling expiry here: require the actual parsed stale event.
		return child.stopEvent == "stale" && !a.status.Valid && a.child == nil &&
			a.status.Generation == first.Generation && a.status.KeyGeneration == first.KeyGeneration
	})
	if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("real stale event left a published PSK")
	}
	select {
	case <-child.done:
	default:
		t.Fatal("real stale child is still running")
	}
	if _, err := os.Stat(child.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("real stale event left private child output")
	}
	next, err := a.request(r, time.Now())
	if err != nil || next.Valid || next.Generation != first.Generation+1 || next.KeyGeneration != first.KeyGeneration {
		t.Fatal("same endpoint did not restart after the real stale event:", err)
	}
}
