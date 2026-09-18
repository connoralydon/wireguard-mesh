//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Requires isolated Linux root, network/mount namespace permissions, kernel
// WireGuard, ip, wg, ping, and tc with clsact, u32, and the drop action. No daemon
// or external network is used. Run only on a disposable test machine:
//
//	WGMESH_REKEY_TEST=1 go test -run '^TestLinuxPSKRekey$' -count=1 -v -timeout=6m
//
// This is an experimental observation test, not a zero-loss or safety test.
// Linux v6.12 and v6.18 set_peer only copy the PSK; existing session keys survive.
// A responder's old next_keypair can later become current and update its handshake
// timestamp. Thus a timestamp after a setter ACK does not identify the PSK used.
// Sources (functions: set_peer, mix_psk, wg_noise_received_with_keypair,
// wg_timers_handshake_complete, decrypt_packet, wg_packet_send_staged_packets):
// https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireguard/netlink.c
// https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireguard/noise.c
// https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireguard/timers.c
// https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireguard/receive.c
// https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireguard/send.c
// https://github.com/torvalds/linux/blob/v6.18/drivers/net/wireguard/messages.h
func TestLinuxPSKRekey(t *testing.T) {
	if os.Getenv("WGMESH_REKEY_TEST") != "1" {
		t.Skip("set WGMESH_REKEY_TEST=1 to enable the Linux PSK rekey test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the namespace test requires isolated root")
	}
	for _, tool := range []string{"ip", "wg", "tc", "ping"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, scenario := range []string{"FreshHandshake", "PendingConfirmation"} {
		t.Run(scenario, func(t *testing.T) {
			pending := scenario == "PendingConfirmation"
			run := func(parent context.Context, ns string, args ...string) (string, error) {
				if ns != "" {
					args = append([]string{"ip", "netns", "exec", ns}, args...)
				}
				cmdCtx, stop := context.WithTimeout(parent, 5*time.Second)
				defer stop()
				cmd := exec.CommandContext(cmdCtx, args[0], args[1:]...)
				cmd.WaitDelay = time.Second
				out, err := cmd.CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			must := func(ns string, args ...string) string {
				t.Helper()
				out, err := run(ctx, ns, args...)
				if err != nil {
					// Do not include command output: key parser errors can contain keys.
					t.Fatalf("namespace %s: %v: %v (output withheld)", ns, args, err)
				}
				return out
			}
			pause := func(d time.Duration) {
				t.Helper()
				select {
				case <-time.After(d):
				case <-ctx.Done():
					t.Fatal("rekey test deadline exceeded")
				}
			}
			root := t.TempDir()
			writeKey := func(name string, key wgtypes.Key) string {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.WriteFile(path, []byte(key.String()+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				return path
			}
			var psk [2]string
			for i := range psk {
				key, err := wgtypes.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				psk[i] = writeKey(fmt.Sprintf("psk%d", i), key)
			}
			prefix := "wgmesh-rekey-" + rand.Text()[:12]
			ns := [2]string{prefix + "-a", prefix + "-b"}
			underlay := [2]string{"192.0.2.1", "192.0.2.2"}
			tunnel := [2]string{"10.78.0.1", "10.78.0.2"}
			var public [2]string
			for i, name := range ns {
				must("", "ip", "netns", "add", name)
				t.Cleanup(func() {
					// Cleanup has its own deadline, even if the test context expired.
					if _, err := run(context.Background(), "", "ip", "netns", "delete", name); err != nil {
						t.Errorf("delete namespace %s: %v", name, err)
					}
				})
				key, err := wgtypes.GeneratePrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				public[i] = key.PublicKey().String()
				private := writeKey(fmt.Sprintf("private%d", i), key)
				must(name, "ip", "link", "set", "lo", "up")
				// Create the device here so its UDP socket is also isolated.
				must(name, "ip", "link", "add", "wg0", "type", "wireguard")
				must(name, "wg", "set", "wg0", "private-key", private, "listen-port", "51820")
				must(name, "ip", "address", "add", tunnel[i]+"/24", "dev", "wg0")
				must(name, "ip", "link", "set", "wg0", "up")
			}
			// Neither end of the underlay ever enters the host network namespace.
			must(ns[0], "ip", "link", "add", "wan0", "type", "veth", "peer", "name", "wan0", "netns", ns[1])
			for i, name := range ns {
				must(name, "ip", "address", "add", underlay[i]+"/24", "dev", "wan0")
				must(name, "ip", "link", "set", "wan0", "up")
				must(name, "tc", "qdisc", "add", "dev", "wan0", "clsact")
				must(name, "wg", "set", "wg0", "peer", public[1-i], "preshared-key", psk[0],
					"endpoint", underlay[1-i]+":51820", "allowed-ips", tunnel[1-i]+"/32")
			}
			checkPeer := func() {
				t.Helper()
				for i, name := range ns {
					if must(name, "wg", "show", "wg0", "peers") != public[1-i] {
						t.Fatal("peer set changed")
					}
					for field, want := range map[string]string{
						"endpoints":   underlay[1-i] + ":51820",
						"allowed-ips": tunnel[1-i] + "/32",
					} {
						got := strings.Fields(must(name, "wg", "show", "wg0", field))
						if len(got) != 2 || got[0] != public[1-i] || got[1] != want {
							t.Fatalf("peer %d: %s changed", i, field)
						}
					}
				}
			}
			handshakes := func() (times [2]int64) {
				t.Helper()
				for i, name := range ns {
					fields := strings.Fields(must(name, "wg", "show", "wg0", "latest-handshakes"))
					if len(fields) != 2 || fields[0] != public[1-i] {
						t.Fatal("unexpected handshake status")
					}
					var err error
					times[i], err = strconv.ParseInt(fields[1], 10, 64)
					if err != nil {
						t.Fatal("invalid handshake timestamp")
					}
				}
				return times
			}
			ping := func(i int) bool {
				t.Helper()
				_, err := run(ctx, ns[i], "ping", "-n", "-I", "wg0", "-c", "1", "-W", "1", "-w", "2", tunnel[1-i])
				var exit *exec.ExitError
				if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
					t.Fatalf("ping command failed: %v", err)
				}
				return err == nil
			}
			filter := func(i, kind int, drop bool) {
				t.Helper()
				args := []string{"tc", "filter", "del", "dev", "wan0", "egress", "protocol", "ip", "pref", strconv.Itoa(kind)}
				if drop {
					args[2] = "add"
					// This test uses IPv4 without options: 20 IP + 8 UDP bytes.
					// Drop, never delay, so removing a filter releases no old packets.
					args = append(args, "u32", "match", "ip", "protocol", "17", "0xff",
						"match", "ip", "dport", "51820", "0xffff",
						"match", "u32", fmt.Sprintf("0x%02x000000", kind), "0xffffffff", "at", "28", "action", "drop")
				}
				must(ns[i], args...)
			}
			if pending {
				filter(0, 4, true) // Prevent the first data packet from confirming B's next_keypair.
			}
			if ok := ping(0); ok == pending {
				t.Fatal("unexpected initial transport result")
			}
			before := handshakes()
			if before[0] == 0 || (before[1] == 0) != pending {
				t.Fatal("initial handshake did not reach the required state")
			}
			for i := range ns {
				filter(i, 1, true)
				filter(i, 2, true)
			}
			checkPeer()
			// Every update after setup contains only the peer identifier and PSK.
			must(ns[1], "wg", "set", "wg0", "peer", public[0], "preshared-key", psk[1])
			updated := time.Now().Unix()
			// wg prints whole seconds, unlike the netlink timespec. Cross a second
			// boundary before the delayed confirmation; never accept equality.
			pause(1100 * time.Millisecond)
			if pending {
				filter(0, 4, false)
			}
			if !ping(0) || !ping(1) {
				t.Fatal("old transport did not survive the PSK mismatch")
			}
			checkPeer()
			after := handshakes()
			if pending {
				if after[0] != before[0] || after[1] <= updated {
					t.Fatal("did not observe post-update confirmation of the old pending keypair")
				}
				t.Log("PSKs differ and handshakes are blocked, but B has a post-update timestamp: old next_keypair promotion")
				return
			}
			if after != before {
				t.Fatal("handshake timestamps changed while handshake packets were blocked")
			}
			t.Log("PSKs differ, old transport works, and handshake timestamps are unchanged")
			must(ns[0], "wg", "set", "wg0", "peer", public[1], "preshared-key", psk[1])
			checkPeer()
			// REJECT_AFTER_TIME is 180s from key derivation, not from the PSK
			// setter or handshake timestamp. Both old sessions completed before
			// the drops and updates. No pending old response is held by this test.
			// 185s is a fixture bound, NOT a general scheduler/queue drain bound:
			// an arbitrarily stalled old handshake worker invalidates that claim.
			t.Log("waiting 185s with handshakes blocked for the old transport keys to expire")
			started := time.Now()
			pause(185 * time.Second)
			elapsed := time.Since(started)
			wallElapsed := time.Duration(time.Now().UnixNano() - started.UnixNano())
			if delta := wallElapsed - elapsed; delta < -time.Second || delta > time.Second {
				t.Fatal("wall clock changed during the observation; timestamps are inconclusive")
			}
			if ping(0) {
				t.Fatal("transport still works past the old-key expiry bound with handshakes blocked")
			}
			if handshakes() != before {
				t.Fatal("unexpected handshake while handshake packets were blocked")
			}
			cutoff := time.Now().Unix()
			pause(1100 * time.Millisecond)
			for i := range ns {
				filter(i, 1, false)
				filter(i, 2, false)
			}
			for deadline := time.Now().Add(30 * time.Second); ; pause(200 * time.Millisecond) {
				// Traffic triggers a handshake, but does not itself prove rekeying.
				ping(0)
				after = handshakes()
				if after[0] > cutoff && after[1] > cutoff {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("no fresh handshake on both peers after the matching PSK-only update")
				}
			}
			checkPeer()
			if !ping(0) || !ping(1) {
				t.Fatal("transport failed after the fresh handshake")
			}
			t.Log("fresh handshake observed on both peers after old-key expiry and removal of handshake drops; endpoint and AllowedIPs retained")
		})
	}
}
