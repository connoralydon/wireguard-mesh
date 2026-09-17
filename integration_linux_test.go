//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Requires root, network namespace permissions, kernel WireGuard, and netem.
// Opt in with WGMESH_NETNS_TEST=1 and WGMESH_TEST_BINARY=/absolute/path/to/daemon.
// The binary must already exist. This test does not build it or use QEMU.
func TestNetNSDirectFailover(t *testing.T) {
	if os.Getenv("WGMESH_NETNS_TEST") != "1" {
		t.Skip("set WGMESH_NETNS_TEST=1 to enable the Linux namespace test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the namespace test requires root")
	}
	binary := os.Getenv("WGMESH_TEST_BINARY")
	if !filepath.IsAbs(binary) {
		t.Fatal("WGMESH_TEST_BINARY must name an existing absolute daemon path")
	}
	for _, tool := range []string{"ip", "wg", "tc", "ping", "sysctl", binary} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	run := func(ns string, args ...string) (string, error) {
		if ns != "" {
			args = append([]string{"ip", "netns", "exec", ns}, args...)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.WaitDelay = time.Second
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	must := func(ns string, args ...string) string {
		t.Helper()
		out, err := run(ns, args...)
		if err != nil {
			t.Fatalf("namespace %s: %v: %v\n%s", ns, args, err, out)
		}
		return strings.TrimSpace(out)
	}
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	prefix := "wgmesh-" + rand.Text()[:12]
	ns := []string{prefix + "-a", prefix + "-b", prefix + "-c"}
	ip := []string{"10.77.0.1", "10.77.0.2", "10.77.0.3"}
	var dirs, public [3]string
	for i, name := range ns {
		must("", "ip", "netns", "add", name)
		t.Cleanup(func() {
			if out, err := run("", "ip", "netns", "delete", name); err != nil {
				t.Errorf("delete namespace %s: %v\n%s", name, err, out)
			}
		})
		dirs[i] = filepath.Join(root, name)
		if err := os.Mkdir(dirs[i], 0700); err != nil {
			t.Fatal(err)
		}
		key := filepath.Join(dirs[i], "private.key")
		write(key, must(name, "wg", "genkey")+"\n")
		must(name, "ip", "link", "set", "lo", "up")
		// Create WireGuard here so its UDP socket belongs to this namespace.
		must(name, "ip", "link", "add", "wg0", "type", "wireguard")
		must(name, "wg", "set", "wg0", "private-key", key, "listen-port", "51820")
		public[i] = must(name, "wg", "show", "wg0", "public-key")
		must(name, "ip", "address", "add", ip[i]+"/24", "dev", "wg0")
		must(name, "ip", "link", "set", "wg0", "up")
	}
	for i := 1; i <= 2; i++ {
		wan, hub := fmt.Sprintf("172.20.%d.2", i), fmt.Sprintf("172.20.%d.1", i)
		dev := fmt.Sprintf("wan%d", i)
		must(ns[i], "ip", "link", "add", "wan0", "type", "veth", "peer", "name", dev, "netns", ns[0])
		must(ns[i], "ip", "address", "add", wan+"/24", "dev", "wan0")
		must(ns[0], "ip", "address", "add", hub+"/24", "dev", dev)
		must(ns[i], "ip", "link", "set", "wan0", "up")
		must(ns[0], "ip", "link", "set", dev, "up")
		must(ns[i], "tc", "qdisc", "add", "dev", "wan0", "root", "netem", "delay", "20ms")
		must(ns[0], "tc", "qdisc", "add", "dev", dev, "root", "netem", "delay", "20ms")
		must(ns[i], "wg", "set", "wg0", "peer", public[0], "allowed-ips", "10.77.0.0/24", "endpoint", hub+":51820")
		must(ns[0], "wg", "set", "wg0", "peer", public[i], "allowed-ips", ip[i]+"/32", "endpoint", wan+":51820")
	}
	must(ns[0], "sysctl", "-qw", "net.ipv4.ip_forward=1")
	// All underlay links stay inside the new namespaces, never on the host.
	must(ns[1], "ip", "link", "add", "lan0", "type", "veth", "peer", "name", "lan1", "netns", ns[2])
	must(ns[2], "ip", "link", "set", "lan1", "name", "lan0")
	for i := 1; i <= 2; i++ {
		must(ns[i], "ip", "address", "add", fmt.Sprintf("192.0.2.%d/24", i+1), "dev", "lan0")
		must(ns[i], "ip", "link", "set", "lan0", "up")
	}
	peerState := func(i int, direct bool) bool {
		want := map[string]string{public[0]: "10.77.0.0/24"}
		if direct {
			want[public[3-i]] = ip[3-i] + "/32"
		}
		keys := strings.Fields(must(ns[i], "wg", "show", "wg0", "peers"))
		if len(keys) != len(want) {
			return false
		}
		for _, key := range keys {
			if _, ok := want[key]; !ok {
				return false
			}
		}
		allowed := strings.Fields(must(ns[i], "wg", "show", "wg0", "allowed-ips"))
		if len(allowed) != 2*len(want) {
			return false
		}
		for j := 0; j < len(allowed); j += 2 {
			if want[allowed[j]] != allowed[j+1] {
				return false
			}
		}
		return true
	}
	ping := func() {
		t.Helper()
		for i := 1; i <= 2; i++ {
			must(ns[i], "ping", "-n", "-I", "wg0", "-c", "3", "-i", "0.2", "-W", "1", "-w", "4", ip[3-i])
		}
	}
	if !peerState(1, false) || !peerState(2, false) {
		t.Fatal("initial peers must contain only the stable hub")
	}
	ping() // Prove stable routing before either daemon starts.
	type service struct {
		name, log string
		done      chan struct{}
		err       error
	}
	var services []*service
	for i := 1; i <= 2; i++ {
		config := filepath.Join(dirs[i], "config.json")
		write(config, fmt.Sprintf(`{"address":%q,"port":51821,"include":["lan0"],
			"peers":[{"public_key":%q,"ip":%q}],"discovery_interval":"1s",
			"broadcast_after":"3s","probe_interval":"200ms","latency_window":"3s",
			"failure_timeout":"1s","cooldown":"3s","minimum_gain":"2ms","minimum_gain_fraction":0.2}`,
			ip[i], public[3-i], ip[3-i]))
		s := &service{name: ns[i], log: filepath.Join(dirs[i], "daemon.log"), done: make(chan struct{})}
		log, err := os.OpenFile(s.log, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = log.Close() })
		cmd := exec.Command("ip", "netns", "exec", ns[i], binary, "-wireguard", "wg0", "-config", config,
			"-state", filepath.Join(dirs[i], "recovery.json"))
		cmd.Env = append(os.Environ(), "NOTIFY_SOCKET=")
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { s.err = cmd.Wait(); close(s.done) }()
		t.Cleanup(func() {
			select {
			case <-s.done:
				t.Errorf("daemon %s exited before cleanup: %v", s.name, s.err)
			default:
				_ = cmd.Process.Signal(syscall.SIGTERM)
				select {
				case <-s.done:
					if s.err != nil {
						t.Errorf("stop daemon %s: %v", s.name, s.err)
					}
				case <-time.After(3 * time.Second):
					_ = cmd.Process.Kill()
					<-s.done
					t.Errorf("daemon %s required SIGKILL", s.name)
				}
			}
			if t.Failed() {
				text, _ := os.ReadFile(s.log)
				t.Logf("daemon %s:\n%s", s.name, text)
			}
		})
		services = append(services, s)
	}
	wait := func(label string, ready func() bool) {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			for _, s := range services {
				select {
				case <-s.done:
					t.Fatalf("daemon %s exited: %v", s.name, s.err)
				default:
				}
			}
			if ready() {
				return
			}
		}
		t.Fatalf("timeout waiting for %s", label)
	}
	wait("direct peers and active paths on both nodes", func() bool {
		for i, s := range services {
			text, err := os.ReadFile(s.log)
			if err != nil || !strings.Contains(string(text), "direct path active") || !peerState(i+1, true) {
				return false
			}
		}
		return true
	})
	ping()
	if !peerState(1, true) || !peerState(2, true) {
		t.Fatal("direct peers disappeared during tunnel ping")
	}
	must(ns[1], "ip", "link", "delete", "lan0") // Deletes both LAN ends.
	wait("managed peers removed and hub AllowedIPs retained", func() bool {
		return peerState(1, false) && peerState(2, false)
	})
	ping()
}
