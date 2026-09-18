package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func rosenpassFixture(t *testing.T) (*rosenpassAdapter, rosenpassRequest, *[]*rosenpassChild) {
	t.Helper()
	dir := t.TempDir()
	runtime := filepath.Join(dir, "private")
	if err := os.Mkdir(runtime, 0700); err != nil {
		t.Fatal(err)
	}
	a := &rosenpassAdapter{
		config: rosenpassConfig{
			Executable: "/bin/rosenpass", Peer: (wgtypes.Key{1}).String(),
			PublicKeyFile: filepath.Join(dir, "public"), SecretKeyFile: filepath.Join(dir, "secret"),
			PeerPublicKeyFile: filepath.Join(dir, "remote"), ListenPort: 9998, RemotePort: 9999,
			PSKFile: filepath.Join(dir, "psk"), RuntimeDir: runtime,
			Socket: filepath.Join(dir, "rpc"), DaemonUID: new(uint32(os.Geteuid())),
		},
		status: rosenpassResponse{Instance: "test-instance"},
	}
	r := rosenpassRequest{Peer: a.config.Peer, Address: netip.MustParseAddr("192.0.2.2"),
		Link: linkAddr{Index: 7, Name: "lan0", Prefix: netip.MustParsePrefix("192.0.2.1/24")}}
	a.validate = func(r rosenpassRequest) (rosenpassRequest, error) {
		return rosenpassOnLink(r, net.Interface{Index: 7, Name: "lan0", Flags: net.FlagUp | net.FlagBroadcast},
			[]netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")})
	}
	var children []*rosenpassChild
	a.start = func(_ rosenpassRequest, generation uint64) (*rosenpassChild, error) {
		dir, err := os.MkdirTemp(runtime, "child-")
		if err != nil {
			return nil, err
		}
		c := &rosenpassChild{generation: generation, dir: dir, raw: filepath.Join(dir, "psk.raw"), done: make(chan struct{})}
		var once sync.Once
		c.kill = func() error { once.Do(func() { close(c.done) }); return nil }
		children = append(children, c)
		return c, nil
	}
	t.Cleanup(func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if err := a.stop(); err != nil {
			t.Error(err)
		}
	})
	return a, r, &children
}

func rosenpassExchange(t *testing.T, a *rosenpassAdapter, c *rosenpassChild, key wgtypes.Key, now time.Time) {
	t.Helper()
	writeTestPSK(t, c.raw, key.String(), now)
	a.event(c, "exchanged", now)
	if !a.status.Valid || a.status.Hash != sha256.Sum256(key[:]) {
		t.Fatal("exchange did not publish the expected hash")
	}
}

func TestRosenpassEvents(t *testing.T) {
	base := "output-key peer " + (wgtypes.Key{2}).String() + ` key-file "psk.raw" `
	for _, tc := range []struct{ line, want string }{
		{base + "exchanged", "exchanged"}, {base + "stale", "stale"},
		{base + "exchanged stale", "invalid"}, {base + "stale exchanged", "invalid"},
		{base + "exchanged ", "invalid"}, {base + "EXCHANGED", "invalid"},
		{"output-key", "invalid"}, {" " + base + "exchanged", "invalid"},
		{"log: " + base + "exchanged", ""}, {"Exchanged key with peer abc", ""},
		{strings.Replace(base, "psk.raw", "another.raw", 1) + "exchanged", "invalid"},
		{strings.Replace(base, "key-file", "outfile", 1) + "exchanged", "invalid"},
		{strings.Replace(base, (wgtypes.Key{2}).String(), strings.Repeat("!", 44), 1) + "exchanged", "invalid"},
		{"", ""}, {strings.Repeat("x", 4096), ""},
	} {
		if got := parseRosenpassEvent(tc.line); got != tc.want {
			t.Errorf("event parser returned %q, want %q", got, tc.want)
		}
	}
}

func TestRosenpassLifecycle(t *testing.T) {
	a, r, children := rosenpassFixture(t)
	now := time.Now()
	status, err := a.request(r, now)
	if err != nil || status.Valid || status.Generation != 1 || status.KeyGeneration != 0 {
		t.Fatal("initial request:", status, err)
	}
	old := a.child
	rosenpassExchange(t, a, old, wgtypes.Key{10}, now)
	first := a.status
	if first.KeyGeneration != 1 {
		t.Fatal("first key generation was not recorded")
	}
	info, err := os.Stat(a.config.PSKFile)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		status, err := a.request(r, now.Add(time.Second))
		if err != nil || status != first || len(*children) != 1 {
			t.Fatal("unchanged endpoint restarted or changed the key:", err)
		}
	}
	a.event(old, "exchanged", now.Add(time.Second))
	unchanged, _ := os.Stat(a.config.PSKFile)
	if !os.SameFile(info, unchanged) || a.status != first {
		t.Fatal("duplicate exchange rewrote or renewed output")
	}
	rosenpassExchange(t, a, old, wgtypes.Key{11}, now.Add(2*time.Second))
	if a.status.Generation != first.Generation || a.status.KeyGeneration != 2 || len(*children) != 1 {
		t.Fatal("normal rekey changed the wrong generation")
	}
	a.event(old, "stale", now.Add(3*time.Second))
	if a.status.Valid || a.child != nil || old.stopEvent != "stale" {
		t.Fatal("stale event did not invalidate and stop the exchange process")
	}
	if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale output was not removed")
	}
	status, err = a.request(r, now.Add(4*time.Second))
	if err != nil || status.Valid || status.Generation != 2 || status.KeyGeneration != 2 || len(*children) != 2 {
		t.Fatal("stale recovery did not start a fresh process generation:", err)
	}
	old = a.child
	rosenpassExchange(t, a, old, wgtypes.Key{12}, now.Add(4*time.Second))
	r.Address = netip.MustParseAddr("192.0.2.3")
	status, err = a.request(r, now.Add(5*time.Second))
	if err != nil || status.Valid || status.Generation != 3 || status.KeyGeneration != 3 || len(*children) != 3 {
		t.Fatal("endpoint change did not invalidate and restart:", status, err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("old child is still running")
	}
	a.event(old, "exchanged", now.Add(6*time.Second))
	if a.status.Valid {
		t.Fatal("delayed old-generation event was accepted")
	}
	rosenpassExchange(t, a, a.child, wgtypes.Key{13}, now.Add(7*time.Second))
	current := a.status
	// Old stdout cannot publish even when a new child has valid output.
	a.event(old, "exchanged", now.Add(8*time.Second))
	a.event(old, "stale", now.Add(8*time.Second))
	a.event(old, "invalid", now.Add(8*time.Second))
	if a.status != current || current.KeyGeneration != 4 {
		t.Fatal("old generation changed the new generation")
	}
	status, err = a.request(rosenpassRequest{Peer: r.Peer}, now.Add(9*time.Second))
	if err != nil || status.Valid || a.child != nil {
		t.Fatal("withdrawal did not stop the child:", err)
	}
}

func TestRosenpassDeathExpiryAndRestart(t *testing.T) {
	for _, mode := range []string{"death", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			a, r, children := rosenpassFixture(t)
			now := time.Now()
			if _, err := a.request(r, now); err != nil {
				t.Fatal(err)
			}
			old := a.child
			rosenpassExchange(t, a, old, wgtypes.Key{21}, now)
			generation := a.status.KeyGeneration
			if mode == "death" {
				old.kill()
				now = now.Add(time.Second)
			} else {
				now = now.Add(rosenpassLifetime)
				writeTestPSK(t, old.raw, (wgtypes.Key{21}).String(), now)
				if err := os.Chtimes(a.config.PSKFile, now, now); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.refresh(now); err != nil || a.status.Valid {
				t.Fatal("dead or expired state stayed valid:", err)
			}
			if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid output remains")
			}
			if mode == "expiry" {
				a.event(old, "exchanged", now)
				if a.status.Valid || a.status.KeyGeneration != generation {
					t.Fatal("fresh mtime and duplicate event renewed an expired key")
				}
			}
			status, err := a.request(r, now.Add(time.Second))
			if err != nil || status.Valid {
				t.Fatal("same-endpoint retry trusted old output:", err)
			}
			wantChildren := 1
			if mode == "death" {
				wantChildren = 2
			}
			if len(*children) != wantChildren || int(status.Generation) != wantChildren {
				t.Fatal("wrong restart generation")
			}
		})
	}
}

func TestRosenpassStaleDuplicate(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	now := time.Now()
	if _, err := a.request(r, now); err != nil {
		t.Fatal(err)
	}
	c := a.child
	key, random := wgtypes.Key{81}, wgtypes.Key{82}
	rosenpassExchange(t, a, c, key, now)
	writeTestPSK(t, c.raw, random.String(), now.Add(time.Second))
	a.event(c, "stale", now.Add(time.Second))
	invalid := a.status
	if invalid.Valid || a.child != nil || c.stopEvent != "stale" {
		t.Fatal("stale event did not stop the child")
	}
	select {
	case <-c.done:
	default:
		t.Fatal("stale child is still running")
	}
	if _, err := os.Stat(c.dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("stale child files remain")
	}
	// Even a recreated raw path cannot make a stopped process authoritative.
	if err := os.Mkdir(c.dir, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(c.dir)
	for _, duplicate := range []wgtypes.Key{random, key, random} {
		writeTestPSK(t, c.raw, duplicate.String(), now.Add(2*time.Second))
		a.event(c, "exchanged", now.Add(2*time.Second))
		if a.status != invalid || a.status.Valid || a.child != nil {
			t.Fatal("a stale or duplicate key was republished")
		}
		if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("stale output was recreated")
		}
	}
	status, err := a.request(r, now.Add(3*time.Second))
	if err != nil || status.Valid || status.Generation != 2 || status.KeyGeneration != 1 || a.child.raw == c.raw {
		t.Fatal("stale recovery reused old process state:", err)
	}
	rosenpassExchange(t, a, a.child, wgtypes.Key{83}, now.Add(3*time.Second))
	if a.status.Generation != 2 || a.status.KeyGeneration != 2 {
		t.Fatal("new process exchange did not advance the key generation")
	}
}

func TestRosenpassQueuedStaleExchange(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	now := time.Now()
	if _, err := a.request(r, now); err != nil {
		t.Fatal(err)
	}
	old := a.child
	rosenpassExchange(t, a, old, wgtypes.Key{88}, now)
	// The child has emitted stale and then exchanged, but the scanner has
	// consumed neither event. The raw file already contains the newer key.
	newKey := wgtypes.Key{89}
	writeTestPSK(t, old.raw, newKey.String(), now.Add(time.Second))
	base := "output-key peer " + (wgtypes.Key{2}).String() + ` key-file "psk.raw" `
	a.event(old, parseRosenpassEvent(base+"stale"), now.Add(time.Second))
	if a.child != nil || a.status.Valid || a.status.KeyGeneration != 1 {
		t.Fatal("queued stale event did not discard the old process")
	}
	status, err := a.request(r, now.Add(2*time.Second))
	if err != nil || status.Valid || status.Generation != 2 || status.KeyGeneration != 1 {
		t.Fatal("same endpoint did not restart with invalid output:", err)
	}
	a.event(old, parseRosenpassEvent(base+"exchanged"), now.Add(2*time.Second))
	if a.status != status {
		t.Fatal("queued old-process exchange changed the new process state")
	}
	// A fresh process may exchange the same bytes: stale must not blacklist
	// a newer raw key that happened to precede consumption of the stale event.
	rosenpassExchange(t, a, a.child, newKey, now.Add(3*time.Second))
	current := a.status
	a.event(old, "stale", now.Add(3*time.Second))
	a.event(old, "exchanged", now.Add(3*time.Second))
	if a.status != current || current.Generation != 2 || current.KeyGeneration != 2 {
		t.Fatal("old queued events affected the recovered exchange")
	}
	status, err = a.request(r, now.Add(4*time.Second))
	if err != nil || status != current {
		t.Fatal("unchanged recovered endpoint did not reuse valid output:", err)
	}
}

func TestRosenpassMalformedEvent(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	now := time.Now()
	if _, err := a.request(r, now); err != nil {
		t.Fatal(err)
	}
	c := a.child
	rosenpassExchange(t, a, c, wgtypes.Key{84}, now)
	first := a.status
	a.event(c, parseRosenpassEvent("unrelated diagnostic"), now)
	if a.status != first {
		t.Fatal("diagnostic line changed status")
	}
	a.event(c, parseRosenpassEvent("output-key malformed"), now)
	if a.status.Valid || a.child != nil || a.status.KeyGeneration != first.KeyGeneration {
		t.Fatal("malformed key event did not stop the child and invalidate output")
	}
	if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("malformed key event left published output")
	}
	a.event(c, "exchanged", now)
	if a.status.Valid {
		t.Fatal("delayed stdout from the stopped child was accepted")
	}
}

func TestRosenpassDeadStdout(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	now := time.Now()
	if _, err := a.request(r, now); err != nil {
		t.Fatal(err)
	}
	c := a.child
	rosenpassExchange(t, a, c, wgtypes.Key{85}, now)
	c.kill()
	writeTestPSK(t, c.raw, (wgtypes.Key{86}).String(), now)
	a.event(c, "exchanged", now) // Buffered bytes may remain after process exit.
	if a.status.Valid || a.child != nil || a.status.KeyGeneration != 1 {
		t.Fatal("buffered stdout from a dead child published a key")
	}
}

func TestRosenpassPublicationGeneration(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	now := time.Now()
	if _, err := a.request(r, now); err != nil {
		t.Fatal(err)
	}
	parent := a.config.PSKFile
	a.config.PSKFile = filepath.Join(parent, "psk")
	writeTestPSK(t, a.child.raw, (wgtypes.Key{87}).String(), now)
	a.event(a.child, "exchanged", now)
	if a.status.Valid || a.status.KeyGeneration != 0 {
		t.Fatal("failed publication advanced the key generation")
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	a.event(a.child, "exchanged", now)
	if !a.status.Valid || a.status.Generation != 1 || a.status.KeyGeneration != 1 {
		t.Fatal("successful retry did not advance the key generation once")
	}
}

func TestRosenpassRejectUnsafeRaw(t *testing.T) {
	for _, mode := range []string{"missing", "partial", "permissions", "old", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			a, r, _ := rosenpassFixture(t)
			now := time.Now()
			if _, err := a.request(r, now); err != nil {
				t.Fatal(err)
			}
			c := a.child
			rosenpassExchange(t, a, c, wgtypes.Key{31}, now)
			switch mode {
			case "missing":
				os.Remove(c.raw)
			case "partial":
				writeTestPSK(t, c.raw, "partial", now)
			case "permissions":
				os.Chmod(c.raw, 0644)
			case "old":
				writeTestPSK(t, c.raw, (wgtypes.Key{32}).String(), now.Add(-rosenpassLifetime))
			case "symlink":
				os.Remove(c.raw)
				os.Symlink(a.config.PSKFile, c.raw)
			}
			a.event(c, "exchanged", now)
			if a.status.Valid {
				t.Fatal("unsafe raw output accepted")
			}
		})
	}
}

func TestRosenpassValidation(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	for _, change := range []func(*rosenpassRequest){
		func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("198.51.100.2") },
		func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("192.0.2.1") },
		func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("192.0.2.255") },
		func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("192.0.2.0") },
		func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("224.0.0.1") },
		func(r *rosenpassRequest) { r.Address = netip.MustParseAddr("::ffff:192.0.2.2") },
		func(r *rosenpassRequest) { r.Link.Index++ },
		func(r *rosenpassRequest) { r.Link.Name = "other" },
		func(r *rosenpassRequest) { r.Link.Prefix = netip.MustParsePrefix("192.0.2.1/16") },
		func(r *rosenpassRequest) { r.Link.Prefix = netip.MustParsePrefix("192.0.2.42/24") },
	} {
		bad := r
		change(&bad)
		if _, err := a.validate(bad); err == nil {
			t.Error("unsafe endpoint accepted")
		}
	}
	if _, err := a.request(rosenpassRequest{Peer: "wrong"}, time.Now()); err == nil {
		t.Fatal("unknown WG peer accepted")
	}
	iface := net.Interface{Index: 7, Name: "lan0", Flags: net.FlagUp}
	r.Link.Prefix = netip.MustParsePrefix("fe80::1/64")
	for _, address := range []string{"fe80::2", "fe80::2%lan0", "fe80::2%7"} {
		r.Address = netip.MustParseAddr(address)
		got, err := rosenpassOnLink(r, iface, []netip.Prefix{r.Link.Prefix})
		if err != nil || got.Address.String() != "fe80::2%7" {
			t.Fatal("IPv6 scope normalization failed:", err)
		}
	}
	r.Address = netip.MustParseAddr("fe80::2%8")
	if _, err := rosenpassOnLink(r, iface, []netip.Prefix{r.Link.Prefix}); err == nil {
		t.Fatal("wrong IPv6 zone accepted")
	}
	r.Address = netip.MustParseAddr("fe80::2")
	for _, flags := range []net.Flags{0, net.FlagUp | net.FlagLoopback, net.FlagUp | net.FlagPointToPoint} {
		iface.Flags = flags
		if _, err := rosenpassOnLink(r, iface, []netip.Prefix{r.Link.Prefix}); err == nil {
			t.Fatal("non-LAN interface accepted")
		}
	}
	if _, err := validateRosenpassRequest(rosenpassRequest{Link: linkAddr{Index: -1}}); err == nil {
		t.Fatal("unassigned local interface accepted")
	}
}

func TestRosenpassConfig(t *testing.T) {
	a, _, _ := rosenpassFixture(t)
	data, _ := json.Marshal(a.config)
	if _, err := readRosenpassConfig(strings.NewReader(string(data))); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*rosenpassConfig){
		func(c *rosenpassConfig) { c.DaemonUID = nil },
		func(c *rosenpassConfig) { c.Peer = "bad key" },
		func(c *rosenpassConfig) { c.ListenPort = 1023 },
		func(c *rosenpassConfig) { c.RemotePort = 0 },
		func(c *rosenpassConfig) { c.PublicKeyFile = "relative" },
		func(c *rosenpassConfig) { c.PSKFile = c.SecretKeyFile },
		func(c *rosenpassConfig) { c.PSKFile = filepath.Join(c.RuntimeDir, "adapter.lock") },
	} {
		c := a.config
		change(&c)
		data, _ := json.Marshal(c)
		if _, err := readRosenpassConfig(strings.NewReader(string(data))); err == nil {
			t.Error("invalid config accepted")
		}
	}
	for _, text := range []string{string(data) + " {}", strings.Repeat(" ", 16385), `{"remote_command":"bad"}`} {
		if _, err := readRosenpassConfig(strings.NewReader(text)); err == nil {
			t.Error("invalid JSON configuration accepted")
		}
	}
	if os.Geteuid() == 0 {
		if err := runRosenpassAdapter(context.Background(), "/not-read-as-root"); err == nil || !strings.Contains(err.Error(), "root") {
			t.Fatal("public entry point did not reject root")
		}
	}
}

func TestRosenpassAtomicOutput(t *testing.T) {
	a, _, _ := rosenpassFixture(t)
	key := wgtypes.Key{41}
	if err := publishRosenpassPSK(a.config.PSKFile, key); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(a.config.PSKFile)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := publishRosenpassPSK(a.config.PSKFile, wgtypes.Key{42}); err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(old)
	info, _ := os.Stat(a.config.PSKFile)
	got, err := readPSKFile(peerSpec{PresharedKeyFile: a.config.PSKFile}, time.Now())
	if string(data) != key.String()+"\n" || info.Mode().Perm() != 0640 || err != nil || got != (wgtypes.Key{42}) {
		t.Fatal("output was not an atomic canonical mode-0640 replacement:", err)
	}
	entries, _ := filepath.Glob(filepath.Join(filepath.Dir(a.config.PSKFile), ".rosenpass-psk-*"))
	if len(entries) != 0 {
		t.Fatal("temporary output files remain")
	}
}

func TestRosenpassTrustedDirectory(t *testing.T) {
	rosenpassVisibleRoot(t)
	// Nix's TMPDIR can have a group-writable /build ancestor. Use sticky /tmp;
	// it can be owned by root or by the build user inside the sandbox.
	t.Setenv("TMPDIR", "/tmp")
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := rosenpassTrustedDir(dir, true); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0770, 0777, 0750} {
		os.Chmod(dir, mode)
		if err := rosenpassTrustedDir(dir, true); err == nil {
			t.Error("unsafe private directory accepted")
		}
	}
	os.Chmod(dir, 0750)
	if err := rosenpassTrustedDir(dir, false); err != nil {
		t.Fatal("producer-owned group-readable directory rejected:", err)
	}
	parent := t.TempDir()
	child := filepath.Join(parent, "private")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := rosenpassTrustedDir(child, true); err != nil {
		t.Fatal("trusted sticky ancestor rejected:", err)
	}
	if err := os.Chmod(parent, 0777); err != nil {
		t.Fatal(err)
	}
	if err := rosenpassTrustedDir(child, true); err == nil {
		t.Fatal("writable ancestor without sticky protection accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(dir, link)
	if err := rosenpassTrustedDir(link, false); err == nil {
		t.Fatal("symlink directory accepted")
	}
}

func TestRosenpassSocket(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: a.config.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serveOne := func() <-chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, err := listener.AcceptUnix()
			if err == nil {
				a.handleConnection(conn)
			}
		}()
		return done
	}
	done := serveOne()
	status, err := queryRosenpass(a.config.Socket, r)
	<-done
	if err != nil || status.Valid || status.Generation != 1 {
		t.Fatal("authorized RPC failed:", err)
	}
	a.mu.Lock()
	rosenpassExchange(t, a, a.child, wgtypes.Key{51}, time.Now())
	a.mu.Unlock()
	done = serveOne()
	status, err = queryRosenpass(a.config.Socket, r)
	<-done
	if err != nil || !status.Valid {
		t.Fatal("valid status RPC failed:", err)
	}
	*a.config.DaemonUID = uint32(os.Geteuid()) + 1
	done = serveOne()
	if _, err := queryRosenpass(a.config.Socket, r); err == nil {
		t.Fatal("wrong SO_PEERCRED UID accepted")
	}
	<-done
	*a.config.DaemonUID = uint32(os.Geteuid())
	for _, data := range []string{strings.Repeat("x", rosenpassRPCSize+1) + "\n", `{"Peer":"x","command":"bad"}` + "\n", "{} {}\n"} {
		done = serveOne()
		conn, err := net.Dial("unix", a.config.Socket)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(rosenpassTimeout))
		fmt.Fprint(conn, data)
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Error("malformed RPC accepted")
		}
		conn.Close()
		<-done
	}
	done = serveOne()
	conn, err := net.Dial("unix", a.config.Socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	select {
	case <-done:
	case <-time.After(rosenpassTimeout + time.Second):
		t.Fatal("incomplete request exceeded the server deadline")
	}
}

// The wrapper execs this test binary, so process monitoring and bounded stdout
// use a real child without requiring Rosenpass or network privileges.
func TestRosenpassChildHelper(t *testing.T) {
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return
	}
	args = args[1:]
	if len(args) != 14 || args[0] != "exchange" || args[1] != "public-key" || args[3] != "secret-key" ||
		args[5] != "listen" || args[7] != "peer" || args[8] != "public-key" || args[10] != "endpoint" ||
		args[12] != "outfile" || args[13] != "psk.raw" || args[6] != "192.0.2.1:9998" || args[11] != "192.0.2.2:9999" {
		os.Exit(2)
	}
	emit := func(key wgtypes.Key, event string) {
		if err := os.WriteFile("psk.raw", []byte(key.String()), 0644); err != nil {
			os.Exit(3)
		}
		fmt.Printf("output-key peer %s key-file \"psk.raw\" %s\n", (wgtypes.Key{2}).String(), event)
	}
	emit(wgtypes.Key{61}, "exchanged")
	for {
		for _, command := range []string{"stale", "rekey", "oversized", "exit"} {
			if _, err := os.Stat(command); err != nil {
				continue
			}
			os.Remove(command)
			switch command {
			case "stale":
				emit(wgtypes.Key{62}, "stale")
			case "rekey":
				emit(wgtypes.Key{63}, "exchanged")
			case "oversized":
				fmt.Println(strings.Repeat("x", 4096))
			case "exit":
				os.Exit(0)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func rosenpassWait(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Rosenpass test timed out")
}

func TestRosenpassRealChild(t *testing.T) {
	a, r, _ := rosenpassFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a.config.Executable = filepath.Join(filepath.Dir(a.config.PSKFile), "fake-rp")
	script := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=^TestRosenpassChildHelper$ -- \"$@\"\n", executable)
	if err := os.WriteFile(a.config.Executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	a.start = a.startProcess
	if _, err := a.request(r, time.Now()); err != nil {
		t.Fatal(err)
	}
	rosenpassWait(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.status.Valid
	})
	a.mu.Lock()
	c := a.child
	first := a.status
	a.mu.Unlock()
	send := func(command string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(c.dir, command), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	send("rekey")
	rosenpassWait(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.status.Valid && a.status.Hash != first.Hash && a.status.Generation == first.Generation &&
			a.status.KeyGeneration == first.KeyGeneration+1 && a.child == c
	})
	send("stale")
	rosenpassWait(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.child == nil && !a.status.Valid && c.stopEvent == "stale"
	})
	restart := func(generation, keyGeneration uint64) {
		t.Helper()
		rosenpassWait(t, func() bool {
			status, err := a.request(r, time.Now())
			return err == nil && status.Valid && status.Generation == generation && status.KeyGeneration == keyGeneration
		})
		a.mu.Lock()
		c = a.child
		a.mu.Unlock()
	}
	restart(first.Generation+1, first.KeyGeneration+2)
	send("oversized")
	rosenpassWait(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.child == nil && !a.status.Valid
	})
	restart(first.Generation+2, first.KeyGeneration+3)
	send("exit")
	rosenpassWait(t, func() bool {
		a.mu.Lock()
		defer a.mu.Unlock()
		return a.child == nil && !a.status.Valid
	})
}

func TestRosenpassServer(t *testing.T) {
	rosenpassVisibleRoot(t)
	t.Setenv("TMPDIR", "/tmp")
	a, _, _ := rosenpassFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeTestPSK(t, a.config.PSKFile, (wgtypes.Key{71}).String(), time.Now())
	if _, err := readPSKFile(peerSpec{PresharedKeyFile: a.config.PSKFile}, time.Now()); err != nil {
		t.Fatal("restart fixture needs a fresh, valid PSK:", err)
	}
	orphan := filepath.Join(a.config.RuntimeDir, "child-old")
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestPSK(t, filepath.Join(orphan, "psk.raw"), (wgtypes.Key{71}).String(), time.Now())
	done := make(chan error, 1)
	go func() { done <- serveRosenpassAdapter(ctx, a.config) }()
	rosenpassWait(t, func() bool {
		select {
		case err := <-done:
			t.Fatalf("Rosenpass server stopped before creating its socket: %v", err)
		default:
		}
		info, err := os.Stat(a.config.Socket)
		return err == nil && info.Mode().Perm() == 0660
	})
	if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("server start retained old output")
	}
	if err := serveRosenpassAdapter(ctx, a.config); err == nil {
		t.Fatal("second adapter acquired the same runtime")
	}
	status, err := queryRosenpass(a.config.Socket, rosenpassRequest{Peer: a.config.Peer})
	if err != nil || status.Valid || status.Instance == "" {
		t.Fatal("server withdrawal RPC failed:", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	writeTestPSK(t, a.config.PSKFile, (wgtypes.Key{71}).String(), time.Now())
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- serveRosenpassAdapter(ctx, a.config) }()
	rosenpassWait(t, func() bool {
		info, err := os.Stat(a.config.Socket)
		return err == nil && info.Mode().Perm() == 0660
	})
	if _, err := os.Stat(a.config.PSKFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("server restart reused a fresh runtime PSK")
	}
	next, err := queryRosenpass(a.config.Socket, rosenpassRequest{Peer: a.config.Peer})
	if err != nil || next.Instance == status.Instance || next.Valid || next.Generation != 0 || next.KeyGeneration != 0 {
		t.Fatal("server restart reused old exchange state:", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func rosenpassVisibleRoot(t *testing.T) {
	t.Helper()
	info, err := os.Stat("/")
	if err != nil {
		t.Fatal(err)
	}
	if uid := info.Sys().(*syscall.Stat_t).Uid; uid != 0 && uid != uint32(os.Geteuid()) {
		// Several different host owners can all appear as the overflow UID.
		// Do not weaken the production ownership policy for a build sandbox.
		t.Skip("trusted-ancestry integration requires visible root ownership; run outside the user-namespace build sandbox")
	}
}
